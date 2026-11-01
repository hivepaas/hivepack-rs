// hivepack-rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! PPMd variant H, as RAR 3 uses it: UnRAR's model.cpp, suballoc.cpp and
//! coder.cpp, originally by Dmitry Shkarin and Dmitry Subbotin.
//!
//! UnRAR keeps the model in a heap of its own, with pointers in it. Here the
//! heap is a byte array and the pointers are offsets into it, in the layout
//! the algorithm was made for: a state of 6 bytes, a context and a unit of 12.
//! UnRAR's larger structures are its adjustment of the same algorithm to
//! 64-bit pointers, which keeps to the sizes of this layout for all decisions
//! (its `FakeUnitsStart`), so what comes out is the same. An offset of 0 is a
//! null pointer: nothing is ever placed at the start of the heap but text,
//! whose first pointer is past its first byte.
//!
//! Memory that is out of the heap reads as zeros and ignores writes, and the
//! loops that look for a symbol stop at the heap's end. A sound model never
//! gets there. UnRAR's checks against an unsound one are kept as they are.

use crate::error::Error;

use super::{UnpIo, Unpack};

const MAX_O: usize = 64;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;

const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const TOT_BITS: u32 = INT_BITS + PERIOD_BITS;
const INTERVAL: u32 = 1 << INT_BITS;
const BIN_SCALE: u32 = 1 << TOT_BITS;
const MAX_FREQ: u32 = 124;

const UNIT_SIZE: u32 = 12;
const FIXED_UNIT_SIZE: u32 = 12;
const STATE_SIZE: u32 = 6;

const N1: usize = 4;
const N2: usize = 4;
const N3: usize = 4;
const N4: usize = (128 + 3 - N1 - 2 * N2 - 3 * N3) / 4;
const N_INDEXES: usize = N1 + N2 + N3 + N4;

const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

/// `GET_MEAN`.
#[inline(always)]
fn get_mean(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}

/// `RARPPM_SEE2_CONTEXT`.
#[derive(Clone, Copy, Default)]
struct See2 {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See2 {
    fn init(&mut self, init_val: u32) {
        self.shift = (PERIOD_BITS - 4) as u8;
        self.summ = (init_val << self.shift) as u16;
        self.count = 4;
    }

    fn get_mean(&mut self) -> u32 {
        let ret = self.summ >> self.shift;
        self.summ = self.summ.wrapping_sub(ret);
        u32::from(ret) + u32::from(ret == 0)
    }

    fn update(&mut self) {
        if u32::from(self.shift) < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_add(self.summ);
                self.count = 3u8.wrapping_shl(u32::from(self.shift));
                self.shift += 1;
            }
        }
    }
}

/// `RARPPM_STATE` out of the heap.
#[derive(Clone, Copy, Default)]
struct State {
    symbol: u8,
    freq: u8,
    successor: u32,
}

/// Which SEE context `makeEscFreq2` chose.
#[derive(Clone, Copy)]
enum SeeChoice {
    Table(usize, usize),
    Dummy,
}

/// `ModelPPM`, with its `RangeCoder` and `SubAllocator`.
pub(super) struct ModelPpm {
    // RangeCoder.
    low: u32,
    code: u32,
    range: u32,
    low_count: u32,
    high_count: u32,
    scale: u32,

    // SubAllocator.
    mem: Vec<u8>,
    sub_allocator_size: u32,
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    glue_count: u8,
    lo_unit: u32,
    hi_unit: u32,
    free_list: [u32; N_INDEXES],
    p_text: u32,
    units_start: u32,
    heap_end: u32,
    fake_units_start: u32,
    /// `s0` of `GlueFreeBlocks`: a unit past the heap's end.
    list_head: u32,

    // ModelPPM.
    see2_cont: [[See2; 16]; 25],
    dummy_see2_cont: See2,
    min_context: u32,
    max_context: u32,
    found_state: u32,
    num_masked: i32,
    init_esc: i32,
    order_fall: i32,
    max_order: i32,
    run_length: i32,
    init_rl: i32,
    char_mask: [u8; 256],
    ns2indx: [u8; 256],
    ns2bs_indx: [u8; 256],
    hb2flag: [u8; 256],
    esc_count: u8,
    prev_success: u8,
    hi_bits_flag: u8,
    bin_summ: [[u16; 64]; 128],
    /// `ps` of `decodeSymbol2`, which is not cleared for each symbol here.
    ps: [u32; 256],
}

impl ModelPpm {
    pub(super) fn new() -> ModelPpm {
        ModelPpm {
            low: 0,
            code: 0,
            range: 0,
            low_count: 0,
            high_count: 0,
            scale: 0,
            mem: Vec::new(),
            sub_allocator_size: 0,
            indx2units: [0; N_INDEXES],
            units2indx: [0; 128],
            glue_count: 0,
            lo_unit: 0,
            hi_unit: 0,
            free_list: [0; N_INDEXES],
            p_text: 0,
            units_start: 0,
            heap_end: 0,
            fake_units_start: 0,
            list_head: 0,
            see2_cont: [[See2::default(); 16]; 25],
            dummy_see2_cont: See2::default(),
            min_context: 0,
            max_context: 0,
            found_state: 0,
            num_masked: 0,
            init_esc: 0,
            order_fall: 0,
            max_order: 0,
            run_length: 0,
            init_rl: 0,
            char_mask: [0; 256],
            ns2indx: [0; 256],
            ns2bs_indx: [0; 256],
            hb2flag: [0; 256],
            esc_count: 0,
            prev_success: 0,
            hi_bits_flag: 0,
            bin_summ: [[0; 64]; 128],
            ps: [0; 256],
        }
    }

    // The heap.

    #[inline(always)]
    fn r8(&self, at: u32) -> u8 {
        self.mem.get(at as usize).copied().unwrap_or(0)
    }

    #[inline(always)]
    fn w8(&mut self, at: u32, value: u8) {
        if let Some(byte) = self.mem.get_mut(at as usize) {
            *byte = value;
        }
    }

    /// `N` bytes at `at`, where all of them are in the heap: one bounds check
    /// for them all.
    #[inline(always)]
    fn bytes<const N: usize>(&self, at: u32) -> Option<&[u8; N]> {
        self.mem.get(at as usize..)?.first_chunk()
    }

    /// As [`ModelPpm::bytes`], to write.
    #[inline(always)]
    fn bytes_mut<const N: usize>(&mut self, at: u32) -> Option<&mut [u8; N]> {
        self.mem.get_mut(at as usize..)?.first_chunk_mut()
    }

    #[inline(always)]
    fn r16(&self, at: u32) -> u16 {
        match self.bytes(at) {
            Some(bytes) => u16::from_le_bytes(*bytes),
            None => u16::from_le_bytes([self.r8(at), self.r8(at.wrapping_add(1))]),
        }
    }

    #[inline(always)]
    fn w16(&mut self, at: u32, value: u16) {
        let [a, b] = value.to_le_bytes();
        match self.bytes_mut(at) {
            Some(bytes) => *bytes = [a, b],
            None => {
                self.w8(at, a);
                self.w8(at.wrapping_add(1), b);
            }
        }
    }

    #[inline(always)]
    fn r32(&self, at: u32) -> u32 {
        match self.bytes(at) {
            Some(bytes) => u32::from_le_bytes(*bytes),
            None => u32::from_le_bytes([
                self.r8(at),
                self.r8(at.wrapping_add(1)),
                self.r8(at.wrapping_add(2)),
                self.r8(at.wrapping_add(3)),
            ]),
        }
    }

    #[inline(always)]
    fn w32(&mut self, at: u32, value: u32) {
        let [a, b, c, d] = value.to_le_bytes();
        match self.bytes_mut(at) {
            Some(bytes) => *bytes = [a, b, c, d],
            None => {
                self.w8(at, a);
                self.w8(at.wrapping_add(1), b);
                self.w8(at.wrapping_add(2), c);
                self.w8(at.wrapping_add(3), d);
            }
        }
    }

    // A state.

    #[inline(always)]
    fn symbol(&self, state: u32) -> u8 {
        self.r8(state)
    }

    #[inline(always)]
    fn freq(&self, state: u32) -> u8 {
        self.r8(state.wrapping_add(1))
    }

    #[inline(always)]
    fn set_freq(&mut self, state: u32, freq: u8) {
        self.w8(state.wrapping_add(1), freq);
    }

    #[inline(always)]
    fn successor(&self, state: u32) -> u32 {
        self.r32(state.wrapping_add(2))
    }

    #[inline(always)]
    fn set_successor(&mut self, state: u32, successor: u32) {
        self.w32(state.wrapping_add(2), successor);
    }

    #[inline(always)]
    fn state(&self, at: u32) -> State {
        State {
            symbol: self.symbol(at),
            freq: self.freq(at),
            successor: self.successor(at),
        }
    }

    #[inline(always)]
    fn set_state(&mut self, at: u32, state: State) {
        self.w8(at, state.symbol);
        self.set_freq(at, state.freq);
        self.set_successor(at, state.successor);
    }

    #[inline(always)]
    fn swap_states(&mut self, a: u32, b: u32) {
        let (x, y) = (self.state(a), self.state(b));
        self.set_state(a, y);
        self.set_state(b, x);
    }

    // A context: `NumStats` at 0, then at 2 either `OneState` or `SummFreq`
    // and at 4 `Stats`, and `Suffix` at 8.

    #[inline(always)]
    fn num_stats(&self, ctx: u32) -> u32 {
        u32::from(self.r16(ctx))
    }

    #[inline(always)]
    fn set_num_stats(&mut self, ctx: u32, value: u32) {
        self.w16(ctx, value as u16);
    }

    #[inline(always)]
    fn summ_freq(&self, ctx: u32) -> u32 {
        u32::from(self.r16(ctx.wrapping_add(2)))
    }

    #[inline(always)]
    fn set_summ_freq(&mut self, ctx: u32, value: u32) {
        self.w16(ctx.wrapping_add(2), value as u16);
    }

    #[inline(always)]
    fn stats(&self, ctx: u32) -> u32 {
        self.r32(ctx.wrapping_add(4))
    }

    #[inline(always)]
    fn set_stats(&mut self, ctx: u32, value: u32) {
        self.w32(ctx.wrapping_add(4), value);
    }

    #[inline(always)]
    fn one_state(ctx: u32) -> u32 {
        ctx.wrapping_add(2)
    }

    #[inline(always)]
    fn suffix(&self, ctx: u32) -> u32 {
        self.r32(ctx.wrapping_add(8))
    }

    #[inline(always)]
    fn set_suffix(&mut self, ctx: u32, value: u32) {
        self.w32(ctx.wrapping_add(8), value);
    }

    /// The state with this symbol among those from `state` on. A sound model
    /// has it, and 0 says it is not sound.
    #[inline(always)]
    fn find_symbol(&self, mut state: u32, symbol: u8) -> u32 {
        while self.symbol(state) != symbol {
            state = state.wrapping_add(STATE_SIZE);
            if state as usize >= self.mem.len() {
                return 0;
            }
        }
        state
    }

    // `SubAllocator`.

    #[inline(always)]
    fn insert_node(&mut self, p: u32, indx: usize) {
        self.w32(p, self.free_list[indx]);
        self.free_list[indx] = p;
    }

    #[inline(always)]
    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.r32(node);
        node
    }

    #[inline(always)]
    fn split_block(&mut self, pv: u32, old_indx: usize, new_indx: usize) {
        let mut u_diff = usize::from(self.indx2units[old_indx] - self.indx2units[new_indx]);
        let mut p = pv + UNIT_SIZE * u32::from(self.indx2units[new_indx]);
        let mut i = usize::from(self.units2indx[u_diff - 1]);
        if usize::from(self.indx2units[i]) != u_diff {
            i -= 1;
            self.insert_node(p, i);
            let units = usize::from(self.indx2units[i]);
            p += UNIT_SIZE * units as u32;
            u_diff -= units;
        }
        self.insert_node(p, usize::from(self.units2indx[u_diff - 1]));
    }

    fn stop_sub_allocator(&mut self) {
        // The memory stays, for whatever still points at it.
        self.sub_allocator_size = 0;
    }

    fn start_sub_allocator(&mut self, sa_size: u32) -> Result<(), Error> {
        let t = sa_size << 20;
        if self.sub_allocator_size == t {
            return Ok(());
        }
        self.stop_sub_allocator();

        // One more unit for HeapEnd's checks, one for alignment in UnRAR, and
        // one for the head of the list of `glue_free_blocks`.
        let alloc_size = t / FIXED_UNIT_SIZE * UNIT_SIZE + 2 * UNIT_SIZE;
        let total = alloc_size as usize + UNIT_SIZE as usize;
        let mut probe = Vec::<u8>::new();
        probe
            .try_reserve_exact(total)
            .map_err(|_| Error::NoMemory)?;
        drop(probe);
        self.mem = vec![0; total];

        self.heap_end = alloc_size - UNIT_SIZE;
        self.list_head = alloc_size;
        self.sub_allocator_size = t;
        Ok(())
    }

    fn init_sub_allocator(&mut self) {
        self.free_list = [0; N_INDEXES];
        self.p_text = 0;

        let size2 = FIXED_UNIT_SIZE * (self.sub_allocator_size / 8 / FIXED_UNIT_SIZE * 7);
        let real_size2 = size2 / FIXED_UNIT_SIZE * UNIT_SIZE;
        let size1 = self.sub_allocator_size - size2;
        let real_size1 = size1 / FIXED_UNIT_SIZE * UNIT_SIZE + UNIT_SIZE;

        self.lo_unit = real_size1;
        self.units_start = real_size1;
        self.fake_units_start = size1;
        self.hi_unit = self.lo_unit + real_size2;

        let mut i = 0;
        let mut k = 1;
        while i < N1 {
            self.indx2units[i] = k;
            i += 1;
            k += 1;
        }
        k += 1;
        while i < N1 + N2 {
            self.indx2units[i] = k;
            i += 1;
            k += 2;
        }
        k += 1;
        while i < N1 + N2 + N3 {
            self.indx2units[i] = k;
            i += 1;
            k += 3;
        }
        k += 1;
        while i < N1 + N2 + N3 + N4 {
            self.indx2units[i] = k;
            i += 1;
            k += 4;
        }
        self.glue_count = 0;
        let mut i = 0;
        for k in 0..128u32 {
            i += usize::from(u32::from(self.indx2units[i]) < k + 1);
            self.units2indx[k as usize] = i as u8;
        }
    }

    // A free block: `Stamp` at 0, `NU` at 2, `next` at 4, `prev` at 8.

    #[inline(always)]
    fn block_next(&self, block: u32) -> u32 {
        self.r32(block + 4)
    }

    #[inline(always)]
    fn block_prev(&self, block: u32) -> u32 {
        self.r32(block + 8)
    }

    #[inline(always)]
    fn block_remove(&mut self, block: u32) {
        let (prev, next) = (self.block_prev(block), self.block_next(block));
        self.w32(prev + 4, next);
        self.w32(next + 8, prev);
    }

    fn glue_free_blocks(&mut self) {
        if self.lo_unit != self.hi_unit {
            self.w8(self.lo_unit, 0);
        }
        let head = self.list_head;
        self.w16(head, 0);
        self.w32(head + 4, head);
        self.w32(head + 8, head);
        for i in 0..N_INDEXES {
            while self.free_list[i] != 0 {
                let p = self.remove_node(i);
                // `insertAt(&s0)`.
                let next = self.block_next(head);
                self.w32(p + 4, next);
                self.w32(p + 8, head);
                self.w32(head + 4, p);
                self.w32(next + 8, p);
                self.w16(p, 0xFFFF);
                self.w16(p + 2, u16::from(self.indx2units[i]));
            }
        }
        let mut p = self.block_next(head);
        while p != head {
            loop {
                let nu = u32::from(self.r16(p + 2));
                let p1 = p + UNIT_SIZE * nu;
                let nu1 = u32::from(self.r16(p1 + 2));
                if self.r16(p1) != 0xFFFF || nu + nu1 >= 0x1_0000 {
                    break;
                }
                self.block_remove(p1);
                self.w16(p + 2, (nu + nu1) as u16);
            }
            p = self.block_next(p);
        }
        loop {
            let mut p = self.block_next(head);
            if p == head {
                break;
            }
            self.block_remove(p);
            let mut sz = usize::from(self.r16(p + 2));
            while sz > 128 {
                self.insert_node(p, N_INDEXES - 1);
                sz -= 128;
                p += UNIT_SIZE * 128;
            }
            if sz == 0 {
                continue;
            }
            let mut i = usize::from(self.units2indx[sz - 1]);
            if usize::from(self.indx2units[i]) != sz {
                i -= 1;
                let k = sz - usize::from(self.indx2units[i]);
                self.insert_node(p + UNIT_SIZE * (sz - k) as u32, k - 1);
            }
            self.insert_node(p, i);
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_count = 255;
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == N_INDEXES {
                self.glue_count = self.glue_count.wrapping_sub(1);
                let bytes = UNIT_SIZE * u32::from(self.indx2units[indx]);
                let fixed = FIXED_UNIT_SIZE * u32::from(self.indx2units[indx]);
                if i64::from(self.fake_units_start) - i64::from(self.p_text) > i64::from(fixed) {
                    self.fake_units_start -= fixed;
                    self.units_start -= bytes;
                    return self.units_start;
                }
                return 0;
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        block
    }

    #[inline(always)]
    fn alloc_units(&mut self, nu: u32) -> u32 {
        let indx = usize::from(self.units2indx[nu as usize - 1]);
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let block = self.lo_unit;
        let bytes = UNIT_SIZE * u32::from(self.indx2units[indx]);
        self.lo_unit += bytes;
        if self.lo_unit <= self.hi_unit {
            return block;
        }
        self.lo_unit -= bytes;
        self.alloc_units_rare(indx)
    }

    #[inline(always)]
    fn alloc_context(&mut self) -> u32 {
        if self.hi_unit != self.lo_unit {
            self.hi_unit -= UNIT_SIZE;
            return self.hi_unit;
        }
        if self.free_list[0] != 0 {
            return self.remove_node(0);
        }
        self.alloc_units_rare(0)
    }

    fn copy_units(&mut self, from: u32, to: u32, nu: u32) {
        let (from, to, bytes) = (from as usize, to as usize, (UNIT_SIZE * nu) as usize);
        if from + bytes <= self.mem.len() && to + bytes <= self.mem.len() {
            self.mem.copy_within(from..from + bytes, to);
        }
    }

    #[inline(always)]
    fn expand_units(&mut self, old: u32, old_nu: u32) -> u32 {
        let i0 = self.units2indx[old_nu as usize - 1];
        let i1 = self.units2indx[old_nu as usize];
        if i0 == i1 {
            return old;
        }
        let block = self.alloc_units(old_nu + 1);
        if block != 0 {
            self.copy_units(old, block, old_nu);
            self.insert_node(old, usize::from(i0));
        }
        block
    }

    fn shrink_units(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = usize::from(self.units2indx[old_nu as usize - 1]);
        let i1 = usize::from(self.units2indx[new_nu as usize - 1]);
        if i0 == i1 {
            return old;
        }
        if self.free_list[i1] != 0 {
            let block = self.remove_node(i1);
            self.copy_units(old, block, new_nu);
            self.insert_node(old, i0);
            block
        } else {
            self.split_block(old, i0, i1);
            old
        }
    }

    fn free_units(&mut self, block: u32, old_nu: u32) {
        self.insert_node(block, usize::from(self.units2indx[old_nu as usize - 1]));
    }

    // `ModelPPM`.

    fn restart_model_rare(&mut self) -> Result<(), Error> {
        self.char_mask = [0; 256];
        self.init_sub_allocator();
        self.init_rl = -self.max_order.min(12) - 1;
        let context = self.alloc_context();
        self.min_context = context;
        self.max_context = context;
        if context == 0 {
            return Err(Error::NoMemory);
        }
        self.set_suffix(context, 0);
        self.order_fall = self.max_order;
        self.set_num_stats(context, 256);
        self.set_summ_freq(context, 257);
        let stats = self.alloc_units(256 / 2);
        self.found_state = stats;
        self.set_stats(context, stats);
        if stats == 0 {
            return Err(Error::NoMemory);
        }
        self.run_length = self.init_rl;
        self.prev_success = 0;
        for i in 0..256u32 {
            let state = stats + i * STATE_SIZE;
            self.set_state(
                state,
                State {
                    symbol: i as u8,
                    freq: 1,
                    successor: 0,
                },
            );
        }

        for i in 0..128 {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                for m in (0..64).step_by(8) {
                    self.bin_summ[i][k + m] = (BIN_SCALE - u32::from(esc) / (i as u32 + 2)) as u16;
                }
            }
        }
        for i in 0..25 {
            for k in 0..16 {
                self.see2_cont[i][k].init(5 * i as u32 + 10);
            }
        }
        Ok(())
    }

    fn start_model_rare(&mut self, max_order: i32) -> Result<(), Error> {
        self.esc_count = 1;
        self.max_order = max_order;
        self.restart_model_rare()?;
        self.ns2bs_indx[0] = 0;
        self.ns2bs_indx[1] = 2;
        self.ns2bs_indx[2..11].fill(2 * 2);
        self.ns2bs_indx[11..256].fill(2 * 3);
        for i in 0..3 {
            self.ns2indx[i] = i as u8;
        }
        let (mut m, mut k, mut step) = (3u8, 1, 1);
        for i in 3..256 {
            self.ns2indx[i] = m;
            k -= 1;
            if k == 0 {
                step += 1;
                k = step;
                m = m.wrapping_add(1);
            }
        }
        self.hb2flag[..0x40].fill(0);
        self.hb2flag[0x40..0x100].fill(0x08);
        self.dummy_see2_cont.shift = PERIOD_BITS as u8;
        Ok(())
    }

    /// `RARPPM_CONTEXT::rescale`.
    fn rescale(&mut self, ctx: u32) {
        let old_ns = self.num_stats(ctx);
        let mut i = old_ns as i32 - 1;
        let stats = self.stats(ctx);
        let mut p = self.found_state;
        while p > stats {
            self.swap_states(p, p.wrapping_sub(STATE_SIZE));
            p = p.wrapping_sub(STATE_SIZE);
        }
        self.set_freq(stats, self.freq(stats).wrapping_add(4));
        self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(4));
        let mut esc_freq = self.summ_freq(ctx) as i32 - i32::from(self.freq(p));
        let adder = i32::from(self.order_fall != 0);
        let freq = ((i32::from(self.freq(p)) + adder) >> 1) as u8;
        self.set_freq(p, freq);
        self.set_summ_freq(ctx, u32::from(freq));
        loop {
            p = p.wrapping_add(STATE_SIZE);
            esc_freq -= i32::from(self.freq(p));
            let freq = ((i32::from(self.freq(p)) + adder) >> 1) as u8;
            self.set_freq(p, freq);
            self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(u32::from(freq)));
            if self.freq(p) > self.freq(p.wrapping_sub(STATE_SIZE)) {
                let tmp = self.state(p);
                let mut p1 = p;
                loop {
                    let before = self.state(p1.wrapping_sub(STATE_SIZE));
                    self.set_state(p1, before);
                    p1 = p1.wrapping_sub(STATE_SIZE);
                    if p1 == stats || tmp.freq <= self.freq(p1.wrapping_sub(STATE_SIZE)) {
                        break;
                    }
                }
                self.set_state(p1, tmp);
            }
            i -= 1;
            if i <= 0 {
                break;
            }
        }
        if self.freq(p) == 0 {
            i = 0;
            loop {
                i += 1;
                p = p.wrapping_sub(STATE_SIZE);
                if self.freq(p) != 0 || p <= stats {
                    break;
                }
            }
            esc_freq += i;
            let num_stats = (self.num_stats(ctx) as i32 - i) as u32;
            self.set_num_stats(ctx, num_stats);
            if num_stats == 1 {
                let mut tmp = self.state(stats);
                loop {
                    tmp.freq -= tmp.freq >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                self.free_units(stats, (old_ns + 1) >> 1);
                self.found_state = ModelPpm::one_state(ctx);
                self.set_state(self.found_state, tmp);
                return;
            }
        }
        esc_freq -= esc_freq >> 1;
        self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(esc_freq as u32));
        let n0 = (old_ns + 1) >> 1;
        let n1 = (self.num_stats(ctx) + 1) >> 1;
        if n0 != n1 {
            let stats = self.shrink_units(stats, n0, n1);
            self.set_stats(ctx, stats);
        }
        self.found_state = self.stats(ctx);
    }

    /// `ModelPPM::CreateSuccessors`.
    #[inline(always)]
    fn create_successors(&mut self, skip: bool, p1: u32) -> u32 {
        let mut pc = self.min_context;
        let up_branch = self.successor(self.found_state);
        let found_symbol = self.symbol(self.found_state);
        let mut ps = [0u32; MAX_O];
        let mut pps = 0;
        let mut no_loop = false;
        if !skip {
            ps[0] = self.found_state;
            pps = 1;
            if self.suffix(pc) == 0 {
                no_loop = true;
            }
        }
        if !no_loop {
            let mut entry = p1;
            loop {
                let p;
                pc = self.suffix(pc);
                if entry != 0 {
                    p = entry;
                    entry = 0;
                } else if self.num_stats(pc) != 1 {
                    p = self.find_symbol(self.stats(pc), found_symbol);
                    if p == 0 {
                        return 0;
                    }
                } else {
                    p = ModelPpm::one_state(pc);
                }
                if self.successor(p) != up_branch {
                    pc = self.successor(p);
                    break;
                }
                if pps >= MAX_O {
                    return 0;
                }
                ps[pps] = p;
                pps += 1;
                if self.suffix(pc) == 0 {
                    break;
                }
            }
        }
        if pps == 0 {
            return pc;
        }
        let up_symbol = self.r8(up_branch);
        let up_successor = up_branch.wrapping_add(1);
        let up_freq = if self.num_stats(pc) != 1 {
            if pc <= self.p_text {
                return 0;
            }
            let p = self.find_symbol(self.stats(pc), up_symbol);
            if p == 0 {
                return 0;
            }
            let cf = u32::from(self.freq(p)).wrapping_sub(1);
            let s0 = self
                .summ_freq(pc)
                .wrapping_sub(self.num_stats(pc))
                .wrapping_sub(cf);
            let more = if 2u32.wrapping_mul(cf) <= s0 {
                u32::from(5u32.wrapping_mul(cf) > s0)
            } else {
                2u32.wrapping_mul(cf)
                    .wrapping_add(3u32.wrapping_mul(s0))
                    .wrapping_sub(1)
                    .checked_div(2u32.wrapping_mul(s0))
                    .unwrap_or(0)
            };
            1u32.wrapping_add(more) as u8
        } else {
            self.freq(ModelPpm::one_state(pc))
        };
        let up_state = State {
            symbol: up_symbol,
            freq: up_freq,
            successor: up_successor,
        };
        while pps > 0 {
            pps -= 1;
            // `createChild`.
            let child = self.alloc_context();
            if child == 0 {
                return 0;
            }
            self.set_num_stats(child, 1);
            self.set_state(ModelPpm::one_state(child), up_state);
            self.set_suffix(child, pc);
            self.set_successor(ps[pps], child);
            pc = child;
        }
        pc
    }

    /// `ModelPPM::UpdateModel`.
    #[inline(always)]
    fn update_model(&mut self) -> Result<(), Error> {
        if !self.update_model_or_restart() {
            self.restart_model_rare()?;
            self.esc_count = 0;
        }
        Ok(())
    }

    /// False where UnRAR goes to `RESTART_MODEL`.
    #[inline(always)]
    fn update_model_or_restart(&mut self) -> bool {
        let mut fs = self.state(self.found_state);
        let mut p = 0;
        if u32::from(fs.freq) < MAX_FREQ / 4 {
            let pc = self.suffix(self.min_context);
            if pc != 0 {
                if self.num_stats(pc) != 1 {
                    p = self.stats(pc);
                    if self.symbol(p) != fs.symbol {
                        p = self.find_symbol(p, fs.symbol);
                        if p == 0 {
                            return false;
                        }
                        if self.freq(p) >= self.freq(p.wrapping_sub(STATE_SIZE)) {
                            self.swap_states(p, p.wrapping_sub(STATE_SIZE));
                            p = p.wrapping_sub(STATE_SIZE);
                        }
                    }
                    if u32::from(self.freq(p)) < MAX_FREQ - 9 {
                        self.set_freq(p, self.freq(p).wrapping_add(2));
                        self.set_summ_freq(pc, self.summ_freq(pc).wrapping_add(2));
                    }
                } else {
                    p = ModelPpm::one_state(pc);
                    let freq = self.freq(p);
                    self.set_freq(p, freq.wrapping_add(u8::from(freq < 32)));
                }
            }
        }
        if self.order_fall == 0 {
            let successor = self.create_successors(true, p);
            self.set_successor(self.found_state, successor);
            self.min_context = successor;
            self.max_context = successor;
            return successor != 0;
        }
        self.w8(self.p_text, fs.symbol);
        self.p_text += 1;
        let mut successor = self.p_text;
        if self.p_text >= self.fake_units_start {
            return false;
        }
        if fs.successor != 0 {
            if fs.successor <= self.p_text {
                fs.successor = self.create_successors(false, p);
                if fs.successor == 0 {
                    return false;
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = fs.successor;
                self.p_text -= u32::from(self.max_context != self.min_context);
            }
        } else {
            self.set_successor(self.found_state, successor);
            fs.successor = self.min_context;
        }
        let ns = self.num_stats(self.min_context);
        let s0 = self
            .summ_freq(self.min_context)
            .wrapping_sub(ns)
            .wrapping_sub(u32::from(fs.freq).wrapping_sub(1));
        let mut pc = self.max_context;
        while pc != self.min_context {
            let mut ns1 = self.num_stats(pc);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let stats = self.expand_units(self.stats(pc), ns1 >> 1);
                    self.set_stats(pc, stats);
                    if stats == 0 {
                        return false;
                    }
                }
                let summ = self.summ_freq(pc);
                let more = u32::from(2 * ns1 < ns)
                    + 2 * (u32::from(4 * ns1 <= ns) & u32::from(summ <= 8 * ns1));
                self.set_summ_freq(pc, summ.wrapping_add(more));
            } else {
                let block = self.alloc_units(1);
                if block == 0 {
                    return false;
                }
                let one = self.state(ModelPpm::one_state(pc));
                self.set_state(block, one);
                self.set_stats(pc, block);
                let freq = u32::from(one.freq);
                let freq = if freq < MAX_FREQ / 4 - 1 {
                    freq + freq
                } else {
                    MAX_FREQ - 4
                };
                self.set_freq(block, freq as u8);
                let summ = (freq as i32)
                    .wrapping_add(self.init_esc)
                    .wrapping_add(i32::from(ns > 3));
                self.set_summ_freq(pc, summ as u32);
            }
            let summ = self.summ_freq(pc);
            let cf = 2u32
                .wrapping_mul(u32::from(fs.freq))
                .wrapping_mul(summ.wrapping_add(6));
            let sf = s0.wrapping_add(summ);
            let cf = if cf < 6u32.wrapping_mul(sf) {
                let cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4u32.wrapping_mul(sf));
                self.set_summ_freq(pc, summ.wrapping_add(3));
                cf
            } else {
                let cf = 4
                    + u32::from(cf >= 9u32.wrapping_mul(sf))
                    + u32::from(cf >= 12u32.wrapping_mul(sf))
                    + u32::from(cf >= 15u32.wrapping_mul(sf));
                self.set_summ_freq(pc, summ.wrapping_add(cf));
                cf
            };
            let state = self.stats(pc).wrapping_add(ns1.wrapping_mul(STATE_SIZE));
            self.set_state(
                state,
                State {
                    symbol: fs.symbol,
                    freq: cf as u8,
                    successor,
                },
            );
            ns1 = ns1.wrapping_add(1);
            self.set_num_stats(pc, ns1);
            pc = self.suffix(pc);
            if pc == 0 {
                // Not in a sound model, where the walk meets min_context.
                return false;
            }
        }
        self.max_context = fs.successor;
        self.min_context = fs.successor;
        true
    }

    /// `RARPPM_CONTEXT::decodeBinSymbol`.
    #[inline(always)]
    fn decode_bin_symbol(&mut self, ctx: u32) {
        let rs = ModelPpm::one_state(ctx);
        let found_symbol = self.symbol(self.found_state);
        self.hi_bits_flag = self.hb2flag[usize::from(found_symbol)];
        let freq = self.freq(rs);
        let symbol = self.symbol(rs);
        let row = usize::from(freq.wrapping_sub(1)) & 127;
        let column = usize::from(self.prev_success)
            + usize::from(
                self.ns2bs_indx[self.num_stats(self.suffix(ctx)).wrapping_sub(1) as usize & 0xff],
            )
            + usize::from(self.hi_bits_flag)
            + 2 * usize::from(self.hb2flag[usize::from(symbol)])
            + ((self.run_length >> 26) & 0x20) as usize;
        let bs = u32::from(self.bin_summ[row][column]);
        self.range >>= TOT_BITS;
        if self
            .code
            .wrapping_sub(self.low)
            .checked_div(self.range)
            .unwrap_or(u32::MAX)
            < bs
        {
            self.found_state = rs;
            self.set_freq(rs, freq.wrapping_add(u8::from(freq < 128)));
            self.low_count = 0;
            self.high_count = bs;
            self.bin_summ[row][column] = (bs + INTERVAL - get_mean(bs, PERIOD_BITS, 2)) as u16;
            self.prev_success = 1;
            self.run_length = self.run_length.wrapping_add(1);
        } else {
            self.low_count = bs;
            let bs = (bs.wrapping_sub(get_mean(bs, PERIOD_BITS, 2))) as u16;
            self.bin_summ[row][column] = bs;
            self.high_count = BIN_SCALE;
            self.init_esc = i32::from(EXP_ESCAPE[usize::from(bs >> 10) & 15]);
            self.num_masked = 1;
            self.char_mask[usize::from(symbol)] = self.esc_count;
            self.prev_success = 0;
            self.found_state = 0;
        }
    }

    /// `RangeCoder::GetCurrentCount`.
    #[inline(always)]
    fn get_current_count(&mut self) -> i32 {
        self.range = self.range.checked_div(self.scale).unwrap_or(0);
        self.code
            .wrapping_sub(self.low)
            .checked_div(self.range)
            // UnRAR would stop with a division by zero: as bad as what follows.
            .unwrap_or(i32::MAX as u32) as i32
    }

    /// `RARPPM_CONTEXT::update1`.
    #[inline(always)]
    fn update1(&mut self, ctx: u32, mut p: u32) {
        self.found_state = p;
        self.set_freq(p, self.freq(p).wrapping_add(4));
        self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(4));
        if self.freq(p) > self.freq(p.wrapping_sub(STATE_SIZE)) {
            self.swap_states(p, p.wrapping_sub(STATE_SIZE));
            p = p.wrapping_sub(STATE_SIZE);
            self.found_state = p;
            if u32::from(self.freq(p)) > MAX_FREQ {
                self.rescale(ctx);
            }
        }
    }

    /// `RARPPM_CONTEXT::decodeSymbol1`.
    #[inline(always)]
    fn decode_symbol1(&mut self, ctx: u32) -> bool {
        self.scale = self.summ_freq(ctx);
        let mut p = self.stats(ctx);
        let count = self.get_current_count();
        if count >= self.scale as i32 {
            return false;
        }
        let mut hi_cnt = i32::from(self.freq(p));
        if count < hi_cnt {
            self.high_count = hi_cnt as u32;
            self.prev_success = u8::from(2 * self.high_count > self.scale);
            self.run_length = self.run_length.wrapping_add(i32::from(self.prev_success));
            self.found_state = p;
            hi_cnt += 4;
            self.set_freq(p, hi_cnt as u8);
            self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(4));
            if hi_cnt > MAX_FREQ as i32 {
                self.rescale(ctx);
            }
            self.low_count = 0;
            return true;
        } else if self.found_state == 0 {
            return false;
        }
        self.prev_success = 0;
        let mut i = self.num_stats(ctx) as i32 - 1;
        loop {
            p = p.wrapping_add(STATE_SIZE);
            hi_cnt += i32::from(self.freq(p));
            if hi_cnt > count {
                break;
            }
            i -= 1;
            if i == 0 {
                let found_symbol = self.symbol(self.found_state);
                self.hi_bits_flag = self.hb2flag[usize::from(found_symbol)];
                self.low_count = hi_cnt as u32;
                self.char_mask[usize::from(self.symbol(p))] = self.esc_count;
                self.num_masked = self.num_stats(ctx) as i32;
                i = self.num_masked - 1;
                self.found_state = 0;
                while i > 0 {
                    p = p.wrapping_sub(STATE_SIZE);
                    self.char_mask[usize::from(self.symbol(p))] = self.esc_count;
                    i -= 1;
                }
                self.high_count = self.scale;
                return true;
            }
            if p as usize >= self.mem.len() {
                return false;
            }
        }
        self.high_count = hi_cnt as u32;
        self.low_count = self.high_count.wrapping_sub(u32::from(self.freq(p)));
        self.update1(ctx, p);
        true
    }

    /// `RARPPM_CONTEXT::update2`.
    #[inline(always)]
    fn update2(&mut self, ctx: u32, p: u32) {
        self.found_state = p;
        self.set_freq(p, self.freq(p).wrapping_add(4));
        self.set_summ_freq(ctx, self.summ_freq(ctx).wrapping_add(4));
        if u32::from(self.freq(p)) > MAX_FREQ {
            self.rescale(ctx);
        }
        self.esc_count = self.esc_count.wrapping_add(1);
        self.run_length = self.init_rl;
    }

    /// `RARPPM_CONTEXT::makeEscFreq2`.
    #[inline(always)]
    fn make_esc_freq2(&mut self, ctx: u32, diff: i32) -> SeeChoice {
        let num_stats = self.num_stats(ctx) as i32;
        if num_stats != 256 {
            let row = usize::from(self.ns2indx[(diff - 1) as usize & 0xff]);
            let column = usize::from(diff < self.num_stats(self.suffix(ctx)) as i32 - num_stats)
                + 2 * usize::from((self.summ_freq(ctx) as i32) < 11 * num_stats)
                + 4 * usize::from(self.num_masked > diff)
                + usize::from(self.hi_bits_flag);
            let row = row.min(24);
            self.scale = self.see2_cont[row][column].get_mean();
            SeeChoice::Table(row, column)
        } else {
            self.scale = 1;
            SeeChoice::Dummy
        }
    }

    /// `RARPPM_CONTEXT::decodeSymbol2`.
    #[inline(always)]
    fn decode_symbol2(&mut self, ctx: u32) -> bool {
        let num_stats = self.num_stats(ctx) as i32;
        if self.num_masked > num_stats {
            return false;
        }
        let mut i = num_stats - self.num_masked;
        let see = self.make_esc_freq2(ctx, i);
        let stats = self.stats(ctx);
        let end = stats.wrapping_add((num_stats as u32).wrapping_mul(STATE_SIZE));
        let mut pps = 0;
        let mut p;
        let mut hi_cnt = 0i32;
        if let Some(states) = self.mem.get(stats as usize..end as usize) {
            // All the states are in the heap: one bounds check for them.
            let mut done = false;
            let (chunks, _) = states.as_chunks::<{ STATE_SIZE as usize }>();
            for (n, state) in chunks.iter().enumerate() {
                if self.char_mask[usize::from(state[0])] == self.esc_count {
                    continue;
                }
                hi_cnt += i32::from(state[1]);
                if pps >= self.ps.len() {
                    return false;
                }
                self.ps[pps] = stats + n as u32 * STATE_SIZE;
                pps += 1;
                i -= 1;
                if i == 0 {
                    done = true;
                    break;
                }
            }
            if !done {
                return false;
            }
        } else {
            p = stats.wrapping_sub(STATE_SIZE);
            loop {
                loop {
                    p = p.wrapping_add(STATE_SIZE);
                    if p >= end {
                        return false;
                    }
                    if self.char_mask[usize::from(self.symbol(p))] != self.esc_count {
                        break;
                    }
                }
                hi_cnt += i32::from(self.freq(p));
                if pps >= self.ps.len() {
                    return false;
                }
                self.ps[pps] = p;
                pps += 1;
                i -= 1;
                if i == 0 {
                    break;
                }
            }
        }
        self.scale = self.scale.wrapping_add(hi_cnt as u32);
        let count = self.get_current_count();
        if count >= self.scale as i32 {
            return false;
        }
        pps = 0;
        p = self.ps[0];
        if count < hi_cnt {
            hi_cnt = 0;
            loop {
                hi_cnt += i32::from(self.freq(p));
                if hi_cnt > count {
                    break;
                }
                pps += 1;
                if pps >= self.ps.len() {
                    return false;
                }
                p = self.ps[pps];
            }
            self.high_count = hi_cnt as u32;
            self.low_count = self.high_count.wrapping_sub(u32::from(self.freq(p)));
            match see {
                SeeChoice::Table(row, column) => self.see2_cont[row][column].update(),
                SeeChoice::Dummy => self.dummy_see2_cont.update(),
            }
            self.update2(ctx, p);
        } else {
            self.low_count = hi_cnt as u32;
            self.high_count = self.scale;
            i = num_stats - self.num_masked;
            loop {
                if pps >= self.ps.len() {
                    return false;
                }
                self.char_mask[usize::from(self.symbol(self.ps[pps]))] = self.esc_count;
                pps += 1;
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            let scale = self.scale as u16;
            match see {
                SeeChoice::Table(row, column) => {
                    let see2 = &mut self.see2_cont[row][column];
                    see2.summ = see2.summ.wrapping_add(scale);
                }
                SeeChoice::Dummy => {
                    let see2 = &mut self.dummy_see2_cont;
                    see2.summ = see2.summ.wrapping_add(scale);
                }
            }
            self.num_masked = num_stats;
        }
        true
    }

    /// `ModelPPM::ClearMask`.
    fn clear_mask(&mut self) {
        self.esc_count = 1;
        self.char_mask = [0; 256];
    }

    /// `ModelPPM::CleanUp`: starts over after a data error.
    pub(super) fn clean_up(&mut self) -> Result<(), Error> {
        self.stop_sub_allocator();
        self.start_sub_allocator(1)?;
        self.start_model_rare(2)
    }

    /// `RangeCoder::InitDecoder`.
    pub(super) fn init_decoder(
        &mut self,
        unp: &mut Unpack,
        io: &mut dyn UnpIo,
    ) -> Result<(), Error> {
        self.low = 0;
        self.code = 0;
        self.range = 0xffff_ffff;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(unp.get_char(io)?);
        }
        Ok(())
    }

    /// `ModelPPM::DecodeInit`, with `EscChar` in `unp`.
    pub(super) fn decode_init(
        &mut self,
        unp: &mut Unpack,
        io: &mut dyn UnpIo,
    ) -> Result<bool, Error> {
        let mut max_order = i32::from(unp.get_char(io)?);
        let reset = max_order & 0x20 != 0;

        let mut max_mb = 0;
        if reset {
            max_mb = u32::from(unp.get_char(io)?);
        } else if self.sub_allocator_size == 0 {
            return Ok(false);
        }
        if max_order & 0x40 != 0 {
            unp.ppm_esc_char = i32::from(unp.get_char(io)?);
        }
        self.init_decoder(unp, io)?;
        if reset {
            max_order = (max_order & 0x1f) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }
            if max_order == 1 {
                self.stop_sub_allocator();
                return Ok(false);
            }
            self.start_sub_allocator(max_mb + 1)?;
            self.start_model_rare(max_order)?;
        }
        Ok(self.min_context != 0)
    }

    /// As if `heap` bytes had been asked for, which no block can ask for.
    #[cfg(test)]
    pub(super) fn set_heap_for_test(&mut self, heap: u32) {
        self.sub_allocator_size = heap;
    }

    /// `StartModelRare`, with the order the model has.
    #[cfg(test)]
    pub(super) fn start_again_for_test(&mut self) -> Result<(), Error> {
        self.start_model_rare(self.max_order)
    }

    /// `ARI_DEC_NORMALIZE`. False for a range of nothing, on which UnRAR
    /// would go on forever.
    #[inline(always)]
    fn normalize(&mut self, unp: &mut Unpack, io: &mut dyn UnpIo) -> Result<bool, Error> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return Ok(true);
                }
                self.range = (self.low as i32).wrapping_neg() as u32 & (BOT - 1);
            }
            if self.range == 0 {
                return Ok(false);
            }
            self.code = (self.code << 8) | u32::from(unp.get_char(io)?);
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    /// `RangeCoder::Decode`.
    #[inline(always)]
    fn decode(&mut self) {
        self.low = self
            .low
            .wrapping_add(self.range.wrapping_mul(self.low_count));
        self.range = self
            .range
            .wrapping_mul(self.high_count.wrapping_sub(self.low_count));
    }

    /// `ModelPPM::DecodeChar`: a symbol, or -1 for corrupt data.
    #[inline(always)]
    pub(super) fn decode_char(
        &mut self,
        unp: &mut Unpack,
        io: &mut dyn UnpIo,
    ) -> Result<i32, Error> {
        if self.min_context <= self.p_text || self.min_context > self.heap_end {
            return Ok(-1);
        }
        if self.num_stats(self.min_context) != 1 {
            let stats = self.stats(self.min_context);
            if stats <= self.p_text || stats > self.heap_end {
                return Ok(-1);
            }
            if !self.decode_symbol1(self.min_context) {
                return Ok(-1);
            }
        } else {
            self.decode_bin_symbol(self.min_context);
        }
        self.decode();
        while self.found_state == 0 {
            if !self.normalize(unp, io)? {
                return Ok(-1);
            }
            loop {
                self.order_fall += 1;
                self.min_context = self.suffix(self.min_context);
                if self.min_context <= self.p_text || self.min_context > self.heap_end {
                    return Ok(-1);
                }
                if self.num_stats(self.min_context) as i32 != self.num_masked {
                    break;
                }
            }
            if !self.decode_symbol2(self.min_context) {
                return Ok(-1);
            }
            self.decode();
        }
        let symbol = i32::from(self.symbol(self.found_state));
        let successor = self.successor(self.found_state);
        if self.order_fall == 0 && successor > self.p_text {
            self.min_context = successor;
            self.max_context = successor;
        } else {
            self.update_model()?;
            if self.esc_count == 0 {
                self.clear_mask();
            }
        }
        if !self.normalize(unp, io)? {
            return Ok(-1);
        }
        Ok(symbol)
    }
}
