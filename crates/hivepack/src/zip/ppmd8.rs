//! PPMd var.I rev. 1, which ZIP's method 98 compresses with: `Ppmd8.c`,
//! the model, and `Ppmd8Dec.c`, its decoder with Subbotin's carryless
//! range coder, from 7-Zip 26.05's C files, which are in the public domain
//! (by Igor Pavlov, after Dmitry Shkarin's PPMd var.I and Dmitry Subbotin's
//! range coder). As 7-Zip builds them: without `PPMD8_FREEZE_SUPPORT`, so
//! that the third restore method is not read.
//!
//! As `hivepack::sevenz`'s port of PPMd var.H, the model's records are in one
//! block of memory, as there, at offsets from its start (7-Zip's refs,
//! without `PPMD_32BIT`), read and written through functions on a byte
//! vector, in little-endian order on every machine, rather than through
//! pointers to structures that overlap. Those structures, by offset:
//!
//! - a context (`CPpmd8_Context`), 12 bytes: `NumStats` at 0, `Flags` at
//!   1, `SummFreq` at 2, `Stats` at 4, `Suffix` at 8; a context of one
//!   symbol keeps its state at 2 (`Ppmd8Context_OneState`), over
//!   `SummFreq` and `Stats`;
//! - a state (`CPpmd_State`), 6 bytes: `Symbol` at 0, `Freq` at 1,
//!   `Successor` at 2, its two halves in little-endian order;
//! - a free block (`CPpmd8_Node`), 12 bytes: `Stamp` at 0, `Next` at 4,
//!   `NU` at 8.

/// `PPMD8_MIN_ORDER`.
pub(crate) const MIN_ORDER: u32 = 2;
/// `PPMD8_MAX_ORDER`.
pub(crate) const MAX_ORDER: u32 = 16;

/// `PPMD8_RESTORE_METHOD_RESTART`; `PPMD8_RESTORE_METHOD_CUT_OFF` is the
/// other, 1.
pub(crate) const RESTORE_METHOD_RESTART: u32 = 0;

/// `PPMD8_SYM_END`.
pub(crate) const SYM_END: i32 = -1;
/// `PPMD8_SYM_ERROR`.
pub(crate) const SYM_ERROR: i32 = -2;

const PPMD_INT_BITS: u32 = 7;
const PPMD_PERIOD_BITS: u32 = 7;
const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);
const PPMD_N1: usize = 4;
const PPMD_N2: usize = 4;
const PPMD_N3: usize = 4;
const PPMD_N4: usize = (128 + 3 - PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4;
const PPMD_NUM_INDEXES: usize = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

const MAX_FREQ: u32 = 124;
const UNIT_SIZE: u32 = 12;
const STATE_SIZE: u32 = 6;
const EMPTY_NODE: u32 = 0xFFFF_FFFF;

const FLAG_RESCALED: u32 = 1 << 2;
const FLAG_PREV_HIGH: u32 = 1 << 4;

const K_TOP: u32 = 1 << 24;
const K_BOT: u32 = 1 << 15;

/// The SEE contexts, `See[24][32]`, then `DummySee`.
const SEE_ROWS: usize = 24;
const DUMMY_SEE: usize = SEE_ROWS * 32;

/// `U2B`.
#[inline(always)]
fn u2b(nu: u32) -> u32 {
    nu.wrapping_mul(UNIT_SIZE)
}

/// `HiBits_Prepare`.
#[inline(always)]
fn hi_bits_prepare(sym: u32) -> u32 {
    sym + 0xC0
}

/// `HiBits_Convert_3`.
#[inline(always)]
fn hi_bits_convert_3(flags: u32) -> u32 {
    (flags >> (8 - 3)) & (1 << 3)
}

/// `HiBits_Convert_4`.
#[inline(always)]
fn hi_bits_convert_4(flags: u32) -> u32 {
    (flags >> (8 - 4)) & (1 << 4)
}

/// `PPMD8_HiBitsFlag_3`.
#[inline(always)]
fn hi_bits_flag_3(sym: u32) -> u32 {
    hi_bits_convert_3(hi_bits_prepare(sym))
}

/// `PPMD8_HiBitsFlag_4`.
#[inline(always)]
fn hi_bits_flag_4(sym: u32) -> u32 {
    hi_bits_convert_4(hi_bits_prepare(sym))
}

/// `PPMD_GET_MEAN`.
#[inline(always)]
fn get_mean(summ: u32) -> u32 {
    (summ + (1 << (PPMD_PERIOD_BITS - 2))) >> PPMD_PERIOD_BITS
}

/// `CPpmd_See`.
#[derive(Clone, Copy, Debug, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

/// `IByteIn`: where the range decoder's bytes come from. At the end of the
/// input it gives 0, and remembers it, as 7-Zip's `CByteInBufWrap` does.
pub(crate) trait ByteIn {
    fn read_byte(&mut self) -> u8;
}

/// Where a `Next` link is, in the walks of the free lists: the head given
/// (`n`, or a free list), or a block's `Next`.
#[derive(Clone, Copy)]
enum Link {
    Head,
    List(usize),
    Node(u32),
}

/// `CPpmd8`, with its range decoder.
pub(crate) struct Ppmd8 {
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    restore_method: u32,
    run_length: i32,
    init_rl: i32,
    size: u32,
    glue_count: u32,
    align_offset: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    range: u32,
    code: u32,
    low: u32,
    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
    free_list: [u32; PPMD_NUM_INDEXES],
    stamps: [u32; PPMD_NUM_INDEXES],
    ns2bs_indx: [u8; 256],
    ns2indx: [u8; 260],
    exp_escape: [u8; 16],
    /// `See[24][32]`, then `DummySee`, in one array as in memory.
    see: [See; DUMMY_SEE + 1],
    /// `BinSumm[25][64]`, in one array as in memory.
    bin_summ: [u16; 25 * 64],
    /// `charMask`, a local of `Ppmd8_DecodeSymbol`: which symbols an escape
    /// has left.
    char_mask: [u8; 256],
    mem: Vec<u8>,
}

impl core::fmt::Debug for Ppmd8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ppmd8")
            .field("size", &self.size)
            .field("max_order", &self.max_order)
            .field("restore_method", &self.restore_method)
            .finish_non_exhaustive()
    }
}

impl Ppmd8 {
    /// `Ppmd8_Construct` and `Ppmd8_Alloc`: `None` if the memory cannot be
    /// had. It is zeroed by the system when it is first touched, so that it
    /// costs what the model uses of it.
    pub(crate) fn new(size: u32) -> Option<Box<Self>> {
        let mut indx2units = [0u8; PPMD_NUM_INDEXES];
        let mut units2indx = [0u8; 128];
        let mut k = 0usize;
        for (i, units) in indx2units.iter_mut().enumerate() {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                units2indx[k] = i as u8;
                k += 1;
            }
            *units = k as u8;
        }

        let mut ns2bs_indx = [3u8 << 1; 256];
        ns2bs_indx[0] = 0;
        ns2bs_indx[1] = 1 << 1;
        ns2bs_indx[2..11].fill(2 << 1);

        let mut ns2indx = [0u8; 260];
        for (i, n) in ns2indx.iter_mut().enumerate().take(5) {
            *n = i as u8;
        }
        let mut m = 5usize;
        let mut k = 1usize;
        for n in ns2indx.iter_mut().skip(5) {
            *n = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
        }

        let align_offset = 4u32.wrapping_sub(size) & 3;
        let total = align_offset as usize + size as usize;
        // That it can be had, before the allocation that cannot fail softly.
        let mut probe = Vec::<u8>::new();
        probe.try_reserve_exact(total).ok()?;
        drop(probe);
        Some(Box::new(Ppmd8 {
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            restore_method: 0,
            run_length: 0,
            init_rl: 0,
            size,
            glue_count: 0,
            align_offset,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            range: 0,
            code: 0,
            low: 0,
            indx2units,
            units2indx,
            free_list: [0; PPMD_NUM_INDEXES],
            stamps: [0; PPMD_NUM_INDEXES],
            ns2bs_indx,
            ns2indx,
            exp_escape: K_EXP_ESCAPE,
            see: [See::default(); DUMMY_SEE + 1],
            bin_summ: [0; 25 * 64],
            char_mask: [0xFF; 256],
            mem: vec![0; total],
        }))
    }

    #[inline(always)]
    fn get8(&self, at: u32) -> u32 {
        u32::from(self.mem[at as usize])
    }

    #[inline(always)]
    fn set8(&mut self, at: u32, v: u32) {
        self.mem[at as usize] = v as u8;
    }

    #[inline(always)]
    fn get16(&self, at: u32) -> u32 {
        let at = at as usize;
        // One bounds check.
        let m = &self.mem[at..at + 2];
        u32::from(u16::from_le_bytes([m[0], m[1]]))
    }

    #[inline(always)]
    fn set16(&mut self, at: u32, v: u32) {
        let at = at as usize;
        self.mem[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
    }

    #[inline(always)]
    fn get32(&self, at: u32) -> u32 {
        let at = at as usize;
        // One bounds check.
        let m = &self.mem[at..at + 4];
        u32::from_le_bytes([m[0], m[1], m[2], m[3]])
    }

    #[inline(always)]
    fn set32(&mut self, at: u32, v: u32) {
        let at = at as usize;
        self.mem[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    // A context's fields.
    #[inline(always)]
    fn num_stats(&self, c: u32) -> u32 {
        self.get8(c)
    }
    #[inline(always)]
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.set8(c, v);
    }
    #[inline(always)]
    fn flags(&self, c: u32) -> u32 {
        self.get8(c + 1)
    }
    #[inline(always)]
    fn set_flags(&mut self, c: u32, v: u32) {
        self.set8(c + 1, v);
    }
    #[inline(always)]
    fn summ_freq(&self, c: u32) -> u32 {
        self.get16(c + 2)
    }
    #[inline(always)]
    fn set_summ_freq(&mut self, c: u32, v: u32) {
        self.set16(c + 2, v);
    }
    #[inline(always)]
    fn stats(&self, c: u32) -> u32 {
        self.get32(c + 4)
    }
    #[inline(always)]
    fn set_stats(&mut self, c: u32, v: u32) {
        self.set32(c + 4, v);
    }
    #[inline(always)]
    fn suffix(&self, c: u32) -> u32 {
        self.get32(c + 8)
    }
    #[inline(always)]
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.set32(c + 8, v);
    }

    // A state's fields; `Ppmd8Context_OneState` is `c + 2`.
    #[inline(always)]
    fn symbol(&self, s: u32) -> u32 {
        self.get8(s)
    }
    #[inline(always)]
    fn set_symbol(&mut self, s: u32, v: u32) {
        self.set8(s, v);
    }
    #[inline(always)]
    fn freq(&self, s: u32) -> u32 {
        self.get8(s + 1)
    }
    #[inline(always)]
    fn set_freq(&mut self, s: u32, freq: u32) {
        self.set8(s + 1, freq);
    }
    /// `Ppmd_GET_SUCCESSOR`.
    #[inline(always)]
    fn successor(&self, s: u32) -> u32 {
        self.get32(s + 2)
    }
    /// `Ppmd8State_SetSuccessor`.
    #[inline(always)]
    fn set_successor(&mut self, s: u32, v: u32) {
        self.set32(s + 2, v);
    }

    /// `*to = *from`, of states.
    #[inline(always)]
    fn copy_state(&mut self, to: u32, from: u32) {
        let from = from as usize;
        self.mem
            .copy_within(from..from + STATE_SIZE as usize, to as usize);
    }

    #[inline(always)]
    fn read_state(&self, s: u32) -> [u8; STATE_SIZE as usize] {
        let s = s as usize;
        let mut state = [0; STATE_SIZE as usize];
        state.copy_from_slice(&self.mem[s..s + STATE_SIZE as usize]);
        state
    }

    #[inline(always)]
    fn write_state(&mut self, s: u32, state: [u8; STATE_SIZE as usize]) {
        let s = s as usize;
        self.mem[s..s + STATE_SIZE as usize].copy_from_slice(&state);
    }

    /// `SWAP_STATES` of states `t1` and `t2`.
    #[inline(always)]
    fn swap_states(&mut self, t1: u32, t2: u32) {
        let tmp = self.read_state(t1);
        self.copy_state(t1, t2);
        self.write_state(t2, tmp);
    }

    /// `*ONE_STATE(ctx) = *s`, but its frequency, as the C code writes it
    /// field by field: the symbol, `freq`, and the successor's halves.
    fn set_one_state(&mut self, ctx: u32, s: u32, freq: u32) {
        let symbol = self.symbol(s);
        self.set8(ctx + 2, symbol);
        self.set8(ctx + 3, freq);
        let successor_0 = self.get16(s + 2);
        let successor_1 = self.get16(s + 4);
        self.set16(ctx + 4, successor_0);
        self.set16(ctx + 6, successor_1);
    }

    // A free block's fields.
    #[inline(always)]
    fn stamp(&self, node: u32) -> u32 {
        self.get32(node)
    }
    #[inline(always)]
    fn next(&self, node: u32) -> u32 {
        self.get32(node + 4)
    }
    #[inline(always)]
    fn nu(&self, node: u32) -> u32 {
        self.get32(node + 8)
    }

    fn set_link(&mut self, link: Link, head: &mut u32, v: u32) {
        match link {
            Link::Head => *head = v,
            Link::List(i) => self.free_list[i] = v,
            Link::Node(node) => self.set32(node + 4, v),
        }
    }

    /// `U2I`.
    #[inline(always)]
    fn u2i(&self, nu: u32) -> u32 {
        u32::from(self.units2indx[nu as usize - 1])
    }

    /// `I2U`.
    #[inline(always)]
    fn i2u(&self, indx: u32) -> u32 {
        u32::from(self.indx2units[indx as usize])
    }

    /// `MEM_12_CPY`.
    fn mem_12_cpy(&mut self, dest: u32, src: u32, num: u32) {
        let src = src as usize;
        self.mem
            .copy_within(src..src + u2b(num) as usize, dest as usize);
    }

    /// `Ppmd8_InsertNode`.
    fn insert_node(&mut self, node: u32, indx: u32) {
        let i = indx as usize;
        self.set32(node, EMPTY_NODE);
        self.set32(node + 4, self.free_list[i]);
        self.set32(node + 8, self.i2u(indx));
        self.free_list[i] = node;
        self.stamps[i] = self.stamps[i].wrapping_add(1);
    }

    /// `Ppmd8_RemoveNode`.
    fn remove_node(&mut self, indx: u32) -> u32 {
        let i = indx as usize;
        let node = self.free_list[i];
        self.free_list[i] = self.next(node);
        self.stamps[i] = self.stamps[i].wrapping_sub(1);
        node
    }

    /// `Ppmd8_SplitBlock`.
    fn split_block(&mut self, ptr: u32, old_indx: u32, new_indx: u32) {
        let nu = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr = ptr + u2b(self.i2u(new_indx));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + u2b(k), nu - k - 1);
        }
        self.insert_node(ptr, i);
    }

    /// `Ppmd8_GlueFreeBlocks`.
    fn glue_free_blocks(&mut self) {
        // The first 32 bits of a unit tell what it is: EMPTY_NODE in a free
        // block, 0 in the guard; neither in a state or a context.
        let mut n = 0u32;

        self.glue_count = 1 << 13;
        self.stamps = [0; PPMD_NUM_INDEXES];

        // We set guard NODE at LoUnit.
        if self.lo_unit != self.hi_unit {
            self.set32(self.lo_unit, 0);
        }

        // Glue free blocks.
        let mut prev = Link::Head;
        for i in 0..PPMD_NUM_INDEXES {
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node = next;
                let mut nu = self.nu(node);
                self.set_link(prev, &mut n, next);
                next = self.next(node);
                if nu != 0 {
                    prev = Link::Node(node);
                    loop {
                        let node2 = node + u2b(nu);
                        if self.stamp(node2) != EMPTY_NODE {
                            break;
                        }
                        nu += self.nu(node2);
                        self.set32(node2 + 8, 0);
                        self.set32(node + 8, nu);
                    }
                }
            }
        }
        self.set_link(prev, &mut n, 0);

        // Fill lists of free blocks.
        while n != 0 {
            let mut node = n;
            let mut nu = self.nu(node);
            n = self.next(node);
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert_node(node, PPMD_NUM_INDEXES as u32 - 1);
                nu -= 128;
                node += u2b(128);
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + u2b(k), nu - k - 1);
            }
            self.insert_node(node, i);
        }
    }

    /// `Ppmd8_AllocUnitsRare`: `None` for NULL.
    fn alloc_units_rare(&mut self, indx: u32) -> Option<u32> {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx as usize] != 0 {
                return Some(self.remove_node(indx));
            }
        }

        let mut i = indx;
        loop {
            i += 1;
            if i == PPMD_NUM_INDEXES as u32 {
                let num_bytes = u2b(self.i2u(indx));
                let us = self.units_start;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if us.wrapping_sub(self.text) > num_bytes {
                    self.units_start = us - num_bytes;
                    Some(self.units_start)
                } else {
                    None
                };
            }
            if self.free_list[i as usize] != 0 {
                break;
            }
        }

        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        Some(block)
    }

    /// `Ppmd8_AllocUnits`.
    fn alloc_units(&mut self, indx: u32) -> Option<u32> {
        if self.free_list[indx as usize] != 0 {
            return Some(self.remove_node(indx));
        }
        let num_bytes = u2b(self.i2u(indx));
        let lo = self.lo_unit;
        if self.hi_unit.wrapping_sub(lo) >= num_bytes {
            self.lo_unit = lo + num_bytes;
            return Some(lo);
        }
        self.alloc_units_rare(indx)
    }

    /// `ShrinkUnits`.
    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1 as usize] != 0 {
            let ptr = self.remove_node(i1);
            self.mem_12_cpy(ptr, old_ptr, new_nu);
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    /// `FreeUnits`.
    fn free_units(&mut self, ptr: u32, nu: u32) {
        let indx = self.u2i(nu);
        self.insert_node(ptr, indx);
    }

    /// `SpecialFreeUnit`.
    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start += UNIT_SIZE;
        }
    }

    /// `ExpandTextArea`.
    fn expand_text_area(&mut self) {
        let mut count = [0u32; PPMD_NUM_INDEXES];

        if self.lo_unit != self.hi_unit {
            self.set32(self.lo_unit, 0);
        }

        let mut node = self.units_start;
        while self.stamp(node) == EMPTY_NODE {
            let nu = self.nu(node);
            self.set32(node, 0);
            count[self.u2i(nu) as usize] += 1;
            node += u2b(nu);
        }
        self.units_start = node;

        let mut head = 0;
        for (i, &cnt) in count.iter().enumerate() {
            let mut cnt = cnt;
            if cnt == 0 {
                continue;
            }
            let mut prev = Link::List(i);
            let mut n = self.free_list[i];
            self.stamps[i] = self.stamps[i].wrapping_sub(cnt);
            loop {
                let node = n;
                n = self.next(node);
                if self.stamp(node) != 0 {
                    prev = Link::Node(node);
                    continue;
                }
                self.set_link(prev, &mut head, n);
                cnt -= 1;
                if cnt == 0 {
                    break;
                }
            }
        }
    }

    /// `RESET_TEXT`.
    fn reset_text(&mut self, offs: u32) {
        self.text = self.align_offset + offs;
    }

    /// `Ppmd8_RestartModel`.
    fn restart_model(&mut self) {
        self.free_list = [0; PPMD_NUM_INDEXES];
        self.stamps = [0; PPMD_NUM_INDEXES];
        self.reset_text(0);
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit; // AllocContext(p)
        let mut s = self.lo_unit; // Ppmd8_AllocUnits(p, PPMD_NUM_INDEXES - 1)

        self.lo_unit += u2b(256 / 2);
        self.max_context = mc;
        self.min_context = mc;
        self.found_state = s;
        self.set_flags(mc, 0);
        self.set_num_stats(mc, 256 - 1);
        self.set_summ_freq(mc, 256 + 1);
        self.set_stats(mc, s);
        self.set_suffix(mc, 0);

        for i in 0..256 {
            self.set_symbol(s, i);
            self.set_freq(s, 1);
            self.set_successor(s, 0);
            s += STATE_SIZE;
        }

        let mut i = 0usize;
        for m in 0..25 {
            while usize::from(self.ns2indx[i]) == m {
                i += 1;
            }
            for (k, &esc) in K_INIT_BIN_ESC.iter().enumerate() {
                let val = (PPMD_BIN_SCALE - u32::from(esc) / (i as u32 + 1)) as u16;
                for r in (0..64).step_by(8) {
                    self.bin_summ[m * 64 + k + r] = val;
                }
            }
        }

        let mut i = 0usize;
        for m in 0..SEE_ROWS {
            while usize::from(self.ns2indx[i + 3]) == m + 3 {
                i += 1;
            }
            let summ = ((2 * i + 5) << (PPMD_PERIOD_BITS - 4)) as u16;
            for k in 0..32 {
                self.see[m * 32 + k] = See {
                    summ,
                    shift: (PPMD_PERIOD_BITS - 4) as u8,
                    count: 7,
                };
            }
        }

        self.see[DUMMY_SEE] = See {
            summ: 0, // unused
            shift: PPMD_PERIOD_BITS as u8,
            count: 64, // unused
        };
    }

    /// `Ppmd8_Init`.
    pub(crate) fn init(&mut self, max_order: u32, restore_method: u32) {
        self.max_order = max_order;
        self.restore_method = restore_method;
        self.restart_model();
    }

    /// `Refresh`: called when symbols (successors) of `ctx` are removed; it
    /// increases its escape frequency by the sum of those removed.
    fn refresh(&mut self, ctx: u32, old_nu: u32, scale: u32) {
        let mut i = self.num_stats(ctx);
        let mut s = self.shrink_units(self.stats(ctx), old_nu, (i + 2) >> 1);
        self.set_stats(ctx, s);

        // As 7-Zip has it, after PPMdI's rev. 2 fix.
        let scale = scale | u32::from(self.summ_freq(ctx) >= 1 << 15);

        let mut flags = hi_bits_prepare(self.symbol(s));
        let mut freq = self.freq(s);
        let mut esc_freq = self.summ_freq(ctx).wrapping_sub(freq);
        freq = (freq + scale) >> scale;
        let mut sum_freq = freq;
        self.set_freq(s, freq);

        loop {
            s += STATE_SIZE;
            let mut freq = self.freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + scale) >> scale;
            sum_freq += freq;
            self.set_freq(s, freq);
            flags |= hi_bits_prepare(self.symbol(s));
            i -= 1;
            if i == 0 {
                break;
            }
        }

        self.set_summ_freq(
            ctx,
            sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale),
        );
        let kept = self.flags(ctx) & (FLAG_PREV_HIGH + FLAG_RESCALED * scale);
        self.set_flags(ctx, kept + hi_bits_convert_3(flags));
    }

    /// `CutOff`: reduces the contexts from `ctx`, of `order`; the context
    /// kept, or 0 for none.
    fn cut_off(&mut self, ctx: u32, order: u32) -> u32 {
        let mut ns = self.num_stats(ctx) as i32;

        if ns == 0 {
            let s = ctx + 2;
            let mut successor = self.successor(s);
            if successor >= self.units_start {
                successor = if order < self.max_order {
                    self.cut_off(successor, order + 1)
                } else {
                    0
                };
                self.set_successor(s, successor);
                if successor != 0 || order <= 9 {
                    // O_BOUND
                    return ctx;
                }
            }
            self.special_free_unit(ctx);
            return 0;
        }

        let nu = (ns as u32 + 2) >> 1;
        let indx = self.u2i(nu);
        let mut stats = self.stats(ctx);

        if stats.wrapping_sub(self.units_start) <= 1 << 14
            && self.stats(ctx) <= self.free_list[indx as usize]
        {
            let ptr = self.remove_node(indx);
            self.set_stats(ctx, ptr);
            self.mem_12_cpy(ptr, stats, nu);
            if stats != self.units_start {
                self.insert_node(stats, indx);
            } else {
                self.units_start += u2b(self.i2u(indx));
            }
            stats = ptr;
        }

        let mut s = stats + ns as u32 * STATE_SIZE;
        loop {
            let successor = self.successor(s);
            if successor < self.units_start {
                let s2 = stats + ns as u32 * STATE_SIZE;
                ns -= 1;
                if order != 0 {
                    if s != s2 {
                        self.copy_state(s, s2);
                    }
                } else {
                    self.swap_states(s, s2);
                    self.set_successor(s2, 0);
                }
            } else if order < self.max_order {
                let kept = self.cut_off(successor, order + 1);
                self.set_successor(s, kept);
            } else {
                self.set_successor(s, 0);
            }
            if s == stats {
                break;
            }
            s -= STATE_SIZE;
        }

        if ns != self.num_stats(ctx) as i32 && order != 0 {
            if ns < 0 {
                self.free_units(stats, nu);
                self.special_free_unit(ctx);
                return 0;
            }
            self.set_num_stats(ctx, ns as u32);
            if ns == 0 {
                let sym = self.symbol(stats);
                let flags = (self.flags(ctx) & FLAG_PREV_HIGH) + hi_bits_flag_3(sym);
                self.set_flags(ctx, flags);
                let freq = (self.freq(stats) + 11) >> 3;
                self.set_one_state(ctx, stats, freq);
                self.free_units(stats, nu);
            } else {
                let scale = u32::from(self.summ_freq(ctx) > 16 * ns as u32);
                self.refresh(ctx, nu, scale);
            }
        }

        ctx
    }

    /// `GetUsedMemory`.
    fn get_used_memory(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..PPMD_NUM_INDEXES {
            v = v.wrapping_add(self.stamps[i].wrapping_mul(self.i2u(i as u32)));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(u2b(v))
    }

    /// `RestoreModel`, when the memory for a context ran out: the symbols
    /// added to the contexts from MaxContext to `ctx_error` are taken back.
    fn restore_model(&mut self, ctx_error: u32) {
        self.reset_text(0);

        let mut c = self.max_context;
        while c != ctx_error {
            let ns = self.num_stats(c).wrapping_sub(1) & 0xFF;
            self.set_num_stats(c, ns);
            if ns == 0 {
                let s = self.stats(c);
                let flags = (self.flags(c) & FLAG_PREV_HIGH) + hi_bits_flag_3(self.symbol(s));
                self.set_flags(c, flags);
                let freq = (self.freq(s) + 11) >> 3;
                self.set_one_state(c, s, freq);
                self.special_free_unit(s);
            } else {
                self.refresh(c, (self.num_stats(c) + 3) >> 1, 0);
            }
            c = self.suffix(c);
        }

        // Increase Escape Freq for context [ctxError ... p->MinContext).
        while c != self.min_context {
            if self.num_stats(c) == 0 {
                let freq = (self.get8(c + 3) + 1) >> 1;
                self.set8(c + 3, freq);
            } else {
                let summ = (self.summ_freq(c) + 4) & 0xFFFF;
                self.set_summ_freq(c, summ);
                if summ > 128 + 4 * self.num_stats(c) {
                    self.refresh(c, (self.num_stats(c) + 2) >> 1, 1);
                }
            }
            c = self.suffix(c);
        }

        if self.restore_method == RESTORE_METHOD_RESTART
            || self.get_used_memory() < (self.size >> 1)
        {
            self.restart_model();
        } else {
            while self.suffix(self.max_context) != 0 {
                self.max_context = self.suffix(self.max_context);
            }
            loop {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                if self.get_used_memory() <= 3 * (self.size >> 2) {
                    break;
                }
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
        self.min_context = self.max_context;
    }

    /// `Ppmd8_CreateSuccessors`: `None` for NULL, memory having run out.
    fn create_successors(&mut self, skip: bool, mut s1: Option<u32>, mut c: u32) -> Option<u32> {
        let mut up_branch = self.successor(self.found_state);
        let mut num_ps = 0usize;
        let mut ps = [0u32; MAX_ORDER as usize + 1];

        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.suffix(c) != 0 {
            c = self.suffix(c);

            let s = if let Some(s) = s1.take() {
                s
            } else if self.num_stats(c) != 0 {
                let sym = self.symbol(self.found_state);
                let mut s = self.stats(c);
                while self.symbol(s) != sym {
                    s += STATE_SIZE;
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 1);
                    self.set_summ_freq(c, self.summ_freq(c) + 1);
                }
                s
            } else {
                let temp = u32::from(self.num_stats(self.suffix(c)) == 0);
                let s = c + 2;
                let freq = self.freq(s);
                self.set_freq(s, freq + (temp & u32::from(freq < 24)));
                s
            };
            let successor = self.successor(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return Some(c);
                }
                break;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        let new_sym = self.get8(up_branch);
        up_branch += 1;
        let flags = hi_bits_flag_4(self.symbol(self.found_state)) + hi_bits_flag_3(new_sym);

        let new_freq = if self.num_stats(c) == 0 {
            self.get8(c + 3)
        } else {
            let mut s = self.stats(c);
            while self.symbol(s) != new_sym {
                s += STATE_SIZE;
            }
            let cf = self.freq(s).wrapping_sub(1);
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            let add = if cf.wrapping_mul(2) <= s0 {
                u32::from(cf.wrapping_mul(5) > s0)
            } else {
                // The C code divides by zero for s0 == 0, which no model of
                // valid symbols has.
                cf.wrapping_add(s0.wrapping_mul(2)).wrapping_sub(3) / s0.max(1)
            };
            1u32.wrapping_add(add) & 0xFF
        };

        loop {
            // AllocContext(p).
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                self.alloc_units_rare(0)?
            };
            self.set_flags(c1, flags);
            self.set_num_stats(c1, 0);
            self.set8(c1 + 2, new_sym);
            self.set8(c1 + 3, new_freq);
            self.set_successor(c1 + 2, up_branch);
            self.set_suffix(c1, c);
            num_ps -= 1;
            self.set_successor(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 {
                break;
            }
        }

        Some(c)
    }

    /// `ReduceOrder`: `None` for NULL.
    fn reduce_order(&mut self, mut s1: Option<u32>, mut c: u32) -> Option<u32> {
        let mut s;
        let c1 = c;
        let up_branch = self.text;

        self.set_successor(self.found_state, up_branch);
        self.order_fall += 1;

        loop {
            if let Some(x) = s1.take() {
                c = self.suffix(c);
                s = x;
            } else {
                if self.suffix(c) == 0 {
                    return Some(c);
                }
                c = self.suffix(c);
                if self.num_stats(c) != 0 {
                    s = self.stats(c);
                    let sym = self.symbol(self.found_state);
                    if self.symbol(s) != sym {
                        loop {
                            s += STATE_SIZE;
                            if self.symbol(s) == sym {
                                break;
                            }
                        }
                    }
                    if self.freq(s) < MAX_FREQ - 9 {
                        self.set_freq(s, self.freq(s) + 2);
                        self.set_summ_freq(c, (self.summ_freq(c) + 2) & 0xFFFF);
                    }
                } else {
                    s = c + 2;
                    let freq = self.freq(s);
                    self.set_freq(s, freq + u32::from(freq < 32));
                }
            }
            if self.successor(s) != 0 {
                break;
            }
            self.set_successor(s, up_branch);
            self.order_fall += 1;
        }

        if self.successor(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, None, c);
            self.set_successor(s, successor.unwrap_or(0));
            self.found_state = s2;
        }

        let successor = self.successor(s);
        if self.order_fall == 1 && c1 == self.max_context {
            self.set_successor(self.found_state, successor);
            self.text -= 1;
        }
        if successor == 0 {
            return None;
        }
        Some(successor)
    }

    /// `Ppmd8_UpdateModel`.
    fn update_model(&mut self) {
        let mut min_successor = self.successor(self.found_state);
        let f_freq = self.freq(self.found_state);
        let f_symbol = self.symbol(self.found_state);

        let mut s: Option<u32> = None;
        if self.freq(self.found_state) < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            // Update Freqs in Suffix Context.
            let c = self.suffix(self.min_context);

            if self.num_stats(c) == 0 {
                let st = c + 2;
                if self.freq(st) < 32 {
                    self.set_freq(st, self.freq(st) + 1);
                }
                s = Some(st);
            } else {
                let sym = self.symbol(self.found_state);
                let mut st = self.stats(c);

                if self.symbol(st) != sym {
                    loop {
                        st += STATE_SIZE;
                        if self.symbol(st) == sym {
                            break;
                        }
                    }
                    if self.freq(st) >= self.freq(st - STATE_SIZE) {
                        self.swap_states(st, st - STATE_SIZE);
                        st -= STATE_SIZE;
                    }
                }

                if self.freq(st) < MAX_FREQ - 9 {
                    self.set_freq(st, self.freq(st) + 2);
                    self.set_summ_freq(c, (self.summ_freq(c) + 2) & 0xFFFF);
                }
                s = Some(st);
            }
        }

        let mut c = self.max_context;
        if self.order_fall == 0 && min_successor != 0 {
            match self.create_successors(true, s, self.min_context) {
                None => {
                    self.set_successor(self.found_state, 0);
                    self.restore_model(c);
                }
                Some(cs) => {
                    self.set_successor(self.found_state, cs);
                    self.min_context = cs;
                    self.max_context = cs;
                }
            }
            return;
        }

        let text = self.text;
        self.set8(text, self.symbol(self.found_state));
        let text = text + 1;
        self.text = text;
        if text >= self.units_start {
            self.restore_model(c);
            return;
        }
        let mut max_successor = text;

        if min_successor == 0 {
            match self.reduce_order(s, self.min_context) {
                None => {
                    self.restore_model(c);
                    return;
                }
                Some(cs) => min_successor = cs,
            }
        } else if min_successor < self.units_start {
            match self.create_successors(false, s, self.min_context) {
                None => {
                    self.restore_model(c);
                    return;
                }
                Some(cs) => min_successor = cs,
            }
        }

        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            max_successor = min_successor;
            self.text -= u32::from(self.max_context != self.min_context);
        }

        let flag = hi_bits_flag_3(f_symbol);
        let ns = self.num_stats(self.min_context);
        let s0 = self
            .summ_freq(self.min_context)
            .wrapping_sub(ns)
            .wrapping_sub(f_freq);

        while c != self.min_context {
            let ns1 = self.num_stats(c);
            let mut sum;

            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    // Expand for one UNIT.
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let Some(ptr) = self.alloc_units(i + 1) else {
                            self.restore_model(c);
                            return;
                        };
                        let old_ptr = self.stats(c);
                        self.mem_12_cpy(ptr, old_ptr, old_nu);
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                sum = self.summ_freq(c);
                // Max increase of Escape_Freq is 1 here.
                sum += u32::from(3 * ns1 + 1 < ns);
            } else {
                let Some(st) = self.alloc_units(0) else {
                    self.restore_model(c);
                    return;
                };
                let mut freq = self.get8(c + 3);
                let symbol = self.get8(c + 2);
                let successor_0 = self.get16(c + 4);
                let successor_1 = self.get16(c + 6);
                self.set_symbol(st, symbol);
                self.set16(st + 2, successor_0);
                self.set16(st + 4, successor_1);
                self.set_stats(c, st);
                if freq < MAX_FREQ / 4 - 1 {
                    freq <<= 1;
                } else {
                    freq = MAX_FREQ - 4;
                }
                self.set_freq(st, freq);
                sum = freq + self.init_esc + u32::from(ns > 2);
            }

            let st = self.stats(c) + (ns1 + 1) * STATE_SIZE;
            let mut cf = 2u32.wrapping_mul(sum + 6).wrapping_mul(f_freq);
            let sf = s0.wrapping_add(sum);
            self.set_symbol(st, f_symbol);
            self.set_num_stats(c, ns1 + 1);
            self.set_successor(st, max_successor);
            self.set_flags(c, self.flags(c) | flag);
            if cf < sf.wrapping_mul(6) {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= sf.wrapping_mul(4));
                sum += 4;
            } else {
                cf = 4
                    + u32::from(cf > sf.wrapping_mul(9))
                    + u32::from(cf > sf.wrapping_mul(12))
                    + u32::from(cf > sf.wrapping_mul(15));
                sum += cf;
            }
            self.set_summ_freq(c, sum);
            self.set_freq(st, cf);
            c = self.suffix(c);
        }
        self.max_context = min_successor;
        self.min_context = min_successor;
    }

    /// `Ppmd8_Rescale`.
    fn rescale(&mut self) {
        let stats = self.stats(self.min_context);
        let mut s = self.found_state;

        // Sort the list by Freq.
        if s != stats {
            let tmp = self.read_state(s);
            loop {
                self.copy_state(s, s - STATE_SIZE);
                s -= STATE_SIZE;
                if s == stats {
                    break;
                }
            }
            self.write_state(s, tmp);
        }

        let mut sum_freq = self.freq(s);
        let mut esc_freq = self.summ_freq(self.min_context).wrapping_sub(sum_freq);

        let adder = u32::from(self.order_fall != 0);

        sum_freq = (sum_freq + 4 + adder) >> 1;
        let mut i = self.num_stats(self.min_context);
        self.set_freq(s, sum_freq);

        loop {
            s += STATE_SIZE;
            let mut freq = self.freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_freq(s, freq);
            if freq > self.freq(s - STATE_SIZE) {
                let tmp = self.read_state(s);
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1 - STATE_SIZE);
                    s1 -= STATE_SIZE;
                    if !(s1 != stats && freq > self.freq(s1 - STATE_SIZE)) {
                        break;
                    }
                }
                self.write_state(s1, tmp);
            }
            i -= 1;
            if i == 0 {
                break;
            }
        }

        if self.freq(s) == 0 {
            // Remove all items with Freq == 0.
            let mut i = 0u32;
            loop {
                i += 1;
                s -= STATE_SIZE;
                if self.freq(s) != 0 {
                    break;
                }
            }

            esc_freq = esc_freq.wrapping_add(i);
            let mc = self.min_context;
            let num_stats = self.num_stats(mc);
            let num_stats_new = num_stats - i;
            self.set_num_stats(mc, num_stats_new);
            let n0 = (num_stats + 2) >> 1;

            if num_stats_new == 0 {
                // The C code divides by zero for esc_freq == 0, which no
                // model of valid symbols has.
                let mut freq = (2 * self.freq(stats))
                    .wrapping_add(esc_freq)
                    .wrapping_sub(1)
                    / esc_freq.max(1);
                if freq > MAX_FREQ / 3 {
                    freq = MAX_FREQ / 3;
                }
                let flags = (self.flags(mc) & FLAG_PREV_HIGH) + hi_bits_flag_3(self.symbol(stats));
                self.set_flags(mc, flags);

                let s = mc + 2;
                self.copy_state(s, stats);
                self.set_freq(s, freq);
                self.found_state = s;
                let indx = self.u2i(n0);
                self.insert_node(stats, indx);
                return;
            }

            let n1 = (num_stats_new + 2) >> 1;
            if n0 != n1 {
                let shrunk = self.shrink_units(stats, n0, n1);
                self.set_stats(mc, shrunk);
            }
        }

        let mc = self.min_context;
        self.set_summ_freq(
            mc,
            sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1),
        );
        self.set_flags(mc, self.flags(mc) | FLAG_RESCALED);
        self.found_state = self.stats(mc);
    }

    /// `Ppmd8_MakeEscFreq`: the SEE context, and the escape frequency.
    fn make_esc_freq(&mut self, num_masked1: u32) -> (usize, u32) {
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats != 0xFF {
            // (3 <= numStats + 2 <= 256) (3 <= NS2Indx[3] and NS2Indx[256] === 26)
            let row = usize::from(self.ns2indx[num_stats as usize + 2]) - 3;
            let see = row * 32
                + usize::from(self.summ_freq(mc) > 11 * (num_stats + 1))
                + 2 * usize::from(2 * num_stats < self.num_stats(self.suffix(mc)) + num_masked1)
                + self.flags(mc) as usize;

            // If (see->Summ) field is larger than 16-bit, we need only low 16
            // bits of Summ.
            let summ = u32::from(self.see[see].summ);
            let r = summ >> self.see[see].shift;
            self.see[see].summ = (summ - r) as u16;
            (see, r + u32::from(r == 0))
        } else {
            (DUMMY_SEE, 1)
        }
    }

    /// `Ppmd_See_UPDATE`.
    fn see_update(&mut self, see: usize) {
        let see = &mut self.see[see];
        if u32::from(see.shift) < PPMD_PERIOD_BITS {
            see.count = see.count.wrapping_sub(1);
            if see.count == 0 {
                see.summ <<= 1;
                see.count = (3u32 << see.shift) as u8;
                see.shift += 1;
            }
        }
    }

    /// `Ppmd8_NextContext`.
    fn next_context(&mut self) {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c >= self.units_start {
            self.max_context = c;
            self.min_context = c;
        } else {
            self.update_model();
        }
    }

    /// `Ppmd8_Update1`.
    fn update1(&mut self) {
        let mut s = self.found_state;
        let freq = self.freq(s) + 4;
        let mc = self.min_context;
        self.set_summ_freq(mc, (self.summ_freq(mc) + 4) & 0xFFFF);
        self.set_freq(s, freq);
        if freq > self.freq(s - STATE_SIZE) {
            self.swap_states(s, s - STATE_SIZE);
            s -= STATE_SIZE;
            self.found_state = s;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    /// `Ppmd8_Update1_0`.
    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        let mut freq = self.freq(s);
        let summ_freq = self.summ_freq(mc);
        self.prev_success = u32::from(2 * freq >= summ_freq); // Ppmd8 (>=)
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.set_summ_freq(mc, (summ_freq + 4) & 0xFFFF);
        freq += 4;
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    /// `Ppmd8_Update2`.
    fn update2(&mut self) {
        let s = self.found_state;
        let freq = self.freq(s) + 4;
        self.run_length = self.init_rl;
        let mc = self.min_context;
        self.set_summ_freq(mc, (self.summ_freq(mc) + 4) & 0xFFFF);
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model();
    }

    /// `Ppmd8_Init_RangeDec`: false if the first four bytes are all 0xFF.
    pub(crate) fn init_range_dec(&mut self, input: &mut impl ByteIn) -> bool {
        self.code = 0;
        self.range = 0xFFFF_FFFF;
        self.low = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(input.read_byte());
        }
        self.code < 0xFFFF_FFFF
    }

    /// `Ppmd8_RangeDec_IsFinishedOK`.
    pub(crate) fn range_dec_is_finished_ok(&self) -> bool {
        self.code == 0
    }

    /// `RC_NORM`.
    #[inline(always)]
    fn rc_norm(&mut self, input: &mut impl ByteIn) {
        loop {
            let again = (self.low ^ self.low.wrapping_add(self.range)) < K_TOP
                || (self.range < K_BOT && {
                    self.range = self.low.wrapping_neg() & (K_BOT - 1);
                    true
                });
            if !again {
                break;
            }
            self.code = (self.code << 8) | u32::from(input.read_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    /// `Ppmd8_RD_Decode`, without its normalization (`RC_NORM_LOCAL`).
    #[inline(always)]
    fn rc_decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
    }

    /// `RC_GetThreshold`: `None` where the C code would divide by zero, for
    /// a range or total of 0, which no model of valid symbols has.
    #[inline(always)]
    fn rc_get_threshold(&mut self, total: u32) -> Option<u32> {
        self.range = self.range.checked_div(total)?;
        self.code.checked_div(self.range)
    }

    /// `PPMD8_CORRECT_SUM_RANGE`.
    #[inline(always)]
    fn correct_sum_range(&self, sum: u32) -> u32 {
        sum.min(self.range)
    }

    /// `Ppmd8_DecodeSymbol`: a byte, `SYM_END` for the end of the payload's
    /// marker, or `SYM_ERROR` for a data error.
    pub(crate) fn decode_symbol(&mut self, input: &mut impl ByteIn) -> i32 {
        if self.num_stats(self.min_context) != 0 {
            let mut s = self.stats(self.min_context);
            let summ_freq = self.correct_sum_range(self.summ_freq(self.min_context));

            let Some(mut count) = self.rc_get_threshold(summ_freq) else {
                return SYM_ERROR;
            };
            let hi_cnt = count;

            count = count.wrapping_sub(self.freq(s));
            if (count as i32) < 0 {
                let freq = self.freq(s);
                self.rc_decode(0, freq);
                self.rc_norm(input);
                self.found_state = s;
                let sym = self.symbol(s);
                self.update1_0();
                return sym as i32;
            }

            self.prev_success = 0;
            let mut i = self.num_stats(self.min_context);

            loop {
                s += STATE_SIZE;
                count = count.wrapping_sub(self.freq(s));
                if (count as i32) < 0 {
                    let freq = self.freq(s);
                    self.rc_decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                    self.rc_norm(input);
                    self.found_state = s;
                    let sym = self.symbol(s);
                    self.update1();
                    return sym as i32;
                }
                i -= 1;
                if i == 0 {
                    break;
                }
            }

            if hi_cnt >= summ_freq {
                return SYM_ERROR;
            }

            let hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc_decode(hi_cnt, summ_freq - hi_cnt);

            self.char_mask = [0xFF; 256];
            let mut s2 = self.stats(self.min_context);
            self.char_mask[self.symbol(s) as usize] = 0;
            loop {
                let sym0 = self.symbol(s2) as usize;
                let sym1 = self.symbol(s2 + STATE_SIZE) as usize;
                s2 += 2 * STATE_SIZE;
                self.char_mask[sym0] = 0;
                self.char_mask[sym1] = 0;
                if s2 >= s {
                    break;
                }
            }
        } else {
            let s = self.min_context + 2;
            let row = usize::from(self.ns2indx[self.freq(s) as usize - 1]);
            let col = self.prev_success as usize
                + ((self.run_length >> 26) as u32 & 0x20) as usize
                + usize::from(
                    self.ns2bs_indx[self.num_stats(self.suffix(self.min_context)) as usize],
                )
                + self.flags(self.min_context) as usize;
            let prob = row * 64 + col;
            let mut pr = u32::from(self.bin_summ[prob]);
            let size0 = (self.range >> 14).wrapping_mul(pr);
            pr -= get_mean(pr);

            if self.code < size0 {
                self.bin_summ[prob] = (pr + (1 << PPMD_INT_BITS)) as u16;

                // RangeDec_DecodeBit0(size0).
                self.range = size0;
                self.rc_norm(input);

                let freq = self.freq(s);
                let c = self.successor(s);
                let sym = self.symbol(s);
                self.found_state = s;
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.set_freq(s, freq + u32::from(freq < 196));
                // NextContext(p).
                if self.order_fall == 0 && c >= self.units_start {
                    self.max_context = c;
                    self.min_context = c;
                } else {
                    self.update_model();
                }
                return sym as i32;
            }

            self.bin_summ[prob] = pr as u16;
            self.init_esc = u32::from(self.exp_escape[(pr >> 10) as usize]);

            // RangeDec_DecodeBit1(rc2, size0).
            self.low = self.low.wrapping_add(size0);
            self.code = self.code.wrapping_sub(size0);
            self.range = (self.range & !(PPMD_BIN_SCALE - 1)).wrapping_sub(size0);

            self.char_mask = [0xFF; 256];
            self.char_mask[self.symbol(self.min_context + 2) as usize] = 0;
            self.prev_success = 0;
        }

        loop {
            self.rc_norm(input);
            let mut mc = self.min_context;
            let num_masked = self.num_stats(mc);

            loop {
                self.order_fall += 1;
                if self.suffix(mc) == 0 {
                    return SYM_END;
                }
                mc = self.suffix(mc);
                if self.num_stats(mc) != num_masked {
                    break;
                }
            }

            let mut s = self.stats(mc);
            let mut hi_cnt;
            {
                let mut num = self.num_stats(mc) + 1;
                let mut num2 = num / 2;

                num &= 1;
                hi_cnt = (self.freq(s) & u32::from(self.char_mask[self.symbol(s) as usize]))
                    & 0u32.wrapping_sub(num);
                s += num * STATE_SIZE;
                self.min_context = mc;

                loop {
                    let sym0 = self.symbol(s) as usize;
                    let sym1 = self.symbol(s + STATE_SIZE) as usize;
                    s += 2 * STATE_SIZE;
                    hi_cnt += self.freq(s - 2 * STATE_SIZE) & u32::from(self.char_mask[sym0]);
                    hi_cnt += self.freq(s - STATE_SIZE) & u32::from(self.char_mask[sym1]);
                    num2 = num2.wrapping_sub(1);
                    if num2 == 0 {
                        break;
                    }
                }
            }

            let (see, mut freq_sum) = self.make_esc_freq(num_masked);
            freq_sum = freq_sum.wrapping_add(hi_cnt);
            let freq_sum2 = self.correct_sum_range(freq_sum);

            let Some(mut count) = self.rc_get_threshold(freq_sum2) else {
                return SYM_ERROR;
            };

            if count < hi_cnt {
                let mut s = self.stats(self.min_context);
                let hi_cnt = count;
                loop {
                    count = count.wrapping_sub(
                        self.freq(s) & u32::from(self.char_mask[self.symbol(s) as usize]),
                    );
                    s += STATE_SIZE;
                    if (count as i32) < 0 {
                        break;
                    }
                }
                s -= STATE_SIZE;
                let freq = self.freq(s);
                self.rc_decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                self.rc_norm(input);

                // New (see->Summ) value can overflow over 16-bits in some rare
                // cases.
                self.see_update(see);
                self.found_state = s;
                let sym = self.symbol(s);
                self.update2();
                return sym as i32;
            }

            if count >= freq_sum2 {
                return SYM_ERROR;
            }

            self.rc_decode(hi_cnt, freq_sum2 - hi_cnt);

            // We increase (see->Summ) for sum of Freqs of all non_Masked
            // symbols.
            self.see[see].summ = self.see[see].summ.wrapping_add(freq_sum as u16);

            let mut s = self.stats(self.min_context);
            let s2 = s + (self.num_stats(self.min_context) + 1) * STATE_SIZE;
            loop {
                self.char_mask[self.symbol(s) as usize] = 0;
                s += STATE_SIZE;
                if s == s2 {
                    break;
                }
            }
        }
    }
}
