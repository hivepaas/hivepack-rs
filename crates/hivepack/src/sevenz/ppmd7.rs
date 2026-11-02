//! PPMd var.H: `Ppmd7.c`, the model, and `Ppmd7Dec.c`, its decoder with 7z's
//! range coder.
//!
//! Differs from the LZMA SDK: the model's records are in one block of
//! memory, as there, at offsets from its start (the SDK's refs, without
//! `PPMD_32BIT`), but read and written through functions on a byte vector,
//! in little-endian order on every machine, rather than through pointers to
//! structures that overlap. Those structures, by offset:
//!
//! - a context (`CPpmd7_Context`), 12 bytes: `NumStats` at 0, `SummFreq` at
//!   2, `Stats` at 4, `Suffix` at 8; a context of one symbol keeps its state
//!   at 2 (`Ppmd7Context_OneState`), over `SummFreq` and `Stats`;
//! - a state (`CPpmd_State`), 6 bytes: `Symbol` at 0, `Freq` at 1,
//!   `Successor` at 2;
//! - a free block (`CPpmd7_Node`): `Stamp` at 0, `NU` at 2, `Next` at 4, or,
//!   in the free lists, the next block's offset at 0.

use crate::sevenz::error::{Error, Result};

/// `PPMD7_MIN_ORDER`.
pub(crate) const MIN_ORDER: u32 = 2;
/// `PPMD7_MAX_ORDER`.
pub(crate) const MAX_ORDER: u32 = 64;
/// `PPMD7_MIN_MEM_SIZE`.
pub(crate) const MIN_MEM_SIZE: u32 = 1 << 11;
/// `PPMD7_MAX_MEM_SIZE`.
pub(crate) const MAX_MEM_SIZE: u32 = 0xFFFF_FFFF - 12 * 3;

/// `PPMD7_SYM_END`.
pub(crate) const SYM_END: i32 = -1;
/// `PPMD7_SYM_ERROR`.
pub(crate) const SYM_ERROR: i32 = -2;

const PPMD_INT_BITS: u32 = 7;
const PPMD_PERIOD_BITS: u32 = 7;
const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);
const PPMD_N1: usize = 4;
const PPMD_N2: usize = 4;
const PPMD_N3: usize = 4;
const PPMD_N4: usize = (128 + 3 - PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4;
const PPMD_NUM_INDEXES: usize = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

const MAX_FREQ: u32 = 124;
const UNIT_SIZE: u32 = 12;
const STATE_SIZE: u32 = 6;
const TOP_VALUE: u32 = 1 << 24;
/// `DummySee`, after the 25 × 16 others.
const DUMMY_SEE: usize = 25 * 16;

/// `U2B`.
#[inline(always)]
fn u2b(nu: u32) -> u32 {
    nu.wrapping_mul(UNIT_SIZE)
}

/// `PPMD7_HiBitsFlag_3`.
#[inline(always)]
fn hi_bits_flag_3(sym: u32) -> u32 {
    ((sym + 0xC0) >> (8 - 3)) & (1 << 3)
}

/// `PPMD7_HiBitsFlag_4`.
#[inline(always)]
fn hi_bits_flag_4(sym: u32) -> u32 {
    ((sym + 0xC0) >> (8 - 4)) & (1 << 4)
}

/// `CPpmd_See`.
#[derive(Clone, Copy, Debug, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

/// `IByteIn`: where the range decoder's bytes come from. At the end of the
/// input it gives 0, and remembers it.
pub(crate) trait ByteIn {
    fn read_byte(&mut self) -> u8;
}

/// `CPpmd7`, with its range decoder (`CPpmd7_RangeDec`).
pub(crate) struct Ppmd7 {
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
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
    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
    free_list: [u32; PPMD_NUM_INDEXES],
    ns2bs_indx: [u8; 256],
    ns2indx: [u8; 256],
    see: [See; DUMMY_SEE + 1],
    bin_summ: [[u16; 64]; 128],
    /// `charMask`, a local of the SDK's `Ppmd7z_DecodeSymbol`: which symbols
    /// an escape has left. Set only by an escape, which most symbols are not.
    char_mask: [u8; 256],
    mem: Vec<u8>,
}

impl core::fmt::Debug for Ppmd7 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ppmd7")
            .field("size", &self.size)
            .field("max_order", &self.max_order)
            .finish_non_exhaustive()
    }
}

impl Ppmd7 {
    /// `Ppmd7_Construct` and `Ppmd7_Alloc`. The memory is zeroed by the
    /// system when it is first touched, so that it costs what the model
    /// uses of it.
    pub(crate) fn new(size: u32) -> Result<Box<Self>> {
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

        let mut ns2indx = [0u8; 256];
        for (i, n) in ns2indx.iter_mut().enumerate().take(3) {
            *n = i as u8;
        }
        let mut m = 3usize;
        let mut k = 1usize;
        for n in ns2indx.iter_mut().skip(3) {
            *n = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }

        let align_offset = 4u32.wrapping_sub(size) & 3;
        let total = align_offset as usize + size as usize;
        // That it can be had, before the allocation that cannot fail softly.
        let mut probe = Vec::<u8>::new();
        probe.try_reserve_exact(total).map_err(|_| Error::Mem)?;
        drop(probe);
        Ok(Box::new(Ppmd7 {
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
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
            indx2units,
            units2indx,
            free_list: [0; PPMD_NUM_INDEXES],
            ns2bs_indx,
            ns2indx,
            see: [See::default(); DUMMY_SEE + 1],
            char_mask: [0xFF; 256],
            bin_summ: [[0; 64]; 128],
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
        self.get16(c)
    }
    #[inline(always)]
    fn summ_freq(&self, c: u32) -> u32 {
        self.get16(c + 2)
    }
    #[inline(always)]
    fn stats(&self, c: u32) -> u32 {
        self.get32(c + 4)
    }
    #[inline(always)]
    fn suffix(&self, c: u32) -> u32 {
        self.get32(c + 8)
    }

    // A state's fields; `Ppmd7Context_OneState` is `c + 2`.
    #[inline(always)]
    fn symbol(&self, s: u32) -> u32 {
        self.get8(s)
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
    /// `SetSuccessor`.
    #[inline(always)]
    fn set_successor(&mut self, s: u32, v: u32) {
        self.set32(s + 2, v);
    }

    /// `s[0] = s[1]`, of states at offsets `to` and `from`.
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

    /// `SWAP_STATES`: states `s` and `s - 1`.
    #[inline(always)]
    fn swap_states(&mut self, s: u32) {
        let tmp = self.read_state(s);
        self.copy_state(s, s - STATE_SIZE);
        self.write_state(s - STATE_SIZE, tmp);
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

    /// `Ppmd7_InsertNode`.
    fn insert_node(&mut self, node: u32, indx: u32) {
        self.set32(node, self.free_list[indx as usize]);
        self.free_list[indx as usize] = node;
    }

    /// `Ppmd7_RemoveNode`.
    fn remove_node(&mut self, indx: u32) -> u32 {
        let node = self.free_list[indx as usize];
        self.free_list[indx as usize] = self.get32(node);
        node
    }

    /// `Ppmd7_SplitBlock`.
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

    /// `Ppmd7_GlueFreeBlocks`.
    fn glue_free_blocks(&mut self) {
        // The first 16 bits of a unit tell what it is: Freq != 0 in a state,
        // NumStats != 0 in a context, 0 in a free block, 1 in the guard.
        let mut n = 0u32;
        self.glue_count = 255;

        // The guard, at LoUnit.
        if self.lo_unit != self.hi_unit {
            self.set16(self.lo_unit, 1);
        }

        // The list of free blocks.
        for i in 0..PPMD_NUM_INDEXES {
            let nu = self.i2u(i as u32);
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                // Don't change the order of the following commands.
                let tmp = next;
                next = self.get32(tmp);
                self.set16(tmp, 0);
                self.set16(tmp + 2, nu);
                self.set32(tmp + 4, n);
                n = tmp;
            }
        }

        let mut head = n;
        // Glue free blocks. Glue and Fill must walk the list in the same
        // direction. `prev` is the block whose Next is the link, none for
        // the head.
        let mut prev: Option<u32> = None;
        while n != 0 {
            let node = n;
            let mut nu = self.get16(node + 2);
            n = self.get32(node + 4);
            if nu == 0 {
                match prev {
                    None => head = n,
                    Some(p) => self.set32(p + 4, n),
                }
                continue;
            }
            prev = Some(node);
            loop {
                let node2 = node + u2b(nu);
                nu += self.get16(node2 + 2);
                if self.get16(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                self.set16(node + 2, nu);
                self.set16(node2 + 2, 0);
            }
        }

        // Fill the lists of free blocks.
        n = head;
        while n != 0 {
            let mut node = n;
            let mut nu = self.get16(node + 2);
            n = self.get32(node + 4);
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

    /// `Ppmd7_AllocUnitsRare`.
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
            if i as usize == PPMD_NUM_INDEXES {
                let num_bytes = u2b(self.i2u(indx));
                let us = self.units_start;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if us - self.text > num_bytes {
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

    /// `Ppmd7_AllocUnits`.
    fn alloc_units(&mut self, indx: u32) -> Option<u32> {
        if self.free_list[indx as usize] != 0 {
            return Some(self.remove_node(indx));
        }
        let num_bytes = u2b(self.i2u(indx));
        let lo = self.lo_unit;
        if self.hi_unit - lo >= num_bytes {
            self.lo_unit = lo + num_bytes;
            return Some(lo);
        }
        self.alloc_units_rare(indx)
    }

    /// `Ppmd7_RestartModel`.
    fn restart_model(&mut self) {
        self.free_list = [0; PPMD_NUM_INDEXES];
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let s = self.lo_unit;
        self.lo_unit += u2b(256 / 2);
        self.max_context = mc;
        self.min_context = mc;
        self.found_state = s;

        self.set16(mc, 256);
        self.set16(mc + 2, 256 + 1);
        self.set32(mc + 4, s);
        self.set32(mc + 8, 0);

        for i in 0..256u32 {
            let state = s + i * STATE_SIZE;
            self.set8(state, i);
            self.set_freq(state, 1);
            self.set_successor(state, 0);
        }

        for i in 0..128u32 {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let val = (PPMD_BIN_SCALE - u32::from(esc) / (i + 2)) as u16;
                for m in (0..64).step_by(8) {
                    self.bin_summ[i as usize][k + m] = val;
                }
            }
        }

        for i in 0..25usize {
            let summ = ((5 * i + 10) << (PPMD_PERIOD_BITS - 4)) as u16;
            for k in 0..16 {
                self.see[i * 16 + k] = See {
                    summ,
                    shift: (PPMD_PERIOD_BITS - 4) as u8,
                    count: 4,
                };
            }
        }

        self.see[DUMMY_SEE] = See {
            summ: 0,
            shift: PPMD_PERIOD_BITS as u8,
            count: 64,
        };
    }

    /// `Ppmd7_Init`.
    pub(crate) fn init(&mut self, max_order: u32) {
        self.max_order = max_order;
        self.restart_model();
    }

    /// `Ppmd7_CreateSuccessors`: the context records for a RAW-Successor,
    /// `FoundState`'s, and for the same one in the suffixes of `MinContext`.
    /// None without memory.
    fn create_successors(&mut self) -> Option<u32> {
        let mut c = self.min_context;
        let mut up_branch = self.successor(self.found_state);
        let mut num_ps = 0;
        let mut ps = [0u32; MAX_ORDER as usize];

        if self.order_fall != 0 {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = if self.num_stats(c) != 1 {
                let sym = self.symbol(self.found_state);
                let mut s = self.stats(c);
                while self.symbol(s) != sym {
                    s += STATE_SIZE;
                }
                s
            } else {
                c + 2
            };
            let successor = self.successor(s);
            if successor != up_branch {
                // A real context record.
                c = successor;
                if num_ps == 0 {
                    // One of max order: no new context is needed.
                    return Some(c);
                }
                break;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        // The new contexts all have one symbol, with a new RAW-Successor to
        // the next position in the raw text.
        let new_sym = self.get8(up_branch);
        up_branch += 1;

        let new_freq = if self.num_stats(c) == 1 {
            self.freq(c + 2)
        } else {
            let mut s = self.stats(c);
            while self.symbol(s) != new_sym {
                s += STATE_SIZE;
            }
            let cf = self.freq(s) - 1;
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            // The frequency of the symbol that will be the successor, against
            // the others'.
            1 + if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + s0 - 1) / (2 * s0) + 1
            }
        };

        // From low order to high.
        loop {
            // AllocContext.
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                self.alloc_units_rare(0)?
            };
            self.set16(c1, 1);
            self.set8(c1 + 2, new_sym);
            self.set_freq(c1 + 2, new_freq);
            self.set_successor(c1 + 2, up_branch);
            self.set32(c1 + 8, c);
            num_ps -= 1;
            self.set_successor(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 {
                break;
            }
        }
        Some(c)
    }

    /// `Ppmd7_UpdateModel`.
    fn update_model(&mut self) {
        let found_state = self.found_state;
        if self.freq(found_state) < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            // Update the frequencies in the suffix context.
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 1 {
                let s = c + 2;
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s) + 1);
                }
            } else {
                let mut s = self.stats(c);
                let sym = self.symbol(found_state);
                if self.symbol(s) != sym {
                    loop {
                        s += STATE_SIZE;
                        if self.symbol(s) == sym {
                            break;
                        }
                    }
                    if self.freq(s) >= self.freq(s - STATE_SIZE) {
                        self.swap_states(s);
                        s -= STATE_SIZE;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 2);
                    self.set16(c + 2, self.summ_freq(c).wrapping_add(2));
                }
            }
        }

        if self.order_fall == 0 {
            // A context of max order: FoundState's successor is a
            // RAW-Successor.
            match self.create_successors() {
                Some(c) => {
                    self.max_context = c;
                    self.min_context = c;
                    self.set_successor(self.found_state, c);
                }
                None => self.restart_model(),
            }
            return;
        }

        // A context of lower order.
        self.set8(self.text, self.symbol(self.found_state));
        self.text += 1;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }
        let mut max_successor = self.text;
        let mut min_successor = self.successor(self.found_state);

        if min_successor != 0 {
            // The next context will be one order higher than MinContext.
            if min_successor <= max_successor {
                // A RAW-Successor: real context records are made.
                let Some(cs) = self.create_successors() else {
                    self.restart_model();
                    return;
                };
                min_successor = cs;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                // The same successor for MinContext and MaxContext: no new
                // RAW-Successor is needed.
                max_successor = min_successor;
                self.text -= u32::from(self.max_context != self.min_context);
            }
        } else {
            // Only the root context of order 0 has NULL-Successors.
            self.set_successor(self.found_state, max_successor);
            min_successor = self.min_context;
        }

        let mc = self.min_context;
        let mut c = self.max_context;
        self.max_context = min_successor;
        self.min_context = min_successor;

        if c == mc {
            return;
        }

        // The pure escape frequency.
        let ns = self.num_stats(mc);
        let s0 = self
            .summ_freq(mc)
            .wrapping_sub(ns)
            .wrapping_sub(self.freq(self.found_state) - 1);

        loop {
            let ns1 = self.num_stats(c);
            let mut sum;
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    // Expand for one unit.
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let Some(ptr) = self.alloc_units(i + 1) else {
                            self.restart_model();
                            return;
                        };
                        let old_ptr = self.stats(c);
                        self.mem_12_cpy(ptr, old_ptr, old_nu);
                        self.insert_node(old_ptr, i);
                        self.set32(c + 4, ptr);
                    }
                }
                sum = self.summ_freq(c);
                // The escape frequency grows by 3 at most here.
                sum += u32::from(2 * ns1 < ns)
                    + 2 * (u32::from(4 * ns1 <= ns) & u32::from(sum <= 8 * ns1));
            } else {
                // A context of 2 symbols, instead of one.
                let Some(s) = self.alloc_units(0) else {
                    self.restart_model();
                    return;
                };
                let mut freq = self.freq(c + 2);
                self.set8(s, self.symbol(c + 2));
                self.set_successor(s, self.successor(c + 2));
                self.set32(c + 4, s);
                if freq < MAX_FREQ / 4 - 1 {
                    freq <<= 1;
                } else {
                    freq = MAX_FREQ - 4;
                }
                self.set_freq(s, freq);
                sum = freq + self.init_esc + u32::from(ns > 3);
            }

            {
                let s = self.stats(c) + ns1 * STATE_SIZE;
                let mut cf = 2u32
                    .wrapping_mul(sum + 6)
                    .wrapping_mul(self.freq(self.found_state));
                let sf = s0.wrapping_add(sum);
                self.set8(s, self.symbol(self.found_state));
                self.set16(c, ns1 + 1);
                self.set_successor(s, max_successor);

                if cf < sf.wrapping_mul(6) {
                    cf = 1 + u32::from(cf > sf) + u32::from(cf >= sf.wrapping_mul(4));
                    sum += 3;
                } else {
                    cf = 4
                        + u32::from(cf >= sf.wrapping_mul(9))
                        + u32::from(cf >= sf.wrapping_mul(12))
                        + u32::from(cf >= sf.wrapping_mul(15));
                    sum += cf;
                }
                self.set16(c + 2, sum);
                self.set_freq(s, cf);
            }
            c = self.suffix(c);
            if c == mc {
                break;
            }
        }
    }

    /// `Ppmd7_Rescale`.
    fn rescale(&mut self) {
        let stats = self.stats(self.min_context);
        let mut s = self.found_state;

        // Sort the list by frequency.
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

        // A symbol may be removed from a context of max order only.
        let adder = u32::from(self.order_fall != 0);

        sum_freq = (sum_freq + 4 + adder) >> 1;
        let mut i = self.num_stats(self.min_context) - 1;
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
                    if s1 == stats || freq <= self.freq(s1 - STATE_SIZE) {
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
            // Remove the items with a frequency of 0.
            let mut i = 0;
            loop {
                i += 1;
                s -= STATE_SIZE;
                if self.freq(s) != 0 {
                    break;
                }
            }
            // The escape frequency grows by the number of symbols removed,
            // 0.5 for each on average after it is halved.
            esc_freq = esc_freq.wrapping_add(i);
            let mc = self.min_context;
            let num_stats = self.num_stats(mc);
            let num_stats_new = num_stats - i;
            self.set16(mc, num_stats_new);
            let n0 = (num_stats + 1) >> 1;

            if num_stats_new == 1 {
                // A context of one symbol.
                let mut freq = self.freq(stats);
                loop {
                    esc_freq >>= 1;
                    freq = (freq + 1) >> 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                let s = mc + 2;
                self.copy_state(s, stats);
                self.set_freq(s, freq);
                self.found_state = s;
                let indx = self.u2i(n0);
                self.insert_node(stats, indx);
                return;
            }

            let n1 = (num_stats_new + 1) >> 1;
            if n0 != n1 {
                let i0 = self.u2i(n0);
                let i1 = self.u2i(n1);
                if i0 != i1 {
                    if self.free_list[i1 as usize] != 0 {
                        let ptr = self.remove_node(i1);
                        self.set32(self.min_context + 4, ptr);
                        self.mem_12_cpy(ptr, stats, n1);
                        self.insert_node(stats, i0);
                    } else {
                        self.split_block(stats, i0, i1);
                    }
                }
            }
        }
        let mc = self.min_context;
        // The escape frequency is halved here.
        self.set16(mc + 2, sum_freq + esc_freq - (esc_freq >> 1));
        self.found_state = self.stats(mc);
    }

    /// `Ppmd7_MakeEscFreq`: the SEE context, and the escape frequency.
    fn make_esc_freq(&mut self, num_masked: u32) -> (usize, u32) {
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats == 256 {
            return (DUMMY_SEE, 1);
        }
        let non_masked = num_stats - num_masked;
        let see = usize::from(self.ns2indx[non_masked as usize - 1]) * 16
            + usize::from(non_masked < self.num_stats(self.suffix(mc)).wrapping_sub(num_stats))
            + 2 * usize::from(self.summ_freq(mc) < 11 * num_stats)
            + 4 * usize::from(num_masked > non_masked)
            + self.hi_bits_flag as usize;
        let entry = &mut self.see[see];
        let summ = u32::from(entry.summ);
        let r = summ >> entry.shift;
        entry.summ = (summ - r) as u16;
        (see, r + u32::from(r == 0))
    }

    /// `Ppmd7_NextContext`.
    #[inline(always)]
    fn next_context(&mut self) {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.max_context = c;
            self.min_context = c;
        } else {
            self.update_model();
        }
    }

    /// `Ppmd7_Update1`.
    fn update1(&mut self) {
        let mut s = self.found_state;
        let freq = self.freq(s) + 4;
        self.set16(
            self.min_context + 2,
            self.summ_freq(self.min_context).wrapping_add(4),
        );
        self.set_freq(s, freq);
        if freq > self.freq(s - STATE_SIZE) {
            self.swap_states(s);
            s -= STATE_SIZE;
            self.found_state = s;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    /// `Ppmd7_Update1_0`.
    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        let freq = self.freq(s);
        let summ_freq = self.summ_freq(mc);
        self.prev_success = u32::from(2 * freq > summ_freq);
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.set16(mc + 2, summ_freq.wrapping_add(4));
        let freq = freq + 4;
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    /// `Ppmd7_Update2`.
    fn update2(&mut self) {
        let s = self.found_state;
        let freq = self.freq(s) + 4;
        self.run_length = self.init_rl;
        self.set16(
            self.min_context + 2,
            self.summ_freq(self.min_context).wrapping_add(4),
        );
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model();
    }

    /// `Ppmd7z_RangeDec_Init`.
    pub(crate) fn range_dec_init(&mut self, input: &mut impl ByteIn) -> bool {
        self.code = 0;
        self.range = 0xFFFF_FFFF;
        if input.read_byte() != 0 {
            return false;
        }
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(input.read_byte());
        }
        self.code < 0xFFFF_FFFF
    }

    /// `Ppmd7z_RangeDec_IsFinishedOK`.
    pub(crate) fn range_dec_is_finished_ok(&self) -> bool {
        self.code == 0
    }

    /// `RC_NORM_1`.
    #[inline(always)]
    fn rc_norm_1(&mut self, input: &mut impl ByteIn) {
        if self.range < TOP_VALUE {
            self.code = (self.code << 8) | u32::from(input.read_byte());
            self.range <<= 8;
        }
    }

    /// `RC_NORM`.
    #[inline(always)]
    fn rc_norm(&mut self, input: &mut impl ByteIn) {
        if self.range < TOP_VALUE {
            self.code = (self.code << 8) | u32::from(input.read_byte());
            self.range <<= 8;
            self.rc_norm_1(input);
        }
    }

    /// `RC_Decode`.
    #[inline(always)]
    fn rc_decode(&mut self, start: u32, size: u32) {
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
    }

    /// `RC_GetThreshold`.
    #[inline(always)]
    fn rc_threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        self.code / self.range
    }

    /// `Ppmd7z_DecodeSymbol`: a byte, or `SYM_END` or `SYM_ERROR`.
    pub(crate) fn decode_symbol(&mut self, input: &mut impl ByteIn) -> i32 {
        let mc = self.min_context;

        if self.num_stats(mc) != 1 {
            let mut s = self.stats(mc);
            let summ_freq = self.summ_freq(mc);
            let mut count = self.rc_threshold(summ_freq);
            let mut hi_cnt = count;

            let freq = self.freq(s);
            count = count.wrapping_sub(freq);
            if (count as i32) < 0 {
                self.rc_decode(0, freq);
                self.rc_norm(input);
                self.found_state = s;
                let sym = self.symbol(s);
                self.update1_0();
                return sym as i32;
            }

            self.prev_success = 0;
            let mut i = self.num_stats(mc) - 1;
            loop {
                s += STATE_SIZE;
                let freq = self.freq(s);
                count = count.wrapping_sub(freq);
                if (count as i32) < 0 {
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

            hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc_decode(hi_cnt, summ_freq.wrapping_sub(hi_cnt));

            self.hi_bits_flag = hi_bits_flag_3(self.symbol(self.found_state));
            // PPMD_SetAllBitsIn256Bytes, and the states' symbols masked.
            self.char_mask.fill(0xFF);
            let mut s2 = self.stats(mc);
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
            let s = mc + 2;
            // Ppmd7_GetBinSumm.
            let sym = self.symbol(s);
            self.hi_bits_flag = hi_bits_flag_3(self.symbol(self.found_state));
            let i = self.freq(s) as usize - 1;
            let j = (self.prev_success
                + ((self.run_length >> 26) as u32 & 0x20)
                + u32::from(self.ns2bs_indx[self.num_stats(self.suffix(mc)) as usize - 1])
                + hi_bits_flag_4(sym)
                + self.hi_bits_flag) as usize;
            let mut pr = u32::from(self.bin_summ[i][j]);
            let size0 = (self.range >> 14) * pr;
            // PPMD_UPDATE_PROB_1.
            pr -= (pr + (1 << (PPMD_PERIOD_BITS - 2))) >> PPMD_PERIOD_BITS;

            if self.code < size0 {
                self.bin_summ[i][j] = (pr + (1 << PPMD_INT_BITS)) as u16;
                self.range = size0;
                // One byte is enough: the probabilities are at least 95, more
                // than 1 << (14 - 8).
                self.rc_norm_1(input);

                let freq = self.freq(s);
                let c = self.successor(s);
                self.found_state = s;
                self.prev_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.set_freq(s, freq + u32::from(freq < 128));
                // NextContext.
                if self.order_fall == 0 && c > self.text {
                    self.max_context = c;
                    self.min_context = c;
                } else {
                    self.update_model();
                }
                return sym as i32;
            }

            self.bin_summ[i][j] = pr as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(pr >> 10) as usize]);
            self.code -= size0;
            self.range -= size0;

            self.char_mask.fill(0xFF);
            self.char_mask[sym as usize] = 0;
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
            let num = self.num_stats(mc);
            let num2 = num / 2;
            let num = num & 1;
            let mut hi_cnt = (self.freq(s) & u32::from(self.char_mask[self.symbol(s) as usize]))
                & 0u32.wrapping_sub(num);
            s += num * STATE_SIZE;
            self.min_context = mc;

            for _ in 0..num2 {
                let sym0 = self.symbol(s) as usize;
                let sym1 = self.symbol(s + STATE_SIZE) as usize;
                hi_cnt += self.freq(s) & u32::from(self.char_mask[sym0]);
                hi_cnt += self.freq(s + STATE_SIZE) & u32::from(self.char_mask[sym1]);
                s += 2 * STATE_SIZE;
            }

            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let freq_sum = esc_freq + hi_cnt;
            let mut count = self.rc_threshold(freq_sum);

            if count < hi_cnt {
                let mut s = self.stats(self.min_context);
                let threshold = count;
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
                self.rc_decode(threshold.wrapping_sub(count).wrapping_sub(freq), freq);
                self.rc_norm(input);

                // Ppmd_See_UPDATE: Summ may overflow 16 bits, in rare cases.
                let entry = &mut self.see[see];
                if u32::from(entry.shift) < PPMD_PERIOD_BITS {
                    entry.count = entry.count.wrapping_sub(1);
                    if entry.count == 0 {
                        entry.summ <<= 1;
                        entry.count = (3u32 << entry.shift) as u8;
                        entry.shift += 1;
                    }
                }
                self.found_state = s;
                let sym = self.symbol(s);
                self.update2();
                return sym as i32;
            }

            if count >= freq_sum {
                return SYM_ERROR;
            }

            self.rc_decode(hi_cnt, freq_sum - hi_cnt);

            // The SEE's sum grows by the frequencies of the symbols not
            // masked; it may overflow 16 bits, in rare cases.
            let entry = &mut self.see[see];
            entry.summ = entry.summ.wrapping_add(freq_sum as u16);

            let mut s = self.stats(self.min_context);
            let end = s + self.num_stats(self.min_context) * STATE_SIZE;
            loop {
                self.char_mask[self.symbol(s) as usize] = 0;
                s += STATE_SIZE;
                if s == end {
                    break;
                }
            }
        }
    }
}
