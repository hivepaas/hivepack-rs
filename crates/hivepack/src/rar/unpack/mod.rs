// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Decompressing: UnRAR's `Unpack` (unpack.cpp, unpackinline.cpp) and its
//! `BitInput` (getbits.cpp), what all its algorithms share. `v15` is the
//! algorithm of RAR 1.3 to 1.5, `v20` that of RAR 2.x, `v30` that of RAR 2.9
//! to 4, with `ppm` and `filters`, and `v50` that of RAR 5.0 and 7.0.
//!
//! One difference from UnRAR, which makes none to what comes out: UnRAR
//! allocates the whole dictionary an entry asks for, and the window here grows
//! as data reaches it, so that a few damaged bytes asking for 4 GiB cost
//! nothing. The window is only ever read where it has been written: a match
//! reaching back further than that gives zeros, in UnRAR too.

mod filters;
#[cfg(test)]
pub(crate) mod oracle_tests;
mod ppm;
mod v15;
mod v20;
mod v30;
mod v50;

use std::fmt;

use crate::rar::error::Error;

use filters::{RarVm, StandardFilter};
use ppm::ModelPpm;
use v15::State15;
use v20::State20;
use v30::{BlockType, Filter30, HUFF_TABLE_SIZE30};

/// `MAX_QUICK_DECODE_BITS`.
const MAX_QUICK_DECODE_BITS: u32 = 9;
/// `MAX_UNPACK_FILTERS`.
const MAX_UNPACK_FILTERS: usize = 8192;
/// `MAX_FILTER_BLOCK_SIZE`.
const MAX_FILTER_BLOCK_SIZE: u32 = 0x40_0000;
/// `UNPACK_MAX_WRITE`.
const UNPACK_MAX_WRITE: usize = 0x40_0000;
/// `UNPACK_MAX_DICT` and the 1 TB of `Unpack::Init`.
const MAX_DICT: u64 = 0x100_0000_0000;

/// `PackDef::MAX_LZ_MATCH`.
const MAX_LZ_MATCH: usize = 0x1001;
/// `PackDef::MAX_INC_LZ_MATCH`.
const MAX_INC_LZ_MATCH: usize = MAX_LZ_MATCH + 3;
/// `PackDef::NC`.
const NC: usize = 306;
/// `PackDef::DCB`.
const DCB: usize = 64;
/// `PackDef::DCX`.
const DCX: usize = 80;
/// `PackDef::LDC`.
const LDC: usize = 16;
/// `PackDef::RC`.
const RC: usize = 44;
/// `PackDef::HUFF_TABLE_SIZEB`.
const HUFF_TABLE_SIZEB: usize = NC + DCB + RC + LDC;
/// `PackDef::HUFF_TABLE_SIZEX`.
const HUFF_TABLE_SIZEX: usize = NC + DCX + RC + LDC;
/// `PackDef::BC`.
const BC: usize = 20;
/// `PackDef::LARGEST_TABLE_SIZE`.
const LARGEST_TABLE_SIZE: usize = 306;
/// `NC20` and `NC30`, which also take the larger quick tables.
const NC20: usize = 298;
const NC30: usize = 299;

/// What decompression reads from and writes to: `ComprDataIO`.
pub(crate) trait UnpIo {
    /// `UnpRead`: packed data, how many bytes, 0 when none is left, and
    /// nothing where it returns -1, for a next volume that is missing.
    fn unp_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error>;
    /// `UnpWrite`: unpacked data.
    fn unp_write(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// `BitInput`: bits from a buffer, the highest first.
struct BitInput {
    in_addr: i32,
    in_bit: u32,
    in_buf: Box<[u8]>,
}

impl BitInput {
    /// `BitInput::MAX_SIZE`.
    const MAX_SIZE: i32 = 0x8000;

    /// Eight more bytes than it holds, all zero: reading past what was read
    /// gives what was there, and that is part of how a damaged archive reads.
    fn new() -> BitInput {
        BitInput {
            in_addr: 0,
            in_bit: 0,
            in_buf: vec![0; BitInput::MAX_SIZE as usize + 8].into_boxed_slice(),
        }
    }

    fn init(&mut self) {
        self.in_addr = 0;
        self.in_bit = 0;
    }

    #[inline(always)]
    fn addbits(&mut self, bits: u32) {
        let bits = bits + self.in_bit;
        self.in_addr += (bits >> 3) as i32;
        self.in_bit = bits & 7;
    }

    /// `getbits`: the next 16 bits.
    #[inline(always)]
    fn getbits(&self) -> u32 {
        let at = self.in_addr as usize;
        let field = (u32::from(self.in_buf[at]) << 16)
            | (u32::from(self.in_buf[at + 1]) << 8)
            | u32::from(self.in_buf[at + 2]);
        (field >> (8 - self.in_bit)) & 0xffff
    }

    /// `getbits32`: the next 32 bits.
    fn getbits32(&self) -> u32 {
        let at = self.in_addr as usize;
        let mut word = [0; 4];
        word.copy_from_slice(&self.in_buf[at..at + 4]);
        (u32::from_be_bytes(word) << self.in_bit)
            | (u32::from(self.in_buf[at + 4]) >> (8 - self.in_bit))
    }

    /// `getbits64`: the next 64 bits.
    fn getbits64(&self) -> u64 {
        let at = self.in_addr as usize;
        let mut word = [0; 8];
        word.copy_from_slice(&self.in_buf[at..at + 8]);
        (u64::from_be_bytes(word) << self.in_bit)
            | u64::from(u32::from(self.in_buf[at + 8]) >> (8 - self.in_bit))
    }
}

/// `DecodeTable`: compressed bits to alphabet numbers.
#[derive(Clone)]
struct DecodeTable {
    max_num: u32,
    decode_len: [u32; 16],
    decode_pos: [u32; 16],
    quick_bits: u32,
    quick_len: [u8; 1 << MAX_QUICK_DECODE_BITS],
    quick_num: [u16; 1 << MAX_QUICK_DECODE_BITS],
    decode_num: [u16; LARGEST_TABLE_SIZE],
}

impl DecodeTable {
    fn zero() -> DecodeTable {
        DecodeTable {
            max_num: 0,
            decode_len: [0; 16],
            decode_pos: [0; 16],
            quick_bits: 0,
            quick_len: [0; 1 << MAX_QUICK_DECODE_BITS],
            quick_num: [0; 1 << MAX_QUICK_DECODE_BITS],
            decode_num: [0; LARGEST_TABLE_SIZE],
        }
    }

    /// `Unpack::MakeDecodeTables`: from the length in bits of every element
    /// of an alphabet of `length_table.len()` elements.
    fn make(&mut self, length_table: &[u8]) {
        let size = length_table.len();
        self.max_num = size as u32;

        let mut length_count = [0u32; 16];
        for &length in length_table {
            length_count[usize::from(length & 0xf)] += 1;
        }
        length_count[0] = 0;

        self.decode_num[..size].fill(0);
        self.decode_pos[0] = 0;
        self.decode_len[0] = 0;

        let mut upper_limit = 0u32;
        for i in 1..16 {
            upper_limit += length_count[i];
            self.decode_len[i] = upper_limit << (16 - i);
            upper_limit *= 2;
            self.decode_pos[i] = self.decode_pos[i - 1] + length_count[i - 1];
        }

        let mut copy_decode_pos = self.decode_pos;
        for (i, &length) in length_table.iter().enumerate() {
            let length = usize::from(length & 0xf);
            if length != 0 {
                let last_pos = copy_decode_pos[length] as usize;
                self.decode_num[last_pos] = i as u16;
                copy_decode_pos[length] += 1;
            }
        }

        self.quick_bits = if size == NC || size == NC20 || size == NC30 {
            MAX_QUICK_DECODE_BITS
        } else {
            MAX_QUICK_DECODE_BITS - 3
        };

        let quick_data_size = 1u32 << self.quick_bits;
        // From 1, so that a corrupt archive still moves forward.
        let mut cur_bit_length = 1u32;
        for code in 0..quick_data_size {
            let bit_field = code << (16 - self.quick_bits);
            while cur_bit_length < 16 && bit_field >= self.decode_len[cur_bit_length as usize] {
                cur_bit_length += 1;
            }
            self.quick_len[code as usize] = cur_bit_length as u8;

            let dist = bit_field.wrapping_sub(self.decode_len[cur_bit_length as usize - 1])
                >> (16 - cur_bit_length);
            let pos = if cur_bit_length < 16 {
                self.decode_pos[cur_bit_length as usize].wrapping_add(dist)
            } else {
                u32::MAX
            };
            self.quick_num[code as usize] = if (pos as usize) < size {
                self.decode_num[pos as usize]
            } else {
                // A table of zero lengths only.
                0
            };
        }
    }

    /// `Unpack::DecodeNumber`.
    #[inline(always)]
    fn decode(&self, inp: &mut BitInput) -> u32 {
        let bit_field = inp.getbits() & 0xfffe;

        if bit_field < self.decode_len[self.quick_bits as usize] {
            let code = (bit_field >> (16 - self.quick_bits)) as usize;
            inp.addbits(u32::from(self.quick_len[code]));
            return u32::from(self.quick_num[code]);
        }

        let mut bits = 15;
        for i in self.quick_bits + 1..15 {
            if bit_field < self.decode_len[i as usize] {
                bits = i;
                break;
            }
        }
        inp.addbits(bits);

        let dist = bit_field.wrapping_sub(self.decode_len[bits as usize - 1]) >> (16 - bits);
        let mut pos = self.decode_pos[bits as usize].wrapping_add(dist);
        if pos >= self.max_num {
            pos = 0;
        }
        u32::from(self.decode_num[pos as usize])
    }
}

/// `UnpackBlockHeader`.
#[derive(Clone, Copy, Default)]
struct BlockHeader {
    block_size: i32,
    block_bit_size: i32,
    block_start: i32,
    last_block_in_file: bool,
    table_present: bool,
}

/// `UnpackBlockTables`.
#[derive(Clone)]
struct BlockTables {
    ld: DecodeTable,
    dd: DecodeTable,
    ldd: DecodeTable,
    rd: DecodeTable,
    bd: DecodeTable,
}

impl BlockTables {
    fn zero() -> BlockTables {
        BlockTables {
            ld: DecodeTable::zero(),
            dd: DecodeTable::zero(),
            ldd: DecodeTable::zero(),
            rd: DecodeTable::zero(),
            bd: DecodeTable::zero(),
        }
    }
}

/// `UnpackFilter`.
#[derive(Clone, Copy)]
struct Filter {
    kind: u8,
    channels: u8,
    next_window: bool,
    block_start: usize,
    block_length: u32,
}

/// `Unpack`: what lasts from one entry to the next, as a solid archive's
/// entries go on from each other.
pub(crate) struct Unpack {
    inp: BitInput,

    filter_src_memory: Vec<u8>,
    filter_dst_memory: Vec<u8>,
    filters: Vec<Filter>,

    old_dist: [usize; 4],
    /// For RAR 2 and older, whose `old_dist` goes round.
    old_dist_ptr: usize,
    last_length: u32,
    /// For RAR 2 and older: in RAR 3 the last distance is `old_dist[0]`.
    last_dist: u32,

    unp_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    wr_ptr: usize,

    read_top: i32,
    read_border: i32,

    block_header: BlockHeader,
    block_tables: Box<BlockTables>,

    write_border: usize,

    /// Written up to its length, at most `alloc_win_size`.
    window: Vec<u8>,
    /// Whether `Window` is not null: `Init` has been through.
    allocated: bool,

    dest_unp_size: i64,
    written_file_size: i64,

    tables_read3: bool,
    tables_read5: bool,

    st15: Box<State15>,
    st20: Box<State20>,

    // RAR 3.
    prev_low_dist: i32,
    low_dist_rep_count: i32,
    /// Out of here while it reads, through `get_char`, from the rest.
    ppm: Option<Box<ModelPpm>>,
    ppm_esc_char: i32,
    unp_old_table: [u8; HUFF_TABLE_SIZE30],
    unp_block_type: BlockType,
    vm: RarVm,
    vm_code_inp: BitInput,
    /// `Filters30`: only the standard filter that each one is.
    filters30: Vec<StandardFilter>,
    prg_stack: Vec<Option<Filter30>>,
    old_filter_lengths: Vec<u32>,
    last_filter: u32,

    alloc_win_size: u64,
    max_win_size: usize,

    extra_dist: bool,
}

impl fmt::Debug for Unpack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unpack")
            .field("alloc_win_size", &self.alloc_win_size)
            .field("max_win_size", &self.max_win_size)
            .finish_non_exhaustive()
    }
}

impl Unpack {
    pub(crate) fn new() -> Unpack {
        let mut unpack = Unpack {
            inp: BitInput::new(),
            filter_src_memory: Vec::new(),
            filter_dst_memory: Vec::new(),
            filters: Vec::new(),
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_length: 0,
            last_dist: 0,
            unp_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            wr_ptr: 0,
            read_top: 0,
            read_border: 0,
            block_header: BlockHeader::default(),
            block_tables: Box::new(BlockTables::zero()),
            write_border: 0,
            window: Vec::new(),
            allocated: false,
            dest_unp_size: 0,
            written_file_size: 0,
            tables_read3: false,
            tables_read5: false,
            st15: Box::new(State15::new()),
            st20: Box::new(State20::new()),
            prev_low_dist: 0,
            low_dist_rep_count: 0,
            ppm: Some(Box::new(ModelPpm::new())),
            ppm_esc_char: 0,
            unp_old_table: [0; HUFF_TABLE_SIZE30],
            unp_block_type: BlockType::Lz,
            vm: RarVm::new(),
            vm_code_inp: BitInput::new(),
            filters30: Vec::new(),
            prg_stack: Vec::new(),
            old_filter_lengths: Vec::new(),
            last_filter: 0,
            alloc_win_size: 0,
            max_win_size: 0,
            extra_dist: false,
        };
        // Done once for all files, so that a first file wrongly called solid
        // starts from something.
        unpack.unp_init_data(false);
        unpack
    }

    /// `Unpack::Init`. [`Error::NoMemory`] where it throws `bad_alloc`.
    pub(crate) fn init(&mut self, win_size: u64, solid: bool) -> Result<(), Error> {
        // At least twice the largest filter block there was, or a block's
        // `NextWindow` might never clear.
        let win_size = win_size.max(0x4_0000);
        if win_size > MAX_DICT {
            return Err(Error::NoMemory);
        }
        if win_size > 0x8000_0000 && usize::BITS <= 32 {
            return Err(Error::NoMemory);
        }

        // A solid stream keeps its window size. A first file with the solid
        // flag gets a window all the same.
        if !solid || !self.allocated {
            self.max_win_size = win_size as usize;
        }

        if win_size <= self.alloc_win_size {
            return Ok(());
        }

        // The window size does not grow in a solid stream.
        if solid && self.allocated {
            return Err(Error::NoMemory);
        }

        // What is in the window is of no more use: see the module's notes
        // for why it grows later.
        self.window = Vec::new();
        self.allocated = true;
        self.alloc_win_size = win_size;
        Ok(())
    }

    /// `Unpack::SetDestSize`.
    pub(crate) fn set_dest_size(&mut self, dest_size: i64) {
        self.dest_unp_size = dest_size;
    }

    /// `Unpack::DoUnpack`, for what has been ported.
    pub(crate) fn do_unpack(
        &mut self,
        method: u32,
        solid: bool,
        io: &mut dyn UnpIo,
    ) -> Result<(), Error> {
        match method {
            // RAR 1.5.
            15 => self.unpack15(solid, io),
            // RAR 2.x, and files larger than 2 GB.
            20 | 26 => self.unpack20(solid, io),
            // RAR 2.9 to 4.
            29 => self.unpack29(solid, io),
            // RAR 5.0 and 7.0.
            50 | 70 => {
                self.extra_dist = method == 70;
                self.unpack5(solid, io)
            }
            _ => Ok(()),
        }
    }

    /// `Unpack::UnpInitData`.
    fn unp_init_data(&mut self, solid: bool) {
        if !solid {
            self.old_dist = [usize::MAX; 4];
            self.old_dist_ptr = 0;
            self.last_dist = u32::MAX;
            self.last_length = 0;
            *self.block_tables = BlockTables::zero();
            self.unp_ptr = 0;
            self.wr_ptr = 0;
            self.prev_ptr = 0;
            self.first_win_done = false;
            self.write_border = self.max_win_size.min(UNPACK_MAX_WRITE);
        }
        // Filters never share several solid files.
        self.filters.clear();

        self.inp.init();
        self.written_file_size = 0;
        self.read_top = 0;
        self.read_border = 0;

        self.block_header = BlockHeader {
            block_size: -1,
            ..BlockHeader::default()
        };
        self.st20.init_data(solid);
        self.unp_init_data30(solid);
        self.unp_init_data50(solid);
    }

    /// `Unpack::GetChar`, for the range coder.
    #[inline(always)]
    fn get_char(&mut self, io: &mut dyn UnpIo) -> Result<u8, Error> {
        if self.inp.in_addr > BitInput::MAX_SIZE - 30 {
            self.unp_read_buf(io)?;
            if self.inp.in_addr >= BitInput::MAX_SIZE {
                return Ok(0);
            }
        }
        let byte = self.inp.in_buf[self.inp.in_addr as usize];
        self.inp.in_addr += 1;
        Ok(byte)
    }

    /// `MaxWinMask`, for the algorithms with windows of a power of 2.
    #[inline(always)]
    fn max_win_mask(&self) -> usize {
        self.max_win_size.wrapping_sub(1)
    }

    /// `Unpack::WrapDown`.
    #[inline(always)]
    fn wrap_down(&self, win_pos: usize) -> usize {
        if win_pos >= self.max_win_size {
            win_pos.wrapping_add(self.max_win_size)
        } else {
            win_pos
        }
    }

    /// `Unpack::WrapUp`.
    #[inline(always)]
    fn wrap_up(&self, win_pos: usize) -> usize {
        if win_pos >= self.max_win_size {
            win_pos.wrapping_sub(self.max_win_size)
        } else {
            win_pos
        }
    }

    /// Makes the window long enough for a match from `unp_ptr`. Past the
    /// window's end a match wraps, and by then the window has its full size.
    ///
    /// Having been through a window means it has its full size for what comes
    /// next, even if the window was made again. That takes a RAR 1.5 entry
    /// solid by the archive's flag and not by its own, whose `Init` makes a
    /// larger window while the stream goes on: then a match reads zeros.
    #[inline(always)]
    fn reserve_window(&mut self) -> Result<(), Error> {
        if self.window.len() < self.max_win_size {
            let needed = if self.first_win_done {
                self.max_win_size
            } else {
                self.unp_ptr + MAX_INC_LZ_MATCH + 1
            };
            if needed > self.window.len() {
                return self.grow_window(needed);
            }
        }
        Ok(())
    }

    #[cold]
    fn grow_window(&mut self, needed: usize) -> Result<(), Error> {
        let size = needed
            .max(self.window.len().saturating_mul(2))
            .max(1 << 20)
            .min(self.max_win_size);
        self.window
            .try_reserve_exact(size - self.window.len())
            .map_err(|_| Error::NoMemory)?;
        self.window.resize(size, 0);
        Ok(())
    }

    /// A window of at least `end` bytes, zeros past what has been written.
    /// Entries of RAR 1.5 that are solid only by the archive's flag can change
    /// the window under what is still to be written: there it is what UnRAR's
    /// cleared window has.
    fn window_up_to(&mut self, end: usize) -> Result<(), Error> {
        if end > self.window.len() {
            self.window
                .try_reserve_exact(end - self.window.len())
                .map_err(|_| Error::NoMemory)?;
            self.window.resize(end, 0);
        }
        Ok(())
    }

    /// `Unpack::InsertOldDist`.
    #[inline(always)]
    fn insert_old_dist(&mut self, distance: usize) {
        self.old_dist[3] = self.old_dist[2];
        self.old_dist[2] = self.old_dist[1];
        self.old_dist[1] = self.old_dist[0];
        self.old_dist[0] = distance;
    }

    /// `Unpack::CopyString`.
    #[inline(always)]
    fn copy_string(&mut self, length: u32, distance: usize) {
        let length = length as usize;
        let mut src_ptr = self.unp_ptr.wrapping_sub(distance);

        if distance > self.unp_ptr {
            src_ptr = src_ptr.wrapping_add(self.max_win_size);

            // A distance past the window, or past what this file has written
            // so far: zeros, so that only the distance is broken, and the
            // result does not depend on files before it.
            if distance > self.max_win_size || !self.first_win_done {
                for _ in 0..length {
                    self.window[self.unp_ptr] = 0;
                    self.unp_ptr = self.wrap_up(self.unp_ptr + 1);
                }
                return;
            }
        }

        let border = self.max_win_size - MAX_INC_LZ_MATCH;
        if src_ptr < border && self.unp_ptr < border {
            let unp_ptr = self.unp_ptr;
            self.unp_ptr += length;
            if distance >= length || src_ptr > unp_ptr {
                self.window.copy_within(src_ptr..src_ptr + length, unp_ptr);
            } else if distance == 1 {
                let byte = self.window[src_ptr];
                self.window[unp_ptr..unp_ptr + length].fill(byte);
            } else if distance == 0 {
                // RAR 1.5 can leave a distance of 0 for a solid entry of a
                // later algorithm: each byte is copied onto itself.
            } else {
                // Overlapping: what was just written is read again, and it
                // repeats, so that each copy can be as long as all before it.
                let mut done = 0;
                let mut step = distance;
                while done < length {
                    let size = step.min(length - done);
                    self.window
                        .copy_within(src_ptr..src_ptr + size, unp_ptr + done);
                    done += size;
                    step += size;
                }
            }
        } else {
            for _ in 0..length {
                self.window[self.unp_ptr] = self.window[self.wrap_up(src_ptr)];
                src_ptr += 1;
                self.unp_ptr = self.wrap_up(self.unp_ptr + 1);
            }
        }
    }
}

/// `Unpack::SlotToLength`.
#[inline(always)]
fn slot_to_length(inp: &mut BitInput, slot: u32) -> u32 {
    let (l_bits, mut length) = if slot < 8 {
        (0, 2 + slot)
    } else {
        let l_bits = slot / 4 - 1;
        (l_bits, 2 + ((4 | (slot & 3)) << l_bits))
    };
    if l_bits > 0 {
        length += inp.getbits() >> (16 - l_bits);
        inp.addbits(l_bits);
    }
    length
}
