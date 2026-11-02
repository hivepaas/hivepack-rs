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

//! The algorithm of RAR 2.9 to 4: UnRAR's unpack30.cpp, Huffman coded LZ or
//! PPMd, with filters.

use crate::rar::error::Error;

use super::filters::{Program, StandardFilter, prepare, read_data};
use super::{BC, BitInput, UnpIo, Unpack};

/// `PackDef::MAX3_LZ_MATCH`.
const MAX3_LZ_MATCH: usize = 0x101;
/// `PackDef::MAX3_INC_LZ_MATCH`.
const MAX3_INC_LZ_MATCH: usize = MAX3_LZ_MATCH + 3;
/// `PackDef::LOW_DIST_REP_COUNT`.
const LOW_DIST_REP_COUNT: i32 = 16;
/// `PackDef::NC30`.
const NC30: usize = 299;
/// `PackDef::DC30`.
const DC30: usize = 60;
/// `PackDef::LDC30`.
const LDC30: usize = 17;
/// `PackDef::RC30`.
const RC30: usize = 28;
/// `PackDef::BC30`.
const BC30: usize = 20;
/// `PackDef::HUFF_TABLE_SIZE30`.
pub(super) const HUFF_TABLE_SIZE30: usize = NC30 + DC30 + RC30 + LDC30;
/// `MAX3_UNPACK_FILTERS`.
const MAX3_UNPACK_FILTERS: usize = 8192;

const L_DECODE: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const L_BITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const D_BIT_LENGTH_COUNTS: [u32; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];
const SD_DECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SD_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// `DDecode` and `DBits`.
const fn distance_tables() -> ([u32; DC30], [u8; DC30]) {
    let mut decode = [0; DC30];
    let mut bits = [0; DC30];
    let (mut dist, mut slot) = (0u32, 0);
    let mut i = 0;
    while i < D_BIT_LENGTH_COUNTS.len() {
        let mut j = 0;
        while j < D_BIT_LENGTH_COUNTS[i] {
            decode[slot] = dist;
            bits[slot] = i as u8;
            slot += 1;
            dist += 1 << i;
            j += 1;
        }
        i += 1;
    }
    (decode, bits)
}

const D_DECODE: [u32; DC30] = distance_tables().0;
const D_BITS: [u8; DC30] = distance_tables().1;

/// `UnpackFilter30`.
#[derive(Clone, Copy)]
pub(super) struct Filter30 {
    block_start: u32,
    block_length: u32,
    next_window: bool,
    prg: Program,
}

/// `BLOCK_LZ` and `BLOCK_PPM`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockType {
    Lz,
    Ppm,
}

impl Unpack {
    /// `Unpack::SafePPMDecodeChar`.
    fn safe_ppm_decode_char(&mut self, io: &mut dyn UnpIo) -> Result<i32, Error> {
        let ch = self.ppm_decode_char(io)?;
        if ch == -1 {
            self.ppm_clean_up()?;
            self.unp_block_type = BlockType::Lz;
        }
        Ok(ch)
    }

    #[inline(always)]
    fn ppm_decode_char(&mut self, io: &mut dyn UnpIo) -> Result<i32, Error> {
        // Out for the call, which needs both: a pointer's move.
        let mut ppm = std::mem::take(&mut self.ppm);
        let model = ppm.as_mut().map(|model| model.decode_char(self, io));
        self.ppm = ppm;
        model.unwrap_or(Ok(-1))
    }

    fn ppm_clean_up(&mut self) -> Result<(), Error> {
        match &mut self.ppm {
            Some(model) => model.clean_up(),
            None => Ok(()),
        }
    }

    /// `Unpack::Unpack29`.
    pub(super) fn unpack29(&mut self, solid: bool, io: &mut dyn UnpIo) -> Result<(), Error> {
        self.unp_init_data(solid);
        if !self.unp_read_buf30(io)? {
            return Ok(());
        }
        if (!solid || !self.tables_read3) && !self.read_tables30(io)? {
            return Ok(());
        }

        loop {
            self.unp_ptr &= self.max_win_mask();

            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            self.reserve_window()?;

            if self.inp.in_addr > self.read_border && !self.unp_read_buf30(io)? {
                break;
            }
            if (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask()) <= MAX3_INC_LZ_MATCH
                && self.wr_ptr != self.unp_ptr
            {
                self.unp_write_buf30(io)?;
                if self.written_file_size > self.dest_unp_size {
                    return Ok(());
                }
            }
            if self.unp_block_type == BlockType::Ppm {
                let ch = self.ppm_decode_char(io)?;
                if ch == -1 {
                    self.ppm_clean_up()?;
                    self.unp_block_type = BlockType::Lz;
                    break;
                }
                if ch == self.ppm_esc_char {
                    let next_ch = self.safe_ppm_decode_char(io)?;
                    if next_ch == 0 {
                        if !self.read_tables30(io)? {
                            break;
                        }
                        continue;
                    }
                    if next_ch == -1 || next_ch == 2 {
                        break;
                    }
                    if next_ch == 3 {
                        if !self.read_vm_code_ppm(io)? {
                            break;
                        }
                        continue;
                    }
                    if next_ch == 4 {
                        let (mut distance, mut length) = (0u32, 0u32);
                        let mut failed = false;
                        for i in 0..4 {
                            let ch = self.safe_ppm_decode_char(io)?;
                            if ch == -1 {
                                failed = true;
                                break;
                            } else if i == 3 {
                                length = u32::from(ch as u8);
                            } else {
                                distance = (distance << 8) + u32::from(ch as u8);
                            }
                        }
                        if failed {
                            break;
                        }
                        self.copy_string(length + 32, (distance + 2) as usize);
                        continue;
                    }
                    if next_ch == 5 {
                        let length = self.safe_ppm_decode_char(io)?;
                        if length == -1 {
                            break;
                        }
                        self.copy_string(length as u32 + 4, 1);
                        continue;
                    }
                    // 1: the escape byte itself.
                }
                self.window[self.unp_ptr] = ch as u8;
                self.unp_ptr += 1;
                continue;
            }

            let number = self.block_tables.ld.decode(&mut self.inp);
            if number < 256 {
                self.window[self.unp_ptr] = number as u8;
                self.unp_ptr += 1;
                continue;
            }
            if number >= 271 {
                let number = (number - 271) as usize;
                let mut length = u32::from(L_DECODE[number]) + 3;
                let bits = u32::from(L_BITS[number]);
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }

                let dist_number = self.block_tables.dd.decode(&mut self.inp) as usize;
                let mut distance = D_DECODE[dist_number] + 1;
                let bits = u32::from(D_BITS[dist_number]);
                if bits > 0 {
                    if dist_number > 9 {
                        if bits > 4 {
                            distance =
                                distance.wrapping_add((self.inp.getbits() >> (20 - bits)) << 4);
                            self.inp.addbits(bits - 4);
                        }
                        if self.low_dist_rep_count > 0 {
                            self.low_dist_rep_count -= 1;
                            distance = distance.wrapping_add(self.prev_low_dist as u32);
                        } else {
                            let low_dist = self.block_tables.ldd.decode(&mut self.inp);
                            if low_dist == 16 {
                                self.low_dist_rep_count = LOW_DIST_REP_COUNT - 1;
                                distance = distance.wrapping_add(self.prev_low_dist as u32);
                            } else {
                                distance = distance.wrapping_add(low_dist);
                                self.prev_low_dist = low_dist as i32;
                            }
                        }
                    } else {
                        distance += self.inp.getbits() >> (16 - bits);
                        self.inp.addbits(bits);
                    }
                }

                if distance >= 0x2000 {
                    length += 1;
                    if distance >= 0x4_0000 {
                        length += 1;
                    }
                }

                self.insert_old_dist(distance as usize);
                self.last_length = length;
                self.copy_string(length, distance as usize);
                continue;
            }
            if number == 256 {
                if !self.read_end_of_block(io)? {
                    break;
                }
                continue;
            }
            if number == 257 {
                if !self.read_vm_code(io)? {
                    break;
                }
                continue;
            }
            if number == 258 {
                if self.last_length != 0 {
                    self.copy_string(self.last_length, self.old_dist[0]);
                }
                continue;
            }
            if number < 263 {
                let dist_num = (number - 259) as usize;
                // An `uint` in UnRAR, on the way to a `size_t`.
                let distance = self.old_dist[dist_num] as u32 as usize;
                self.old_dist.copy_within(0..dist_num, 1);
                self.old_dist[0] = distance;

                let length_number = self.block_tables.rd.decode(&mut self.inp) as usize;
                let mut length = u32::from(L_DECODE[length_number]) + 2;
                let bits = u32::from(L_BITS[length_number]);
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                self.last_length = length;
                self.copy_string(length, distance);
                continue;
            }
            // Below 271.
            let number = (number - 263) as usize;
            let mut distance = u32::from(SD_DECODE[number]) + 1;
            let bits = u32::from(SD_BITS[number]);
            if bits > 0 {
                distance += self.inp.getbits() >> (16 - bits);
                self.inp.addbits(bits);
            }
            self.insert_old_dist(distance as usize);
            self.last_length = 2;
            self.copy_string(2, distance as usize);
        }
        self.unp_write_buf30(io)
    }

    /// `Unpack::ReadEndOfBlock`.
    fn read_end_of_block(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let bit_field = self.inp.getbits();
        let new_table;
        let mut new_file = false;

        // "1":  no new file, new table just here.
        // "00": new file, no new table.
        // "01": new file, new table at the start of the next file.
        if bit_field & 0x8000 != 0 {
            new_table = true;
            self.inp.addbits(1);
        } else {
            new_file = true;
            new_table = bit_field & 0x4000 != 0;
            self.inp.addbits(2);
        }
        self.tables_read3 = !new_table;

        if new_file {
            return Ok(false);
        }
        self.read_tables30(io)
    }

    /// `Unpack::ReadVMCode`.
    fn read_vm_code(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let first_byte = self.inp.getbits() >> 8;
        self.inp.addbits(8);
        let mut length = (first_byte & 7) + 1;
        if length == 7 {
            length = (self.inp.getbits() >> 8) + 7;
            self.inp.addbits(8);
        } else if length == 8 {
            length = self.inp.getbits();
            self.inp.addbits(16);
        }
        if length == 0 {
            return Ok(false);
        }
        let mut vm_code = vec![0; length as usize];
        for i in 0..length {
            // The new buffer if only one byte is left, though if all but the
            // last byte were read, one is enough.
            if self.inp.in_addr >= self.read_top - 1 && !self.unp_read_buf30(io)? && i < length - 1
            {
                return Ok(false);
            }
            vm_code[i as usize] = (self.inp.getbits() >> 8) as u8;
            self.inp.addbits(8);
        }
        Ok(self.add_vm_code(first_byte, &vm_code))
    }

    /// `Unpack::ReadVMCodePPM`.
    fn read_vm_code_ppm(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let first_byte = self.safe_ppm_decode_char(io)?;
        if first_byte == -1 {
            return Ok(false);
        }
        let first_byte = first_byte as u32;
        let mut length = (first_byte & 7) + 1;
        if length == 7 {
            let b1 = self.safe_ppm_decode_char(io)?;
            if b1 == -1 {
                return Ok(false);
            }
            length = b1 as u32 + 7;
        } else if length == 8 {
            let b1 = self.safe_ppm_decode_char(io)?;
            if b1 == -1 {
                return Ok(false);
            }
            let b2 = self.safe_ppm_decode_char(io)?;
            if b2 == -1 {
                return Ok(false);
            }
            length = b1 as u32 * 256 + b2 as u32;
        }
        if length == 0 {
            return Ok(false);
        }
        let mut vm_code = vec![0; length as usize];
        for byte in &mut vm_code {
            let ch = self.safe_ppm_decode_char(io)?;
            if ch == -1 {
                return Ok(false);
            }
            *byte = ch as u8;
        }
        Ok(self.add_vm_code(first_byte, &vm_code))
    }

    /// `Unpack::AddVMCode`.
    fn add_vm_code(&mut self, first_byte: u32, code: &[u8]) -> bool {
        let code_size = code.len() as u32;
        self.vm_code_inp.init();
        let copy = code.len().min(BitInput::MAX_SIZE as usize);
        self.vm_code_inp.in_buf[..copy].copy_from_slice(&code[..copy]);

        let mut filt_pos;
        if first_byte & 0x80 != 0 {
            filt_pos = read_data(&mut self.vm_code_inp);
            if filt_pos == 0 {
                self.init_filters30(false);
            } else {
                filt_pos = filt_pos.wrapping_sub(1);
            }
        } else {
            filt_pos = self.last_filter;
        }

        let filters = self.filters30.len() as u64;
        if u64::from(filt_pos) > filters
            || u64::from(filt_pos) > self.old_filter_lengths.len() as u64
        {
            return false;
        }
        self.last_filter = filt_pos;
        let new_filter = u64::from(filt_pos) == filters;

        if new_filter {
            if filt_pos as usize > MAX3_UNPACK_FILTERS {
                return false;
            }
            self.filters30.push(StandardFilter::None);
            // Before it is set, as corrupt data can come to it first.
            self.old_filter_lengths.push(0);
        }

        // What is empty goes to the stack's end.
        let used = self.prg_stack.iter().filter(|f| f.is_some()).count();
        let mut empty_count = self.prg_stack.len() - used;
        if empty_count > 0 {
            let len = self.prg_stack.len();
            self.prg_stack.retain(Option::is_some);
            self.prg_stack.resize(len, None);
        }
        if empty_count == 0 {
            if self.prg_stack.len() > MAX3_UNPACK_FILTERS {
                return false;
            }
            self.prg_stack.push(None);
            empty_count = 1;
        }
        let stack_pos = self.prg_stack.len() - empty_count;

        let mut block_start = read_data(&mut self.vm_code_inp);
        if first_byte & 0x40 != 0 {
            block_start = block_start.wrapping_add(258);
        }
        let stack_block_start =
            ((block_start as usize).wrapping_add(self.unp_ptr) & self.max_win_mask()) as u32;
        let block_length;
        if first_byte & 0x20 != 0 {
            block_length = read_data(&mut self.vm_code_inp);
            self.old_filter_lengths[filt_pos as usize] = block_length;
        } else {
            // Maybe not set yet in corrupt data, which is why it starts as 0.
            block_length = self
                .old_filter_lengths
                .get(filt_pos as usize)
                .copied()
                .unwrap_or(0);
        }

        let next_window = self.wr_ptr != self.unp_ptr
            && (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask())
                <= block_start as usize;

        let mut prg = Program::new();
        prg.init_r[4] = block_length;

        if first_byte & 0x10 != 0 {
            let init_mask = self.vm_code_inp.getbits() >> 9;
            self.vm_code_inp.addbits(7);
            for i in 0..7 {
                if init_mask & (1 << i) != 0 {
                    prg.init_r[i] = read_data(&mut self.vm_code_inp);
                }
            }
        }

        let filter = Filter30 {
            block_start: stack_block_start,
            block_length,
            next_window,
            prg,
        };
        self.prg_stack[stack_pos] = Some(filter);

        if new_filter {
            let vm_code_size = read_data(&mut self.vm_code_inp);
            if vm_code_size >= 0x1_0000
                || vm_code_size == 0
                || u64::from(self.vm_code_inp.in_addr as u32) + u64::from(vm_code_size)
                    > u64::from(code_size)
            {
                return false;
            }
            let mut vm_code = vec![0; vm_code_size as usize];
            for byte in &mut vm_code {
                // `BitInput::Overflow(3)`.
                if self.vm_code_inp.in_addr + 3 >= BitInput::MAX_SIZE {
                    return false;
                }
                *byte = (self.vm_code_inp.getbits() >> 8) as u8;
                self.vm_code_inp.addbits(8);
            }
            let kind = prepare(&vm_code);
            // `VM.Prepare` leaves it alone for anything else.
            if kind != StandardFilter::None {
                self.filters30[filt_pos as usize] = kind;
            }
        }
        let kind = self.filters30[filt_pos as usize];
        if let Some(Some(filter)) = self.prg_stack.get_mut(stack_pos) {
            filter.prg.kind = kind;
        }
        true
    }

    /// `Unpack::UnpReadBuf30`.
    pub(super) fn unp_read_buf30(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let mut data_size = self.read_top - self.inp.in_addr;
        if data_size < 0 {
            return Ok(false);
        }
        if self.inp.in_addr > BitInput::MAX_SIZE / 2 {
            if data_size > 0 {
                let from = self.inp.in_addr as usize;
                self.inp
                    .in_buf
                    .copy_within(from..from + data_size as usize, 0);
            }
            self.inp.in_addr = 0;
            self.read_top = data_size;
        } else {
            data_size = self.read_top;
        }
        let (from, to) = (data_size as usize, BitInput::MAX_SIZE as usize);
        let read_code = io.unp_read(&mut self.inp.in_buf[from..to])?;
        self.read_top += read_code.unwrap_or(0) as i32;
        self.read_border = self.read_top - 30;
        Ok(read_code.is_some())
    }

    /// `Unpack::UnpWriteBuf30`.
    fn unp_write_buf30(&mut self, io: &mut dyn UnpIo) -> Result<(), Error> {
        let mask = self.max_win_mask();
        let mut written_border = self.wr_ptr as u32 as usize;
        let mut write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
        let mut i = 0;
        while i < self.prg_stack.len() {
            // Filters work on a copy in the filters' memory: what is in the
            // window stays as it is for later matches.
            let Some(flt) = self.prg_stack[i] else {
                i += 1;
                continue;
            };
            if flt.next_window {
                if let Some(Some(flt)) = self.prg_stack.get_mut(i) {
                    flt.next_window = false;
                }
                i += 1;
                continue;
            }
            let block_start = flt.block_start as usize;
            let block_length = flt.block_length as usize;
            if (block_start.wrapping_sub(written_border) & mask) < write_size {
                if written_border != block_start {
                    self.unp_write_area(written_border, block_start, io)?;
                    written_border = block_start;
                    write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
                }
                if block_length <= write_size {
                    let block_end = block_start.wrapping_add(block_length) & mask;
                    if block_start < block_end || block_end == 0 {
                        self.vm
                            .set_memory(0, &self.window[block_start..block_start + block_length]);
                    } else {
                        let first_part_length = self.max_win_size - block_start;
                        // Without wrapping around if the length is 0: this reads to
                        // the dictionary's end, which may not be written, or here
                        // not even there yet. In UnRAR's oracle it is zeros too.
                        let written = self.window.len().min(self.max_win_size);
                        self.vm.set_memory_filling(
                            0,
                            &self.window[block_start.min(written)..written],
                            first_part_length,
                        );
                        self.vm
                            .set_memory(first_part_length, &self.window[..block_end]);
                    }

                    let mut prg = flt.prg;
                    self.execute_code(&mut prg);
                    let mut filtered_data = prg.filtered_data;
                    let mut filtered_data_size = prg.filtered_data_size;

                    self.prg_stack[i] = None;
                    while i + 1 < self.prg_stack.len() {
                        let Some(next_filter) = self.prg_stack[i + 1] else {
                            break;
                        };
                        if next_filter.block_start as usize != block_start
                            || next_filter.block_length != filtered_data_size
                            || next_filter.next_window
                        {
                            break;
                        }

                        // Several filters on the same block.
                        if let Some(from) = filtered_data {
                            self.vm
                                .set_memory_from_self(from, filtered_data_size as usize);
                        }
                        let mut next_prg = next_filter.prg;
                        self.execute_code(&mut next_prg);
                        filtered_data = next_prg.filtered_data;
                        filtered_data_size = next_prg.filtered_data_size;
                        i += 1;
                        self.prg_stack[i] = None;
                    }
                    if let Some(from) = filtered_data {
                        io.unp_write(self.vm.memory(from, filtered_data_size as usize))?;
                    } else {
                        io.unp_write(&[])?;
                    }
                    self.written_file_size += i64::from(filtered_data_size);
                    written_border = block_end;
                    write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
                } else {
                    // It crosses the border of what can be written: next time.
                    for flt in self.prg_stack[i..].iter_mut().flatten() {
                        flt.next_window = false;
                    }
                    self.wr_ptr = written_border;
                    return Ok(());
                }
            }
            i += 1;
        }

        self.unp_write_area(written_border, self.unp_ptr, io)?;
        self.wr_ptr = self.unp_ptr;
        Ok(())
    }

    /// `Unpack::ExecuteCode`.
    fn execute_code(&mut self, prg: &mut Program) {
        prg.init_r[6] = self.written_file_size as u32;
        self.vm.execute(prg);
    }

    /// `Unpack::ReadTables30`.
    fn read_tables30(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        if self.inp.in_addr > self.read_top - 25 && !self.unp_read_buf30(io)? {
            return Ok(false);
        }
        self.inp.addbits((8 - self.inp.in_bit) & 7);
        let bit_field = self.inp.getbits();
        if bit_field & 0x8000 != 0 {
            self.unp_block_type = BlockType::Ppm;
            let mut ppm = std::mem::take(&mut self.ppm);
            let done = ppm.as_mut().map(|model| model.decode_init(self, io));
            self.ppm = ppm;
            return done.unwrap_or(Ok(false));
        }
        self.unp_block_type = BlockType::Lz;

        self.prev_low_dist = 0;
        self.low_dist_rep_count = 0;

        if bit_field & 0x4000 == 0 {
            self.unp_old_table = [0; HUFF_TABLE_SIZE30];
        }
        self.inp.addbits(2);

        let mut bit_length = [0u8; BC];
        let mut i = 0;
        while i < BC {
            let length = (self.inp.getbits() >> 12) as u8;
            self.inp.addbits(4);
            if length == 15 {
                let zero_count = (self.inp.getbits() >> 12) as u8;
                self.inp.addbits(4);
                if zero_count == 0 {
                    bit_length[i] = 15;
                } else {
                    let mut zero_count = zero_count + 2;
                    while zero_count > 0 && i < BC {
                        zero_count -= 1;
                        bit_length[i] = 0;
                        i += 1;
                    }
                    i -= 1;
                }
            } else {
                bit_length[i] = length;
            }
            i += 1;
        }
        self.block_tables.bd.make(&bit_length[..BC30]);

        let mut table = [0u8; HUFF_TABLE_SIZE30];
        let mut i = 0;
        while i < HUFF_TABLE_SIZE30 {
            if self.inp.in_addr > self.read_top - 5 && !self.unp_read_buf30(io)? {
                return Ok(false);
            }
            let number = self.block_tables.bd.decode(&mut self.inp);
            if number < 16 {
                table[i] = (number as u8 + self.unp_old_table[i]) & 0xf;
                i += 1;
            } else if number < 18 {
                let n = if number == 16 {
                    let n = (self.inp.getbits() >> 13) + 3;
                    self.inp.addbits(3);
                    n
                } else {
                    let n = (self.inp.getbits() >> 9) + 11;
                    self.inp.addbits(7);
                    n
                };
                if i == 0 {
                    return Ok(false);
                }
                for _ in 0..n {
                    if i >= HUFF_TABLE_SIZE30 {
                        break;
                    }
                    table[i] = table[i - 1];
                    i += 1;
                }
            } else {
                let n = if number == 18 {
                    let n = (self.inp.getbits() >> 13) + 3;
                    self.inp.addbits(3);
                    n
                } else {
                    let n = (self.inp.getbits() >> 9) + 11;
                    self.inp.addbits(7);
                    n
                };
                for _ in 0..n {
                    if i >= HUFF_TABLE_SIZE30 {
                        break;
                    }
                    table[i] = 0;
                    i += 1;
                }
            }
        }
        self.tables_read3 = true;
        if self.inp.in_addr > self.read_top {
            return Ok(false);
        }
        let tables = &mut *self.block_tables;
        tables.ld.make(&table[..NC30]);
        tables.dd.make(&table[NC30..NC30 + DC30]);
        tables.ldd.make(&table[NC30 + DC30..NC30 + DC30 + LDC30]);
        tables
            .rd
            .make(&table[NC30 + DC30 + LDC30..NC30 + DC30 + LDC30 + RC30]);
        self.unp_old_table = table;
        Ok(true)
    }

    /// `Unpack::UnpInitData30`.
    pub(super) fn unp_init_data30(&mut self, solid: bool) {
        if !solid {
            self.tables_read3 = false;
            self.unp_old_table = [0; HUFF_TABLE_SIZE30];
            self.ppm_esc_char = 2;
            self.unp_block_type = BlockType::Lz;
        }
        self.init_filters30(solid);
    }

    /// `Unpack::InitFilters30`.
    fn init_filters30(&mut self, solid: bool) {
        if !solid {
            self.old_filter_lengths.clear();
            self.last_filter = 0;
            self.filters30.clear();
        }
        self.prg_stack.clear();
    }
}
