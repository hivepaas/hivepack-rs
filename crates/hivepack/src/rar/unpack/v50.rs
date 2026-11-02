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

//! The algorithm of RAR 5.0 and 7.0: UnRAR's unpack50.cpp. Its fragmented
//! window (unpack50frag.cpp), for 32-bit systems that cannot allocate a whole
//! one, and its threads (unpack50mt.cpp) are left out: what comes out is the
//! same.

use crate::rar::error::Error;

use super::{
    BC, BitInput, DCB, DCX, Filter, HUFF_TABLE_SIZEB, HUFF_TABLE_SIZEX, LDC, MAX_FILTER_BLOCK_SIZE,
    MAX_INC_LZ_MATCH, MAX_UNPACK_FILTERS, NC, RC, UNPACK_MAX_WRITE, UnpIo, Unpack, slot_to_length,
};

/// `FILTER_DELTA`.
const FILTER_DELTA: u8 = 0;
/// `FILTER_E8`.
const FILTER_E8: u8 = 1;
/// `FILTER_E8E9`.
const FILTER_E8E9: u8 = 2;
/// `FILTER_ARM`.
const FILTER_ARM: u8 = 3;
/// `FILTER_NONE`.
const FILTER_NONE: u8 = 10;

/// `Unpack::ReadFilterData`.
fn read_filter_data(inp: &mut BitInput) -> u32 {
    let byte_count = (inp.getbits() >> 14) + 1;
    inp.addbits(2);

    let mut data = 0u32;
    for i in 0..byte_count {
        data = data.wrapping_add((inp.getbits() >> 8) << (i * 8));
        inp.addbits(8);
    }
    data
}

impl Unpack {
    /// `Unpack::Unpack5`.
    pub(super) fn unpack5(&mut self, solid: bool, io: &mut dyn UnpIo) -> Result<(), Error> {
        self.unp_init_data(solid);
        if !self.unp_read_buf(io)? {
            return Ok(());
        }

        // Tables are read at least once, whatever the flag of this block says.
        if !self.read_block_header(io)? || !self.read_tables(io)? || !self.tables_read5 {
            return Ok(());
        }

        loop {
            self.unp_ptr = self.wrap_up(self.unp_ptr);

            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            self.reserve_window()?;

            if self.inp.in_addr >= self.read_border {
                let mut file_done = false;

                // A loop: an empty block with only a Huffman table leaves us
                // on the block's border again.
                loop {
                    let end = self.block_header.block_start + self.block_header.block_size - 1;
                    if !(self.inp.in_addr > end
                        || self.inp.in_addr == end
                            && self.inp.in_bit as i32 >= self.block_header.block_bit_size)
                    {
                        break;
                    }
                    if self.block_header.last_block_in_file {
                        file_done = true;
                        break;
                    }
                    if !self.read_block_header(io)? || !self.read_tables(io)? {
                        return Ok(());
                    }
                }
                if file_done || !self.unp_read_buf(io)? {
                    break;
                }
            }

            // write_border == unp_ptr means the whole window is ahead.
            if self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr)) <= MAX_INC_LZ_MATCH
                && self.write_border != self.unp_ptr
            {
                self.unp_write_buf(io)?;
                if self.written_file_size > self.dest_unp_size {
                    return Ok(());
                }
            }

            let main_slot = self.block_tables.ld.decode(&mut self.inp);
            if main_slot < 256 {
                self.window[self.unp_ptr] = main_slot as u8;
                self.unp_ptr += 1;
                continue;
            }
            if main_slot >= 262 {
                let mut length = slot_to_length(&mut self.inp, main_slot - 262);

                let mut distance = 1usize;
                let dist_slot = self.block_tables.dd.decode(&mut self.inp);
                let d_bits;
                if dist_slot < 4 {
                    d_bits = 0;
                    distance += dist_slot as usize;
                } else {
                    d_bits = dist_slot / 2 - 1;
                    distance = distance
                        .wrapping_add(((2 | (dist_slot & 1)) as usize).wrapping_shl(d_bits));
                }

                if d_bits > 0 {
                    if d_bits >= 4 {
                        if d_bits > 4 {
                            let high = if d_bits > 36 {
                                (self.inp.getbits64() as usize) >> (68 - d_bits)
                            } else {
                                (self.inp.getbits32() as usize) >> (36 - d_bits)
                            };
                            distance = distance.wrapping_add(high.wrapping_shl(4));
                            self.inp.addbits(d_bits - 4);
                        }
                        let low_dist = self.block_tables.ldd.decode(&mut self.inp);
                        distance = distance.wrapping_add(low_dist as usize);

                        // A 32-bit size_t cannot hold these. A distance that
                        // cannot be gives zeros in `copy_string`.
                        if usize::BITS == 32 && d_bits >= 30 {
                            distance = usize::MAX;
                        }
                    } else {
                        distance += (self.inp.getbits() >> (16 - d_bits)) as usize;
                        self.inp.addbits(d_bits);
                    }
                }

                if distance > 0x100 {
                    length += 1;
                    if distance > 0x2000 {
                        length += 1;
                        if distance > 0x4_0000 {
                            length += 1;
                        }
                    }
                }

                self.insert_old_dist(distance);
                self.last_length = length;
                self.copy_string(length, distance);
                continue;
            }
            if main_slot == 256 {
                let Some(filter) = self.read_filter(io)? else {
                    break;
                };
                self.add_filter(filter, io)?;
                continue;
            }
            if main_slot == 257 {
                if self.last_length != 0 {
                    self.copy_string(self.last_length, self.old_dist[0]);
                }
                continue;
            }
            // Below 262.
            let dist_num = (main_slot - 258) as usize;
            let distance = self.old_dist[dist_num];
            self.old_dist.copy_within(0..dist_num, 1);
            self.old_dist[0] = distance;

            let length_slot = self.block_tables.rd.decode(&mut self.inp);
            let length = slot_to_length(&mut self.inp, length_slot);
            self.last_length = length;
            self.copy_string(length, distance);
        }
        self.unp_write_buf(io)
    }

    /// `Unpack::ReadFilter`. `None` when the buffer cannot be refilled.
    fn read_filter(&mut self, io: &mut dyn UnpIo) -> Result<Option<Filter>, Error> {
        if self.inp.in_addr > self.read_top - 16 && !self.unp_read_buf(io)? {
            return Ok(None);
        }

        let block_start = read_filter_data(&mut self.inp);
        let mut block_length = read_filter_data(&mut self.inp);
        if block_length > MAX_FILTER_BLOCK_SIZE {
            block_length = 0;
        }

        let kind = (self.inp.getbits() >> 13) as u8;
        self.inp.addbits(3);

        let mut channels = 0;
        if kind == FILTER_DELTA {
            channels = (self.inp.getbits() >> 11) as u8 + 1;
            self.inp.addbits(5);
        }

        Ok(Some(Filter {
            kind,
            channels,
            next_window: false,
            block_start: block_start as usize,
            block_length,
        }))
    }

    /// `Unpack::AddFilter`.
    fn add_filter(&mut self, mut filter: Filter, io: &mut dyn UnpIo) -> Result<(), Error> {
        if self.filters.len() >= MAX_UNPACK_FILTERS {
            self.unp_write_buf(io)?;
            if self.filters.len() >= MAX_UNPACK_FILTERS {
                // Still too many: no excessive memory use.
                self.filters.clear();
            }
        }

        // A filter starting so far ahead that it points at old data not
        // written yet waits for that data.
        filter.next_window = self.wr_ptr != self.unp_ptr
            && self.wrap_down(self.wr_ptr.wrapping_sub(self.unp_ptr)) <= filter.block_start;

        // Can be many times the window in a malformed archive.
        filter.block_start = filter.block_start.wrapping_add(self.unp_ptr) % self.max_win_size;
        self.filters.push(filter);
        Ok(())
    }

    /// `Unpack::UnpReadBuf`.
    pub(super) fn unp_read_buf(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let mut data_size = self.read_top - self.inp.in_addr;
        if data_size < 0 {
            return Ok(false);
        }
        // Not used by RAR 3, whose PPMd comes here too, and may run over.
        self.block_header.block_size = self
            .block_header
            .block_size
            .wrapping_sub(self.inp.in_addr - self.block_header.block_start);
        if self.inp.in_addr > BitInput::MAX_SIZE / 2 {
            // Past half of the buffer: what is left goes to its start, which
            // also means the caller cannot cross the buffer's end even if
            // nothing is read here.
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
        let mut read_code = Some(0);
        if BitInput::MAX_SIZE != data_size {
            let (from, to) = (data_size as usize, BitInput::MAX_SIZE as usize);
            read_code = io.unp_read(&mut self.inp.in_buf[from..to])?;
        }
        self.read_top += read_code.unwrap_or(0) as i32;
        self.read_border = self.read_top - 30;
        self.block_header.block_start = self.inp.in_addr;
        if self.block_header.block_size != -1 {
            // Back to the main loop before the buffer's end when a block
            // ends before it.
            self.read_border = self.read_border.min(
                self.block_header
                    .block_start
                    .wrapping_add(self.block_header.block_size)
                    .wrapping_sub(1),
            );
        }
        Ok(read_code.is_some())
    }

    /// `Unpack::UnpWriteBuf`.
    pub(super) fn unp_write_buf(&mut self, io: &mut dyn UnpIo) -> Result<(), Error> {
        let mut written_border = self.wr_ptr;
        let full_write_size = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
        let mut write_size_left = full_write_size;
        let mut not_all_filters_processed = false;
        for i in 0..self.filters.len() {
            // Filters work on a copy: what is in the window stays as it is
            // for later matches.
            let flt = self.filters[i];
            if flt.kind == FILTER_NONE {
                continue;
            }
            if flt.next_window {
                // Its start is in this range only through wrapping around.
                if self.wrap_down(flt.block_start.wrapping_sub(self.wr_ptr)) <= full_write_size {
                    self.filters[i].next_window = false;
                }
                continue;
            }
            let block_start = flt.block_start;
            let block_length = flt.block_length as usize;
            if self.wrap_down(block_start.wrapping_sub(written_border)) < write_size_left {
                if written_border != block_start {
                    self.unp_write_area(written_border, block_start, io)?;
                    written_border = block_start;
                    write_size_left = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
                }
                if block_length <= write_size_left {
                    if block_length > 0 {
                        // Set to 0 also for invalid filters.
                        let block_end = self.wrap_up(block_start + block_length);

                        let mut mem = std::mem::take(&mut self.filter_src_memory);
                        mem.clear();
                        if block_start < block_end || block_end == 0 {
                            mem.extend_from_slice(
                                &self.window[block_start..block_start + block_length],
                            );
                        } else {
                            mem.extend_from_slice(&self.window[block_start..self.max_win_size]);
                            mem.extend_from_slice(&self.window[..block_end]);
                        }

                        let filtered = self.apply_filter(&mut mem, &flt);
                        self.filters[i].kind = FILTER_NONE;
                        match filtered {
                            FilterOutput::Source => io.unp_write(&mem)?,
                            FilterOutput::Destination => io.unp_write(&self.filter_dst_memory)?,
                            FilterOutput::Nothing => {}
                        }
                        self.filter_src_memory = mem;

                        self.written_file_size += block_length as i64;
                        written_border = block_end;
                        write_size_left = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
                    }
                } else {
                    // It crosses the border of what can be written: next time.
                    self.wr_ptr = written_border;

                    // Filter starts only increase, so the rest wait as well.
                    for flt in &mut self.filters[i..] {
                        if flt.kind != FILTER_NONE {
                            flt.next_window = false;
                        }
                    }

                    not_all_filters_processed = true;
                    break;
                }
            }
        }

        self.filters.retain(|flt| flt.kind != FILTER_NONE);

        if !not_all_filters_processed {
            self.unp_write_area(written_border, self.unp_ptr, io)?;
            self.wr_ptr = self.unp_ptr;
        }

        // In blocks of at most UNPACK_MAX_WRITE, not whole windows, which
        // also keeps the filters' number reasonable.
        self.write_border = self.wrap_up(self.unp_ptr + self.max_win_size.min(UNPACK_MAX_WRITE));

        // The nearest of that and the actual border. Equal to unp_ptr means
        // the whole window is ahead.
        if self.write_border == self.unp_ptr
            || self.wr_ptr != self.unp_ptr
                && self.wrap_down(self.wr_ptr.wrapping_sub(self.unp_ptr))
                    < self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr))
        {
            self.write_border = self.wr_ptr;
        }
        Ok(())
    }

    /// `Unpack::ApplyFilter`: in place in `data`, or into `filter_dst_memory`.
    fn apply_filter(&mut self, data: &mut [u8], flt: &Filter) -> FilterOutput {
        match flt.kind {
            FILTER_E8 | FILTER_E8E9 => {
                let file_offset = self.written_file_size as u32;
                const FILE_SIZE: u32 = 0x100_0000;
                let cmp_byte2 = if flt.kind == FILTER_E8E9 { 0xe9 } else { 0xe8 };
                let mut cur_pos = 0usize;
                while cur_pos + 4 < data.len() {
                    let cur_byte = data[cur_pos];
                    cur_pos += 1;
                    if cur_byte == 0xe8 || cur_byte == cmp_byte2 {
                        let offset = (cur_pos as u32).wrapping_add(file_offset) % FILE_SIZE;
                        let mut word = [0; 4];
                        word.copy_from_slice(&data[cur_pos..cur_pos + 4]);
                        let addr = u32::from_le_bytes(word);

                        if addr & 0x8000_0000 != 0 {
                            if addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                                data[cur_pos..cur_pos + 4]
                                    .copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                            }
                        } else if addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0 {
                            data[cur_pos..cur_pos + 4]
                                .copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
                        }

                        cur_pos += 4;
                    }
                }
                FilterOutput::Source
            }
            FILTER_ARM => {
                let file_offset = self.written_file_size as u32;
                let mut cur_pos = 0usize;
                while cur_pos + 3 < data.len() {
                    let d = &mut data[cur_pos..cur_pos + 4];
                    // BL with the "always" condition.
                    if d[3] == 0xeb {
                        let offset = u32::from(d[0])
                            .wrapping_add(u32::from(d[1]) * 0x100)
                            .wrapping_add(u32::from(d[2]) * 0x1_0000)
                            .wrapping_sub(file_offset.wrapping_add(cur_pos as u32) / 4);
                        d[0] = offset as u8;
                        d[1] = (offset >> 8) as u8;
                        d[2] = (offset >> 16) as u8;
                    }
                    cur_pos += 4;
                }
                FilterOutput::Source
            }
            FILTER_DELTA => {
                let channels = usize::from(flt.channels);
                self.filter_dst_memory.clear();
                self.filter_dst_memory.resize(data.len(), 0);
                let mut src_pos = 0;
                // Each channel's bytes are together: back to their places.
                for cur_channel in 0..channels {
                    let mut prev_byte = 0u8;
                    let mut dest_pos = cur_channel;
                    while dest_pos < data.len() {
                        prev_byte = prev_byte.wrapping_sub(data[src_pos]);
                        src_pos += 1;
                        self.filter_dst_memory[dest_pos] = prev_byte;
                        dest_pos += channels;
                    }
                }
                FilterOutput::Destination
            }
            _ => FilterOutput::Nothing,
        }
    }

    /// `Unpack::UnpWriteArea`.
    pub(super) fn unp_write_area(
        &mut self,
        start_ptr: usize,
        end_ptr: usize,
        io: &mut dyn UnpIo,
    ) -> Result<(), Error> {
        if end_ptr < start_ptr {
            self.unp_write_data(start_ptr, self.max_win_size, io)?;
            self.unp_write_data(0, end_ptr, io)
        } else {
            self.unp_write_data(start_ptr, end_ptr, io)
        }
    }

    /// `Unpack::UnpWriteData`, for a part of the window.
    fn unp_write_data(&mut self, from: usize, to: usize, io: &mut dyn UnpIo) -> Result<(), Error> {
        if self.written_file_size >= self.dest_unp_size {
            return Ok(());
        }
        let size = to - from;
        let left_to_write = self.dest_unp_size - self.written_file_size;
        let write_size = if size as i64 > left_to_write {
            left_to_write as usize
        } else {
            size
        };
        io.unp_write(&self.window[from..from + write_size])?;
        self.written_file_size += size as i64;
        Ok(())
    }

    /// `Unpack::UnpInitData50`.
    pub(super) fn unp_init_data50(&mut self, solid: bool) {
        if !solid {
            self.tables_read5 = false;
        }
    }

    /// `Unpack::ReadBlockHeader`.
    fn read_block_header(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        if self.inp.in_addr > self.read_top - 7 && !self.unp_read_buf(io)? {
            return Ok(false);
        }
        self.inp.addbits((8 - self.inp.in_bit) & 7);

        let block_flags = (self.inp.getbits() >> 8) as u8;
        self.inp.addbits(8);
        let byte_count = u32::from((block_flags >> 3) & 3) + 1;

        if byte_count == 4 {
            return Ok(false);
        }

        self.block_header.block_bit_size = i32::from(block_flags & 7) + 1;

        let saved_check_sum = (self.inp.getbits() >> 8) as u8;
        self.inp.addbits(8);

        let mut block_size = 0i32;
        for i in 0..byte_count {
            block_size += ((self.inp.getbits() >> 8) << (i * 8)) as i32;
            self.inp.addbits(8);
        }

        self.block_header.block_size = block_size;
        let check_sum =
            (0x5a ^ i32::from(block_flags) ^ block_size ^ (block_size >> 8) ^ (block_size >> 16))
                as u8;

        // A block of size 0 is possible, only to carry the last block's flag.
        if check_sum != saved_check_sum {
            return Ok(false);
        }

        self.block_header.block_start = self.inp.in_addr;

        // in_addr is past the bits above, so it is not 0, and this does not
        // overflow even for a size of 0.
        self.read_border = self
            .read_border
            .min(self.block_header.block_start + block_size - 1);

        self.block_header.last_block_in_file = block_flags & 0x40 != 0;
        self.block_header.table_present = block_flags & 0x80 != 0;

        Ok(true)
    }

    /// `Unpack::ReadTables`.
    fn read_tables(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        if !self.block_header.table_present {
            return Ok(true);
        }

        if self.inp.in_addr > self.read_top - 25 && !self.unp_read_buf(io)? {
            return Ok(false);
        }

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

        self.block_tables.bd.make(&bit_length);

        let mut table = [0u8; HUFF_TABLE_SIZEX];
        let table_size = if self.extra_dist {
            HUFF_TABLE_SIZEX
        } else {
            HUFF_TABLE_SIZEB
        };
        let mut i = 0;
        while i < table_size {
            if self.inp.in_addr > self.read_top - 5 && !self.unp_read_buf(io)? {
                return Ok(false);
            }
            let number = self.block_tables.bd.decode(&mut self.inp);
            if number < 16 {
                table[i] = number as u8;
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
                // No "repeat previous" at the first position.
                if i == 0 {
                    return Ok(false);
                }
                for _ in 0..n {
                    if i >= table_size {
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
                    if i >= table_size {
                        break;
                    }
                    table[i] = 0;
                    i += 1;
                }
            }
        }
        self.tables_read5 = true;
        if self.inp.in_addr > self.read_top {
            return Ok(false);
        }
        let d_codes = if self.extra_dist { DCX } else { DCB };
        let tables = &mut *self.block_tables;
        tables.ld.make(&table[..NC]);
        tables.dd.make(&table[NC..NC + d_codes]);
        tables.ldd.make(&table[NC + d_codes..NC + d_codes + LDC]);
        tables
            .rd
            .make(&table[NC + d_codes + LDC..NC + d_codes + LDC + RC]);
        Ok(true)
    }
}

#[cfg(test)]
impl Unpack {
    /// `apply_filter`, and what it leaves to write.
    pub(super) fn apply_filter_for_test<'a>(
        &'a mut self,
        data: &'a mut [u8],
        flt: &Filter,
    ) -> Option<&'a [u8]> {
        match self.apply_filter(data, flt) {
            FilterOutput::Source => Some(data),
            FilterOutput::Destination => Some(&self.filter_dst_memory),
            FilterOutput::Nothing => None,
        }
    }
}

/// Where `apply_filter` left what to write.
enum FilterOutput {
    Source,
    Destination,
    Nothing,
}
