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

//! RAR 3's filters: UnRAR's rarvm.cpp. Its virtual machine is long gone, and
//! a filter's code is only compared with the standard filters' CRCs.

/// `VM_MEMSIZE`.
pub(super) const VM_MEMSIZE: usize = 0x4_0000;
const VM_MEMMASK: u32 = VM_MEMSIZE as u32 - 1;
/// `MAX3_UNPACK_CHANNELS`.
const MAX3_UNPACK_CHANNELS: u32 = 1024;

/// `VM_StandardFilters`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StandardFilter {
    None,
    E8,
    E8E9,
    Itanium,
    Rgb,
    Audio,
    Delta,
}

/// `VM_PreparedProgram`: where a run left its output, an offset into memory.
#[derive(Clone, Copy)]
pub(super) struct Program {
    pub(super) kind: StandardFilter,
    pub(super) init_r: [u32; 7],
    pub(super) filtered_data: Option<usize>,
    pub(super) filtered_data_size: u32,
}

impl Program {
    pub(super) fn new() -> Program {
        Program {
            kind: StandardFilter::None,
            init_r: [0; 7],
            filtered_data: None,
            filtered_data_size: 0,
        }
    }
}

/// `RarVM::Prepare`: which standard filter this code is, if any.
pub(super) fn prepare(code: &[u8]) -> StandardFilter {
    let Some((&check, rest)) = code.split_first() else {
        return StandardFilter::None;
    };
    if rest.iter().fold(0, |sum, &byte| sum ^ byte) != check {
        return StandardFilter::None;
    }
    let crc = crate::deflate::crc32(0, code);
    const LIST: [(usize, u32, StandardFilter); 6] = [
        (53, 0xad57_6887, StandardFilter::E8),
        (57, 0x3cd7_e57e, StandardFilter::E8E9),
        (120, 0x3769_893f, StandardFilter::Itanium),
        (29, 0x0e06_077d, StandardFilter::Delta),
        (149, 0x1c2c_5dc8, StandardFilter::Rgb),
        (216, 0xbc85_e701, StandardFilter::Audio),
    ];
    for (length, list_crc, kind) in LIST {
        if list_crc == crc && length == code.len() {
            return kind;
        }
    }
    StandardFilter::None
}

/// `RarVM`: its memory, which lasts from one filter to the next. It starts as
/// zeros, and the oracle's allocator makes UnRAR's so too: damaged data can ask
/// a filter to read more than it was given.
pub(super) struct RarVm {
    mem: Vec<u8>,
}

impl RarVm {
    pub(super) fn new() -> RarVm {
        RarVm {
            mem: vec![0; VM_MEMSIZE + 4],
        }
    }

    /// `RarVM::SetMemory`.
    pub(super) fn set_memory(&mut self, pos: usize, data: &[u8]) {
        if pos < VM_MEMSIZE {
            let size = data.len().min(VM_MEMSIZE - pos);
            self.mem[pos..pos + size].copy_from_slice(&data[..size]);
        }
    }

    /// `RarVM::SetMemory` of `size` bytes, zeros after `data`.
    pub(super) fn set_memory_filling(&mut self, pos: usize, data: &[u8], size: usize) {
        if pos < VM_MEMSIZE {
            let size = size.min(VM_MEMSIZE - pos);
            let copied = data.len().min(size);
            self.mem[pos..pos + copied].copy_from_slice(&data[..copied]);
            self.mem[pos + copied..pos + size].fill(0);
        }
    }

    /// `RarVM::SetMemory` from its own memory.
    pub(super) fn set_memory_from_self(&mut self, from: usize, size: usize) {
        if from != 0 {
            let size = size.min(VM_MEMSIZE);
            self.mem.copy_within(from..from + size, 0);
        }
    }

    pub(super) fn memory(&self, from: usize, size: usize) -> &[u8] {
        &self.mem[from..from + size]
    }

    /// `RarVM::Execute`.
    pub(super) fn execute(&mut self, prg: &mut Program) {
        prg.filtered_data = None;
        if prg.kind != StandardFilter::None {
            let success = self.execute_standard_filter(prg.kind, &prg.init_r);
            let block_size = prg.init_r[4] & VM_MEMMASK;
            prg.filtered_data_size = block_size;
            prg.filtered_data = Some(match prg.kind {
                StandardFilter::Delta | StandardFilter::Rgb | StandardFilter::Audio => {
                    if 2 * block_size as usize > VM_MEMSIZE || !success {
                        0
                    } else {
                        block_size as usize
                    }
                }
                _ => 0,
            });
        }
    }

    /// `RarVM::ExecuteStandardFilter`.
    fn execute_standard_filter(&mut self, kind: StandardFilter, r: &[u32; 7]) -> bool {
        let mem = &mut self.mem[..];
        match kind {
            StandardFilter::E8 | StandardFilter::E8E9 => {
                let (data_size, file_offset) = (r[4], r[6]);
                if data_size as usize > VM_MEMSIZE || data_size < 4 {
                    return false;
                }
                const FILE_SIZE: u32 = 0x100_0000;
                let cmp_byte2 = if kind == StandardFilter::E8E9 {
                    0xe9
                } else {
                    0xe8
                };
                let mut cur_pos = 0u32;
                while cur_pos < data_size - 4 {
                    let cur_byte = mem[cur_pos as usize];
                    cur_pos += 1;
                    if cur_byte == 0xe8 || cur_byte == cmp_byte2 {
                        let offset = cur_pos.wrapping_add(file_offset);
                        let at = cur_pos as usize;
                        let addr =
                            u32::from_le_bytes([mem[at], mem[at + 1], mem[at + 2], mem[at + 3]]);
                        if addr & 0x8000_0000 != 0 {
                            if addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                                mem[at..at + 4]
                                    .copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                            }
                        } else if addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0 {
                            mem[at..at + 4]
                                .copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
                        }
                        cur_pos += 4;
                    }
                }
            }
            StandardFilter::Itanium => {
                let data_size = r[4];
                let mut file_offset = r[6] >> 4;
                if data_size as usize > VM_MEMSIZE || data_size < 21 {
                    return false;
                }
                const MASKS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
                let mut cur_pos = 0u32;
                while cur_pos < data_size - 21 {
                    let data = &mut mem[cur_pos as usize..];
                    let byte = i32::from(data[0] & 0x1f) - 0x10;
                    if byte >= 0 {
                        let cmd_mask = MASKS[byte as usize];
                        if cmd_mask != 0 {
                            for i in 0..=2 {
                                if cmd_mask & (1 << i) != 0 {
                                    let start_pos = i * 41 + 5;
                                    let op_type = itanium_get_bits(data, start_pos + 37, 4);
                                    if op_type == 5 {
                                        let offset = itanium_get_bits(data, start_pos + 13, 20);
                                        itanium_set_bits(
                                            data,
                                            offset.wrapping_sub(file_offset) & 0xf_ffff,
                                            start_pos + 13,
                                            20,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    cur_pos += 16;
                    file_offset = file_offset.wrapping_add(1);
                }
            }
            StandardFilter::Delta => {
                let (data_size, channels) = (r[4], r[0]);
                let border = data_size.wrapping_mul(2) as usize;
                if data_size as usize > VM_MEMSIZE / 2
                    || channels > MAX3_UNPACK_CHANNELS
                    || channels == 0
                {
                    return false;
                }
                let mut src_pos = 0;
                for cur_channel in 0..channels {
                    let mut prev_byte = 0u8;
                    let mut dest_pos = (data_size + cur_channel) as usize;
                    while dest_pos < border {
                        prev_byte = prev_byte.wrapping_sub(mem[src_pos]);
                        src_pos += 1;
                        mem[dest_pos] = prev_byte;
                        dest_pos += channels as usize;
                    }
                }
            }
            StandardFilter::Rgb => {
                let data_size = r[4];
                let width = r[0].wrapping_sub(3);
                let pos_r = r[1];
                if data_size as usize > VM_MEMSIZE / 2
                    || data_size < 3
                    || width > data_size
                    || pos_r > 2
                {
                    return false;
                }
                let dest = data_size as usize;
                let mut src = 0;
                for cur_channel in 0..3 {
                    let mut prev_byte = 0u32;
                    let mut i = cur_channel;
                    while i < data_size {
                        let predicted = if i >= width + 3 {
                            let upper = dest + (i - width) as usize;
                            let upper_byte = u32::from(mem[upper]);
                            let upper_left_byte = u32::from(mem[upper - 3]);
                            let predicted = prev_byte
                                .wrapping_add(upper_byte)
                                .wrapping_sub(upper_left_byte);
                            let pa = (predicted.wrapping_sub(prev_byte) as i32).wrapping_abs();
                            let pb = (predicted.wrapping_sub(upper_byte) as i32).wrapping_abs();
                            let pc =
                                (predicted.wrapping_sub(upper_left_byte) as i32).wrapping_abs();
                            if pa <= pb && pa <= pc {
                                prev_byte
                            } else if pb <= pc {
                                upper_byte
                            } else {
                                upper_left_byte
                            }
                        } else {
                            prev_byte
                        };
                        let byte = predicted.wrapping_sub(u32::from(mem[src])) as u8;
                        src += 1;
                        mem[dest + i as usize] = byte;
                        prev_byte = u32::from(byte);
                        i += 3;
                    }
                }
                let border = data_size - 2;
                let mut i = pos_r;
                while i < border {
                    let at = dest + i as usize;
                    let g = mem[at + 1];
                    mem[at] = mem[at].wrapping_add(g);
                    mem[at + 2] = mem[at + 2].wrapping_add(g);
                    i += 3;
                }
            }
            StandardFilter::Audio => {
                let (data_size, channels) = (r[4], r[0]);
                if data_size as usize > VM_MEMSIZE / 2 || channels > 128 || channels == 0 {
                    return false;
                }
                let dest = data_size as usize;
                let mut src = 0;
                for cur_channel in 0..channels {
                    let (mut prev_byte, mut prev_delta) = (0u32, 0u32);
                    let mut dif = [0u32; 7];
                    let (mut d1, mut d2) = (0i32, 0i32);
                    let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
                    let mut i = cur_channel;
                    let mut byte_count = 0u32;
                    while i < data_size {
                        let d3 = d2;
                        d2 = (prev_delta as i32).wrapping_sub(d1);
                        d1 = prev_delta as i32;

                        let predicted = 8u32
                            .wrapping_mul(prev_byte)
                            .wrapping_add(k1.wrapping_mul(d1) as u32)
                            .wrapping_add(k2.wrapping_mul(d2) as u32)
                            .wrapping_add(k3.wrapping_mul(d3) as u32);
                        let predicted = (predicted >> 3) & 0xff;

                        let cur_byte = mem[src];
                        src += 1;

                        let predicted = predicted.wrapping_sub(u32::from(cur_byte));
                        mem[dest + i as usize] = predicted as u8;
                        prev_delta =
                            i32::from(predicted.wrapping_sub(prev_byte) as u8 as i8) as u32;
                        prev_byte = predicted;

                        let d = (i32::from(cur_byte as i8) as u32).wrapping_shl(3) as i32;

                        let abs = |v: i32| v.wrapping_abs() as u32;
                        dif[0] = dif[0].wrapping_add(abs(d));
                        dif[1] = dif[1].wrapping_add(abs(d.wrapping_sub(d1)));
                        dif[2] = dif[2].wrapping_add(abs(d.wrapping_add(d1)));
                        dif[3] = dif[3].wrapping_add(abs(d.wrapping_sub(d2)));
                        dif[4] = dif[4].wrapping_add(abs(d.wrapping_add(d2)));
                        dif[5] = dif[5].wrapping_add(abs(d.wrapping_sub(d3)));
                        dif[6] = dif[6].wrapping_add(abs(d.wrapping_add(d3)));

                        if byte_count & 0x1f == 0 {
                            let mut min_dif = dif[0];
                            let mut num_min_dif = 0;
                            dif[0] = 0;
                            for (j, value) in dif.iter_mut().enumerate().skip(1) {
                                if *value < min_dif {
                                    min_dif = *value;
                                    num_min_dif = j;
                                }
                                *value = 0;
                            }
                            match num_min_dif {
                                1 if k1 >= -16 => k1 -= 1,
                                2 if k1 < 16 => k1 += 1,
                                3 if k2 >= -16 => k2 -= 1,
                                4 if k2 < 16 => k2 += 1,
                                5 if k3 >= -16 => k3 -= 1,
                                6 if k3 < 16 => k3 += 1,
                                _ => {}
                            }
                        }
                        i += channels;
                        byte_count += 1;
                    }
                }
            }
            StandardFilter::None => {}
        }
        true
    }
}

/// `RarVM::FilterItanium_GetBits`.
fn itanium_get_bits(data: &[u8], bit_pos: u32, bit_count: u32) -> u32 {
    let at = (bit_pos / 8) as usize;
    let field = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
    (field >> (bit_pos & 7)) & (0xffff_ffff >> (32 - bit_count))
}

/// `RarVM::FilterItanium_SetBits`.
fn itanium_set_bits(data: &mut [u8], bit_field: u32, bit_pos: u32, bit_count: u32) {
    let at = (bit_pos / 8) as usize;
    let in_bit = bit_pos & 7;
    let mut and_mask = !((0xffff_ffffu32 >> (32 - bit_count)) << in_bit);
    let mut bit_field = bit_field << in_bit;
    for i in 0..4 {
        data[at + i] &= and_mask as u8;
        data[at + i] |= bit_field as u8;
        and_mask = (and_mask >> 8) | 0xff00_0000;
        bit_field >>= 8;
    }
}

/// `RarVM::ReadData`.
pub(super) fn read_data(inp: &mut super::BitInput) -> u32 {
    let mut data = inp.getbits();
    match data & 0xc000 {
        0 => {
            inp.addbits(6);
            (data >> 10) & 0xf
        }
        0x4000 => {
            if data & 0x3c00 == 0 {
                data = 0xffff_ff00 | ((data >> 2) & 0xff);
                inp.addbits(14);
            } else {
                data = (data >> 6) & 0xff;
                inp.addbits(10);
            }
            data
        }
        0x8000 => {
            inp.addbits(2);
            data = inp.getbits();
            inp.addbits(16);
            data
        }
        _ => {
            inp.addbits(2);
            data = inp.getbits() << 16;
            inp.addbits(16);
            data |= inp.getbits();
            inp.addbits(16);
            data
        }
    }
}
