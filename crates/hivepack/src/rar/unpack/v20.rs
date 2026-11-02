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

//! The algorithm of RAR 2.x: UnRAR's `Unpack20` (unpack20.cpp), with its audio
//! blocks.

use crate::rar::error::Error;

use super::{BitInput, DecodeTable, NC20, UnpIo, Unpack};

const DC20: usize = 48;
const RC20: usize = 28;
const BC20: usize = 19;
const MC20: usize = 257;

static L_DECODE: [u32; RC20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
static L_BITS: [u32; RC20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
static D_DECODE: [u32; DC20] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
static D_BITS: [u32; DC20] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
static SD_DECODE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
static SD_BITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// `Inp.getbits()>>(16-Bits)`, and past them: nothing for no bits.
#[inline(always)]
fn extra_bits(inp: &mut BitInput, bits: u32) -> u32 {
    if bits == 0 {
        return 0;
    }
    let value = inp.getbits() >> (16 - bits);
    inp.addbits(bits);
    value
}

/// `AudioVariables`.
#[derive(Clone, Copy, Default)]
struct AudioVariables {
    k1: i32,
    k2: i32,
    k3: i32,
    k4: i32,
    k5: i32,
    d1: i32,
    d2: i32,
    d3: i32,
    d4: i32,
    last_delta: i32,
    dif: [u32; 11],
    byte_count: u32,
    last_char: i32,
}

/// What RAR 2's algorithm keeps: from `Unpack`.
pub(super) struct State20 {
    md: Box<[DecodeTable; 4]>,
    unp_old_table20: [u8; MC20 * 4],
    tables_read2: bool,
    unp_audio_block: bool,
    unp_channels: usize,
    unp_cur_channel: usize,
    unp_channel_delta: i32,
    aud_v: [AudioVariables; 4],
}

impl State20 {
    pub(super) fn new() -> State20 {
        State20 {
            md: Box::new([
                DecodeTable::zero(),
                DecodeTable::zero(),
                DecodeTable::zero(),
                DecodeTable::zero(),
            ]),
            unp_old_table20: [0; MC20 * 4],
            tables_read2: false,
            unp_audio_block: false,
            unp_channels: 1,
            unp_cur_channel: 0,
            unp_channel_delta: 0,
            aud_v: [AudioVariables::default(); 4],
        }
    }

    /// `Unpack::UnpInitData20`.
    pub(super) fn init_data(&mut self, solid: bool) {
        if !solid {
            self.tables_read2 = false;
            self.unp_audio_block = false;
            self.unp_channel_delta = 0;
            self.unp_cur_channel = 0;
            self.unp_channels = 1;
            self.aud_v = [AudioVariables::default(); 4];
            self.unp_old_table20 = [0; MC20 * 4];
            for table in self.md.iter_mut() {
                *table = DecodeTable::zero();
            }
        }
    }

    /// `Unpack::DecodeAudio`.
    fn decode_audio(&mut self, delta: i32) -> u8 {
        let channel_delta = self.unp_channel_delta;
        let v = &mut self.aud_v[self.unp_cur_channel];
        v.byte_count = v.byte_count.wrapping_add(1);
        v.d4 = v.d3;
        v.d3 = v.d2;
        v.d2 = v.last_delta.wrapping_sub(v.d1);
        v.d1 = v.last_delta;
        let p_ch = 8i32
            .wrapping_mul(v.last_char)
            .wrapping_add(v.k1.wrapping_mul(v.d1))
            .wrapping_add(v.k2.wrapping_mul(v.d2))
            .wrapping_add(v.k3.wrapping_mul(v.d3))
            .wrapping_add(v.k4.wrapping_mul(v.d4))
            .wrapping_add(v.k5.wrapping_mul(channel_delta));
        let p_ch = (p_ch >> 3) & 0xff;

        let ch = p_ch.wrapping_sub(delta);

        let d = i32::from(delta as i8) << 3;

        let dif_of = |value: i32| value.wrapping_abs() as u32;
        let additions = [
            d,
            d.wrapping_sub(v.d1),
            d.wrapping_add(v.d1),
            d.wrapping_sub(v.d2),
            d.wrapping_add(v.d2),
            d.wrapping_sub(v.d3),
            d.wrapping_add(v.d3),
            d.wrapping_sub(v.d4),
            d.wrapping_add(v.d4),
            d.wrapping_sub(channel_delta),
            d.wrapping_add(channel_delta),
        ];
        for (dif, addition) in v.dif.iter_mut().zip(additions) {
            *dif = dif.wrapping_add(dif_of(addition));
        }

        let last_delta = i32::from(ch.wrapping_sub(v.last_char) as i8);
        self.unp_channel_delta = last_delta;
        v.last_delta = last_delta;
        v.last_char = ch;

        if v.byte_count & 0x1f == 0 {
            let mut min_dif = v.dif[0];
            let mut num_min_dif = 0;
            v.dif[0] = 0;
            for i in 1..v.dif.len() {
                if v.dif[i] < min_dif {
                    min_dif = v.dif[i];
                    num_min_dif = i;
                }
                v.dif[i] = 0;
            }
            let (k, down) = match num_min_dif {
                1 => (&mut v.k1, true),
                2 => (&mut v.k1, false),
                3 => (&mut v.k2, true),
                4 => (&mut v.k2, false),
                5 => (&mut v.k3, true),
                6 => (&mut v.k3, false),
                7 => (&mut v.k4, true),
                8 => (&mut v.k4, false),
                9 => (&mut v.k5, true),
                10 => (&mut v.k5, false),
                _ => return ch as u8,
            };
            if down {
                if *k >= -16 {
                    *k -= 1;
                }
            } else if *k < 16 {
                *k += 1;
            }
        }
        ch as u8
    }
}

impl Unpack {
    /// `Unpack::CopyString20`.
    #[inline(always)]
    fn copy_string20(&mut self, length: u32, distance: u32) {
        self.last_dist = distance;
        self.old_dist[self.old_dist_ptr] = distance as usize;
        // Needed if a RAR 1.5 file is called after RAR 2.0.
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.dest_unp_size -= i64::from(length);
        self.copy_string(length, distance as usize);
    }

    /// `Unpack::Unpack20`.
    ///
    /// A table of a later algorithm can decode more than the tables here have,
    /// when solid entries go from RAR 2 to RAR 3 and back: UnRAR reads past
    /// its static arrays then, and what it finds there is its compiler's
    /// doing. Here it is zero.
    pub(super) fn unpack20(&mut self, solid: bool, io: &mut dyn UnpIo) -> Result<(), Error> {
        self.unp_init_data(solid);
        if !self.unp_read_buf(io)? {
            return Ok(());
        }
        if (!solid || !self.st20.tables_read2) && !self.read_tables20(io)? {
            return Ok(());
        }
        self.dest_unp_size -= 1;

        while self.dest_unp_size >= 0 {
            self.unp_ptr &= self.max_win_mask();

            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;

            if self.inp.in_addr > self.read_top - 30 && !self.unp_read_buf(io)? {
                break;
            }
            if self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask() < 270
                && self.wr_ptr != self.unp_ptr
            {
                self.unp_write_buf20(io)?;
            }
            self.reserve_window()?;
            if self.st20.unp_audio_block {
                let channel = self.st20.unp_cur_channel;
                let audio_number = self.st20.md[channel].decode(&mut self.inp);

                if audio_number == 256 {
                    if !self.read_tables20(io)? {
                        break;
                    }
                    continue;
                }
                self.window[self.unp_ptr] = self.st20.decode_audio(audio_number as i32);
                self.unp_ptr += 1;
                self.st20.unp_cur_channel += 1;
                if self.st20.unp_cur_channel == self.st20.unp_channels {
                    self.st20.unp_cur_channel = 0;
                }
                self.dest_unp_size -= 1;
                continue;
            }

            let number = self.block_tables.ld.decode(&mut self.inp);
            if number < 256 {
                self.window[self.unp_ptr] = number as u8;
                self.unp_ptr += 1;
                self.dest_unp_size -= 1;
                continue;
            }
            if number > 269 {
                let number = (number - 270) as usize;
                let mut length = L_DECODE.get(number).copied().unwrap_or(0) + 3;
                length += extra_bits(&mut self.inp, L_BITS.get(number).copied().unwrap_or(0));

                let dist_number = self.block_tables.dd.decode(&mut self.inp) as usize;
                let mut distance = D_DECODE.get(dist_number).copied().unwrap_or(0) + 1;
                distance +=
                    extra_bits(&mut self.inp, D_BITS.get(dist_number).copied().unwrap_or(0));

                if distance >= 0x2000 {
                    length += 1;
                    if distance >= 0x40000 {
                        length += 1;
                    }
                }

                self.copy_string20(length, distance);
                continue;
            }
            if number == 269 {
                if !self.read_tables20(io)? {
                    break;
                }
                continue;
            }
            if number == 256 {
                self.copy_string20(self.last_length, self.last_dist);
                continue;
            }
            if number < 261 {
                let place = self.old_dist_ptr.wrapping_sub(number as usize - 256) & 3;
                let distance = self.old_dist[place] as u32;
                let length_number = self.block_tables.rd.decode(&mut self.inp) as usize;
                let mut length = L_DECODE.get(length_number).copied().unwrap_or(0) + 2;
                length += extra_bits(
                    &mut self.inp,
                    L_BITS.get(length_number).copied().unwrap_or(0),
                );
                if distance >= 0x101 {
                    length += 1;
                    if distance >= 0x2000 {
                        length += 1;
                        if distance >= 0x40000 {
                            length += 1;
                        }
                    }
                }
                self.copy_string20(length, distance);
                continue;
            }
            let number = (number - 261) as usize;
            let distance = SD_DECODE[number] + 1 + extra_bits(&mut self.inp, SD_BITS[number]);
            self.copy_string20(2, distance);
        }
        self.read_last_tables(io)?;
        self.unp_write_buf20(io)
    }

    /// `Unpack::UnpWriteBuf20`.
    pub(super) fn unp_write_buf20(&mut self, io: &mut dyn UnpIo) -> Result<(), Error> {
        if self.unp_ptr < self.wr_ptr {
            let tail = self.wr_ptr.wrapping_neg() & self.max_win_mask();
            self.window_up_to(self.wr_ptr + tail)?;
            io.unp_write(&self.window[self.wr_ptr..self.wr_ptr + tail])?;
            io.unp_write(&self.window[..self.unp_ptr])?;
        } else {
            self.window_up_to(self.unp_ptr)?;
            io.unp_write(&self.window[self.wr_ptr..self.unp_ptr])?;
        }
        self.wr_ptr = self.unp_ptr;
        Ok(())
    }

    /// `Unpack::ReadTables20`.
    fn read_tables20(&mut self, io: &mut dyn UnpIo) -> Result<bool, Error> {
        let mut bit_length = [0u8; BC20];
        let mut table = [0u8; MC20 * 4];
        if self.inp.in_addr > self.read_top - 25 && !self.unp_read_buf(io)? {
            return Ok(false);
        }
        let bit_field = self.inp.getbits();
        self.st20.unp_audio_block = bit_field & 0x8000 != 0;

        if bit_field & 0x4000 == 0 {
            self.st20.unp_old_table20 = [0; MC20 * 4];
        }
        self.inp.addbits(2);

        let table_size = if self.st20.unp_audio_block {
            self.st20.unp_channels = ((bit_field >> 12) & 3) as usize + 1;
            if self.st20.unp_cur_channel >= self.st20.unp_channels {
                self.st20.unp_cur_channel = 0;
            }
            self.inp.addbits(2);
            MC20 * self.st20.unp_channels
        } else {
            NC20 + DC20 + RC20
        };

        for length in &mut bit_length {
            *length = (self.inp.getbits() >> 12) as u8;
            self.inp.addbits(4);
        }
        self.block_tables.bd.make(&bit_length);
        let mut i = 0;
        while i < table_size {
            if self.inp.in_addr > self.read_top - 5 && !self.unp_read_buf(io)? {
                return Ok(false);
            }
            let number = self.block_tables.bd.decode(&mut self.inp);
            if number < 16 {
                table[i] = (number as u8 + self.st20.unp_old_table20[i]) & 0xf;
                i += 1;
            } else if number == 16 {
                let n = (self.inp.getbits() >> 14) + 3;
                self.inp.addbits(2);
                if i == 0 {
                    // No "repeat previous" code at the first position.
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
                let n = if number == 17 {
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
        self.st20.tables_read2 = true;
        if self.inp.in_addr > self.read_top {
            return Ok(true);
        }
        if self.st20.unp_audio_block {
            for channel in 0..self.st20.unp_channels {
                self.st20.md[channel].make(&table[channel * MC20..(channel + 1) * MC20]);
            }
        } else {
            self.block_tables.ld.make(&table[..NC20]);
            self.block_tables.dd.make(&table[NC20..NC20 + DC20]);
            self.block_tables
                .rd
                .make(&table[NC20 + DC20..NC20 + DC20 + RC20]);
        }
        self.st20.unp_old_table20[..table_size].copy_from_slice(&table[..table_size]);
        Ok(true)
    }

    /// `Unpack::ReadLastTables`.
    fn read_last_tables(&mut self, io: &mut dyn UnpIo) -> Result<(), Error> {
        if self.read_top >= self.inp.in_addr + 5 {
            let end = if self.st20.unp_audio_block {
                let channel = self.st20.unp_cur_channel;
                self.st20.md[channel].decode(&mut self.inp) == 256
            } else {
                self.block_tables.ld.decode(&mut self.inp) == 269
            };
            if end {
                self.read_tables20(io)?;
            }
        }
        Ok(())
    }
}
