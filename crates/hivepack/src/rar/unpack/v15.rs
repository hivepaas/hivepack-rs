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

//! The algorithm of RAR 1.3 to 1.5: UnRAR's `Unpack15` (unpack15.cpp). No
//! table comes with the data here: the bytes and the distances are ranked by
//! how often they were seen, and the rank is what is coded.

use crate::rar::error::Error;

use super::{BitInput, UnpIo, Unpack};

const STARTL1: u32 = 2;
static DEC_L1: [u32; 11] = [
    0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff,
];
static POS_L1: [u32; 13] = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];

const STARTL2: u32 = 3;
static DEC_L2: [u32; 10] = [
    0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff,
];
static POS_L2: [u32; 13] = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];

const STARTHF0: u32 = 4;
static DEC_HF0: [u32; 9] = [
    0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
static POS_HF0: [u32; 13] = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];

const STARTHF1: u32 = 5;
static DEC_HF1: [u32; 8] = [
    0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
static POS_HF1: [u32; 13] = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];

const STARTHF2: u32 = 5;
static DEC_HF2: [u32; 8] = [
    0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
static POS_HF2: [u32; 13] = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];

const STARTHF3: u32 = 6;
static DEC_HF3: [u32; 7] = [0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
static POS_HF3: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];

const STARTHF4: u32 = 8;
static DEC_HF4: [u32; 6] = [0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
static POS_HF4: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

static SHORT_LEN1: [u32; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
static SHORT_XOR1: [u32; 15] = [
    0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];
static SHORT_LEN2: [u32; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
static SHORT_XOR2: [u32; 15] = [
    0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];

/// `Unpack::DecodeNum`. Every table ends in 0xffff, above any `num` here, so
/// the search stops within it, and within `pos_tab`.
#[inline]
fn decode_num(inp: &mut BitInput, start_pos: u32, dec_tab: &[u32], pos_tab: &[u32; 13]) -> u32 {
    let num = inp.getbits() & 0xfff0;
    let mut i = 0;
    while dec_tab[i] <= num {
        i += 1;
    }
    let start_pos = start_pos + i as u32;
    inp.addbits(start_pos);
    let below = if i > 0 { dec_tab[i - 1] } else { 0 };
    ((num - below) >> (16 - start_pos)) + pos_tab[start_pos as usize]
}

/// `Unpack::CorrHuff`.
fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
    let mut chars = char_set.iter_mut();
    for i in (0..8).rev() {
        for _ in 0..32 {
            if let Some(c) = chars.next() {
                *c = (*c & !0xff) | i;
            }
        }
    }
    *num_to_place = [0; 256];
    for (i, place) in num_to_place.iter_mut().take(7).enumerate() {
        *place = (7 - i as u8) * 32;
    }
}

/// What RAR 1.5's algorithm keeps: from `Unpack`.
pub(super) struct State15 {
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    flag_buf: u32,
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    buf60: u32,
    num_huf: u32,
    st_mode: bool,
    l_count: u32,
    flags_cnt: i32,
    nhfb: u32,
    nlzb: u32,
    max_dist3: u32,
}

impl State15 {
    /// What `Unpack`'s constructor gets to: `UnpInitData15(false)` and
    /// `InitHuff`.
    pub(super) fn new() -> State15 {
        let mut state = State15 {
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            flag_buf: 0,
            avr_plc: 0,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            buf60: 0,
            num_huf: 0,
            st_mode: false,
            l_count: 0,
            flags_cnt: 0,
            nhfb: 0,
            nlzb: 0,
            max_dist3: 0,
        };
        state.init_data(false);
        state.init_huff();
        state
    }

    /// `Unpack::UnpInitData15`.
    fn init_data(&mut self, solid: bool) {
        if !solid {
            self.avr_plc_b = 0;
            self.avr_ln1 = 0;
            self.avr_ln2 = 0;
            self.avr_ln3 = 0;
            self.num_huf = 0;
            self.buf60 = 0;
            self.avr_plc = 0x3500;
            self.max_dist3 = 0x2001;
            self.nhfb = 0x80;
            self.nlzb = 0x80;
        }
        self.flags_cnt = 0;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;
    }

    /// `Unpack::InitHuff`.
    fn init_huff(&mut self) {
        for i in 0..256u16 {
            self.ch_set[usize::from(i)] = i << 8;
            self.ch_set_b[usize::from(i)] = i << 8;
            self.ch_set_a[usize::from(i)] = i;
            self.ch_set_c[usize::from(i)] = (i.wrapping_neg() & 0xff) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }
}

impl Unpack {
    /// `Unpack::Unpack15`.
    pub(super) fn unpack15(&mut self, solid: bool, io: &mut dyn UnpIo) -> Result<(), Error> {
        self.unp_init_data(solid);
        self.st15.init_data(solid);
        self.unp_read_buf(io)?;
        if solid {
            self.unp_ptr = self.wr_ptr;
        } else {
            self.st15.init_huff();
            self.unp_ptr = 0;
        }
        self.dest_unp_size -= 1;
        if self.dest_unp_size >= 0 {
            self.get_flags_buf();
            self.st15.flags_cnt = 8;
        }

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
            if self.st15.st_mode {
                self.huff_decode();
                continue;
            }

            self.st15.flags_cnt -= 1;
            if self.st15.flags_cnt < 0 {
                self.get_flags_buf();
                self.st15.flags_cnt = 7;
            }

            if self.st15.flag_buf & 0x80 != 0 {
                self.st15.flag_buf <<= 1;
                if self.st15.nlzb > self.st15.nhfb {
                    self.long_lz();
                } else {
                    self.huff_decode();
                }
            } else {
                self.st15.flag_buf <<= 1;
                self.st15.flags_cnt -= 1;
                if self.st15.flags_cnt < 0 {
                    self.get_flags_buf();
                    self.st15.flags_cnt = 7;
                }
                if self.st15.flag_buf & 0x80 != 0 {
                    self.st15.flag_buf <<= 1;
                    if self.st15.nlzb > self.st15.nhfb {
                        self.huff_decode();
                    } else {
                        self.long_lz();
                    }
                } else {
                    self.st15.flag_buf <<= 1;
                    self.short_lz();
                }
            }
        }
        self.unp_write_buf20(io)
    }

    /// `Unpack::ShortLZ`.
    fn short_lz(&mut self) {
        self.st15.num_huf = 0;

        let mut bit_field = self.inp.getbits();
        if self.st15.l_count == 2 {
            self.inp.addbits(1);
            if bit_field >= 0x8000 {
                self.copy_string15(self.last_dist, self.last_length);
                return;
            }
            bit_field <<= 1;
            self.st15.l_count = 0;
        }

        bit_field >>= 8;

        // `GetShortLen1` and `GetShortLen2`: one length of each table depends
        // on `Buf60`. The search stops by the 15th for any byte.
        let (lengths, xors, of_buf60) = if self.st15.avr_ln1 < 37 {
            (&SHORT_LEN1, &SHORT_XOR1, 1)
        } else {
            (&SHORT_LEN2, &SHORT_XOR2, 3)
        };
        let short_len = |pos: usize, buf60: u32| {
            if pos == of_buf60 {
                buf60 + 3
            } else {
                lengths[pos]
            }
        };
        let mut length = 0;
        while (bit_field ^ xors[length]) & !(0xff >> short_len(length, self.st15.buf60)) != 0 {
            length += 1;
        }
        self.inp.addbits(short_len(length, self.st15.buf60));
        let mut length = length as u32;

        if length >= 9 {
            if length == 9 {
                self.st15.l_count += 1;
                self.copy_string15(self.last_dist, self.last_length);
                return;
            }
            if length == 14 {
                self.st15.l_count = 0;
                let length = decode_num(&mut self.inp, STARTL2, &DEC_L2, &POS_L2) + 5;
                let distance = (self.inp.getbits() >> 1) | 0x8000;
                self.inp.addbits(15);
                self.last_length = length;
                self.last_dist = distance;
                self.copy_string15(distance, length);
                return;
            }

            self.st15.l_count = 0;
            let save_length = length;
            let distance =
                self.old_dist[self.old_dist_ptr.wrapping_sub(length as usize - 9) & 3] as u32;
            length = decode_num(&mut self.inp, STARTL1, &DEC_L1, &POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.st15.buf60 ^= 1;
                return;
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.st15.max_dist3 {
                length += 1;
            }

            self.old_dist[self.old_dist_ptr] = distance as usize;
            self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
            self.last_length = length;
            self.last_dist = distance;
            self.copy_string15(distance, length);
            return;
        }

        self.st15.l_count = 0;
        self.st15.avr_ln1 += length;
        self.st15.avr_ln1 -= self.st15.avr_ln1 >> 4;

        let distance_place =
            (decode_num(&mut self.inp, STARTHF2, &DEC_HF2, &POS_HF2) & 0xff) as usize;
        let mut distance = u32::from(self.st15.ch_set_a[distance_place]);
        if distance_place > 0 {
            let last_distance = self.st15.ch_set_a[distance_place - 1];
            self.st15.ch_set_a[distance_place] = last_distance;
            self.st15.ch_set_a[distance_place - 1] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.old_dist[self.old_dist_ptr] = distance as usize;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
        self.copy_string15(distance, length);
    }

    /// `Unpack::LongLZ`.
    fn long_lz(&mut self) {
        let st = &mut self.st15;
        st.num_huf = 0;
        st.nlzb += 16;
        if st.nlzb > 0xff {
            st.nlzb = 0x90;
            st.nhfb >>= 1;
        }
        let old_avr2 = st.avr_ln2;

        let bit_field = self.inp.getbits();
        let mut length = if st.avr_ln2 >= 122 {
            decode_num(&mut self.inp, STARTL2, &DEC_L2, &POS_L2)
        } else if st.avr_ln2 >= 64 {
            decode_num(&mut self.inp, STARTL1, &DEC_L1, &POS_L1)
        } else if bit_field < 0x100 {
            self.inp.addbits(16);
            bit_field
        } else {
            let mut length = 0;
            while (bit_field << length) & 0x8000 == 0 {
                length += 1;
            }
            self.inp.addbits(length + 1);
            length
        };

        st.avr_ln2 += length;
        st.avr_ln2 -= st.avr_ln2 >> 5;

        let distance_place = if st.avr_plc_b > 0x28ff {
            decode_num(&mut self.inp, STARTHF2, &DEC_HF2, &POS_HF2)
        } else if st.avr_plc_b > 0x6ff {
            decode_num(&mut self.inp, STARTHF1, &DEC_HF1, &POS_HF1)
        } else {
            decode_num(&mut self.inp, STARTHF0, &DEC_HF0, &POS_HF0)
        };

        st.avr_plc_b += distance_place;
        st.avr_plc_b -= st.avr_plc_b >> 8;
        let distance_place = (distance_place & 0xff) as usize;
        let (mut distance, new_distance_place) = loop {
            let distance = u32::from(st.ch_set_b[distance_place]);
            let slot = &mut st.n_to_pl_b[(distance & 0xff) as usize];
            let new_distance_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            let distance = distance + 1;
            if distance & 0xff == 0 {
                corr_huff(&mut st.ch_set_b, &mut st.n_to_pl_b);
            } else {
                break (distance, new_distance_place);
            }
        };

        st.ch_set_b[distance_place] = st.ch_set_b[new_distance_place];
        st.ch_set_b[new_distance_place] = distance as u16;

        distance = ((distance & 0xff00) | (self.inp.getbits() >> 8)) >> 1;
        self.inp.addbits(7);

        let old_avr3 = st.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= st.max_dist3 {
                st.avr_ln3 += 1;
                st.avr_ln3 -= st.avr_ln3 >> 8;
            } else if st.avr_ln3 > 0 {
                st.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= st.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        st.max_dist3 = if old_avr3 > 0xb0 || (st.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            0x7f00
        } else {
            0x2001
        };
        self.old_dist[self.old_dist_ptr] = distance as usize;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
        self.copy_string15(distance, length);
    }

    /// `Unpack::HuffDecode`.
    fn huff_decode(&mut self) {
        let bit_field = self.inp.getbits();
        let avr_plc = self.st15.avr_plc;
        let inp = &mut self.inp;
        let place = if avr_plc > 0x75ff {
            decode_num(inp, STARTHF4, &DEC_HF4, &POS_HF4)
        } else if avr_plc > 0x5dff {
            decode_num(inp, STARTHF3, &DEC_HF3, &POS_HF3)
        } else if avr_plc > 0x35ff {
            decode_num(inp, STARTHF2, &DEC_HF2, &POS_HF2)
        } else if avr_plc > 0x0dff {
            decode_num(inp, STARTHF1, &DEC_HF1, &POS_HF1)
        } else {
            decode_num(inp, STARTHF0, &DEC_HF0, &POS_HF0)
        };
        let mut byte_place = (place & 0xff) as usize;
        if self.st15.st_mode {
            if byte_place == 0 && bit_field > 0xfff {
                byte_place = 0x100;
            }
            if byte_place == 0 {
                let bit_field = self.inp.getbits();
                self.inp.addbits(1);
                if bit_field & 0x8000 != 0 {
                    self.st15.num_huf = 0;
                    self.st15.st_mode = false;
                } else {
                    let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                    self.inp.addbits(1);
                    let distance = decode_num(&mut self.inp, STARTHF2, &DEC_HF2, &POS_HF2);
                    let distance = (distance << 5) | (self.inp.getbits() >> 11);
                    self.inp.addbits(5);
                    self.copy_string15(distance, length);
                }
                return;
            }
            byte_place -= 1;
        } else {
            let num_huf = self.st15.num_huf;
            self.st15.num_huf = num_huf.wrapping_add(1);
            if num_huf >= 16 && self.st15.flags_cnt == 0 {
                self.st15.st_mode = true;
            }
        }
        let st = &mut self.st15;
        st.avr_plc += byte_place as u32;
        st.avr_plc -= st.avr_plc >> 8;
        st.nhfb += 16;
        if st.nhfb > 0xff {
            st.nhfb = 0x90;
            st.nlzb >>= 1;
        }

        self.window[self.unp_ptr] = (st.ch_set[byte_place] >> 8) as u8;
        self.unp_ptr += 1;
        self.dest_unp_size -= 1;

        let (cur_byte, new_byte_place) = loop {
            let cur_byte = u32::from(st.ch_set[byte_place]);
            let slot = &mut st.n_to_pl[(cur_byte & 0xff) as usize];
            let new_byte_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            let cur_byte = cur_byte + 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut st.ch_set, &mut st.n_to_pl);
            } else {
                break (cur_byte, new_byte_place);
            }
        };

        st.ch_set[byte_place] = st.ch_set[new_byte_place];
        st.ch_set[new_byte_place] = cur_byte as u16;
    }

    /// `Unpack::GetFlagsBuf`.
    fn get_flags_buf(&mut self) {
        let flags_place = decode_num(&mut self.inp, STARTHF2, &DEC_HF2, &POS_HF2) as usize;

        // The table's last item is not used for the flags, and a corrupt
        // archive can still come to it.
        if flags_place >= self.st15.ch_set_c.len() {
            return;
        }

        let st = &mut self.st15;
        let (flags, new_flags_place) = loop {
            let flags = u32::from(st.ch_set_c[flags_place]);
            st.flag_buf = flags >> 8;
            let slot = &mut st.n_to_pl_c[(flags & 0xff) as usize];
            let new_flags_place = usize::from(*slot);
            *slot = slot.wrapping_add(1);
            let flags = flags + 1;
            if flags & 0xff != 0 {
                break (flags, new_flags_place);
            }
            corr_huff(&mut st.ch_set_c, &mut st.n_to_pl_c);
        };

        st.ch_set_c[flags_place] = st.ch_set_c[new_flags_place];
        st.ch_set_c[new_flags_place] = flags as u16;
    }

    /// `Unpack::CopyString15`.
    fn copy_string15(&mut self, distance: u32, length: u32) {
        self.dest_unp_size -= i64::from(length);
        let distance = distance as usize;
        let mask = self.max_win_mask();
        // Distance can be 0 in corrupt archives.
        let zeros = (!self.first_win_done && distance > self.unp_ptr)
            || distance > self.max_win_size
            || distance == 0;
        for _ in 0..length {
            self.window[self.unp_ptr] = if zeros {
                0
            } else {
                self.window[self.unp_ptr.wrapping_sub(distance) & mask]
            };
            self.unp_ptr = (self.unp_ptr + 1) & mask;
        }
    }
}
