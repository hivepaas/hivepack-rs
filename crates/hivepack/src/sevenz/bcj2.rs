//! The BCJ2 decoder: `Bcj2.c`, and the delta filter's: `Delta.c`.
//!
//! BCJ2 splits x86 code into four streams: the code itself (`MAIN`), the
//! absolute addresses of its CALLs (`CALL`) and JUMPs (`JUMP`), big-endian,
//! and a range-coded stream (`RC`) telling which E8, E9 and 0F 8x bytes
//! start a converted branch.
//!
//! Differs from the LZMA SDK: the buffers are slices, which a call consumes
//! from the front, and the output a slice with a position.

use crate::sevenz::error::{Error, Result};

/// `BCJ2_NUM_STREAMS`.
pub(crate) const NUM_STREAMS: usize = 4;
/// `BCJ2_STREAM_MAIN`.
pub(crate) const STREAM_MAIN: usize = 0;
/// `BCJ2_STREAM_CALL`.
pub(crate) const STREAM_CALL: usize = 1;
/// `BCJ2_STREAM_JUMP`.
pub(crate) const STREAM_JUMP: usize = 2;
/// `BCJ2_STREAM_RC`.
pub(crate) const STREAM_RC: usize = 3;
/// `BCJ2_DEC_STATE_ORIG_0`.
const DEC_STATE_ORIG_0: usize = NUM_STREAMS;
/// `BCJ2_DEC_STATE_ORIG_3`.
const DEC_STATE_ORIG_3: usize = NUM_STREAMS + 3;
/// `BCJ2_DEC_STATE_ORIG`.
const DEC_STATE_ORIG: usize = NUM_STREAMS + 4;
/// `BCJ2_DEC_STATE_ERROR`.
const DEC_STATE_ERROR: usize = NUM_STREAMS + 5;

const TOP_VALUE: u32 = 1 << 24;
const NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_TOTAL_BITS;
const NUM_MOVE_BITS: u32 = 5;

/// `BCJ2_IS_32BIT_STREAM`.
fn is_32bit_stream(s: usize) -> bool {
    s.wrapping_sub(STREAM_CALL) < 2
}

/// `CBcj2Dec`, without the buffers, which each call is given.
#[derive(Clone, Debug)]
pub(crate) struct Bcj2Dec {
    /// `BCJ2_STREAM_MAIN` has more priority than `BCJ2_STATE_ORIG`.
    pub(crate) state: usize,
    /// The base address for decoding.
    ip: u32,
    /// Bytes of a converted address not yet written.
    temp: u32,
    range: u32,
    pub(crate) code: u32,
    probs: [u16; 2 + 256],
}

/// The streams a call reads, consumed from the front, and the output, written
/// from `dest_pos`.
pub(crate) struct Bufs<'a, 'b> {
    pub(crate) bufs: [&'a [u8]; NUM_STREAMS],
    pub(crate) dest: &'b mut [u8],
    pub(crate) dest_pos: usize,
}

impl Bcj2Dec {
    /// `Bcj2Dec_Init`.
    pub(crate) fn new() -> Self {
        Bcj2Dec {
            state: STREAM_RC,
            ip: 0,
            temp: 0,
            range: 0,
            code: 0,
            probs: [(BIT_MODEL_TOTAL >> 1) as u16; 2 + 256],
        }
    }

    /// `Bcj2Dec_IsMaybeFinished`.
    pub(crate) fn is_maybe_finished(&self) -> bool {
        self.state == STREAM_MAIN && self.code == 0
    }

    /// `Bcj2Dec_Decode`: as much as the streams and the output allow. The
    /// state then tells which stream it needs more of (`BCJ2_STREAM_*`), or
    /// that the output is full.
    pub(crate) fn decode(&mut self, p: &mut Bufs<'_, '_>) -> Result<()> {
        let mut v = self.temp;
        if self.range <= 5 {
            let mut code = self.code;
            // In case of a data error.
            self.state = DEC_STATE_ERROR;
            while self.range != 5 {
                if self.range == 1 && code != 0 {
                    return Err(Error::Data);
                }
                let Some((&b, rest)) = p.bufs[STREAM_RC].split_first() else {
                    self.state = STREAM_RC;
                    return Ok(());
                };
                p.bufs[STREAM_RC] = rest;
                code = (code << 8) | u32::from(b);
                self.code = code;
                self.range += 1;
            }
            if code == 0xffff_ffff {
                return Err(Error::Data);
            }
            self.range = 0xffff_ffff;
        }
        {
            let mut state = self.state;
            // BCJ2_IS_32BIT_STREAM() is checked here instead of in the main
            // loop.
            if is_32bit_stream(state) {
                let Some((word, rest)) = p.bufs[state].split_first_chunk::<4>() else {
                    return Ok(());
                };
                p.bufs[state] = rest;
                let ip = self.ip.wrapping_add(4);
                v = u32::from_be_bytes(*word).wrapping_sub(ip);
                self.ip = ip;
                state = DEC_STATE_ORIG_0;
            }
            if state.wrapping_sub(DEC_STATE_ORIG_0) < 4 {
                loop {
                    if p.dest_pos == p.dest.len() {
                        self.state = state;
                        self.temp = v;
                        return Ok(());
                    }
                    p.dest[p.dest_pos] = v as u8;
                    p.dest_pos += 1;
                    state += 1;
                    if state == DEC_STATE_ORIG_3 + 1 {
                        break;
                    }
                    v >>= 8;
                }
            }
        }

        loop {
            if self.range < TOP_VALUE {
                let Some((&b, rest)) = p.bufs[STREAM_RC].split_first() else {
                    self.state = STREAM_RC;
                    self.temp = v;
                    return Ok(());
                };
                p.bufs[STREAM_RC] = rest;
                self.range <<= 8;
                self.code = (self.code << 8) | u32::from(b);
            }
            {
                // The main stream copied up to a byte that may start a
                // converted branch.
                let src = p.bufs[STREAM_MAIN];
                let room = p.dest.len() - p.dest_pos;
                let num = src.len().min(room);
                let mut n = 0;
                let mut stopped = false;
                while n < num {
                    let b = u32::from(src[n]);
                    p.dest[p.dest_pos + n] = b as u8;
                    n += 1;
                    v = (v << 24) | b;
                    if (b + (0x100 - 0xe8)) & 0xfe == 0 {
                        stopped = true;
                        break;
                    }
                    if v.wrapping_sub((0x0f << 24) + 0x80) & (((1u32 << (4 + 24)) - 1) << 4) == 0 {
                        stopped = true;
                        break;
                    }
                }
                p.bufs[STREAM_MAIN] = &src[n..];
                p.dest_pos += n;
                self.ip = self.ip.wrapping_add(n as u32);
                if !stopped {
                    // The main stream or the output at their ends: the state
                    // MAIN has more priority than ORIG.
                    self.state = if p.bufs[STREAM_MAIN].is_empty() {
                        STREAM_MAIN
                    } else {
                        DEC_STATE_ORIG
                    };
                    self.temp = v;
                    return Ok(());
                }

                let c = ((v.wrapping_add(0x17)) >> 6) & 1;
                let index =
                    ((0u32.wrapping_sub(c) & ((v >> 24) & 0xff)) + c + ((v >> 5) & 1)) as usize;
                let ttt = u32::from(self.probs[index]);
                let bound = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * ttt;
                if self.code < bound {
                    self.range = bound;
                    self.probs[index] = (ttt + ((BIT_MODEL_TOTAL - ttt) >> NUM_MOVE_BITS)) as u16;
                    continue;
                }
                self.range -= bound;
                self.code -= bound;
                self.probs[index] = (ttt - (ttt >> NUM_MOVE_BITS)) as u16;
            }
            {
                let cj = ((v.wrapping_add(0x57) >> 6) & 1) as usize + STREAM_CALL;
                let Some((word, rest)) = p.bufs[cj].split_first_chunk::<4>() else {
                    self.state = cj;
                    break;
                };
                p.bufs[cj] = rest;
                v = u32::from_be_bytes(*word);
                let ip = self.ip.wrapping_add(4);
                v = v.wrapping_sub(ip);
                self.ip = ip;
                let rem = p.dest.len() - p.dest_pos;
                if rem < 4 {
                    for k in 0..rem {
                        p.dest[p.dest_pos + k] = v as u8;
                        v >>= 8;
                    }
                    self.temp = v;
                    p.dest_pos += rem;
                    self.state = DEC_STATE_ORIG_0 + rem;
                    break;
                }
                p.dest[p.dest_pos..p.dest_pos + 4].copy_from_slice(&v.to_le_bytes());
                v >>= 24;
                p.dest_pos += 4;
            }
        }

        if self.range < TOP_VALUE
            && let Some((&b, rest)) = p.bufs[STREAM_RC].split_first()
        {
            p.bufs[STREAM_RC] = rest;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(b);
        }
        Ok(())
    }
}

/// `DELTA_STATE_SIZE`.
const DELTA_STATE_SIZE: usize = 256;

/// The delta filter's decoder (`Delta_Decode`), streaming: each byte plus
/// the one `dist` bytes before it.
#[derive(Clone, Debug)]
pub(crate) struct Delta {
    dist: usize,
    history: [u8; DELTA_STATE_SIZE],
    pos: u8,
}

impl Delta {
    /// `Delta_Init`, with a distance of 1 to 256.
    pub(crate) fn new(dist: usize) -> Self {
        Delta {
            dist,
            history: [0; DELTA_STATE_SIZE],
            pos: 0,
        }
    }

    /// `Delta_Decode`.
    pub(crate) fn decode(&mut self, data: &mut [u8]) {
        for b in data {
            let back = self.history[(self.pos as usize + self.dist) & 0xFF];
            *b = b.wrapping_add(back);
            self.history[self.pos as usize] = *b;
            self.pos = self.pos.wrapping_sub(1);
        }
    }
}
