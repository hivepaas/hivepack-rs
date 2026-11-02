//! Bitstreams, written forwards and read backwards: port of
//! `common/bitstream.h`.
//!
//! zstd writes its entropy-coded streams forwards and reads them backwards,
//! from the last byte to the first. The writer collects bits in a register
//! and flushes whole bytes to memory; the reader keeps a window of the
//! stream in a register and refills it from memory.
//!
//! The writer's register is 64 bits on every machine, as on 64-bit machines
//! in libzstd; the bytes written are the same with a 32-bit one, which
//! flushes more often. What does depend on it is when a stream is found not
//! to fit (see [`BitCStream::close`]), and there the port does what libzstd
//! does on 64-bit machines.
//!
//! Differs from libzstd, for the reader:
//! - The register is 64 bits on every machine. libzstd uses `size_t`, so 32
//!   bits on 32-bit machines, where it refills more often. The bits read are
//!   the same.
//! - The position is an index into the stream instead of a pointer. Every
//!   read stays inside the stream, as in C: the position starts 8 bytes
//!   before the end (or at the start of a shorter stream) and only moves
//!   towards the start.
//! - When too many bits have been read, libzstd points the reader at a word
//!   of zeros. The port leaves the position alone. Once that has happened
//!   every refill reports [`BitDStatus::Overflow`] before looking at the
//!   position, and [`BitDStream::end_of_dstream`] is false, so where the
//!   position points no longer matters.

use super::bits::highbit32;
use super::error_private::{Result, error};
use super::mem::{read_le64, write_le64};

/// The size of the register, in bytes: `sizeof(bitD->bitContainer)` on a
/// 64-bit machine.
const CONTAINER_BYTES: usize = 8;
const CONTAINER_BITS: u32 = 64;

/// `BIT_mask`: the low `n` bits, for `n` up to 31.
const BIT_MASK: [u32; 32] = {
    let mut mask = [0u32; 32];
    let mut n = 0;
    while n < 32 {
        mask[n] = ((1u64 << n) - 1) as u32;
        n += 1;
    }
    mask
};

/// `BIT_CStream_t`: a bitstream being written into `dst`.
///
/// Positions are indices into `dst`, as libzstd's pointers would be. Every
/// flush writes a whole register, at a place that never passes
/// `dst.len() - 8` (`endPtr`), so the write stays inside `dst`.
///
/// Differs from libzstd: `endPtr` is worked out from `dst` rather than
/// kept, and [`BitCStream::flush_bits`] holds the position back at
/// `endPtr` when it writes rather than after, so that the position itself
/// may pass `endPtr` by up to 7 once the stream does not fit.
pub(crate) struct BitCStream<'a> {
    bit_container: u64,
    bit_pos: u32,
    dst: &'a mut [u8],
    ptr: usize,
}

impl<'a> BitCStream<'a> {
    /// `BIT_initCStream`: `dst` must be longer than the register.
    pub(crate) fn new(dst: &'a mut [u8]) -> Result<Self> {
        if dst.len() <= CONTAINER_BYTES {
            return error!(DstSizeTooSmall);
        }
        Ok(BitCStream {
            bit_container: 0,
            bit_pos: 0,
            dst,
            ptr: 0,
        })
    }

    /// `endPtr`: the last position a whole register can be written at.
    #[inline(always)]
    fn end_ptr(&self) -> usize {
        self.dst.len() - CONTAINER_BYTES
    }

    /// The bits the register holds, not yet flushed.
    pub(crate) fn bit_pos(&self) -> u32 {
        self.bit_pos
    }

    /// `BIT_addBits`: up to 31 bits, the low ones of `value`. The register
    /// must have room for them.
    #[inline(always)]
    pub(crate) fn add_bits(&mut self, value: u64, nb_bits: u32) {
        debug_assert!(nb_bits < 32);
        debug_assert!(nb_bits + self.bit_pos < CONTAINER_BITS);
        // BIT_getLowerBits, `BIT_mask[nb_bits]` worked out rather than
        // looked up, which saves a bounds check.
        self.bit_container |= (value & ((1u64 << nb_bits) - 1)) << self.bit_pos;
        self.bit_pos += nb_bits;
    }

    /// `BIT_addBitsFast`: `value` must have no bits above `nb_bits`.
    #[inline(always)]
    pub(crate) fn add_bits_fast(&mut self, value: u64, nb_bits: u32) {
        debug_assert!(value >> nb_bits == 0);
        debug_assert!(nb_bits + self.bit_pos < CONTAINER_BITS);
        self.bit_container |= value << self.bit_pos;
        self.bit_pos += nb_bits;
    }

    /// `BIT_flushBitsFast`: only when the stream is known to fit, so that
    /// the position stays at or before `endPtr`.
    #[inline(always)]
    pub(crate) fn flush_bits_fast(&mut self) {
        let nb_bytes = (self.bit_pos >> 3) as usize;
        debug_assert!(self.bit_pos < CONTAINER_BITS);
        debug_assert!(self.ptr <= self.end_ptr());
        write_le64(self.dst, self.ptr, self.bit_container);
        self.ptr += nb_bytes;
        self.bit_pos &= 7;
        self.bit_container = self.bit_container.wrapping_shr(nb_bytes as u32 * 8);
    }

    /// `BIT_flushBits`: never writes past `endPtr`. A stream that does not
    /// fit shows only when it is closed.
    ///
    /// Differs from libzstd: the position may pass `endPtr` by up to 7,
    /// and the write goes to the position or `endPtr`, whichever is first.
    /// libzstd holds the position back after the write instead, so it
    /// writes at the same place. Held back here, the position is one the
    /// compiler knows to be at most `endPtr`, and it drops the bounds check
    /// of the write.
    #[inline(always)]
    pub(crate) fn flush_bits(&mut self) {
        let nb_bytes = (self.bit_pos >> 3) as usize;
        debug_assert!(self.bit_pos < CONTAINER_BITS);
        let at = self.ptr.min(self.end_ptr());
        self.dst[at..at + CONTAINER_BYTES].copy_from_slice(&self.bit_container.to_le_bytes());
        self.ptr = at + nb_bytes;
        self.bit_pos &= 7;
        self.bit_container = self.bit_container.wrapping_shr(nb_bytes as u32 * 8);
    }

    /// `BIT_closeCStream`: adds the end mark and flushes. Returns the size
    /// of the stream, or 0 if it did not fit: when it reached `endPtr`,
    /// 8 bytes before the end of `dst`.
    pub(crate) fn close(mut self) -> usize {
        self.add_bits_fast(1, 1); // the end mark
        self.flush_bits();
        if self.ptr >= self.end_ptr() {
            return 0;
        }
        self.ptr + usize::from(self.bit_pos > 0)
    }
}

/// `BIT_DStream_status`: what a refill found.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum BitDStatus {
    /// The register is full again.
    Unfinished = 0,
    /// The start of the stream is near: the register holds fewer bits.
    EndOfBuffer = 1,
    /// Every bit of the stream has been read, exactly.
    Completed = 2,
    /// More bits were read than the stream holds.
    Overflow = 3,
}

/// `BIT_DStream_t`
#[derive(Clone)]
pub(crate) struct BitDStream<'a> {
    pub(crate) bit_container: u64,
    pub(crate) bits_consumed: u32,
    /// Where the register was read from, as an index into `src`: libzstd's
    /// `ptr - start`. `limitPtr` is `start + CONTAINER_BYTES`.
    ptr: usize,
    src: &'a [u8],
}

impl<'a> BitDStream<'a> {
    /// `BIT_initDStream`. `src` must be exactly the bitstream.
    pub(crate) fn new(src: &'a [u8]) -> Result<Self> {
        let size = src.len();
        if size < 1 {
            return error!(SrcSizeWrong);
        }
        let last_byte = src[size - 1];
        if size >= CONTAINER_BYTES {
            // The normal case.
            let ptr = size - CONTAINER_BYTES;
            if last_byte == 0 {
                // No end mark.
                return error!(Generic);
            }
            Ok(BitDStream {
                bit_container: read_le64(src, ptr),
                bits_consumed: 8 - highbit32(u32::from(last_byte)),
                ptr,
                src,
            })
        } else {
            // libzstd's switch, whose cases fall through from srcSize down to 2.
            let mut bit_container = u64::from(src[0]);
            for (i, &byte) in src.iter().enumerate().skip(1) {
                bit_container += u64::from(byte) << (8 * i);
            }
            if last_byte == 0 {
                // No end mark.
                return error!(CorruptionDetected);
            }
            let bits_consumed = 8 - highbit32(u32::from(last_byte));
            Ok(BitDStream {
                bit_container,
                bits_consumed: bits_consumed + ((CONTAINER_BYTES - size) as u32) * 8,
                ptr: 0,
                src,
            })
        }
    }

    /// A reader positioned at `ptr` in `src`, with `bits_consumed` bits of
    /// the register already read: what `HUF_initRemainingDStream` builds to
    /// finish a stream after the fast Huffman loop. `src` is the whole input
    /// of that loop, so the reader may go back as far as its start.
    pub(crate) fn from_parts(src: &'a [u8], ptr: usize, bits_consumed: u32) -> Self {
        BitDStream {
            bit_container: read_le64(src, ptr),
            bits_consumed,
            ptr,
            src,
        }
    }

    /// `BIT_lookBits`: the next `nb_bits` bits, without consuming them. Reads
    /// past the register give unspecified bits, as in C.
    #[inline(always)]
    pub(crate) fn look_bits(&self, nb_bits: u32) -> u64 {
        // BIT_getMiddleBits
        debug_assert!(nb_bits < 32);
        let start = CONTAINER_BITS
            .wrapping_sub(self.bits_consumed)
            .wrapping_sub(nb_bits);
        (self.bit_container >> (start & (CONTAINER_BITS - 1))) & ((1u64 << nb_bits) - 1)
    }

    /// `BIT_lookBitsFast`: only for `nb_bits >= 1`.
    #[inline(always)]
    pub(crate) fn look_bits_fast(&self, nb_bits: u32) -> u64 {
        debug_assert!(nb_bits >= 1);
        let reg_mask = CONTAINER_BITS - 1;
        (self.bit_container << (self.bits_consumed & reg_mask))
            >> ((reg_mask + 1).wrapping_sub(nb_bits) & reg_mask)
    }

    /// `BIT_skipBits`
    #[inline(always)]
    pub(crate) fn skip_bits(&mut self, nb_bits: u32) {
        self.bits_consumed = self.bits_consumed.wrapping_add(nb_bits);
    }

    /// `BIT_readBits`
    #[inline(always)]
    pub(crate) fn read_bits(&mut self, nb_bits: u32) -> u64 {
        let value = self.look_bits(nb_bits);
        self.skip_bits(nb_bits);
        value
    }

    /// `BIT_readBitsFast`: only for `nb_bits >= 1`.
    #[inline(always)]
    pub(crate) fn read_bits_fast(&mut self, nb_bits: u32) -> u64 {
        let value = self.look_bits_fast(nb_bits);
        self.skip_bits(nb_bits);
        value
    }

    /// `BIT_reloadDStream_internal`: needs `bits_consumed <= 64`, and enough
    /// bytes before the position to move back by.
    #[inline(always)]
    fn reload_internal(&mut self) -> BitDStatus {
        debug_assert!(self.bits_consumed <= CONTAINER_BITS);
        self.ptr -= (self.bits_consumed >> 3) as usize;
        self.bits_consumed &= 7;
        self.bit_container = read_le64(self.src, self.ptr);
        BitDStatus::Unfinished
    }

    /// `BIT_reloadDStreamFast`: needs `bits_consumed <= 64`. Reports
    /// [`BitDStatus::Overflow`] near the start of the stream, where
    /// [`BitDStream::reload`] has to take over.
    #[inline(always)]
    pub(crate) fn reload_fast(&mut self) -> BitDStatus {
        if self.ptr < CONTAINER_BYTES {
            return BitDStatus::Overflow;
        }
        self.reload_internal()
    }

    /// `BIT_reloadDStream`: refills the register without reading outside
    /// the stream. After [`BitDStatus::Unfinished`] it holds at least 57 bits.
    #[inline(always)]
    pub(crate) fn reload(&mut self) -> BitDStatus {
        if self.bits_consumed > CONTAINER_BITS {
            // Overflow: an error, or the end of the stream. Once in this
            // state, the stream stays in it.
            return BitDStatus::Overflow;
        }
        if self.ptr >= CONTAINER_BYTES {
            return self.reload_internal();
        }
        if self.ptr == 0 {
            // The end of the bitstream: nothing to refill.
            if self.bits_consumed < CONTAINER_BITS {
                return BitDStatus::EndOfBuffer;
            }
            return BitDStatus::Completed;
        }
        // 0 < ptr < limitPtr: move back carefully.
        let mut nb_bytes = (self.bits_consumed >> 3) as usize;
        let mut result = BitDStatus::Unfinished;
        if self.ptr < nb_bytes {
            nb_bytes = self.ptr;
            result = BitDStatus::EndOfBuffer;
        }
        self.ptr -= nb_bytes;
        self.bits_consumed -= (nb_bytes as u32) * 8;
        // The stream is longer than the register here (a shorter one starts
        // at ptr == 0), so the read stays inside it.
        self.bit_container = read_le64(self.src, self.ptr);
        result
    }

    /// `BIT_endOfDStream`: whether every bit has been read, exactly.
    #[inline(always)]
    pub(crate) fn end_of_dstream(&self) -> bool {
        self.ptr == 0 && self.bits_consumed == CONTAINER_BITS
    }
}
