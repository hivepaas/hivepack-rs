//! Validating the Index against the Blocks decoded: port of
//! `common/index_hash.c`, with the size functions of `common/index.h`.

use crate::xz::block::{UNPADDED_SIZE_MAX, UNPADDED_SIZE_MIN, vli_ceil4};
use crate::xz::check::{CHECK_BEST, CheckState, crc32};
use crate::xz::common::{Ret, VLI_MAX};
use crate::xz::stream_flags::{BACKWARD_SIZE_MAX, STREAM_HEADER_SIZE};
use crate::xz::vli;

/// `INDEX_INDICATOR`.
pub(crate) const INDEX_INDICATOR: u8 = 0;

/// `index_size_unpadded`.
fn index_size_unpadded(count: u64, index_list_size: u64) -> u64 {
    // Index Indicator + Number of Records + List of Records + CRC32
    1 + u64::from(vli::size(count)) + index_list_size + 4
}

/// `index_size`.
pub(crate) fn index_size(count: u64, index_list_size: u64) -> u64 {
    vli_ceil4(index_size_unpadded(count, index_list_size))
}

/// `index_stream_size`.
fn index_stream_size(blocks_size: u64, count: u64, index_list_size: u64) -> u64 {
    STREAM_HEADER_SIZE as u64
        + blocks_size
        + index_size(count, index_list_size)
        + STREAM_HEADER_SIZE as u64
}

/// `lzma_index_hash_info`.
#[derive(Clone)]
struct Info {
    blocks_size: u64,
    uncompressed_size: u64,
    count: u64,
    index_list_size: u64,
    check: CheckState,
}

impl Info {
    fn new() -> Info {
        Info {
            blocks_size: 0,
            uncompressed_size: 0,
            count: 0,
            index_list_size: 0,
            check: CheckState::new(CHECK_BEST),
        }
    }

    /// `hash_append`.
    fn append(&mut self, unpadded_size: u64, uncompressed_size: u64) {
        self.blocks_size += vli_ceil4(unpadded_size);
        self.uncompressed_size += uncompressed_size;
        self.index_list_size +=
            u64::from(vli::size(unpadded_size)) + u64::from(vli::size(uncompressed_size));
        self.count += 1;

        // Differs from liblzma, without a difference to see: liblzma
        // hashes the two sizes as they are in memory, which this does in
        // little-endian order, the same for the Blocks and the Records.
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&unpadded_size.to_le_bytes());
        sizes[8..].copy_from_slice(&uncompressed_size.to_le_bytes());
        self.check.update(CHECK_BEST, &sizes);
    }
}

/// The sequence of `lzma_index_hash`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Block,
    Count,
    Unpadded,
    Uncompressed,
    PaddingInit,
    Padding,
    Crc32,
}

/// `lzma_index_hash`.
pub(crate) struct IndexHash {
    sequence: Sequence,
    /// Information collected while decoding the actual Blocks.
    blocks: Info,
    /// Information collected from the Index field.
    records: Info,
    /// Number of Records not fully decoded.
    remaining: u64,
    /// Unpadded Size currently being read from an Index Record.
    unpadded_size: u64,
    /// Uncompressed Size currently being read from an Index Record.
    uncompressed_size: u64,
    /// Position in variable-length integers when decoding them from the
    /// List of Records.
    pos: usize,
    /// CRC32 of the Index.
    crc32: u32,
}

impl IndexHash {
    /// `lzma_index_hash_init`.
    pub(crate) fn new() -> IndexHash {
        IndexHash {
            sequence: Sequence::Block,
            blocks: Info::new(),
            records: Info::new(),
            remaining: 0,
            unpadded_size: 0,
            uncompressed_size: 0,
            pos: 0,
            crc32: 0,
        }
    }

    /// `lzma_index_hash_size`.
    pub(crate) fn size(&self) -> u64 {
        // Get the size of the Index from ->blocks instead of ->records for
        // cases where application wants to know the Index Size before
        // decoding the Index.
        index_size(self.blocks.count, self.blocks.index_list_size)
    }

    /// `lzma_index_hash_append`.
    pub(crate) fn append(&mut self, unpadded_size: u64, uncompressed_size: u64) -> Ret {
        // Validate the arguments.
        if self.sequence != Sequence::Block
            || !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&unpadded_size)
            || uncompressed_size > VLI_MAX
        {
            return Ret::ProgError;
        }

        // Update the hash.
        self.blocks.append(unpadded_size, uncompressed_size);

        // Validate the properties of *info are still in allowed limits.
        if self.blocks.blocks_size > VLI_MAX
            || self.blocks.uncompressed_size > VLI_MAX
            || index_size(self.blocks.count, self.blocks.index_list_size) > BACKWARD_SIZE_MAX
            || index_stream_size(
                self.blocks.blocks_size,
                self.blocks.count,
                self.blocks.index_list_size,
            ) > VLI_MAX
        {
            return Ret::DataError;
        }
        Ret::Ok
    }

    /// `lzma_index_hash_decode`: reads the Index; `LZMA_STREAM_END` once it
    /// is read and agrees with the Blocks.
    pub(crate) fn decode(&mut self, input: &[u8], in_pos: &mut usize) -> Ret {
        // Catch zero input buffer here, because in contrast to Index
        // encoder and decoder functions, applications call this function
        // directly instead of via lzma_code(), which does the buffer
        // checking.
        if *in_pos >= input.len() {
            return Ret::BufError;
        }

        // NOTE: This function has many similarities to index_encode() and
        // index_decode() functions found from index_encoder.c and
        // index_decoder.c. See the comments especially in
        // index_encoder.c.
        let in_start = *in_pos;
        let mut ret = Ret::Ok;

        'out: while *in_pos < input.len() {
            match self.sequence {
                Sequence::Block => {
                    // Check the Index Indicator is present.
                    let byte = input[*in_pos];
                    *in_pos += 1;
                    if byte != INDEX_INDICATOR {
                        return Ret::DataError;
                    }
                    self.sequence = Sequence::Count;
                }
                Sequence::Count => {
                    ret = vli::decode(&mut self.remaining, &mut self.pos, input, in_pos);
                    if ret != Ret::StreamEnd {
                        break 'out;
                    }

                    // The count must match the count of the Blocks decoded.
                    if self.remaining != self.blocks.count {
                        return Ret::DataError;
                    }

                    ret = Ret::Ok;
                    self.pos = 0;

                    // Handle the special case when there are no Blocks.
                    self.sequence = if self.remaining == 0 {
                        Sequence::PaddingInit
                    } else {
                        Sequence::Unpadded
                    };
                }
                Sequence::Unpadded | Sequence::Uncompressed => {
                    let unpadded = self.sequence == Sequence::Unpadded;
                    let size = if unpadded {
                        &mut self.unpadded_size
                    } else {
                        &mut self.uncompressed_size
                    };
                    ret = vli::decode(size, &mut self.pos, input, in_pos);
                    if ret != Ret::StreamEnd {
                        break 'out;
                    }

                    ret = Ret::Ok;
                    self.pos = 0;

                    if unpadded {
                        if !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&self.unpadded_size) {
                            return Ret::DataError;
                        }
                        self.sequence = Sequence::Uncompressed;
                    } else {
                        // Update the hash.
                        self.records
                            .append(self.unpadded_size, self.uncompressed_size);

                        // Verify that we don't go over the known sizes.
                        // Note that this validation is simpler than the
                        // one used in lzma_index_hash_append(), because
                        // here we know that values in index_hash->blocks
                        // are already validated and we are fine as long as
                        // we don't exceed them in index_hash->records.
                        if self.blocks.blocks_size < self.records.blocks_size
                            || self.blocks.uncompressed_size < self.records.uncompressed_size
                            || self.blocks.index_list_size < self.records.index_list_size
                        {
                            return Ret::DataError;
                        }

                        // Check if this was the last Record.
                        self.remaining -= 1;
                        self.sequence = if self.remaining == 0 {
                            Sequence::PaddingInit
                        } else {
                            Sequence::Unpadded
                        };
                    }
                }
                Sequence::PaddingInit | Sequence::Padding => {
                    if self.sequence == Sequence::PaddingInit {
                        self.pos = (4u64.wrapping_sub(index_size_unpadded(
                            self.records.count,
                            self.records.index_list_size,
                        )) & 3) as usize;
                        self.sequence = Sequence::Padding;
                    }

                    if self.pos > 0 {
                        self.pos -= 1;
                        let byte = input[*in_pos];
                        *in_pos += 1;
                        if byte != 0x00 {
                            return Ret::DataError;
                        }
                        continue;
                    }

                    // Compare the sizes.
                    if self.blocks.blocks_size != self.records.blocks_size
                        || self.blocks.uncompressed_size != self.records.uncompressed_size
                        || self.blocks.index_list_size != self.records.index_list_size
                    {
                        return Ret::DataError;
                    }

                    // Finish the hashes and compare them.
                    self.blocks.check.finish(CHECK_BEST);
                    self.records.check.finish(CHECK_BEST);
                    let size = CHECK_BEST.size() as usize;
                    if self.blocks.check.buffer[..size] != self.records.check.buffer[..size] {
                        return Ret::DataError;
                    }

                    // Finish the CRC32 calculation.
                    self.crc32 = crc32(&input[in_start..*in_pos], self.crc32);

                    self.sequence = Sequence::Crc32;
                    return self.decode_crc32(input, in_pos);
                }
                Sequence::Crc32 => return self.decode_crc32(input, in_pos),
            }
        }

        // out:
        // Update the CRC32.
        //
        // Avoid null pointer + 0 (undefined behavior) in "in + in_start".
        // In such a case we had no input and thus in_used == 0.
        let in_used = *in_pos - in_start;
        if in_used > 0 {
            self.crc32 = crc32(&input[in_start..*in_pos], self.crc32);
        }
        ret
    }

    /// `SEQ_CRC32`: the Index's CRC32, against the one computed.
    fn decode_crc32(&mut self, input: &[u8], in_pos: &mut usize) -> Ret {
        loop {
            if *in_pos == input.len() {
                return Ret::Ok;
            }
            let byte = input[*in_pos];
            *in_pos += 1;
            if (self.crc32 >> (self.pos * 8)) & 0xFF != u32::from(byte) {
                return Ret::DataError;
            }
            self.pos += 1;
            if self.pos >= 4 {
                break;
            }
        }
        Ret::StreamEnd
    }
}
