//! Superblocks, the blocks of `ZSTD_c_targetCBlockSize`: port of
//! `compress/zstd_compress_superblock.c`.
//!
//! A block's sequences, once found, are cut into sub-blocks of about the
//! target size compressed, each a block of its own that a decoder can use
//! as soon as it has it. The tables are those of the whole block: the first
//! sub-block that can carries their descriptions, the others use them
//! again (`set_repeat`). What does not compress is stored raw.
//!
//! libzstd passes the sub-blocks' functions its `bmi2` flag, which changes
//! nothing in the port, and `longOffsets`, which only splits the offsets'
//! bits in two on 32-bit machines, with the same bits written; the port
//! leaves both out, and writes the sequences as libzstd does on 64-bit
//! machines (see `docs/porting.md`).

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::huf::HUF_SYMBOLVALUE_MAX;
use crate::zstd::common::mem::write_le32;
use crate::zstd::common::zstd_internal::{
    BlockType, DEFAULT_MAX_OFF, LL_BITS, LL_DEFAULT_NORM, LL_DEFAULT_NORM_LOG, LONGNBSEQ, MAX_LL,
    MAX_ML, MAX_OFF, MAX_SEQ, MINMATCH, ML_BITS, ML_DEFAULT_NORM, ML_DEFAULT_NORM_LOG,
    OF_DEFAULT_NORM, OF_DEFAULT_NORM_LOG, SymbolEncodingType, ZSTD_BLOCKHEADERSIZE,
};
use crate::zstd::compress::hist::{HIST_WKSP_SIZE_U32, hist_count_fast_wksp, hist_count_wksp};
use crate::zstd::compress::huf_compress::{
    HufCTable, huf_compress1x_using_ctable, huf_compress4x_using_ctable,
    huf_estimate_compressed_size,
};
use crate::zstd::compress::zstd_compress::{
    CCtxParams, EntropyCTablesMetadata, FseCTablesMetadata, HufCTablesMetadata,
    ZSTD_TARGETCBLOCKSIZE_MIN, zstd_build_block_entropy_stats, zstd_update_rep,
};
use crate::zstd::compress::zstd_compress_internal::{
    CompressedBlockState, EntropyCTables, FseCTables, HufCTables, SeqDef, SeqStore, SeqStoreView,
    zstd_get_sequence_length, zstd_no_compress_block,
};
use crate::zstd::compress::zstd_compress_literals::{
    zstd_compress_rle_literals_block, zstd_no_compress_literals,
};
use crate::zstd::compress::zstd_compress_sequences::{
    zstd_cross_entropy_cost, zstd_encode_sequences, zstd_fse_bit_cost,
};

/// `ZSTD_compressSubBlock_literal`: the literals section of a sub-block,
/// as `huf_metadata` says for the whole superblock: raw, one byte
/// repeated, or Huffman-compressed with its table, `huf_table`. With
/// `write_entropy`, a new table's description goes in front; otherwise the
/// table is used again (`set_repeat`). `entropy_written` tells whether the
/// literals went out compressed, the description with them.
///
/// The header's size is chosen before the compressed size is known, for a
/// description of up to 200 bytes, so it may be larger than needed; when
/// the compressed size does not fit it, the literals are stored raw, as
/// they are when they expand without a description to write.
///
/// Returns the section's size, or 0 when the literals do not compress into
/// `dst`.
fn zstd_compress_sub_block_literal(
    huf_table: &HufCTable,
    huf_metadata: &HufCTablesMetadata,
    literals: &[u8],
    dst: &mut [u8],
    write_entropy: bool,
    entropy_written: &mut bool,
) -> Result<usize> {
    let lit_size = literals.len();
    let header = if write_entropy { 200 } else { 0 };
    let lh_size =
        3 + usize::from(lit_size >= 1024 - header) + usize::from(lit_size >= (16 << 10) - header);
    let single_stream = lh_size == 3;
    let h_type = if write_entropy {
        huf_metadata.h_type
    } else {
        SymbolEncodingType::Repeat
    };

    *entropy_written = false;
    match huf_metadata.h_type {
        _ if lit_size == 0 => return zstd_no_compress_literals(dst, literals),
        SymbolEncodingType::Basic => return zstd_no_compress_literals(dst, literals),
        SymbolEncodingType::Rle => {
            // Differs from libzstd: libzstd writes the section, up to 4
            // bytes, without checking the room for it, and past the end
            // when there is too little; the sequences section after it
            // then finds less than its 4 bytes, and fails. The port fails
            // the same way without writing.
            if dst.len() < 4 {
                return error!(DstSizeTooSmall);
            }
            return Ok(zstd_compress_rle_literals_block(dst, literals));
        }
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {}
    }

    // The new table's description.
    let des_size = if write_entropy && huf_metadata.h_type == SymbolEncodingType::Compressed {
        huf_metadata.huf_des_size
    } else {
        0
    };
    // Differs from libzstd: libzstd writes the description without
    // checking the room for it, and past the end when the header and it
    // do not fit; the Huffman streams then get a room that wraps around,
    // their end before their start, and give 0, as they do when they do
    // not fit. The port gives 0 without writing.
    if lh_size + des_size > dst.len() {
        return Ok(0);
    }
    dst[lh_size..lh_size + des_size].copy_from_slice(&huf_metadata.huf_des_buffer[..des_size]);
    let mut op = lh_size + des_size;
    let mut c_lit_size = des_size;

    {
        // The flags change nothing in the port.
        let c_size = if single_stream {
            huf_compress1x_using_ctable(&mut dst[op..], literals, huf_table, 0)
        } else {
            huf_compress4x_using_ctable(&mut dst[op..], literals, huf_table, 0)
        };
        op += c_size;
        c_lit_size += c_size;
        if c_size == 0 {
            // They do not fit.
            return Ok(0);
        }
        // Expanded, without a description to write: raw.
        if !write_entropy && c_lit_size >= lit_size {
            return zstd_no_compress_literals(dst, literals);
        }
        // With one, they may expand, as long as the header still holds
        // their size.
        if lh_size < 3 + usize::from(c_lit_size >= 1024) + usize::from(c_lit_size >= 16 << 10) {
            debug_assert!(c_lit_size > lit_size);
            return zstd_no_compress_literals(dst, literals);
        }
    }

    // The header.
    let (lit, c_lit, h) = (lit_size as u32, c_lit_size as u32, h_type as u32);
    match lh_size {
        // 2 - 2 - 10 - 10
        3 => {
            let lhc = h + (u32::from(!single_stream) << 2) + (lit << 4) + (c_lit << 14);
            dst[..3].copy_from_slice(&lhc.to_le_bytes()[..3]);
        }
        // 2 - 2 - 14 - 14
        4 => write_le32(dst, 0, h + (2 << 2) + (lit << 4) + (c_lit << 18)),
        // 2 - 2 - 18 - 18
        _ => {
            write_le32(dst, 0, h + (3 << 2) + (lit << 4) + (c_lit << 22));
            dst[4] = (c_lit >> 10) as u8;
        }
    }
    *entropy_written = true;
    Ok(op)
}

/// `ZSTD_seqDecompressedSize`: the bytes the `nb_seqs` sequences of `seqs`
/// from `start` decode to, with `lit_size` literals: those of the
/// sequences, and for the last sub-block the block's last literals too.
fn zstd_seq_decompressed_size(
    seqs: &SeqStoreView<'_>,
    start: usize,
    nb_seqs: usize,
    lit_size: usize,
    last_sub_block: bool,
) -> usize {
    let mut match_length_sum = 0;
    let mut lit_length_sum = 0;
    for n in start..start + nb_seqs {
        let seq_len = zstd_get_sequence_length(seqs, n);
        lit_length_sum += seq_len.lit_length as usize;
        match_length_sum += seq_len.match_length as usize;
    }
    if last_sub_block {
        debug_assert!(lit_length_sum <= lit_size);
    } else {
        debug_assert!(lit_length_sum == lit_size);
    }
    match_length_sum + lit_size
}

/// `ZSTD_compressSubBlock_sequences`: the sequences section of a
/// sub-block, the codes encoded with the superblock's tables. With
/// `write_entropy`, the section says how each kind is encoded, with the
/// descriptions of the new tables; otherwise each is used again
/// (`set_repeat`). `entropy_written` tells whether that went out.
///
/// Returns the section's size, or 0 when the block should be stored raw,
/// for the decoders of zstd 1.4.0 and earlier.
#[allow(clippy::too_many_arguments)]
fn zstd_compress_sub_block_sequences(
    fse_tables: &FseCTables,
    fse_metadata: &FseCTablesMetadata,
    sequences: &[SeqDef],
    ll_code: &[u8],
    ml_code: &[u8],
    of_code: &[u8],
    dst: &mut [u8],
    write_entropy: bool,
    entropy_written: &mut bool,
) -> Result<usize> {
    let nb_seq = sequences.len();
    let oend = dst.len();
    let mut op = 0;

    *entropy_written = false;
    // The sequences' header.
    if oend - op < 3 /* the largest nbSeq */ + 1
    /* seqHead */
    {
        return error!(DstSizeTooSmall);
    }
    if nb_seq < 128 {
        dst[op] = nb_seq as u8;
        op += 1;
    } else if nb_seq < LONGNBSEQ {
        dst[op] = ((nb_seq >> 8) + 0x80) as u8;
        dst[op + 1] = nb_seq as u8;
        op += 2;
    } else {
        dst[op] = 0xFF;
        crate::zstd::common::mem::write_le16(dst, op + 1, (nb_seq - LONGNBSEQ) as u16);
        op += 3;
    }
    if nb_seq == 0 {
        return Ok(op);
    }

    // seqHead: how each kind of code is encoded.
    let seq_head = op;
    op += 1;
    if write_entropy {
        dst[seq_head] = (((fse_metadata.ll_type as u32) << 6)
            + ((fse_metadata.of_type as u32) << 4)
            + ((fse_metadata.ml_type as u32) << 2)) as u8;
        let size = fse_metadata.fse_tables_size;
        // Differs from libzstd: libzstd writes the descriptions without
        // checking the room for them, and past the end when they do not
        // fit; the bitstream then gets a room that wraps around, its end
        // before its start, and fails with dstSize_tooSmall, as it does
        // when it does not fit. The port fails without writing.
        if size > oend - op {
            return error!(DstSizeTooSmall);
        }
        dst[op..op + size].copy_from_slice(&fse_metadata.fse_tables_buffer[..size]);
        op += size;
    } else {
        let repeat = SymbolEncodingType::Repeat as u32;
        dst[seq_head] = ((repeat << 6) + (repeat << 4) + (repeat << 2)) as u8;
    }

    {
        let bitstream_size = zstd_encode_sequences(
            &mut dst[op..],
            &fse_tables.matchlength_ctable,
            ml_code,
            &fse_tables.offcode_ctable,
            of_code,
            &fse_tables.litlength_ctable,
            ll_code,
            sequences,
        )?;
        op += bitstream_size;
        // zstd 1.3.4 and earlier report corruption when FSE_readNCount()
        // gets fewer than 4 bytes (fixed in zstd pull request 1146). That
        // happens when the last new table's description is 2 bytes and the
        // bitstream 1 byte. In this very rare case the block is stored raw.
        if write_entropy
            && fse_metadata.last_count_size != 0
            && fse_metadata.last_count_size + bitstream_size < 4
        {
            // A description of 2 bytes or more and a bitstream of 1 or
            // more: 3.
            debug_assert!(fse_metadata.last_count_size + bitstream_size == 3);
            return Ok(0);
        }
    }

    // zstd 1.4.0 and earlier report an error when the sequences section's
    // body is less than 3 bytes (fixed in zstd pull request 1664). That
    // happens when the tables are used again after a block that encoded
    // them as one symbol: then the block is stored raw.
    if op - seq_head < 4 {
        return Ok(0);
    }

    *entropy_written = true;
    Ok(op)
}

/// `ZSTD_compressSubBlock`: one sub-block, its header included, into
/// `dst`: the literals and the sequences of `sequences`, with their codes,
/// encoded with the superblock's tables, `entropy`. `write_lit_entropy`
/// and `write_seq_entropy` ask for the tables' descriptions, and
/// `lit_entropy_written` and `seq_entropy_written` tell whether they went
/// out.
///
/// Returns the sub-block's size, or 0 when it does not compress.
#[allow(clippy::too_many_arguments)]
fn zstd_compress_sub_block(
    entropy: &EntropyCTables,
    entropy_metadata: &EntropyCTablesMetadata,
    sequences: &[SeqDef],
    literals: &[u8],
    ll_code: &[u8],
    ml_code: &[u8],
    of_code: &[u8],
    dst: &mut [u8],
    write_lit_entropy: bool,
    write_seq_entropy: bool,
    lit_entropy_written: &mut bool,
    seq_entropy_written: &mut bool,
    last_block: bool,
) -> Result<usize> {
    let mut op = ZSTD_BLOCKHEADERSIZE;
    if dst.len() < op {
        // Not in practice: the first sub-block has 6 bytes or more
        // (ZSTD_compress_frameChunk), and the others 8 or more, as the
        // bitstream of the one before stops that far from its end.
        // Differs from libzstd: libzstd would start the literals after the
        // block's header though it does not fit, in a room that wraps
        // around. Raw literals, or one byte repeated, would then be written
        // past the end, and the sequences section after them find less
        // than its 4 bytes and fail; Huffman streams would give 0 (see
        // zstd_compress_sub_block_literal). The port does the same without
        // writing.
        *lit_entropy_written = false;
        *seq_entropy_written = false;
        let huf = &entropy_metadata.huf;
        return if literals.is_empty()
            || matches!(
                huf.h_type,
                SymbolEncodingType::Basic | SymbolEncodingType::Rle
            ) {
            error!(DstSizeTooSmall)
        } else {
            Ok(0)
        };
    }
    {
        let c_lit_size = zstd_compress_sub_block_literal(
            &entropy.huf.ctable,
            &entropy_metadata.huf,
            literals,
            &mut dst[op..],
            write_lit_entropy,
            lit_entropy_written,
        )?;
        if c_lit_size == 0 {
            return Ok(0);
        }
        op += c_lit_size;
    }
    {
        let c_seq_size = zstd_compress_sub_block_sequences(
            &entropy.fse,
            &entropy_metadata.fse,
            sequences,
            ll_code,
            ml_code,
            of_code,
            &mut dst[op..],
            write_seq_entropy,
            seq_entropy_written,
        )?;
        if c_seq_size == 0 {
            return Ok(0);
        }
        op += c_seq_size;
    }
    // The block header.
    {
        let c_size = op - ZSTD_BLOCKHEADERSIZE;
        let c_block_header24 =
            u32::from(last_block) + ((BlockType::Compressed as u32) << 1) + ((c_size as u32) << 3);
        dst[..3].copy_from_slice(&c_block_header24.to_le_bytes()[..3]);
    }
    Ok(op)
}

/// `ZSTD_estimateSubBlockSize_literal`: the size of the literals section
/// of `literals`, with a header of 3 bytes, and the table's description if
/// `write_entropy`.
fn zstd_estimate_sub_block_size_literal(
    literals: &[u8],
    huf: &HufCTables,
    huf_metadata: &HufCTablesMetadata,
    write_entropy: bool,
) -> usize {
    let lit_size = literals.len();
    // A header of 3 bytes, whatever the size.
    let literal_section_header_size = 3;
    match huf_metadata.h_type {
        SymbolEncodingType::Basic => lit_size,
        SymbolEncodingType::Rle => 1,
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            let mut count = [0u32; HUF_SYMBOLVALUE_MAX as usize + 1];
            let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
            let mut max_symbol_value = HUF_SYMBOLVALUE_MAX;
            if hist_count_wksp(&mut count, &mut max_symbol_value, literals, &mut hist_wksp).is_err()
            {
                return lit_size;
            }
            let mut c_lit_size_estimate =
                huf_estimate_compressed_size(&huf.ctable, &count, max_symbol_value);
            if write_entropy {
                c_lit_size_estimate += huf_metadata.huf_des_size;
            }
            c_lit_size_estimate + literal_section_header_size
        }
    }
}

/// `ZSTD_estimateSubBlockSize_symbolType`: the bytes of one kind of code,
/// `code_table`, with its encoding and table, and the codes' extra bits
/// (for offsets, the code itself).
#[allow(clippy::too_many_arguments)]
fn zstd_estimate_sub_block_size_symbol_type(
    encoding_type: SymbolEncodingType,
    code_table: &[u8],
    max_code: u32,
    fse_ctable: &[u32],
    additional_bits: Option<&[u8]>,
    default_norm: &[i16],
    default_norm_log: u32,
    default_max: u32,
) -> usize {
    let nb_seq = code_table.len();
    let mut count = [0u32; MAX_SEQ as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let mut max = max_code;

    // Cannot fail: the codes are trusted to be at most `max`.
    let _ = hist_count_fast_wksp(&mut count, &mut max, code_table, &mut hist_wksp);
    let size_in_bits = match encoding_type {
        SymbolEncodingType::Basic => {
            // Chosen, so valid.
            debug_assert!(max <= default_max);
            if max <= default_max {
                Ok(zstd_cross_entropy_cost(
                    default_norm,
                    default_norm_log,
                    &count,
                    max,
                ))
            } else {
                error!(Generic)
            }
        }
        SymbolEncodingType::Rle => Ok(0),
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            zstd_fse_bit_cost(fse_ctable, &count, max)
        }
    };
    let Ok(mut size_in_bits) = size_in_bits else {
        return nb_seq * 10;
    };
    for &code in code_table {
        size_in_bits += match additional_bits {
            Some(bits) => usize::from(bits[usize::from(code)]),
            None => usize::from(code),
        };
    }
    size_in_bits / 8
}

/// `ZSTD_estimateSubBlockSize_sequences`: the size of the sequences
/// section of these codes, with a header of 3 bytes, and the tables'
/// descriptions if `write_entropy`.
fn zstd_estimate_sub_block_size_sequences(
    of_code_table: &[u8],
    ll_code_table: &[u8],
    ml_code_table: &[u8],
    fse_tables: &FseCTables,
    fse_metadata: &FseCTablesMetadata,
    write_entropy: bool,
) -> usize {
    // A header of 3 bytes, whatever the number of sequences.
    let sequences_section_header_size = 3;
    let mut c_seq_size_estimate = 0;
    if of_code_table.is_empty() {
        return sequences_section_header_size;
    }
    c_seq_size_estimate += zstd_estimate_sub_block_size_symbol_type(
        fse_metadata.of_type,
        of_code_table,
        MAX_OFF,
        &fse_tables.offcode_ctable,
        None,
        &OF_DEFAULT_NORM,
        OF_DEFAULT_NORM_LOG,
        DEFAULT_MAX_OFF,
    );
    c_seq_size_estimate += zstd_estimate_sub_block_size_symbol_type(
        fse_metadata.ll_type,
        ll_code_table,
        MAX_LL,
        &fse_tables.litlength_ctable,
        Some(&LL_BITS),
        &LL_DEFAULT_NORM,
        LL_DEFAULT_NORM_LOG,
        MAX_LL,
    );
    c_seq_size_estimate += zstd_estimate_sub_block_size_symbol_type(
        fse_metadata.ml_type,
        ml_code_table,
        MAX_ML,
        &fse_tables.matchlength_ctable,
        Some(&ML_BITS),
        &ML_DEFAULT_NORM,
        ML_DEFAULT_NORM_LOG,
        MAX_ML,
    );
    if write_entropy {
        c_seq_size_estimate += fse_metadata.fse_tables_size;
    }
    c_seq_size_estimate + sequences_section_header_size
}

/// `EstimatedBlockSize`
#[derive(Clone, Copy, Debug)]
struct EstimatedBlockSize {
    /// The literals section.
    est_lit_size: usize,
    /// The whole block, its header included.
    est_block_size: usize,
}

/// `ZSTD_estimateSubBlockSize`: the size of a block of `literals` and of
/// sequences with these codes, encoded with `entropy` as `entropy_metadata`
/// says, its header included.
#[allow(clippy::too_many_arguments)]
fn zstd_estimate_sub_block_size(
    literals: &[u8],
    of_code_table: &[u8],
    ll_code_table: &[u8],
    ml_code_table: &[u8],
    entropy: &EntropyCTables,
    entropy_metadata: &EntropyCTablesMetadata,
    write_lit_entropy: bool,
    write_seq_entropy: bool,
) -> EstimatedBlockSize {
    let est_lit_size = zstd_estimate_sub_block_size_literal(
        literals,
        &entropy.huf,
        &entropy_metadata.huf,
        write_lit_entropy,
    );
    let est_block_size = zstd_estimate_sub_block_size_sequences(
        of_code_table,
        ll_code_table,
        ml_code_table,
        &entropy.fse,
        &entropy_metadata.fse,
        write_seq_entropy,
    ) + est_lit_size
        + ZSTD_BLOCKHEADERSIZE;
    EstimatedBlockSize {
        est_lit_size,
        est_block_size,
    }
}

/// `ZSTD_needSequenceEntropyTables`: whether the sequences need a table
/// described in the block: a new one, or one symbol.
fn zstd_need_sequence_entropy_tables(fse_metadata: &FseCTablesMetadata) -> bool {
    [
        fse_metadata.ll_type,
        fse_metadata.ml_type,
        fse_metadata.of_type,
    ]
    .iter()
    .any(|&encoding_type| {
        matches!(
            encoding_type,
            SymbolEncodingType::Compressed | SymbolEncodingType::Rle
        )
    })
}

/// `countLiterals`: the literals of the `seq_count` sequences of `seqs`
/// from `start`.
fn count_literals(seqs: &SeqStoreView<'_>, start: usize, seq_count: usize) -> usize {
    (start..start + seq_count)
        .map(|n| zstd_get_sequence_length(seqs, n).lit_length as usize)
        .sum()
}

/// `BYTESCALE`: the costs' fixed point, in 256ths of a byte.
const BYTESCALE: usize = 256;

/// `sizeBlockSequences`: how many of `sequences` the next sub-block takes:
/// at least one, and more while their estimated cost, from the average
/// costs of a literal and of a sequence, stays within `target_budget`
/// (with a generous room for the tables of the first sub-block); past it,
/// more still while they are not estimated to compress.
///
/// The lengths are the sequences' 16 bits, without the long length's
/// 0x10000, as in libzstd.
fn size_block_sequences(
    sequences: &[SeqDef],
    target_budget: usize,
    avg_lit_cost: usize,
    avg_seq_cost: usize,
    first_sub_block: bool,
) -> usize {
    // The tables: a generous estimate.
    let header_size = usize::from(first_sub_block) * 120 * BYTESCALE;
    let mut budget = header_size;

    // The first sequence: at least one.
    budget += usize::from(sequences[0].lit_length) * avg_lit_cost + avg_seq_cost;
    if budget > target_budget {
        return 1;
    }
    let mut in_size = usize::from(sequences[0].lit_length)
        + (usize::from(sequences[0].ml_base) + MINMATCH as usize);

    for (n, seq) in sequences.iter().enumerate().skip(1) {
        let current_cost = usize::from(seq.lit_length) * avg_lit_cost + avg_seq_cost;
        budget += current_cost;
        in_size += usize::from(seq.lit_length) + (usize::from(seq.ml_base) + MINMATCH as usize);
        // Stop at the budget, but go on while the sub-block is not
        // estimated to compress.
        if budget > target_budget && budget < in_size * BYTESCALE {
            return n;
        }
    }
    sequences.len()
}

/// `ZSTD_compressSubBlock_multi`: the block `src`, its sequences and
/// literals `seqs` (the whole store), as sub-blocks into `dst`, the tables
/// in `next_cblock`, as `entropy_metadata` says: compressed, the tables'
/// descriptions in the first that can carry them, and what is left at the
/// end raw. The repeat offsets in `next_cblock` follow the sequences
/// written, from those of `prev_cblock`.
///
/// Returns the size of the sub-blocks, or 0 when the block should be one
/// raw block: when it is not estimated to compress, or the tables could
/// not go out.
#[allow(clippy::too_many_arguments)]
fn zstd_compress_sub_block_multi(
    seqs: &SeqStoreView<'_>,
    prev_cblock: &CompressedBlockState,
    next_cblock: &mut CompressedBlockState,
    entropy_metadata: &EntropyCTablesMetadata,
    target_cblock_size: usize,
    dst: &mut [u8],
    src: &[u8],
    last_block: bool,
) -> Result<usize> {
    let send = seqs.sequences.len();
    // Where the sub-blocks are in the sequences, the literals, the input
    // and the output.
    let mut sp = 0;
    let nb_seqs = send;
    let lend = seqs.literals.len();
    let mut lp = 0;
    let nb_literals = lend;
    let iend = src.len();
    let mut ip = 0;
    let mut op = 0;
    // At least the smallest target, to limit the side effects.
    let min_target = ZSTD_TARGETCBLOCKSIZE_MIN as usize;
    let target_cblock_size = min_target.max(target_cblock_size);
    let mut write_lit_entropy = entropy_metadata.huf.h_type == SymbolEncodingType::Compressed;
    let mut write_seq_entropy = true;

    // An estimate for the whole block first, if it has sequences.
    let estimate = (nb_seqs > 0).then(|| {
        zstd_estimate_sub_block_size(
            seqs.literals,
            seqs.of_code,
            seqs.ll_code,
            seqs.ml_code,
            &next_cblock.entropy,
            entropy_metadata,
            write_lit_entropy,
            write_seq_entropy,
        )
    });
    if let Some(ebs) = estimate {
        // The average costs, in 256ths of a byte.
        let avg_lit_cost = (ebs.est_lit_size * BYTESCALE)
            .checked_div(nb_literals)
            .unwrap_or(BYTESCALE);
        let avg_seq_cost = (ebs.est_block_size - ebs.est_lit_size) * BYTESCALE / nb_seqs;
        let nb_sub_blocks =
            ((ebs.est_block_size + target_cblock_size / 2) / target_cblock_size).max(1);
        let avg_block_budget = ebs.est_block_size * BYTESCALE / nb_sub_blocks;
        // Never raised, in libzstd either.
        let mut block_budget_supp = 0;
        // A block not estimated to compress becomes one raw block.
        if ebs.est_block_size > src.len() {
            return Ok(0);
        }

        // The sub-blocks.
        debug_assert!(nb_sub_blocks > 0);
        for n in 0..nb_sub_blocks - 1 {
            // The sequences of the sub-block.
            let seq_count = size_block_sequences(
                &seqs.sequences[sp..],
                avg_block_budget + block_budget_supp,
                avg_lit_cost,
                avg_seq_cost,
                n == 0,
            );
            debug_assert!(seq_count <= send - sp);
            // Those to the last are the last sub-block's (a
            // simplification).
            if sp + seq_count == send {
                break;
            }
            debug_assert!(seq_count > 0);
            let mut lit_entropy_written = false;
            let mut seq_entropy_written = false;
            let lit_size = count_literals(seqs, sp, seq_count);
            let decompressed_size =
                zstd_seq_decompressed_size(seqs, sp, seq_count, lit_size, false);
            let seq_end = sp + seq_count;
            let c_size = zstd_compress_sub_block(
                &next_cblock.entropy,
                entropy_metadata,
                &seqs.sequences[sp..seq_end],
                &seqs.literals[lp..lp + lit_size],
                &seqs.ll_code[sp..seq_end],
                &seqs.ml_code[sp..seq_end],
                &seqs.of_code[sp..seq_end],
                &mut dst[op..],
                write_lit_entropy,
                write_seq_entropy,
                &mut lit_entropy_written,
                &mut seq_entropy_written,
                false,
            )?;

            // Kept if it compresses; otherwise its sequences join the next
            // sub-block's.
            if c_size > 0 && c_size < decompressed_size {
                debug_assert!(ip + decompressed_size <= iend);
                ip += decompressed_size;
                lp += lit_size;
                op += c_size;
                // The tables go out once.
                if lit_entropy_written {
                    write_lit_entropy = false;
                }
                if seq_entropy_written {
                    write_seq_entropy = false;
                }
                sp = seq_end;
                block_budget_supp = 0;
            }
        }
    }

    // The last sub-block, with the block's last literals.
    {
        let mut lit_entropy_written = false;
        let mut seq_entropy_written = false;
        let lit_size = lend - lp;
        let seq_count = send - sp;
        let decompressed_size = zstd_seq_decompressed_size(seqs, sp, seq_count, lit_size, true);
        let c_size = zstd_compress_sub_block(
            &next_cblock.entropy,
            entropy_metadata,
            &seqs.sequences[sp..],
            &seqs.literals[lp..],
            &seqs.ll_code[sp..],
            &seqs.ml_code[sp..],
            &seqs.of_code[sp..],
            &mut dst[op..],
            write_lit_entropy,
            write_seq_entropy,
            &mut lit_entropy_written,
            &mut seq_entropy_written,
            last_block,
        )?;
        if c_size > 0 && c_size < decompressed_size {
            debug_assert!(ip + decompressed_size <= iend);
            ip += decompressed_size;
            lp += lit_size;
            op += c_size;
            if lit_entropy_written {
                write_lit_entropy = false;
            }
            if seq_entropy_written {
                write_seq_entropy = false;
            }
            sp += seq_count;
        }
    }
    debug_assert!(lp <= lend);

    if write_lit_entropy {
        // The literals' table never went out: the next block has the
        // previous one.
        next_cblock.entropy.huf.clone_from(&prev_cblock.entropy.huf);
    }
    if write_seq_entropy && zstd_need_sequence_entropy_tables(&entropy_metadata.fse) {
        // The sequences' tables never went out, though the sub-blocks
        // need them: one raw block instead.
        return Ok(0);
    }

    if ip < iend {
        // What is left goes out raw.
        let c_size = zstd_no_compress_block(&mut dst[op..], &src[ip..], last_block)?;
        debug_assert!(c_size != 0);
        op += c_size;
        // The repeat offsets again: the sequences after `sp` did not go
        // out.
        if sp < send {
            let mut rep = prev_cblock.rep;
            for n in 0..sp {
                let ll0 = zstd_get_sequence_length(seqs, n).lit_length == 0;
                zstd_update_rep(&mut rep, seqs.sequences[n].off_base, u32::from(ll0));
            }
            next_cblock.rep = rep;
        }
    }

    Ok(op)
}

/// `ZSTD_compressSuperBlock`: the block `src`, its sequences and literals
/// found into `seq_store`, as sub-blocks of about the context's target size
/// (`ZSTD_c_targetCBlockSize`), each with its header, into `dst`; the
/// tables, built from `prev_cblock`'s as for one block, and the repeat
/// offsets into `next_cblock`.
///
/// Returns their size, or 0 when the block should be one raw block. Their
/// size is not bound by `ZSTD_compressBound`: see
/// `ZSTD_compressBlock_targetCBlockSize_body`.
///
/// Differs from libzstd: libzstd takes the context; the port takes the
/// parts of it the superblocks use.
pub(crate) fn zstd_compress_super_block(
    seq_store: &mut SeqStore,
    prev_cblock: &CompressedBlockState,
    next_cblock: &mut CompressedBlockState,
    params: &CCtxParams,
    dst: &mut [u8],
    src: &[u8],
    last_block: bool,
) -> Result<usize> {
    let whole = seq_store.whole();
    let mut seqs = seq_store.view(&whole);
    let entropy_metadata = zstd_build_block_entropy_stats(
        &mut seqs,
        &prev_cblock.entropy,
        &mut next_cblock.entropy,
        params,
    )?;
    zstd_compress_sub_block_multi(
        &seqs,
        prev_cblock,
        next_cblock,
        &entropy_metadata,
        params.target_cblock_size,
        dst,
        src,
        last_block,
    )
}
