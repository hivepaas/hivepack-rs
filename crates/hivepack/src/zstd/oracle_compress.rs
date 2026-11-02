//! Comparison of the encoder's entropy coding with libzstd's: histograms,
//! FSE and Huffman tables, their descriptions, the streams written with
//! them, and whole blocks entropy-coded from their sequences, with the
//! tables kept from block to block. `tools/zstd-oracle` answers the
//! requests (see its comment for the commands); [`answer`] gives the
//! port's answers in the same format.
//!
//! As for the decoder, the tests compare thousands of generated requests
//! with libzstd live where the oracle is built, and replay recorded answers
//! everywhere, from `testdata/oracle/compress.txt`. `cargo test -p
//! hivepack::zstd record_compress_answers -- --ignored` rewrites it.
//!
//! The oracle answers whole tables, with the cells a function leaves alone
//! still holding a filler, so the port must write exactly the cells
//! libzstd writes: libzstd keeps its tables from block to block, and reads
//! old cells back.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::zstd::common::bitstream::BitCStream;
use crate::zstd::common::error_private::ErrorCode;
use crate::zstd::common::fse::{
    FseCState, fse_bit_cost, fse_blockbound, fse_ctable_size_u32, fse_get_max_nb_bits,
};
use crate::zstd::compress::fse_compress::{
    fse_build_ctable_rle, fse_build_ctable_wksp, fse_compress_using_ctable, fse_ncount_write_bound,
    fse_normalize_count, fse_optimal_table_log, fse_optimal_table_log_internal, fse_write_ncount,
};
use crate::zstd::compress::hist::{
    HIST_WKSP_SIZE_U32, hist_count_fast_wksp, hist_count_simple, hist_count_wksp,
};
use crate::zstd::compress::huf_compress::{
    HUF_CTABLE_SIZE, HufCTable, HufRepeat, huf_build_ctable_wksp, huf_compress_bound,
    huf_compress1x_repeat, huf_compress4x_repeat, huf_optimal_table_log, huf_read_ctable,
    huf_read_ctable_header, huf_write_ctable_wksp,
};
use crate::zstd::compress::zstd_cdict::CDict;
use crate::zstd::compress::zstd_compress::{
    CCtx, CParameter, CParameterKind, EndDirective, SequenceFormat, zstd_compress_bound,
    zstd_entropy_compress_seq_store, zstd_level_ported,
};
use crate::zstd::compress::zstd_compress_internal::{
    DictAttachPref, EntropyCTables, FseRepeat, LongLengthType, ParamSwitch, SeqDef, SeqStore,
    Strategy, zstd_literals_compression_is_disabled,
};
use crate::zstd::decompress::zstd_ddict::DictContentType;
use crate::zstd::decompress::zstd_decompress::{InBuffer, OutBuffer, ResetDirective};
use crate::zstd::decompress::zstd_decompress_internal::Format;
use crate::zstd::oracle::{
    Oracle, Rng, failed, fnv64, hex, list, mutate, recorded_form, repository, unhex, unlist,
};
use crate::zstd::oracle_sequences::SequenceSteps;
use std::sync::Arc;

/// The fillers the oracle starts its tables with.
const FILLER_WORD: u32 = 0xdead_beef;
const FILLER_NORM: i16 = 0x7777;
const FILLER_COUNT: u32 = 0xaaaa_aaaa;
const FILLER_ELT: u64 = (FILLER_WORD as u64) << 32 | FILLER_WORD as u64;

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/compress.txt")
}

fn number<T: std::str::FromStr>(text: &str) -> T {
    text.parse()
        .unwrap_or_else(|_| panic!("a number, not {text:.40}"))
}

fn counts(text: &str) -> Vec<u32> {
    unlist(text).into_iter().map(|c| c as u32).collect()
}

fn norms(text: &str) -> Vec<i16> {
    unlist(text).into_iter().map(|c| c as i16).collect()
}

/// A Huffman table as the oracle writes it: little-endian words in hex.
fn table_hex(table: &HufCTable) -> String {
    let bytes: Vec<u8> = table.iter().flat_map(|w| w.to_le_bytes()).collect();
    hex(&bytes)
}

/// A Huffman table up to its largest symbol, as `hufcompress` answers it.
fn used_table_hex(table: &HufCTable) -> String {
    let used = usize::from(huf_read_ctable_header(table).max_symbol_value) + 2;
    let bytes: Vec<u8> = table[..used].iter().flat_map(|w| w.to_le_bytes()).collect();
    hex(&bytes)
}

/// A Huffman table from its words, the ones left out being filler.
fn table_unhex(text: &str) -> Box<HufCTable> {
    let bytes = unhex(text);
    let mut table = Box::new([FILLER_ELT; HUF_CTABLE_SIZE]);
    for (word, chunk) in table.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    table
}

thread_local! {
    /// The context `compress` uses again and again, as the oracle does.
    static CCTX: RefCell<CCtx> = RefCell::new(CCtx::new());

    /// The tables of the block before and of the next one, kept from
    /// request to request as the oracle keeps them, and which is which.
    static SEQ_ENTROPY: RefCell<([Box<EntropyCTables>; 2], usize)> = RefCell::new((
        [EntropyCTables::filled(FILLER_WORD), EntropyCTables::filled(FILLER_WORD)],
        0,
    ));
}

/// The tables as the oracle hashes them: the FSE words, then the Huffman
/// elements up to the table's largest symbol, little-endian.
fn entropy_digest(entropy: &EntropyCTables) -> u64 {
    let mut bytes = Vec::new();
    for table in [
        &entropy.fse.offcode_ctable[..],
        &entropy.fse.matchlength_ctable[..],
        &entropy.fse.litlength_ctable[..],
    ] {
        bytes.extend(table.iter().flat_map(|w| w.to_le_bytes()));
    }
    let used = usize::from(huf_read_ctable_header(&entropy.huf.ctable).max_symbol_value) + 2;
    bytes.extend(
        entropy.huf.ctable[..used]
            .iter()
            .flat_map(|w| w.to_le_bytes()),
    );
    fnv64(&bytes)
}

/// The port's answer to `seqblock`.
fn seq_block(
    strategy: &str,
    literal_mode: &str,
    target_length: &str,
    dst_capacity: &str,
    literals: &str,
    sequences: &str,
) -> String {
    let literals = unhex(literals);
    let triples = unlist(sequences);
    let mut store = SeqStore::with_literals(&literals, triples.len() / 3);
    let mut block_size = literals.len();
    for (i, triple) in triples.chunks(3).enumerate() {
        let (off_base, lit_length, match_length) = (triple[0], triple[1], triple[2]);
        let ml_base = match_length - 3;
        if lit_length > 0xFFFF || ml_base > 0xFFFF {
            store.long_length_type = if lit_length > 0xFFFF {
                LongLengthType::LiteralLength
            } else {
                LongLengthType::MatchLength
            };
            store.long_length_pos = i as u32;
        }
        store.sequences.push(SeqDef {
            off_base: off_base as u32,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
        block_size += match_length as usize;
    }
    let strategy = Strategy::from_number(number(strategy)).expect("a strategy");
    let literal_mode = match literal_mode {
        "1" => ParamSwitch::Enable,
        "2" => ParamSwitch::Disable,
        _ => ParamSwitch::Auto,
    };
    let disable =
        zstd_literals_compression_is_disabled(literal_mode, strategy, number(target_length));
    let mut dst = vec![0u8; number(dst_capacity)];
    SEQ_ENTROPY.with(|state| {
        let (tables, prev) = &mut *state.borrow_mut();
        let (first, second) = tables.split_at_mut(1);
        let (prev_entropy, next_entropy) = if *prev == 0 {
            (&first[0], &mut second[0])
        } else {
            (&second[0], &mut first[0])
        };
        let result = zstd_entropy_compress_seq_store(
            &mut store,
            prev_entropy,
            next_entropy,
            strategy,
            disable,
            &mut dst,
            block_size,
            false,
        );
        let size = match result {
            Ok(size) => size,
            Err(error) => return failed(error),
        };
        // As ZSTD_compressBlock_internal does.
        if size > 1 {
            *prev = 1 - *prev;
        }
        let entropy = &mut tables[*prev];
        if entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
            entropy.fse.offcode_repeat_mode = FseRepeat::Check;
        }
        format!(
            "ok {size} {} {},{},{},{} {:016x}",
            hex(&dst[..size]),
            entropy.huf.repeat_mode as i32,
            entropy.fse.offcode_repeat_mode as i32,
            entropy.fse.matchlength_repeat_mode as i32,
            entropy.fse.litlength_repeat_mode as i32,
            entropy_digest(entropy)
        )
    })
}

/// The port's answer to one of the encoder's requests.
pub(crate) fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["hist", mode, max_sv, src] => {
            let src = unhex(src);
            let mut count = [FILLER_COUNT; 256];
            let mut max_sv: u32 = number(max_sv);
            let mut wksp = [0u32; HIST_WKSP_SIZE_U32];
            let result = match mode {
                "wksp" => hist_count_wksp(&mut count, &mut max_sv, &src, &mut wksp),
                "simple" => Ok(hist_count_simple(&mut count, &mut max_sv, &src) as usize),
                _ => hist_count_fast_wksp(&mut count, &mut max_sv, &src, &mut wksp),
            };
            match result {
                Ok(largest) => format!("ok {largest} {max_sv} {}", list(count)),
                Err(error) => failed(error),
            }
        }
        ["fseoptlog", max_table_log, src_size, max_sv, minus] => format!(
            "ok {}",
            fse_optimal_table_log_internal(
                number(max_table_log),
                number(src_size),
                number(max_sv),
                number(minus)
            )
        ),
        ["fsenorm", table_log, use_low_prob_count, count] => {
            let count = counts(count);
            let total: usize = count.iter().map(|&c| c as usize).sum();
            let mut norm = [FILLER_NORM; 256];
            match fse_normalize_count(
                &mut norm,
                number(table_log),
                &count,
                total,
                count.len() as u32 - 1,
                use_low_prob_count == "1",
            ) {
                Ok(log) => format!("ok {log} {}", list(&norm[..count.len()])),
                Err(error) => failed(error),
            }
        }
        ["fsencount", buffer_size, max_sv, table_log, norm] => {
            let mut buffer = vec![0u8; number(buffer_size)];
            match fse_write_ncount(&mut buffer, &norms(norm), number(max_sv), number(table_log)) {
                Ok(size) => format!("ok {}", hex(&buffer[..size])),
                Err(error) => failed(error),
            }
        }
        ["fsectable", max_sv, table_log, norm] => {
            let max_sv: u32 = number(max_sv);
            let table_log: u32 = number(table_log);
            let mut ct = vec![FILLER_WORD; fse_ctable_size_u32(table_log, max_sv)];
            match fse_build_ctable_wksp(&mut ct, &norms(norm), max_sv, table_log) {
                Ok(()) => {
                    let state = FseCState::new(&ct);
                    let symbol_tt = state.symbol_tt();
                    let costs = (0..=max_sv).map(|s| fse_bit_cost(&ct, symbol_tt, table_log, s, 8));
                    let max_bits = (0..=max_sv).map(|s| fse_get_max_nb_bits(&ct, symbol_tt, s));
                    format!("ok {} {} {}", list(&ct), list(costs), list(max_bits))
                }
                Err(error) => failed(error),
            }
        }
        ["fsectablerle", symbol] => {
            let symbol: u8 = number(symbol);
            let mut ct = vec![FILLER_WORD; 2 + 2 * (usize::from(symbol) + 1)];
            fse_build_ctable_rle(&mut ct, symbol);
            format!("ok {}", list(&ct))
        }
        [
            "fsecompress",
            max_table_log,
            use_low_prob_count,
            dst_capacity,
            src,
        ] => {
            let src = unhex(src);
            let mut count = [0u32; 256];
            let mut max_sv = 255;
            let largest = hist_count_simple(&mut count, &mut max_sv, &src);
            if src.len() < 2 || largest as usize == src.len() {
                return "none".into();
            }
            let table_log = fse_optimal_table_log(number(max_table_log), src.len(), max_sv);
            let mut norm = [0i16; 256];
            if let Err(error) = fse_normalize_count(
                &mut norm,
                table_log,
                &count,
                src.len(),
                max_sv,
                use_low_prob_count == "1",
            ) {
                return failed(error);
            }
            let mut ct = vec![0u32; fse_ctable_size_u32(12, 255)];
            if let Err(error) = fse_build_ctable_wksp(&mut ct, &norm, max_sv, table_log) {
                return failed(error);
            }
            let mut dst = vec![0u8; number(dst_capacity)];
            let size = fse_compress_using_ctable(&mut dst, &src, &ct);
            format!("ok {table_log} {size} {}", hex(&dst[..size]))
        }
        ["bitc", dst_capacity, ops] => {
            let mut dst = vec![0u8; number(dst_capacity)];
            let ops = unlist(ops);
            let mut bit_c = match BitCStream::new(&mut dst) {
                Ok(bit_c) => bit_c,
                Err(error) => return failed(error),
            };
            for op in ops.chunks(3) {
                let (value, nb_bits) = (op[0] as u64, op[1] as u32);
                if op[2] == 2 {
                    bit_c.add_bits_fast(value, nb_bits);
                } else {
                    bit_c.add_bits(value, nb_bits);
                }
                if op[2] != 0 {
                    bit_c.flush_bits();
                }
            }
            let size = bit_c.close();
            format!("ok {size} {}", hex(&dst[..size]))
        }
        ["hufctable", max_nb_bits, count] => {
            let count = counts(count);
            let max_sv = count.len() as u32 - 1;
            let mut table = Box::new([FILLER_ELT; HUF_CTABLE_SIZE]);
            match huf_build_ctable_wksp(&mut table, &count, max_sv, number(max_nb_bits)) {
                Ok(max_bits) => {
                    let mut text = format!("ok {max_bits} {}", table_hex(&table));
                    let mut dst = [0u8; 4096];
                    let _ = match huf_write_ctable_wksp(&mut dst, &table, max_sv, max_bits) {
                        Ok(size) => write!(text, " {}", hex(&dst[..size])),
                        Err(error) => write!(text, " {}", failed(error)),
                    };
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["hufoptlog", max_table_log, flags, count] => {
            let count = counts(count);
            let total: usize = count.iter().map(|&c| c as usize).sum();
            let mut table = Box::new([FILLER_ELT; HUF_CTABLE_SIZE]);
            format!(
                "ok {}",
                huf_optimal_table_log(
                    number(max_table_log),
                    total,
                    count.len() as u32 - 1,
                    &mut table,
                    &count,
                    number(flags)
                )
            )
        }
        [
            "hufcompress",
            streams,
            max_sv,
            huff_log,
            flags,
            dst_capacity,
            repeat,
            table,
            src,
        ] => {
            let src = unhex(src);
            let mut dst = vec![0u8; number(dst_capacity)];
            let mut old = (table != "-").then(|| table_unhex(table));
            let mut repeat = match number::<i32>(repeat) {
                0 => HufRepeat::None,
                1 => HufRepeat::Check,
                _ => HufRepeat::Valid,
            };
            let has_table = old.is_some();
            let compress = if streams == "1" {
                huf_compress1x_repeat
            } else {
                huf_compress4x_repeat
            };
            let result = compress(
                &mut dst,
                &src,
                number(max_sv),
                number(huff_log),
                old.as_deref_mut(),
                has_table.then_some(&mut repeat),
                number(flags),
            );
            match result {
                Ok(size) => format!(
                    "ok {size} {} {} {}",
                    if has_table { repeat as i32 } else { -1 },
                    hex(&dst[..size]),
                    old.as_deref()
                        .map_or_else(|| "-".to_string(), used_table_hex)
                ),
                Err(error) => failed(error),
            }
        }
        ["hufreadctable", max_sv, src] => {
            let mut table = Box::new([FILLER_ELT; HUF_CTABLE_SIZE]);
            let mut max_sv: u32 = number(max_sv);
            let mut has_zero_weights = false;
            match huf_read_ctable(&mut table, &mut max_sv, &unhex(src), &mut has_zero_weights) {
                Ok(size) => format!(
                    "ok {size} {max_sv} {} {}",
                    u8::from(has_zero_weights),
                    table_hex(&table)
                ),
                Err(error) => failed(error),
            }
        }
        ["compress", level, dst_capacity, src] => {
            let src = unhex(src);
            let mut dst = vec![0u8; number(dst_capacity)];
            CCTX.with(
                |cctx| match cctx.borrow_mut().compress(&mut dst, &src, number(level)) {
                    Ok(size) => format!("ok {}", hex(&dst[..size])),
                    Err(error) => failed(error),
                },
            )
        }
        ["cstream", capacity, steps, src] => cstream(capacity, steps, src, "-", "-"),
        ["cstream", capacity, steps, src, dict] => cstream(capacity, steps, src, dict, "-"),
        ["cstream", capacity, steps, src, dict, seqs] => cstream(capacity, steps, src, dict, seqs),
        ["seqreset"] => {
            SEQ_ENTROPY.with(|state| {
                *state.borrow_mut() = (
                    [
                        EntropyCTables::filled(FILLER_WORD),
                        EntropyCTables::filled(FILLER_WORD),
                    ],
                    0,
                );
            });
            "ok".into()
        }
        [
            "seqblock",
            strategy,
            literal_mode,
            target_length,
            dst_capacity,
            literals,
            sequences,
        ] => seq_block(
            strategy,
            literal_mode,
            target_length,
            dst_capacity,
            literals,
            sequences,
        ),
        _ => panic!("unknown request {request:.200}"),
    }
}

/// The parameter of libzstd's number `number` (a `ZSTD_cParameter`), with
/// `value`, as `ZSTD_CCtx_setParameter` takes it. The requests only have
/// values the port's parameters can hold.
fn c_parameter(number: i64, value: i64) -> CParameter {
    let flag = value != 0;
    let unsigned = || u32::try_from(value).expect("a value the parameter holds");
    let switch = || match value {
        0 => ParamSwitch::Auto,
        1 => ParamSwitch::Enable,
        2 => ParamSwitch::Disable,
        _ => panic!("switch {value}"),
    };
    let stable = || match value {
        0 => false,
        1 => true,
        _ => panic!("buffer mode {value}"),
    };
    match number {
        100 => CParameter::CompressionLevel(value as i32),
        101 => CParameter::WindowLog(unsigned()),
        102 => CParameter::HashLog(unsigned()),
        103 => CParameter::ChainLog(unsigned()),
        104 => CParameter::SearchLog(unsigned()),
        105 => CParameter::MinMatch(unsigned()),
        106 => CParameter::TargetLength(unsigned()),
        107 => CParameter::Strategy(match value {
            0 => None,
            _ => Some(Strategy::from_number(unsigned()).expect("a strategy")),
        }),
        200 => CParameter::ContentSizeFlag(flag),
        201 => CParameter::ChecksumFlag(flag),
        202 => CParameter::DictIdFlag(flag),
        // ZSTD_c_format
        10 => CParameter::Format(match value {
            0 => Format::Zstd1,
            1 => Format::Zstd1Magicless,
            _ => panic!("format {value}"),
        }),
        // ZSTD_c_literalCompressionMode
        1002 => CParameter::LiteralCompressionMode(switch()),
        // ZSTD_c_srcSizeHint
        1004 => CParameter::SrcSizeHint(unsigned()),
        // ZSTD_c_stableInBuffer, ZSTD_c_stableOutBuffer
        1006 => CParameter::StableInBuffer(stable()),
        1007 => CParameter::StableOutBuffer(stable()),
        // ZSTD_c_maxBlockSize
        1015 => CParameter::MaxBlockSize(unsigned()),
        // ZSTD_c_blockSplitterLevel
        1017 => CParameter::BlockSplitterLevel(unsigned()),
        // ZSTD_c_splitAfterSequences
        1010 => CParameter::SplitAfterSequences(switch()),
        // ZSTD_c_enableLongDistanceMatching, ZSTD_c_ldmHashLog,
        // ZSTD_c_ldmMinMatch, ZSTD_c_ldmBucketSizeLog, ZSTD_c_ldmHashRateLog
        160 => CParameter::EnableLongDistanceMatching(switch()),
        161 => CParameter::LdmHashLog(unsigned()),
        162 => CParameter::LdmMinMatch(unsigned()),
        163 => CParameter::LdmBucketSizeLog(unsigned()),
        164 => CParameter::LdmHashRateLog(unsigned()),
        // ZSTD_c_useRowMatchFinder
        1011 => CParameter::UseRowMatchFinder(switch()),
        // ZSTD_c_enableDedicatedDictSearch
        1005 => CParameter::EnableDedicatedDictSearch(flag),
        // ZSTD_c_nbWorkers, ZSTD_c_jobSize, ZSTD_c_overlapLog,
        // ZSTD_c_rsyncable
        400 => CParameter::NbWorkers(unsigned()),
        401 => CParameter::JobSize(unsigned()),
        402 => CParameter::OverlapLog(value as i32),
        500 => CParameter::Rsyncable(flag),
        // ZSTD_c_forceMaxWindow, ZSTD_c_deterministicRefPrefix,
        // ZSTD_c_prefetchCDictTables
        1000 => CParameter::ForceMaxWindow(flag),
        1012 => CParameter::DeterministicRefPrefix(flag),
        1013 => CParameter::PrefetchCDictTables(switch()),
        // ZSTD_c_forceAttachDict
        1001 => CParameter::ForceAttachDict(match value {
            0 => DictAttachPref::DefaultAttach,
            1 => DictAttachPref::ForceAttach,
            2 => DictAttachPref::ForceCopy,
            3 => DictAttachPref::ForceLoad,
            _ => panic!("dictionary attach preference {value}"),
        }),
        // ZSTD_c_blockDelimiters, ZSTD_c_validateSequences,
        // ZSTD_c_enableSeqProducerFallback, ZSTD_c_repcodeResolution
        1008 => CParameter::BlockDelimiters(match value {
            0 => SequenceFormat::NoBlockDelimiters,
            1 => SequenceFormat::ExplicitBlockDelimiters,
            _ => panic!("sequence format {value}"),
        }),
        1009 => CParameter::ValidateSequences(stable()),
        1014 => CParameter::EnableSeqProducerFallback(stable()),
        1016 => CParameter::RepcodeResolution(switch()),
        _ => panic!("parameter {number}"),
    }
}

/// The parameter of libzstd's number `number`, as
/// `ZSTD_CCtx_getParameter` takes it.
pub(crate) fn c_parameter_kind(number: i64) -> CParameterKind {
    use CParameterKind as K;
    match number {
        100 => K::CompressionLevel,
        101 => K::WindowLog,
        102 => K::HashLog,
        103 => K::ChainLog,
        104 => K::SearchLog,
        105 => K::MinMatch,
        106 => K::TargetLength,
        107 => K::Strategy,
        200 => K::ContentSizeFlag,
        201 => K::ChecksumFlag,
        202 => K::DictIdFlag,
        10 => K::Format,
        1002 => K::LiteralCompressionMode,
        1004 => K::SrcSizeHint,
        1006 => K::StableInBuffer,
        1007 => K::StableOutBuffer,
        1015 => K::MaxBlockSize,
        1017 => K::BlockSplitterLevel,
        1010 => K::SplitAfterSequences,
        160 => K::EnableLongDistanceMatching,
        161 => K::LdmHashLog,
        162 => K::LdmMinMatch,
        163 => K::LdmBucketSizeLog,
        164 => K::LdmHashRateLog,
        1011 => K::UseRowMatchFinder,
        1005 => K::EnableDedicatedDictSearch,
        400 => K::NbWorkers,
        401 => K::JobSize,
        402 => K::OverlapLog,
        500 => K::Rsyncable,
        1001 => K::ForceAttachDict,
        1008 => K::BlockDelimiters,
        1009 => K::ValidateSequences,
        1014 => K::EnableSeqProducerFallback,
        1016 => K::RepcodeResolution,
        _ => panic!("parameter {number}"),
    }
}

/// `cstream`: a new context through the steps, as the oracle takes it
/// through them; reset after a failed call, but for buffers not as stable
/// as promised, which is found before anything changes. `dict` is the
/// dictionary bytes of the steps that set one, `seqs` the sequences of the
/// steps of the sequence API (see [`SequenceSteps`]).
#[allow(clippy::too_many_lines)]
fn cstream(capacity: &str, steps: &str, src: &str, dict: &str, seqs: &str) -> String {
    let capacity: usize = number(capacity);
    let steps = unlist(steps);
    let src = unhex(src);
    let dict = unhex(dict);
    let mut sequence_steps = SequenceSteps::new(seqs);
    let mut cctx = CCtx::new();
    let mut out = vec![0u8; capacity];
    let (mut in_pos, mut out_pos) = (0usize, 0usize);
    let mut text = String::from("ok");
    for step in steps.chunks(3) {
        let (op, a, b) = (step[0], step[1], step[2]);
        // The dictionary's bytes: b at a, or the first a.
        let dict_at = (a.max(0) as usize).min(dict.len());
        let dict_piece = &dict[dict_at..dict_at + (b.max(0) as usize).min(dict.len() - dict_at)];
        let dict_head = &dict[..(a.max(0) as usize).min(dict.len())];
        if (11..=18).contains(&op) {
            let content_type = |which| match which {
                1 => DictContentType::RawContent,
                2 => DictContentType::FullDict,
                _ => DictContentType::Auto,
            };
            let result = match op {
                11..=13 => cctx.load_dictionary_advanced(dict_piece, content_type(op - 11)),
                14 => cctx.ref_prefix(dict_piece),
                15 => cctx.ref_prefix_advanced(dict_piece, DictContentType::Auto),
                16 | 17 => {
                    let cdict = if op == 16 {
                        CDict::new(dict_head, b as i32)
                    } else {
                        cctx.cdict_with_requested_parameters(dict_head, content_type(b))
                    };
                    match cdict {
                        Ok(cdict) => cctx.ref_cdict(Some(Arc::new(cdict))),
                        Err(_) => {
                            text.push_str(" n");
                            continue;
                        }
                    }
                }
                _ => cctx.ref_cdict(None),
            };
            let _ = match result {
                Err(error) => write!(text, " e{}/{in_pos}/{out_pos}", error.code().number()),
                Ok(()) => {
                    sequence_steps.dictionary_set(op, b, dict_piece, dict_head);
                    write!(text, " s")
                }
            };
            continue;
        }
        if (19..=28).contains(&op) {
            let answer = sequence_steps.step(
                &mut cctx,
                [op, a, b],
                &src,
                &mut out[..capacity],
                &mut in_pos,
                &mut out_pos,
            );
            text.push_str(&answer);
            continue;
        }
        let in_end = (in_pos + a.max(0) as usize).min(src.len());
        let out_end = if op == 10 {
            capacity
        } else {
            (out_pos + b.max(0) as usize).min(capacity)
        };
        let mut input = InBuffer {
            src: &src[..in_end],
            pos: if op == 10 {
                (in_pos + b as usize).min(in_end)
            } else {
                in_pos
            },
        };
        let mut output = OutBuffer {
            dst: &mut out[..out_end],
            pos: out_pos,
        };
        let result = match op {
            0..=2 => {
                let directive = [
                    EndDirective::Continue,
                    EndDirective::Flush,
                    EndDirective::End,
                ][op as usize];
                cctx.compress_stream2(&mut output, &mut input, directive)
                    .map(Some)
            }
            3 => cctx.compress_stream(&mut output, &mut input).map(Some),
            4 => cctx.flush_stream(&mut output).map(Some),
            5 => cctx.end_stream(&mut output).map(Some),
            6 => {
                let result = cctx.compress2(&mut output.dst[out_pos..], &input.src[in_pos..]);
                if let Ok(size) = result {
                    input.pos = in_end;
                    output.pos = out_pos + size;
                    // With a sequence producer, a check that the frame
                    // decodes back, when asked for.
                    text.push_str(sequence_steps.check_frame(
                        &output.dst[out_pos..out_pos + size],
                        &input.src[in_pos..in_end],
                    ));
                }
                result.map(Some)
            }
            7 => cctx.set_parameter(c_parameter(a, b)).map(|()| None),
            10 => cctx
                .compress_stream2(&mut output, &mut input, EndDirective::Continue)
                .map(Some),
            8 => cctx
                .reset(match a {
                    1 => ResetDirective::SessionOnly,
                    2 => ResetDirective::Parameters,
                    _ => ResetDirective::SessionAndParameters,
                })
                .map(|()| None),
            _ => cctx
                .set_pledged_src_size(if a < 0 { u64::MAX } else { a as u64 })
                .map(|()| None),
        };
        in_pos = input.pos;
        out_pos = output.pos;
        if op <= 6 || op == 10 {
            sequence_steps.frame_started();
        }
        let unstable = result
            .as_ref()
            .is_err_and(|error| error.code() == ErrorCode::StabilityConditionNotRespected);
        if result.is_err() && !unstable && (op <= 6 || op == 10) {
            // A context must be reset after an error, before it is used
            // again: libzstd's then reads what the input buffers of earlier
            // calls held, and the port refuses to.
            let _ = cctx.reset(ResetDirective::SessionOnly);
        }
        let _ = match result {
            Err(error) => write!(text, " e{}/{in_pos}/{out_pos}", error.code().number()),
            Ok(None) => write!(text, " s"),
            // libzstd prints the result as an unsigned int.
            Ok(Some(r)) => write!(text, " {}/{in_pos}/{out_pos}", r as u32),
        };
    }
    let _ = write!(text, " {:016x}", fnv64(&out[..out_pos]));
    text
}

/// Bytes for the entropy coders: text-like, skewed, random, one symbol, or
/// with the structure of LZ77.
pub(crate) fn data(rng: &mut Rng, len: usize) -> Vec<u8> {
    match rng.range(0, 5) {
        0 | 1 => rng.huffman_data(len),
        2 => rng.lz_data(len),
        3 => rng.bytes(len),
        4 => vec![rng.next() as u8; len],
        _ => {
            // A few symbols, one of them rare.
            let alphabet = rng.range(2, 6);
            (0..len)
                .map(|_| {
                    if rng.range(0, 200) == 0 {
                        200
                    } else {
                        rng.range(0, alphabet - 1) as u8
                    }
                })
                .collect()
        }
    }
}

/// Symbol counts for a Huffman tree: the usual skew, or growing like the
/// Fibonacci numbers, which makes trees deeper than any table allows.
fn huffman_counts(rng: &mut Rng) -> Vec<u64> {
    if rng.range(0, 4) == 0 {
        let symbols = rng.range(3, 40) as usize;
        let (mut a, mut b) = (1u64, 1u64);
        let mut counts: Vec<u64> = (0..symbols)
            .map(|_| {
                let c = a;
                (a, b) = (b, (a + b).min(1 << 20));
                c + rng.range(0, 1)
            })
            .collect();
        if rng.range(0, 1) == 0 {
            counts.reverse();
        }
        counts
    } else {
        let symbols = if rng.range(0, 2) == 0 {
            rng.range(2, 256)
        } else {
            rng.range(2, 40)
        } as usize;
        rng.histogram(symbols)
    }
}

fn cardinality(counts: &[u64]) -> u32 {
    counts.iter().filter(|&&c| c > 0).count() as u32
}

/// `HUF_minTableLog`
fn min_table_log(cardinality: u32) -> u64 {
    u64::from(31 - cardinality.leading_zeros() + 1)
}

/// Requests for each of the encoder's commands, about `per_command` of
/// each.
pub(crate) fn requests(oracle: &mut Oracle, rng: &mut Rng, per_command: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // Histograms, small and above the 1500 bytes where libzstd counts in
    // four tables, with the largest symbol given right, too small (an
    // error), or larger.
    for i in 0..per_command {
        let len = match i % 10 {
            0 => 0,
            1..=3 => rng.range(1500, 20_000),
            _ => rng.range(1, 1600),
        } as usize;
        let src = data(rng, len);
        let largest = u64::from(src.iter().copied().max().unwrap_or(0));
        let mode = ["simple", "fast", "wksp"][rng.range(0, 2) as usize];
        let max_sv = match (mode, rng.range(0, 3)) {
            ("wksp", 0) => largest.saturating_sub(1),
            ("wksp", 1) => rng.range(0, 255),
            (_, 2) => 255,
            _ => rng.range(largest, 255),
        };
        requests.push(format!("hist {mode} {max_sv} {}", hex(&src)));
    }

    // Table logs, of two symbols or more: libzstd takes one symbol for RLE,
    // and its log of 0 is undefined.
    for _ in 0..per_command {
        let src_size = match rng.range(0, 2) {
            0 => rng.range(2, 100),
            1 => rng.range(2, 5000),
            _ => rng.range(2, 1 << 20),
        };
        requests.push(format!(
            "fseoptlog {} {src_size} {} {}",
            rng.range(0, 15),
            rng.range(1, 255),
            rng.range(0, 3)
        ));
    }

    // Normalized counts, then their descriptions and tables.
    let mut distributions = Vec::new();
    for i in 0..per_command {
        let symbols = if rng.range(0, 3) == 0 {
            rng.range(2, 256)
        } else {
            rng.range(2, 53)
        } as usize;
        // Near-even counts over almost as many symbols as the table has
        // cells: rounding them up overshoots, and libzstd falls back to its
        // second method (FSE_normalizeM2), sometimes to its corner cases.
        let m2_log = rng.range(5, 7);
        let (mut count, table_log) = match i % 6 {
            0 => {
                let mut count = vec![1u64; symbols];
                count[rng.range(0, symbols as u64 - 1) as usize] = rng.range(100, 100_000);
                (count, rng.range(5, 12))
            }
            1 => (
                (0..symbols).map(|_| rng.range(0, 3)).collect(),
                rng.range(5, 12),
            ),
            2 => {
                let symbols = rng.range((1 << m2_log) / 3, (1 << m2_log) - 1) as usize;
                let base = rng.range(1, 40);
                let mut count: Vec<u64> = (0..symbols)
                    .map(|_| base + rng.range(0, base / 2 + 1))
                    .collect();
                if rng.range(0, 1) == 0 {
                    count[0] = base * rng.range(2, 40);
                }
                (count, m2_log)
            }
            _ => {
                let table_log = match rng.range(0, 9) {
                    0 => rng.range(0, 13),
                    _ => rng.range(5, 12),
                };
                (rng.histogram(symbols), table_log)
            }
        };
        if count.iter().sum::<u64>() < 2 {
            count[0] = 2;
        }
        let symbols = count.len();
        let use_low = rng.range(0, 1);
        let request = format!("fsenorm {table_log} {use_low} {}", list(&count));
        if let Some(ok) = oracle.ask(&request).strip_prefix("ok ") {
            let (log, norm) = ok.split_once(' ').expect("log and counts");
            if log != "0" {
                distributions.push((log.to_string(), norm.to_string(), symbols - 1));
            }
        }
        requests.push(request);
    }
    for (i, (table_log, norm, max_sv)) in distributions.iter().enumerate() {
        requests.push(format!("fsectable {max_sv} {table_log} {norm}"));
        // The description: in a large buffer, one about the right size, or
        // a small one; sometimes of a damaged distribution.
        let norm_values = norms(norm);
        let bound = fse_ncount_write_bound(*max_sv as u32, number(table_log));
        let buffer = match rng.range(0, 3) {
            0 => 4096,
            1 => bound,
            2 => rng.range(0, bound as u64 + 2) as usize,
            _ => rng.range(0, 8) as usize,
        };
        let norm = if i % 5 == 4 {
            let mut damaged = norm_values.clone();
            let at = rng.range(0, damaged.len() as u64 - 1) as usize;
            damaged[at] = damaged[at].wrapping_add(rng.range(0, 4) as i16 - 2);
            list(damaged)
        } else {
            norm.clone()
        };
        let table_log = if i % 17 == 0 {
            rng.range(0, 15).to_string()
        } else {
            table_log.clone()
        };
        requests.push(format!("fsencount {buffer} {max_sv} {table_log} {norm}"));
    }
    for _ in 0..per_command / 10 {
        requests.push(format!("fsectablerle {}", rng.range(0, 255)));
    }

    // FSE streams of data, with every table log and room around the bound
    // where libzstd stops checking the output.
    for i in 0..per_command {
        let len = if i % 10 == 0 {
            rng.range(0, 100_000)
        } else {
            rng.range(0, 3000)
        } as usize;
        let src = data(rng, len);
        let bound = fse_blockbound(len) as u64;
        let capacity = match rng.range(0, 3) {
            0 => bound + rng.range(0, 100),
            1 => bound.saturating_sub(rng.range(1, 20)),
            2 => rng.range(0, bound),
            _ => rng.range(0, 12),
        };
        requests.push(format!(
            "fsecompress {} {} {capacity} {}",
            rng.range(0, 12),
            rng.range(0, 1),
            hex(&src)
        ));
    }

    // Bitstreams written in random steps, flushed in time.
    for i in 0..per_command {
        let capacity = if i % 4 == 0 {
            rng.range(0, 4096)
        } else {
            rng.range(0, 40)
        };
        let mut ops = Vec::new();
        let mut bit_pos = 0;
        for _ in 0..rng.range(0, 60) {
            let nb_bits = rng.range(0, (63 - bit_pos).min(31));
            let how = if bit_pos + nb_bits > 40 {
                rng.range(1, 2)
            } else {
                rng.range(0, 2)
            };
            let value = if how == 2 {
                rng.next() & ((1 << nb_bits) - 1)
            } else {
                rng.next() >> 24
            };
            ops.extend([value, nb_bits, how]);
            bit_pos += nb_bits;
            if how != 0 {
                bit_pos &= 7;
            }
        }
        if bit_pos > 62 {
            ops.extend([0, 0, 1]);
        }
        requests.push(format!("bitc {capacity} {}", list(ops)));
    }

    // Huffman tables, their descriptions, and the descriptions read back.
    let mut tables = Vec::new();
    let mut full_tables = Vec::new();
    for i in 0..per_command {
        let counts = if i % 6 == 5 {
            // Every symbol present, as in a dictionary's table.
            (0..256).map(|_| rng.range(1, 2000)).collect()
        } else {
            huffman_counts(rng)
        };
        let cardinality = cardinality(&counts);
        if cardinality < 2 {
            continue;
        }
        let max_nb_bits = rng.range(min_table_log(cardinality), 12);
        let request = format!("hufctable {max_nb_bits} {}", list(&counts));
        let reply = oracle.ask(&request);
        if let Some(ok) = reply.strip_prefix("ok ") {
            let words: Vec<&str> = ok.split(' ').collect();
            tables.push(words[1].to_string());
            if counts.len() == 256 && cardinality == 256 {
                full_tables.push(words[1].to_string());
            }
            if let Some(description) = words.get(2).filter(|w| !w.starts_with("err")) {
                let description = unhex(description);
                let src = match i % 4 {
                    3 => mutate(rng, &description),
                    _ => description,
                };
                let max_sv = if rng.range(0, 4) == 0 {
                    rng.range(0, 255)
                } else {
                    255
                };
                requests.push(format!("hufreadctable {max_sv} {}", hex(&src)));
            }
        }
        requests.push(request);
        let flags = [0, 2, 1, 3][rng.range(0, 3) as usize];
        requests.push(format!(
            "hufoptlog {} {flags} {}",
            rng.range(0, 12),
            list(&counts)
        ));
    }
    for _ in 0..per_command / 10 {
        let len = rng.range(0, 40) as usize;
        requests.push(format!(
            "hufreadctable {} {}",
            rng.range(0, 255),
            hex(&rng.bytes(len))
        ));
    }

    // Huffman-compressed literals, as the block compressor asks for them:
    // one or four streams, a previous table or none and how far to trust
    // it, the flags, and room that is plenty, tight or too little. They come
    // in runs of blocks from the same source, each block given the table
    // the one before left, as the block compressor does.
    let mut made = 0;
    while made < per_command {
        let blocks = rng.range(1, 4) as usize;
        let block_len = match rng.range(0, 19) {
            0 => rng.range(20_000, 128 * 1024 / blocks as u64),
            1 => rng.range(0, 12),
            _ => rng.range(0, 3000),
        } as usize;
        let source = if rng.range(0, 2) == 0 {
            rng.huffman_data(blocks * block_len)
        } else {
            data(rng, blocks * block_len)
        };
        let streams = if rng.range(0, 2) == 0 { 1 } else { 4 };
        let mut previous: Option<(i32, String)> = None;
        for src in source.chunks(block_len.max(1)).take(blocks) {
            made += 1;
            let len = src.len();
            let largest = u64::from(src.iter().copied().max().unwrap_or(0));
            let flags = rng.range(0, 15);
            let max_sv = match rng.range(0, 9) {
                0 => 0,
                1 => largest,
                // Too small, which counting finds, when the sampling (which
                // trusts it) does not run first.
                2 if flags & 8 == 0 || len < 40_960 => largest.saturating_sub(1),
                3 => rng.range(largest, 255),
                _ => 255,
            };
            // libzstd asks for 11; with fewer bits than its symbols need, its
            // tree building fails badly, so never fewer.
            let mut present = [false; 256];
            for &byte in src {
                present[usize::from(byte)] = true;
            }
            let symbols = present.iter().filter(|&&p| p).count() as u32;
            let huff_log = match rng.range(0, 19) {
                0 => 0,
                1 => 13,
                2..=11 => 11,
                _ => rng.range(min_table_log(symbols.max(1)).max(6), 12),
            };
            let bound = huf_compress_bound(len) as u64;
            let capacity = match rng.range(0, 5) {
                0 => rng.range(len as u64 / 2, bound),
                1 => rng.range(0, 40),
                _ => (bound + 100).min(1 << 20),
            };
            // A previous table: the one the block before left, still to be
            // checked; none; one just built; or one with all 256 symbols,
            // which is "valid", as the tables of dictionaries are (libzstd
            // uses a valid table without looking at its symbols).
            let (repeat, table) = match (previous.take(), rng.range(0, 5)) {
                (Some(previous), 0..=3) => previous,
                (_, 0) => (0, "-".to_string()),
                (_, 1) if !full_tables.is_empty() => (
                    2,
                    full_tables[rng.range(0, full_tables.len() as u64 - 1) as usize].clone(),
                ),
                _ if !tables.is_empty() => (
                    rng.range(0, 1) as i32,
                    tables[rng.range(0, tables.len() as u64 - 1) as usize].clone(),
                ),
                _ => (0, "-".to_string()),
            };
            let request = format!(
                "hufcompress {streams} {max_sv} {huff_log} {flags} {capacity} {repeat} {table} {}",
                hex(src)
            );
            if let Some(ok) = oracle.ask(&request).strip_prefix("ok ") {
                let words: Vec<&str> = ok.split(' ').collect();
                // A new table is checked before it is used again; an old one
                // keeps how far it is trusted.
                let repeat: i32 = number(words[1]);
                if repeat >= 0 {
                    previous = Some((repeat.max(1), words[3].to_string()));
                }
            }
            requests.push(request);
        }
    }

    // Blocks of sequences in runs, each run with the tables kept from block
    // to block, its sequences drawn the same way throughout, so that the
    // tables are used again.
    for chain in 0..per_command / 8 {
        requests.extend(seq_chain(rng, chain));
    }

    // Whole frames, at the levels the port has for their size.
    for i in 0..per_command / 4 {
        requests.push(frame_request(rng, i));
    }

    // Streaming scripts.
    for i in 0..per_command / 4 {
        requests.push(cstream_request(rng, i));
    }

    // Valid tables, as a dictionary gives them: used without a look when
    // the flags prefer them, otherwise when they cost less.
    for _ in 0..per_command / 10 {
        let Some(table) = (!full_tables.is_empty())
            .then(|| full_tables[rng.range(0, full_tables.len() as u64 - 1) as usize].clone())
        else {
            break;
        };
        let len = rng.range(13, 3000) as usize;
        let src = if rng.range(0, 1) == 0 {
            rng.bytes(len)
        } else {
            rng.huffman_data(len)
        };
        let flags = if rng.range(0, 1) == 0 {
            4
        } else {
            rng.range(0, 15)
        };
        let streams = if rng.range(0, 2) == 0 { 1 } else { 4 };
        requests.push(format!(
            "hufcompress {streams} 255 11 {flags} {} 2 {table} {}",
            huf_compress_bound(len),
            hex(&src)
        ));
    }

    requests
}

/// The data of a frame: as `data`, or pieces of different kinds one after
/// another, where libzstd may end a block early.
pub(crate) fn frame_data(rng: &mut Rng, len: usize) -> Vec<u8> {
    if rng.range(0, 2) != 0 {
        return data(rng, len);
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let piece = (rng.range(1000, 80_000) as usize).min(len - out.len());
        out.extend(data(rng, piece));
    }
    out
}

/// A `compress` request, at a level the port has for its size, with room
/// enough, barely enough, or too little.
fn frame_request(rng: &mut Rng, i: usize) -> String {
    // Sizes on both sides of where the tables of levels change, and powers
    // of 2, where the window just holds the input.
    const EDGES: [u64; 14] = [
        1024, 2048, 4096, 8192, 16_383, 16_384, 16_385, 65_536, 131_071, 131_072, 131_073, 262_143,
        262_144, 262_145,
    ];
    let len = match i % 12 {
        0 => rng.range(0, 16),
        1 => rng.range(16_000, 17_000),
        2 => rng.range(120_000, 140_000),
        3 => rng.range(250_000, 270_000),
        4 => rng.range(300_000, 1 << 20),
        5 => EDGES[rng.range(0, EDGES.len() as u64 - 1) as usize],
        _ => rng.range(0, 6000),
    } as usize;
    let src = frame_data(rng, len);
    // A level the port has for the size; the fast ones the most often.
    let level: i64 = loop {
        let level = match rng.range(0, 9) {
            0 => -(rng.range(1, 10) as i64),
            1 => -(rng.range(1, 200_000) as i64),
            2 => 2,
            3 => 3,
            4..=6 => rng.range(4, 22) as i64,
            _ => 1,
        };
        if zstd_level_ported(level as i32, len as u64) {
            break level;
        }
    };
    let bound = zstd_compress_bound(len).unwrap_or(0) as u64;
    let capacity = match rng.range(0, 7) {
        0 => rng.range(0, 30),
        1 => rng.range(len as u64 / 3, bound),
        _ => bound,
    };
    // The oracle's output holds 1 MiB.
    let capacity = capacity.min(1 << 20);
    format!("compress {level} {capacity} {}", hex(&src))
}

/// A `cstream` request: parameters, maybe a pledged size, then streaming
/// calls over the data, cut at random, with parameters set in between;
/// sometimes several frames, and `compress2`.
fn cstream_request(rng: &mut Rng, i: usize) -> String {
    let len = match i % 8 {
        0 => rng.range(0, 64),
        1 => rng.range(100_000, 400_000),
        2 => rng.range(4000, 40_000),
        _ => rng.range(0, 3900),
    } as usize;
    let src = frame_data(rng, len);
    let mut steps: Vec<i64> = Vec::new();
    let small = len < 50_000;

    // The parameters: every level, small windows and blocks for the input
    // buffer to wrap around.
    let stable_in = rng.range(0, 3) == 0;
    let stable_out = rng.range(0, 3) == 0;
    let level: i64 = match rng.range(0, 11) {
        0 => -(rng.range(1, 10) as i64),
        1 => 1,
        2 => 2,
        3 | 4 => 3,
        5..=7 => rng.range(4, 8) as i64,
        8 => rng.range(9, 15) as i64,
        _ => rng.range(16, 22) as i64,
    };
    steps.extend([7, 100, level]);
    // The lazy strategies with the row match finder or the hash chain: on,
    // off, or as the window decides.
    steps.extend([7, 1011, rng.range(0, 2) as i64]);
    // The block splitter after the sequences: on, off, or as the strategy
    // decides (on for btopt and up with windows of 128 KB or more).
    steps.extend([7, 1010, rng.range(0, 2) as i64]);
    if rng.range(0, 1) == 0 {
        let window_log = if small {
            rng.range(9, 13)
        } else {
            rng.range(10, 18)
        };
        steps.extend([7, 101, window_log as i64]);
    }
    if rng.range(0, 2) == 0 {
        let max_block = [0, 1000, 1024, 1500, 4096, 131_072][rng.range(0, 5) as usize];
        steps.extend([7, 1015, max_block]);
    }
    for (number, low, high) in [
        (102, 5, 18),
        (103, 5, 18),
        (104, 0, 8),
        (105, 2, 8),
        (106, 0, 300),
        (107, 0, 9),
        (200, 0, 1),
        (201, 0, 1),
        (202, 0, 1),
        (10, 0, 1),
        (1002, 0, 2),
        (1004, 0, 300_000),
        (1017, 0, 7),
    ] {
        if rng.range(0, 4) == 0 {
            steps.extend([7, number, rng.range(low, high) as i64]);
        }
    }
    if rng.range(0, 2) == 0 {
        // Long distance matching, on, off or auto (on for btopt and up with
        // windows of 128 MB or more), with small parameters so that it
        // finds matches in these inputs, some out of bounds; and a small
        // window, which it would otherwise set to 2^27 bytes, with up to
        // 2^26 entries in its hash table.
        steps.extend([7, 160, rng.range(0, 2) as i64]);
        for (number, low, high) in [(161, 5, 18), (162, 3, 80), (163, 0, 9), (164, 0, 4)] {
            if rng.range(0, 1) == 0 {
                steps.extend([7, number, rng.range(low, high) as i64]);
            }
        }
        let window_log = if small {
            rng.range(10, 13)
        } else {
            rng.range(10, 18)
        };
        steps.extend([7, 101, window_log as i64]);
    }
    if rng.range(0, 2) == 0 {
        // The optimal parser's strategies, at any level.
        steps.extend([7, 107, rng.range(7, 9) as i64]);
    }
    if rng.range(0, 1) == 0 {
        // A shortest match of 3 bytes, for the optimal parser's 3-byte
        // hash table.
        steps.extend([7, 105, 3]);
    }
    steps.extend([7, 1006, i64::from(stable_in)]);
    steps.extend([7, 1007, i64::from(stable_out)]);
    // A dictionary, a third of the time: loaded, a prefix, or a CDict, made
    // for a level or with the parameters set, attached, copied in or
    // loaded again.
    let dict = if rng.range(0, 2) == 0 {
        cstream_dict(rng, &src)
    } else {
        Vec::new()
    };
    if !dict.is_empty() {
        steps.extend(cstream_dict_steps(rng, dict.len(), stable_in));
    }
    if rng.range(0, 3) == 0 {
        // Not a size just short with a stable input buffer: the hint of
        // the next frame's ZSTD_compressStream then wraps around to what
        // reads as an error in libzstd, a number for the port.
        let pledged = match rng.range(0, 4) {
            0 => -1,
            1 if !stable_in => len as i64 + 1,
            2 if !stable_in => (len as i64 - 1).max(0),
            _ => len as i64,
        };
        steps.extend([9, pledged, 0]);
    }

    // The calls. The output is all of it with a stable output buffer, so
    // that its room stays the same; otherwise pieces of it.
    // Sizes on both sides of a full block, and of the most input a stable
    // buffer waits for before a frame starts.
    let piece = |rng: &mut Rng| -> i64 {
        (match rng.range(0, 7) {
            0 | 1 => rng.range(0, 16),
            2 => rng.range(1, 2000),
            3 => rng.range(1, 40_000),
            4 => [1000, 1023, 1024, 1025, 1500, 4095, 4096, 4097][rng.range(0, 7) as usize],
            5 => rng.range(131_070, 131_074),
            _ => rng.range(1, 300_000),
        }) as i64
    };
    let calls = rng.range(1, if small { 40 } else { 200 });
    let mut given = 0i64;
    for _ in 0..calls {
        // With a stable input buffer, the port differs from libzstd in
        // ZSTD_flushStream, ZSTD_endStream, and after a reset while input
        // waits (see CCtx::flush_stream and CCtx::reset): none of them.
        // Nor ZSTD_compressStream: its hint wraps around when more input
        // waits than a block holds, to what can read as an error to the
        // oracle, which then resets while input waits.
        let op = match rng.range(0, 20) {
            14..=16 | 18 | 19 if stable_in => 0,
            20 => 10,
            0..=10 => 0,
            11 | 12 => 1,
            13 => 2,
            14 => 3,
            15 => 4,
            16 => 5,
            17 => 7,
            _ => 8,
        };
        if !dict.is_empty() && rng.range(0, 30) == 0 {
            // Another dictionary: refused while a frame is open.
            steps.extend(cstream_dict_steps(rng, dict.len(), stable_in));
        }
        match op {
            7 => {
                // While streaming: allowed for the level, not the window.
                let (number, value) = if rng.range(0, 1) == 0 {
                    (100, rng.range(1, 3) as i64)
                } else {
                    (101, rng.range(10, 14) as i64)
                };
                steps.extend([7, number, value]);
            }
            8 => {
                if rng.range(0, 3) == 0 {
                    steps.extend([8, rng.range(1, 3) as i64, 0]);
                } else {
                    steps.extend([0, piece(rng), piece(rng)]);
                }
            }
            10 => {
                // The input moved on: a stable buffer must not be.
                let a = piece(rng);
                given += a;
                steps.extend([10, a, rng.range(0, 2) as i64]);
            }
            _ => {
                let a = piece(rng);
                given += a;
                let b = if stable_out { 1 << 30 } else { piece(rng) };
                steps.extend([op, a, b]);
            }
        }
    }
    // The end of the frame, and more after it, sometimes.
    for _ in 0..rng.range(1, 6) {
        let b = if stable_out { 1 << 30 } else { piece(rng) * 8 };
        steps.extend([2, len as i64 - given.min(len as i64) + 1, b]);
    }
    if !stable_in && rng.range(0, 5) == 0 {
        steps.extend([6, rng.range(0, 5000) as i64, rng.range(0, 1 << 20) as i64]);
        steps.extend([0, piece(rng), piece(rng), 2, 1 << 30, 1 << 30]);
    }

    let bound = zstd_compress_bound(len).unwrap_or(0) as u64;
    let capacity = match rng.range(0, 7) {
        0 => rng.range(0, 40),
        1 => rng.range(len as u64 / 3, bound + 30),
        _ => 2 * bound + 64,
    };
    if dict.is_empty() {
        format!("cstream {capacity} {} {}", list(steps), hex(&src))
    } else {
        format!(
            "cstream {capacity} {} {} {}",
            list(steps),
            hex(&src),
            hex(&dict)
        )
    }
}

/// A `cstream` request with workers (`ZSTD_c_nbWorkers`), their job size,
/// overlap and synchronization points, and the other parameters, the block
/// splitter level among them, which zstd-safe does not set; a dictionary
/// sometimes, a prefix read as `ZSTD_dct_auto` among them; then
/// `ZSTD_compress2` of an input on both sides of 512 KB, where workers
/// start, up to the oracle's 1 MB. With workers, only `ZSTD_compress2`
/// gives the same answers every time: how far a streaming call goes
/// depends on the threads (`tests/compress_mt.rs` streams with them).
fn cstream_workers_request(rng: &mut Rng) -> String {
    let len = if rng.range(0, 4) == 0 {
        rng.range(400_000, 524_288)
    } else {
        rng.range(524_289, 1_000_000)
    } as usize;
    let src = frame_data(rng, len);
    let level: i64 = match rng.range(0, 6) {
        0 => -(rng.range(1, 5) as i64),
        1 | 2 => rng.range(1, 3) as i64,
        3 => rng.range(4, 9) as i64,
        4 => rng.range(10, 15) as i64,
        _ => rng.range(16, 19) as i64,
    };
    let mut steps: Vec<i64> = vec![7, 100, level, 7, 400, rng.range(1, 8) as i64];
    if rng.range(0, 1) == 0 {
        let job_size = [0, 1, 524_288, 600_000][rng.range(0, 3) as usize];
        steps.extend([7, 401, job_size]);
    }
    if rng.range(0, 1) == 0 {
        steps.extend([7, 402, rng.range(0, 9) as i64]);
    }
    if rng.range(0, 3) == 0 {
        steps.extend([7, 500, 1]);
    }
    if rng.range(0, 1) == 0 {
        steps.extend([7, 201, 1]);
    }
    if rng.range(0, 2) == 0 {
        steps.extend([7, 1017, rng.range(0, 6) as i64]);
    }
    if rng.range(0, 2) == 0 {
        steps.extend([7, 1010, rng.range(0, 2) as i64]);
    }
    if rng.range(0, 2) == 0 {
        steps.extend([7, 101, rng.range(10, 22) as i64]);
    }
    if rng.range(0, 3) == 0 {
        steps.extend([7, 107, rng.range(1, 9) as i64]);
    }
    if rng.range(0, 4) == 0 {
        // Long distance matching, with a small window and small
        // parameters.
        steps.extend([7, 160, 1, 7, 162, rng.range(4, 64) as i64]);
        steps.extend([
            7,
            164,
            rng.range(0, 4) as i64,
            7,
            101,
            rng.range(10, 20) as i64,
        ]);
    }
    let dict = if rng.range(0, 1) == 0 {
        cstream_dict(rng, &src)
    } else {
        Vec::new()
    };
    if !dict.is_empty() {
        steps.extend(cstream_dict_steps(rng, dict.len(), false));
    }
    // Room for the frame, or less.
    let bound = zstd_compress_bound(len).unwrap_or(0) as i64;
    let room = if rng.range(0, 7) == 0 {
        rng.range(0, bound as u64) as i64
    } else {
        bound
    };
    steps.extend([6, len as i64, room]);
    let capacity = 1 << 20;
    if dict.is_empty() {
        format!("cstream {capacity} {} {}", list(steps), hex(&src))
    } else {
        format!(
            "cstream {capacity} {} {} {}",
            list(steps),
            hex(&src),
            hex(&dict)
        )
    }
}

/// The dictionary bytes of a `cstream` request: a zstd dictionary libzstd
/// trains on pieces of `src` (or of data like it), some cut short; raw
/// content, a piece of `src`; or random bytes.
pub(crate) fn cstream_dict(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
    match rng.range(0, 4) {
        0 | 1 => {
            let corpus = if src.len() > 20_000 {
                src.to_vec()
            } else {
                frame_data(rng, 60_000)
            };
            let samples: Vec<&[u8]> = corpus.chunks(rng.range(100, 600) as usize).collect();
            let size = rng.range(256, 12_000) as usize;
            match zstd::dict::from_samples(&samples, size) {
                Ok(mut dict) => {
                    if rng.range(0, 7) == 0 {
                        // Cut short: no longer a zstd dictionary to read.
                        dict.truncate(rng.range(8, 200) as usize);
                    }
                    dict
                }
                Err(_) => corpus[..corpus.len().min(5000)].to_vec(),
            }
        }
        2 if !src.is_empty() => {
            let at = rng.range(0, src.len() as u64 - 1) as usize;
            let len = (rng.range(1, 60_000) as usize).min(src.len() - at);
            src[at..at + len].to_vec()
        }
        _ => {
            let len = rng.range(1, 3000) as usize;
            rng.bytes(len)
        }
    }
}

/// Steps that set a dictionary from `dict_len` bytes for the next frames:
/// first the attach preference (as libzstd decides, attach, copy, or load
/// again), then one of the dictionary steps, mostly with all the bytes.
///
/// With a stable input buffer, none that can fail as the frame starts (a
/// dictionary read as a zstd one): the oracle then resets the context,
/// which drops the input waiting in the port (see `CCtx::reset_session`).
pub(crate) fn cstream_dict_steps(rng: &mut Rng, dict_len: usize, stable_in: bool) -> Vec<i64> {
    let len = dict_len as i64;
    let (at, size) = if rng.range(0, 3) == 0 {
        let at = rng.range(0, dict_len as u64) as i64;
        (
            at,
            rng.range(0, (dict_len as u64).saturating_sub(at as u64)) as i64,
        )
    } else {
        (0, len)
    };
    // Every attach preference: default, attach, copy, load.
    let mut steps = vec![7, 1001, rng.range(0, 3) as i64];
    match rng.range(0, 9) {
        0 | 2 | 4 if stable_in => steps.extend([12, at, size]),
        0 => steps.extend([11, at, size]),
        1 => steps.extend([12, at, size]),
        2 => steps.extend([13, at, size]),
        3 => steps.extend([14, at, size]),
        4 => steps.extend([15, at, size]),
        // CDicts of a byte or more: one made for an empty dictionary takes
        // the level's tables for an input of unknown size, up to 640 MB.
        5 | 6 => {
            let level = match rng.range(0, 4) {
                0 => -(rng.range(1, 5) as i64),
                1 => 0,
                _ => rng.range(1, 22) as i64,
            };
            steps.extend([16, size.max(1), level]);
        }
        7 => steps.extend([17, size.max(1), rng.range(0, 2) as i64]),
        _ => steps.extend([18, 0, 0]),
    }
    steps
}

/// How a run of blocks draws its sequences.
struct SeqProfile {
    max_literals: u64,
    max_match: u64,
    repeat_one_in: u64,
    max_offset_log: u64,
}

/// One length, mostly small, up to `max`.
pub(crate) fn small_length(rng: &mut Rng, max: u64) -> u64 {
    match rng.range(0, 9) {
        0 => rng.range(0, max),
        1..=3 => rng.range(0, max.min(64)),
        _ => rng.range(0, max.min(12)),
    }
}

/// A run of blocks of sequences: `seqreset`, then the blocks.
fn seq_chain(rng: &mut Rng, chain: usize) -> Vec<String> {
    let mut requests = vec!["seqreset".to_string()];
    let strategy = match rng.range(0, 1) {
        0 => rng.range(1, 9),
        _ => rng.range(1, 2),
    };
    let literal_mode = [0, 0, 0, 1, 2][rng.range(0, 4) as usize];
    let target_length = if rng.range(0, 3) == 0 {
        rng.range(1, 64)
    } else {
        0
    };
    let profile = SeqProfile {
        max_literals: [8, 40, 300, 3000][rng.range(0, 3) as usize],
        max_match: [8, 40, 300, 70_000][rng.range(0, 3) as usize],
        repeat_one_in: rng.range(2, 8),
        max_offset_log: rng.range(3, 27),
    };
    // The literals of all the blocks come from one source, so that a
    // block's Huffman table may serve the next; sometimes they are one
    // byte repeated.
    let literal_source = match chain % 10 {
        3 => vec![rng.next() as u8; 1 << 17],
        4 => rng.bytes(1 << 17),
        _ => rng.huffman_data(1 << 17),
    };
    // Mostly small blocks; some full ones; now and then one with so many
    // sequences that their count takes 3 bytes, or exactly as many as the
    // count's sizes change at.
    let many = chain % 25 == 7;
    let exactly =
        (chain % 25 == 8).then(|| [127usize, 128, 0x7EFF, 0x7F00][rng.range(0, 3) as usize]);
    for _ in 0..rng.range(1, 8) {
        let budget = if many {
            128 * 1024
        } else if rng.range(0, 7) == 0 {
            rng.range(20_000, 128 * 1024)
        } else {
            rng.range(0, 6000)
        } as usize;
        let mut triples = Vec::new();
        let mut literal_count = 0usize;
        let mut size = 0usize;
        let mut long_used = false;
        loop {
            if exactly.is_some_and(|n| triples.len() == 3 * n) {
                break;
            }
            let (lit_length, match_length) = if many || exactly.is_some() {
                (0, 3)
            } else {
                let mut lit_length = small_length(rng, profile.max_literals);
                let mut match_length = 3 + small_length(rng, profile.max_match);
                if !long_used && rng.range(0, 60) == 0 {
                    // A length over 0xFFFF, as one sequence of a block may
                    // have.
                    long_used = true;
                    if rng.range(0, 1) == 0 {
                        lit_length = rng.range(0x10000, 0x10000 + 2000);
                    } else {
                        match_length = rng.range(0x10003, 0x10003 + 2000);
                    }
                }
                (lit_length, match_length)
            };
            if exactly.is_none()
                && size + (lit_length + match_length) as usize > budget.min(128 * 1024 - 64)
            {
                break;
            }
            let off_base = if rng.range(0, profile.repeat_one_in - 1) == 0 {
                rng.range(1, 3)
            } else {
                let offset_log = rng.range(0, profile.max_offset_log);
                3 + rng.range(1, 1 << offset_log)
            };
            triples.extend([off_base, lit_length, match_length]);
            literal_count += lit_length as usize;
            size += (lit_length + match_length) as usize;
        }
        // The last literals, after the last sequence.
        let last = rng.range(0, 64) as usize;
        literal_count += last;
        size += last;
        let start = rng.range(0, ((1 << 17) - literal_count) as u64) as usize;
        let literals = &literal_source[start..start + literal_count];
        let capacity = match rng.range(0, 5) {
            0 => rng.range(0, size as u64),
            1 => rng.range(0, 30),
            _ => (size + 1000).min(1 << 20) as u64,
        };
        requests.push(format!(
            "seqblock {strategy} {literal_mode} {target_length} {capacity} {} {}",
            hex(literals),
            list(triples)
        ));
    }
    requests
}

/// The kinds of a frame's blocks, and whether a full-size one was ended
/// early, for the statistics of the live comparison.
fn frame_block_kinds(frame: &[u8]) -> Vec<String> {
    let descriptor = frame[4];
    let single_segment = descriptor & 0x20 != 0;
    let fcs = [usize::from(single_segment), 2, 4, 8][usize::from(descriptor >> 6)];
    let mut at = 5 + usize::from(!single_segment) + fcs;
    let mut kinds = Vec::new();
    loop {
        let header = u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], 0]);
        let (last, kind, size) = (header & 1, (header >> 1) & 3, (header >> 3) as usize);
        kinds.push(format!(
            "compress block {}",
            ["raw", "rle", "compressed", "reserved"][kind as usize]
        ));
        at += 3 + if kind == 1 { 1 } else { size };
        if last != 0 {
            break;
        }
    }
    kinds
}

/// How a compressed block encodes its parts: its literals, and each kind of
/// code, for the statistics of the live comparison.
fn seq_block_kinds(block: &[u8]) -> Vec<String> {
    const NAMES: [&str; 4] = ["basic", "rle", "compressed", "repeat"];
    let lit_type = usize::from(block[0] & 3);
    let size_format = (block[0] >> 2) & 3;
    let header = u32::from_le_bytes([
        block[0],
        *block.get(1).unwrap_or(&0),
        *block.get(2).unwrap_or(&0),
        *block.get(3).unwrap_or(&0),
    ]);
    let lit_section = match (lit_type, size_format) {
        (0 | 1, 0 | 2) => {
            1 + if lit_type == 0 {
                (block[0] >> 3) as usize
            } else {
                1
            }
        }
        (0 | 1, 1) => {
            2 + if lit_type == 0 {
                ((header & 0xFFFF) >> 4) as usize
            } else {
                1
            }
        }
        (0 | 1, _) => {
            3 + if lit_type == 0 {
                ((header & 0xFF_FFFF) >> 4) as usize
            } else {
                1
            }
        }
        (_, 0 | 1) => 3 + ((header >> 14) & 0x3FF) as usize,
        (_, 2) => 4 + (header >> 18) as usize,
        _ => 5 + ((header >> 22) as usize | (usize::from(block[4]) << 10)),
    };
    let mut kinds = vec![format!("seqblock literals {}", NAMES[lit_type])];
    let mut at = lit_section;
    let nb_seq = match block.get(at) {
        None => return kinds,
        Some(&b) if b < 128 => {
            at += 1;
            usize::from(b)
        }
        Some(&b) if b < 255 => {
            at += 2;
            (usize::from(b - 0x80) << 8) + usize::from(block[at - 1])
        }
        Some(_) => {
            at += 3;
            usize::from(u16::from_le_bytes([block[at - 2], block[at - 1]])) + 0x7F00
        }
    };
    if nb_seq >= 0x7F00 {
        kinds.push("seqblock nbSeq >= LONGNBSEQ".into());
    }
    if nb_seq > 0 {
        let head = block[at];
        for (name, shift) in [("ll", 6), ("of", 4), ("ml", 2)] {
            kinds.push(format!(
                "seqblock {name} {}",
                NAMES[usize::from((head >> shift) & 3)]
            ));
        }
    }
    kinds
}

#[test]
fn port_matches_libzstd_compression() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng::new(0x5EED_0101);
    let requests = requests(&mut oracle, &mut rng, 1500);
    let mut problems = Vec::new();
    // How each command was answered: ok, an error, or otherwise; and for
    // Huffman compression, how the table was chosen.
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
        let command = request.split(' ').next().unwrap_or_default();
        let words: Vec<&str> = want.split(' ').collect();
        if command == "compress" && words[0] == "ok" {
            for kind in frame_block_kinds(&unhex(words[1])) {
                *outcomes.entry(kind).or_default() += 1;
            }
        }
        if command == "cstream" && words[0] == "ok" {
            if request.split(' ').count() == 5 {
                *outcomes
                    .entry("cstream with a dictionary".into())
                    .or_default() += 1;
            }
            for word in &words[1..words.len() - 1] {
                let outcome = match word.split_once('/') {
                    Some((code, _)) if code.starts_with('e') => format!("cstream step {code}"),
                    // No CDict made, from a dictionary that cannot be read.
                    None if *word == "n" => "cstream step n".to_string(),
                    _ => "cstream step ok".to_string(),
                };
                *outcomes.entry(outcome).or_default() += 1;
            }
        }
        if command == "seqblock" && words[0] == "ok" && words[1] != "0" {
            for kind in seq_block_kinds(&unhex(words[2])) {
                *outcomes.entry(kind).or_default() += 1;
            }
        }
        let outcome = match (command, words[0]) {
            ("hufcompress", "ok") if words[1] == "0" || words[1] == "1" => {
                format!("hufcompress ok {}", words[1])
            }
            ("hufcompress", "ok") => format!("hufcompress ok, repeat {}", words[2]),
            (_, "err") => format!("{command} err {}", words[1]),
            (_, first) => format!("{command} {first}"),
        };
        *outcomes.entry(outcome).or_default() += 1;
    }
    eprintln!(
        "compared {} requests with libzstd: {outcomes:?}",
        requests.len()
    );
    assert!(
        problems.is_empty(),
        "{} requests checked, {} differences:\n{}",
        requests.len(),
        problems.len(),
        problems[..problems.len().min(20)].join("\n")
    );
}

/// `ZSTD_compress2` with workers against libzstd's, through `cstream`
/// requests (see `cstream_workers_request`), where the oracle is built with
/// libzstd's threads (`scripts/testdata.py` builds it so): one built from
/// older sources answers `zstdmt` "bad", and the test is skipped.
#[test]
fn port_matches_libzstd_compression_with_workers() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    if oracle.try_ask("zstdmt") != "1" {
        eprintln!(
            "skipping: the oracle is built without libzstd's threads \
             (scripts/testdata.py fetch --group generated)"
        );
        return;
    }
    let mut rng = Rng::new(0x5EED_4D55);
    let count = if cfg!(debug_assertions) { 30 } else { 120 };
    let mut problems = Vec::new();
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for _ in 0..count {
        let request = cstream_workers_request(&mut rng);
        let want = oracle.ask(&request);
        let got = answer(&request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
        // How the frame ended: compressed, or the error.
        let words: Vec<&str> = want.split(' ').collect();
        let last = words[words.len().saturating_sub(2)];
        let outcome = match last.split_once('/') {
            Some((code, _)) if code.starts_with('e') => format!("compress2 {code}"),
            _ => "compress2 ok".to_string(),
        };
        *outcomes.entry(outcome).or_default() += 1;
    }
    eprintln!("compared {count} frames with workers: {outcomes:?}");
    assert!(
        problems.is_empty(),
        "{} differences:\n{}",
        problems.len(),
        problems[..problems.len().min(10)].join("\n")
    );
}

#[test]
fn port_matches_recorded_compression_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/compress.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 1000, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/compress.txt from the oracle"]
fn record_compress_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng::new(0x5EED_0102);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle) about compression, replayed by\n\
         # crates/hivepack/src/zstd/oracle_compress.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features record_compress_answers -- --ignored\n",
    );
    // Runs of blocks are kept whole or left out whole, since each block
    // depends on the ones before.
    let mut runs: Vec<Vec<String>> = Vec::new();
    for request in requests(&mut oracle, &mut rng, 200) {
        if request == "seqreset" || !request.starts_with("seqblock") {
            runs.push(Vec::new());
        }
        if let Some(run) = runs.last_mut() {
            run.push(request);
        }
    }
    for run in runs {
        // Keep the file small: the large inputs are for the live comparison.
        // Huffman requests carry a table, of up to 4 KB of hex.
        let fits = run.iter().all(|request| {
            let limit = if request.starts_with("hufcompress")
                || request.starts_with("seqblock")
                || request.starts_with("compress")
                || request.starts_with("cstream")
            {
                8000
            } else {
                3000
            };
            request.len() <= limit
        });
        if !fits {
            continue;
        }
        for request in run {
            let reply = oracle.ask(&request);
            let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
        }
    }
    std::fs::write(recorded_path(), text).expect("written");
}
