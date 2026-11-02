//! Comparison of the sequence API with libzstd's: frames compressed from
//! sequences the caller gives (`ZSTD_compressSequences`,
//! `ZSTD_compressSequencesAndLiterals`), sequences generated
//! (`ZSTD_generateSequences`) and merged (`ZSTD_mergeBlockDelimiters`), and
//! frames whose blocks a sequence producer finds the sequences of
//! (`ZSTD_registerSequenceProducer`), through the steps 19 to 28 of the
//! oracle's `cstream` request (see `tools/zstd-oracle/oracle.c`). zstd-safe
//! offers none of them.
//!
//! The oracle's sequence producer, `oracle_producer`, is mirrored here,
//! [`OracleProducer`]: a small greedy match finder that fails when told to.
//!
//! As for the other requests, the tests compare thousands of generated
//! requests with libzstd live where the oracle is built, and replay
//! recorded answers everywhere, from `testdata/oracle/sequences.txt`.
//! `cargo test -p hivepack --all-features record_sequence_answers -- --ignored`
//! rewrites it. The frames of the requests whose sequences make the input
//! are also decoded with the port's decoder (the step 28): one that does
//! not decode back makes the port's answer differ.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::zstd::compress::zstd_compress::{
    CCtx, SEQUENCE_PRODUCER_ERROR, Sequence, SequenceProducer, merge_block_delimiters,
    sequence_bound, zstd_compress_bound,
};
use crate::zstd::decompress::zstd_ddict::DictContentType;
use crate::zstd::decompress::zstd_decompress::DParameter;
use crate::zstd::decompress::zstd_decompress_internal::{DCtx, Format};
use crate::zstd::oracle::{Oracle, Rng, fnv64, hex, list, recorded_form, repository, unlist};
use crate::zstd::oracle_compress::{
    answer, cstream_dict, cstream_dict_steps, frame_data, small_length,
};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/sequences.txt")
}

/// The sequences of a request: quadruples offset, literal length, match
/// length and `rep`, as `ZSTD_Sequence`'s `unsigned` fields take them.
fn sequences_unlist(text: &str) -> Vec<Sequence> {
    unlist(text)
        .chunks(4)
        .map(|q| Sequence {
            offset: q[0] as u32,
            lit_length: q[1] as u32,
            match_length: q[2] as u32,
            rep: q[3] as u32,
        })
        .collect()
}

/// The sequences as a request lists them.
fn sequences_list(seqs: &[Sequence]) -> String {
    list(
        seqs.iter()
            .flat_map(|s| [s.offset, s.lit_length, s.match_length, s.rep]),
    )
}

/// FNV-1a of sequences, each as its four fields, little-endian: the
/// oracle's `seqs_hash`.
fn seqs_hash(seqs: &[Sequence]) -> u64 {
    let bytes: Vec<u8> = seqs
        .iter()
        .flat_map(|s| [s.offset, s.lit_length, s.match_length, s.rep])
        .flat_map(u32::to_le_bytes)
        .collect();
    fnv64(&bytes)
}

/// The oracle's `oracle_producer`, of the step 19, mirrored: a greedy match
/// finder over the block alone, that fails as `kind` and `error_every` say
/// (see the oracle).
pub(crate) struct OracleProducer {
    kind: u32,
    error_every: u32,
    calls: u32,
    table: Vec<u32>,
}

impl OracleProducer {
    pub(crate) fn new(kind: u32, error_every: u32) -> Self {
        OracleProducer {
            kind,
            error_every,
            calls: 0,
            table: Vec::new(),
        }
    }
}

impl SequenceProducer for OracleProducer {
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        src: &[u8],
        _dict: &[u8],
        compression_level: i32,
        window_size: usize,
    ) -> usize {
        let call = self.calls;
        self.calls = self.calls.wrapping_add(1);
        let variant = self.kind & 3;
        let mls = if variant == 1 { 3 } else { 4 };
        let hash_log = 8 + if compression_level < 0 {
            0
        } else {
            (compression_level % 8) as u32
        };
        let capacity = out_seqs.len();
        if self.error_every != 0 && call % self.error_every == self.error_every - 1 {
            match (call / self.error_every) % 4 {
                0 => return SEQUENCE_PRODUCER_ERROR,
                1 => return capacity + 1,
                2 => return 0,
                _ => {
                    for seq in out_seqs.iter_mut() {
                        *seq = Sequence {
                            offset: 1,
                            lit_length: 0,
                            match_length: 1,
                            rep: 0,
                        };
                    }
                    return capacity;
                }
            }
        }
        if variant == 2 {
            out_seqs[0] = Sequence {
                offset: 0,
                lit_length: src.len() as u32,
                match_length: 0,
                rep: 0,
            };
            return 1;
        }
        self.table.clear();
        self.table.resize(1 << hash_log, 0);
        let (mut pos, mut anchor, mut n) = (0usize, 0usize, 0usize);
        let mut last_offset = 0u32;
        while pos + 4 <= src.len() && n + 2 < capacity {
            let mut length = 0;
            let mut found = None;
            if variant == 3 && last_offset != 0 && last_offset as usize <= pos {
                let cand = pos - last_offset as usize;
                while pos + length < src.len() && src[cand + length] == src[pos + length] {
                    length += 1;
                }
                if length >= mls {
                    found = Some(cand);
                } else {
                    length = 0;
                }
            }
            let value = if mls == 3 {
                u32::from(src[pos]) | u32::from(src[pos + 1]) << 8 | u32::from(src[pos + 2]) << 16
            } else {
                u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]])
            };
            let h = (value.wrapping_mul(2_654_435_761) >> (32 - hash_log)) as usize;
            let cand = self.table[h];
            self.table[h] = pos as u32 + 1;
            if found.is_none() && cand != 0 && pos - (cand as usize - 1) <= window_size {
                let c = cand as usize - 1;
                while pos + length < src.len() && src[c + length] == src[pos + length] {
                    length += 1;
                }
                if length >= mls {
                    found = Some(c);
                } else {
                    length = 0;
                }
            }
            let Some(match_start) = found else {
                pos += 1;
                continue;
            };
            let mut offset = (pos - match_start) as u32;
            last_offset = offset;
            if self.kind & 16 != 0 && n % 5 == 4 {
                length = 2;
            }
            if self.kind & 32 != 0 && n % 3 == 2 {
                offset = 0x7FFF_FFFF;
            }
            out_seqs[n] = Sequence {
                offset,
                lit_length: (pos - anchor) as u32,
                match_length: length as u32,
                rep: 0,
            };
            n += 1;
            pos += length;
            anchor = pos;
        }
        if self.kind & 4 != 0 || anchor < src.len() {
            out_seqs[n] = Sequence {
                offset: 0,
                lit_length: if self.kind & 8 != 0 {
                    0
                } else {
                    (src.len() - anchor) as u32
                },
                match_length: 0,
                rep: 0,
            };
            n += 1;
        }
        n
    }
}

/// The dictionary a frame is decoded with: its bytes, how to read them,
/// and whether it is a prefix, for one frame.
type DecodeDict = (Vec<u8>, DictContentType, bool);

/// Whether `frame` decodes to `expected` with the port's decoder, with
/// `dict`.
fn decodes_to(frame: &[u8], expected: &[u8], dict: Option<&DecodeDict>) -> bool {
    let mut dctx = DCtx::new();
    if !frame.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        && dctx
            .set_parameter(DParameter::Format(Format::Zstd1Magicless))
            .is_err()
    {
        return false;
    }
    let mut out = vec![0u8; expected.len() + 1];
    let result = match dict {
        None => dctx.decompress(&mut out, frame),
        Some((bytes, DictContentType::RawContent, true)) => dctx
            .ref_prefix(bytes)
            .and_then(|()| dctx.decompress(&mut out, frame)),
        // A prefix read as a zstd dictionary if it is one.
        Some((bytes, _, true)) => dctx.decompress_using_dict(&mut out, frame, bytes),
        Some((bytes, content_type, false)) => dctx
            .load_dictionary_advanced(bytes, *content_type)
            .and_then(|()| dctx.decompress(&mut out, frame)),
    };
    matches!(result, Ok(size) if out[..size] == *expected)
}

/// The state of the steps 19 to 28 of a `cstream` request: the sequences
/// and their window, and what the decode checks need.
pub(crate) struct SequenceSteps {
    seqs: Vec<Sequence>,
    nseqs: usize,
    win_first: usize,
    win_count: usize,
    /// The decompressed size of the step 22; negative for the window's.
    decompressed: i64,
    /// Whether the frames of the steps 6, 21 and 22 are to decode back
    /// (the step 28).
    expect_decodable: bool,
    /// The dictionary the steps set last, for the decode checks.
    decode_dict: Option<DecodeDict>,
}

impl SequenceSteps {
    /// The state of a request with the sequences `seqs` (a list, or "-").
    pub(crate) fn new(seqs: &str) -> Self {
        let seqs = sequences_unlist(seqs);
        let nseqs = seqs.len();
        SequenceSteps {
            seqs,
            nseqs,
            win_first: 0,
            win_count: nseqs,
            decompressed: -1,
            expect_decodable: false,
            decode_dict: None,
        }
    }

    /// The dictionary step `op` (11 to 18) succeeded, with `piece` (the b
    /// bytes at a) or `head` (the first a bytes) of the dictionary bytes.
    pub(crate) fn dictionary_set(&mut self, op: i64, b: i64, piece: &[u8], head: &[u8]) {
        let content_type = |which| match which {
            1 => DictContentType::RawContent,
            2 => DictContentType::FullDict,
            _ => DictContentType::Auto,
        };
        self.decode_dict = match op {
            11..=13 if !piece.is_empty() => Some((piece.to_vec(), content_type(op - 11), false)),
            14 if !piece.is_empty() => Some((piece.to_vec(), DictContentType::RawContent, true)),
            15 if !piece.is_empty() => Some((piece.to_vec(), DictContentType::Auto, true)),
            16 => Some((head.to_vec(), DictContentType::Auto, false)),
            17 => Some((head.to_vec(), content_type(b), false)),
            _ => None,
        };
    }

    /// A frame was started (or could have been): a prefix serves only one.
    pub(crate) fn frame_started(&mut self) {
        if self.decode_dict.as_ref().is_some_and(|dict| dict.2) {
            self.decode_dict = None;
        }
    }

    /// When the frames are to decode back: a marker unless `frame` decodes
    /// to `expected`; nothing otherwise.
    pub(crate) fn check_frame(&self, frame: &[u8], expected: &[u8]) -> &'static str {
        if !self.expect_decodable || decodes_to(frame, expected, self.decode_dict.as_ref()) {
            ""
        } else {
            " does-not-decode"
        }
    }

    /// The step `[op, a, b]`, 19 to 28, on `cctx`, over `src` and `out`
    /// from the positions, which it moves on as the oracle does. Returns
    /// its answer.
    pub(crate) fn step(
        &mut self,
        cctx: &mut CCtx,
        [op, a, b]: [i64; 3],
        src: &[u8],
        out: &mut [u8],
        in_pos: &mut usize,
        out_pos: &mut usize,
    ) -> String {
        let capacity = out.len();
        let in_end = (*in_pos + a.max(0) as usize).min(src.len());
        let out_end = (*out_pos + b.max(0) as usize).min(capacity);
        let window = self.win_first..self.win_first + self.win_count;
        let failed = |error: crate::zstd::Error, in_pos: usize, out_pos: usize| {
            format!(" e{}/{in_pos}/{out_pos}", error.code().number())
        };
        match op {
            19 => {
                cctx.register_sequence_producer(Some(Box::new(OracleProducer::new(
                    a as u32, b as u32,
                ))));
                " s".into()
            }
            20 => {
                cctx.register_sequence_producer(None);
                " s".into()
            }
            21 => {
                let result = cctx.compress_sequences(
                    &mut out[*out_pos..out_end],
                    &self.seqs[window],
                    &src[*in_pos..in_end],
                );
                let mut text = String::new();
                match result {
                    Ok(size) => {
                        text.push_str(
                            self.check_frame(
                                &out[*out_pos..*out_pos + size],
                                &src[*in_pos..in_end],
                            ),
                        );
                        *in_pos = in_end;
                        *out_pos += size;
                        let _ = write!(text, " {}/{in_pos}/{out_pos}", size as u32);
                    }
                    Err(error) => text = failed(error, *in_pos, *out_pos),
                }
                self.frame_started();
                text
            }
            22 => {
                let total = self.seqs[window.clone()].iter().fold(0usize, |sum, s| {
                    sum.wrapping_add(s.lit_length as usize)
                        .wrapping_add(s.match_length as usize)
                });
                let d_size = if self.decompressed < 0 {
                    total
                } else {
                    self.decompressed as usize
                };
                let result = cctx.compress_sequences_and_literals(
                    &mut out[*out_pos..out_end],
                    &self.seqs[window],
                    &src[*in_pos..in_end],
                    d_size,
                );
                let mut text = String::new();
                match result {
                    Ok(size) => {
                        let end = if d_size < src.len() - in_end {
                            in_end + d_size
                        } else {
                            src.len()
                        };
                        text.push_str(
                            self.check_frame(&out[*out_pos..*out_pos + size], &src[in_end..end]),
                        );
                        *in_pos = end;
                        *out_pos += size;
                        let _ = write!(text, " {}/{in_pos}/{out_pos}", size as u32);
                    }
                    Err(error) => text = failed(error, *in_pos, *out_pos),
                }
                self.frame_started();
                text
            }
            23 => {
                self.win_first = (a.max(0) as usize).min(self.nseqs);
                self.win_count = if b < 0 || b as usize > self.nseqs - self.win_first {
                    self.nseqs - self.win_first
                } else {
                    b as usize
                };
                " s".into()
            }
            24 => {
                self.decompressed = a;
                " s".into()
            }
            25 => {
                let piece = &src[*in_pos..in_end];
                let room = if b < 0 {
                    sequence_bound(piece.len())
                } else {
                    b as usize
                };
                if self.seqs.len() < room {
                    self.seqs.resize(room, Sequence::default());
                }
                self.seqs[..room].fill(Sequence::default());
                #[allow(deprecated)]
                let result = cctx.generate_sequences(&mut self.seqs[..room], piece);
                self.frame_started();
                match result {
                    Ok(count) => {
                        self.nseqs = count;
                        self.win_first = 0;
                        self.win_count = count;
                        format!(
                            " {count}/{in_pos}/{out_pos}:{:016x}",
                            seqs_hash(&self.seqs[..count])
                        )
                    }
                    Err(error) => failed(error, *in_pos, *out_pos),
                }
            }
            26 => format!(
                " v{}",
                cctx.get_parameter(crate::zstd::oracle_compress::c_parameter_kind(a))
            ),
            27 => {
                self.win_count = merge_block_delimiters(&mut self.seqs[window]);
                format!(
                    " m{}:{:016x}",
                    self.win_count,
                    seqs_hash(&self.seqs[self.win_first..self.win_first + self.win_count])
                )
            }
            _ => {
                self.expect_decodable = true;
                " s".into()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Requests

/// Sequences and the input they make, built together: each match copies
/// what is `offset` back, so that any offset within the input so far and
/// the dictionary is valid.
struct Built {
    seqs: Vec<Sequence>,
    src: Vec<u8>,
    /// The literals, one after the other.
    literals: Vec<u8>,
}

/// How [`build_sequences`] makes sequences.
struct BuildPlan<'a> {
    /// The dictionary the offsets may reach into, at the start.
    dict: &'a [u8],
    len: usize,
    /// With block delimiters, the largest block.
    blocks: Option<usize>,
    min_match: u32,
    /// The window: offsets reach no farther once the input is larger.
    window: usize,
    /// One in how many matches is as long as 2000 bytes.
    long_one_in: u64,
}

/// Sequences making about `plan.len` bytes, with block delimiters ending
/// blocks of up to `plan.blocks` bytes, or without them.
fn build_sequences(rng: &mut Rng, plan: &BuildPlan<'_>) -> Built {
    let mut history = plan.dict.to_vec();
    let dict_len = plan.dict.len();
    let mut seqs = Vec::new();
    let mut literals = Vec::new();
    let mut offsets = [1usize, 4, 8];
    let alphabet = rng.range(2, 255) as u8;
    let mut pending_literals = 0u32;
    let len = plan.len;
    let block_max = plan.blocks.unwrap_or(len.max(1));
    while history.len() - dict_len < len {
        let block_len =
            (rng.range(1, block_max as u64) as usize).min(len - (history.len() - dict_len));
        let block_end = history.len() + block_len;
        loop {
            let room = block_end - history.len();
            let lit = (small_length(rng, 40) as usize).min(room);
            if room - lit < plan.min_match as usize + 1 {
                break;
            }
            let longest = if rng.range(0, plan.long_one_in) == 0 {
                2000
            } else {
                60
            };
            let match_length =
                (plan.min_match as usize + small_length(rng, longest) as usize).min(room - lit);
            for _ in 0..lit {
                let byte = rng.range(0, u64::from(alphabet)) as u8;
                history.push(byte);
                literals.push(byte);
            }
            // Within the input so far and the dictionary, and as
            // ZSTD_validateSequence counts from the match's end, within
            // the window past it.
            let pos = history.len() - dict_len;
            let reach = if pos + match_length > plan.window {
                plan.window.min(pos + dict_len)
            } else {
                pos + dict_len
            };
            let offset = match rng.range(0, 5) {
                0..=1 if offsets[0] <= reach => offsets[0],
                2 if offsets[1] <= reach => offsets[1],
                3 if lit == 0 && offsets[0] > 1 && offsets[0] - 1 <= reach => offsets[0] - 1,
                _ if reach == 0 => 0,
                _ => {
                    let far = 1usize << rng.range(3, 17);
                    rng.range(1, reach.min(far) as u64) as usize
                }
            };
            if offset == 0 {
                // Nothing to copy yet: literals.
                for _ in 0..match_length {
                    let byte = rng.range(0, u64::from(alphabet)) as u8;
                    history.push(byte);
                    literals.push(byte);
                }
                pending_literals += (lit + match_length) as u32;
                continue;
            }
            for _ in 0..match_length {
                let byte = history[history.len() - offset];
                history.push(byte);
            }
            offsets = [offset, offsets[0], offsets[1]];
            seqs.push(Sequence {
                offset: offset as u32,
                lit_length: pending_literals + lit as u32,
                match_length: match_length as u32,
                rep: rng.range(0, 3) as u32,
            });
            pending_literals = 0;
        }
        // The rest of the block: literals.
        let rest = block_end - history.len();
        for _ in 0..rest {
            let byte = rng.range(0, u64::from(alphabet)) as u8;
            history.push(byte);
            literals.push(byte);
        }
        pending_literals += rest as u32;
        if plan.blocks.is_some() {
            seqs.push(Sequence {
                offset: 0,
                lit_length: pending_literals,
                match_length: 0,
                rep: rng.range(0, 3) as u32,
            });
            pending_literals = 0;
        }
    }
    Built {
        seqs,
        src: history.split_off(dict_len),
        literals,
    }
}

/// Parameters for the frames of sequences, as `cstream` steps: a level, and
/// some of the others that change them.
fn frame_parameter_steps(rng: &mut Rng, steps: &mut Vec<i64>) {
    let level: i64 = match rng.range(0, 5) {
        0 => -(rng.range(1, 7) as i64),
        1 => rng.range(1, 9) as i64,
        2 => rng.range(10, 22) as i64,
        _ => 3,
    };
    steps.extend([7, 100, level]);
    for (number, low, high) in [
        // The strategy (for the entropy coding: minGain, and the literals
        // of fast), the target length, the checksum, the content size,
        // the dictionary ID, the format, the literal compression mode.
        (107, 0, 9),
        (106, 0, 300),
        (201, 0, 1),
        (200, 0, 1),
        (202, 0, 1),
        (10, 0, 1),
        (1002, 0, 2),
    ] {
        if rng.range(0, 4) == 0 {
            steps.extend([7, number, rng.range(low, high) as i64]);
        }
    }
}

/// Steps reading back the sequence API's parameters, and sometimes all the
/// others.
fn get_parameter_steps(rng: &mut Rng, steps: &mut Vec<i64>) {
    let all = [
        100, 101, 102, 103, 104, 105, 106, 107, 200, 201, 202, 10, 1002, 1004, 1006, 1007, 1015,
        1017, 1010, 160, 161, 162, 163, 164, 1011, 1005, 400, 401, 402, 500, 1001, 1008, 1009,
        1014, 1016,
    ];
    if rng.range(0, 4) == 0 {
        for number in all {
            steps.extend([26, number, 0]);
        }
    } else {
        for number in [1008, 1009, 1014, 1016] {
            steps.extend([26, number, 0]);
        }
    }
}

/// A request that generates the sequences of an input with libzstd's match
/// finder (`ZSTD_generateSequences`), at a level and with parameters, then
/// compresses them back with `ZSTD_compressSequences`, with block
/// delimiters, or merged (`ZSTD_mergeBlockDelimiters`) and without.
fn generated_request(rng: &mut Rng, i: usize, small: bool) -> String {
    let len = match i % 8 {
        0 => rng.range(0, 40),
        1 => rng.range(100_000, 300_000),
        // A last block too small to have sequences.
        2 => 131_072 + rng.range(1, 6),
        _ => rng.range(40, 20_000),
    } as usize;
    let len = if small { len.min(SMALL) } else { len };
    let src = frame_data(rng, len);
    let mut steps: Vec<i64> = Vec::new();
    get_parameter_steps(rng, &mut steps);

    // The generation: every level, strategies, the block splitter after the
    // sequences, blocks and windows.
    let level: i64 = match rng.range(0, 6) {
        0 => -(rng.range(1, 7) as i64),
        1 | 2 => rng.range(1, 9) as i64,
        3 | 4 => rng.range(10, 19) as i64,
        _ => rng.range(19, 22) as i64,
    };
    steps.extend([7, 100, level]);
    if rng.range(0, 3) == 0 {
        steps.extend([7, 107, rng.range(1, 9) as i64]);
    }
    if rng.range(0, 2) == 0 {
        steps.extend([7, 1010, rng.range(0, 2) as i64]);
    }
    let gen_block = if rng.range(0, 3) == 0 {
        let max_block = [1024, 4096, 20_000][rng.range(0, 2) as usize];
        steps.extend([7, 1015, max_block]);
        max_block as usize
    } else {
        131_072
    };
    if rng.range(0, 3) == 0 {
        steps.extend([7, 105, rng.range(3, 7) as i64]);
    }
    let set_window = rng.range(0, 5) == 0;
    if set_window {
        steps.extend([7, 101, rng.range(10, 17) as i64]);
    }
    if rng.range(0, 6) == 0 {
        // Long distance matching, with small parameters.
        steps.extend([7, 160, 1, 7, 162, rng.range(4, 64) as i64]);
    }
    // A dictionary, sometimes: the sequences reach into it.
    let mut dict = if rng.range(0, 3) == 0 && !src.is_empty() {
        cstream_dict(rng, &src)
    } else {
        Vec::new()
    };
    if small {
        dict.truncate(SMALL);
    }
    let mut dict_steps = Vec::new();
    if !dict.is_empty() {
        dict_steps = cstream_dict_steps(rng, dict.len(), false);
        steps.extend(&dict_steps);
    }
    let workers = rng.range(0, 15) == 0;
    if workers {
        steps.extend([7, 400, 2]);
    }
    let room: i64 = match rng.range(0, 9) {
        0 => rng.range(0, 40) as i64,
        _ => -1,
    };
    steps.extend([25, len as i64, room]);
    if workers {
        steps.extend([7, 400, 0]);
    }

    // The compression of the sequences.
    if rng.range(0, 4) == 0 {
        steps.extend([27, 0, 0, 7, 1008, 0]);
    } else {
        steps.extend([7, 1008, 1]);
    }
    let validate = rng.range(0, 1) == 0;
    steps.extend([7, 1009, i64::from(validate)]);
    steps.extend([7, 1016, rng.range(0, 2) as i64]);
    frame_parameter_steps(rng, &mut steps);
    let mut decodable = !set_window;
    if rng.range(0, 6) == 0 {
        // Smaller blocks than the sequences' (explicit delimiters fail).
        steps.extend([7, 1015, [1024, 2000][rng.range(0, 1) as usize]]);
    } else {
        steps.extend([7, 1015, gen_block as i64]);
    }
    if rng.range(0, 6) == 0 {
        // A longer shortest match: the validation fails on shorter ones.
        steps.extend([7, 105, rng.range(4, 7) as i64]);
    }
    // A prefix serves one frame: set again for the sequences.
    if dict_steps.len() == 6 && (dict_steps[3] == 14 || dict_steps[3] == 15) {
        steps.extend(&dict_steps[3..]);
    }
    if !dict.is_empty() && rng.range(0, 8) == 0 {
        // The sequences without their dictionary.
        steps.extend([18, 0, 0]);
        decodable = false;
    }
    if decodable {
        steps.extend([28, 0, 0]);
    }
    let bound = zstd_compress_bound(len).unwrap_or(0) as i64;
    let room = match rng.range(0, 8) {
        0 => rng.range(18, (bound as u64).max(19)) as i64,
        _ => bound + 64,
    };
    steps.extend([21, len as i64, room]);
    get_parameter_steps(rng, &mut steps);
    match rng.range(0, 5) {
        // Still in the frame for most parameters, until a reset.
        0 => steps.extend([7, 1009, 1, 7, 100, 5, 8, 1, 0, 7, 1009, 0]),
        // An empty frame next: the sequences are not read.
        1 => steps.extend([21, 0, 100]),
        _ => {}
    }
    let capacity = 2 * bound + 200;
    format!(
        "cstream {capacity} {} {} {} -",
        list(steps),
        hex(&src),
        hex(&dict)
    )
}

/// A request that compresses sequences built with their input
/// (`build_sequences`), valid or with a fault, with block delimiters or
/// without, with a dictionary prefix sometimes.
fn built_request(rng: &mut Rng, i: usize, small: bool) -> String {
    let explicit = rng.range(0, 2) != 0;
    let max_block = if rng.range(0, 3) == 0 {
        [1024, 3000, 20_000][rng.range(0, 2) as usize]
    } else {
        131_072
    };
    let len = match i % 6 {
        0 => rng.range(0, 20),
        1 => rng.range(50_000, 400_000),
        _ => rng.range(20, 30_000),
    } as usize;
    let len = if small { len.min(SMALL) } else { len };
    let min_match = if rng.range(0, 2) == 0 { 3 } else { 4 };
    let window_log = (rng.range(0, 4) == 0).then(|| rng.range(10, 17));
    let dict = if rng.range(0, 3) == 0 {
        let dict_len = rng.range(1, if small { SMALL as u64 } else { 5000 }) as usize;
        rng.lz_data(dict_len)
    } else {
        Vec::new()
    };
    let plan = BuildPlan {
        dict: &dict,
        len,
        blocks: explicit.then_some(max_block.min(window_log.map_or(usize::MAX, |log| 1 << log))),
        min_match,
        window: window_log.map_or(usize::MAX, |log| 1 << log),
        long_one_in: if rng.range(0, 3) == 0 { 4 } else { 200 },
    };
    let Built {
        mut seqs, mut src, ..
    } = build_sequences(rng, &plan);

    let mut steps: Vec<i64> = vec![7, 1008, i64::from(explicit)];
    frame_parameter_steps(rng, &mut steps);
    let validate = rng.range(0, 2) != 0;
    steps.extend([7, 1009, i64::from(validate)]);
    steps.extend([7, 1016, rng.range(0, 2) as i64]);
    steps.extend([7, 1015, max_block as i64]);
    steps.extend([7, 105, i64::from(min_match)]);
    if let Some(log) = window_log {
        steps.extend([7, 101, log as i64]);
    }
    if rng.range(0, 8) == 0 {
        // A sequence producer registered: matches of 3 bytes are valid,
        // and blocks hold more sequences.
        steps.extend([19, 0, 0]);
    }
    if !dict.is_empty() {
        steps.extend([14, 0, dict.len() as i64]);
    }

    // A fault, a third of the time.
    let mut valid = true;
    if rng.range(0, 2) == 0 && !seqs.is_empty() {
        valid = false;
        let at = rng.range(0, seqs.len() as u64 - 1) as usize;
        let is_match = seqs[at].match_length != 0;
        match rng.range(0, 8) {
            // An offset too far.
            0 if is_match => seqs[at].offset += 1 << rng.range(0, 20),
            // A match too short for the shortest match, or of 0 to 2 bytes.
            1 if is_match => {
                let shorter = rng.range(1, u64::from(seqs[at].match_length.min(4)));
                seqs[at].match_length -= shorter as u32;
                seqs[at].lit_length += shorter as u32;
            }
            // A delimiter missing.
            2 if explicit => {
                seqs.pop();
            }
            // An input too short for the sequences (only with delimiters:
            // without, libzstd can then read out of its buffers).
            3 if explicit && !src.is_empty() => {
                src.truncate(src.len() - rng.range(1, src.len().min(100) as u64) as usize);
            }
            // An input longer than the sequences: without delimiters, the
            // rest is literals, and valid.
            4 => {
                let more = rng.range(1, 300) as usize;
                src.extend(rng.bytes(more));
                valid = !explicit;
            }
            // An offset of 0 with a match.
            5 if is_match => seqs[at].offset = 0,
            // A delimiter in the middle (without delimiters, a sequence
            // like any other).
            6 if is_match && seqs[at].lit_length > 0 => {
                seqs.insert(
                    at,
                    Sequence {
                        offset: 0,
                        lit_length: 0,
                        match_length: 0,
                        rep: 0,
                    },
                );
                valid = explicit;
            }
            _ => valid = true,
        }
    }
    if valid && rng.range(0, 6) != 0 {
        steps.extend([28, 0, 0]);
    }
    let bound = zstd_compress_bound(src.len()).unwrap_or(0) as i64;
    let room = match rng.range(0, 8) {
        0 => rng.range(18, (bound as u64).max(19)) as i64,
        _ => bound + 64,
    };
    steps.extend([21, src.len() as i64, room]);
    if rng.range(0, 4) == 0 {
        get_parameter_steps(rng, &mut steps);
    }
    let capacity = bound + 200;
    format!(
        "cstream {capacity} {} {} {} {}",
        list(steps),
        hex(&src),
        hex(&dict),
        sequences_list(&seqs)
    )
}

/// A request for `ZSTD_compressSequencesAndLiterals`, of sequences built
/// with their input: the literals, then the input they make, in the
/// request's input; valid, or with a fault.
fn literals_request(rng: &mut Rng, i: usize, small: bool) -> String {
    let len = match i % 6 {
        0 => rng.range(0, 30),
        1 => rng.range(50_000, 300_000),
        _ => rng.range(30, 30_000),
    } as usize;
    let len = if small { len.min(SMALL) } else { len };
    let max_block = if rng.range(0, 3) == 0 {
        [2000, 20_000][rng.range(0, 1) as usize]
    } else {
        131_072
    };
    let plan = BuildPlan {
        dict: &[],
        len,
        blocks: Some(max_block),
        min_match: if rng.range(0, 2) == 0 { 3 } else { 4 },
        window: usize::MAX,
        long_one_in: if rng.range(0, 3) == 0 { 4 } else { 200 },
    };
    let Built {
        mut seqs,
        src,
        mut literals,
    } = build_sequences(rng, &plan);
    let mut steps: Vec<i64> = vec![7, 1008, 1];
    frame_parameter_steps(rng, &mut steps);
    // No checksum (unless as a fault).
    steps.extend([7, 201, 0]);
    steps.extend([7, 1016, rng.range(0, 2) as i64]);
    if rng.range(0, 8) == 0 {
        steps.extend([19, 0, 0]);
    }
    let mut valid = true;
    let mut lit_count = literals.len() as i64;
    match rng.range(0, 14) {
        0 => {
            steps.extend([7, 201, 1]);
            valid = false;
        }
        1 => {
            steps.extend([7, 1009, 1]);
            valid = false;
        }
        2 => {
            steps.extend([7, 1008, 0]);
            valid = false;
        }
        // Too few literals, or too many.
        3 if lit_count > 0 => {
            lit_count -= rng.range(1, lit_count.min(50) as u64) as i64;
            valid = false;
        }
        4 => {
            let more = rng.range(1, 50) as usize;
            literals.extend(rng.bytes(more));
            lit_count += more as i64;
            valid = false;
        }
        // Another decompressed size.
        5 => {
            steps.extend([
                24,
                (src.len() as i64 + rng.range(0, 20) as i64 - 10).max(0),
                0,
            ]);
            valid = false;
        }
        // No delimiter at the end.
        6 if !seqs.is_empty() => {
            seqs.pop();
            valid = false;
        }
        // Literals that do not compress, or no sequences at all.
        7 => {
            let n = literals.len();
            literals = rng.bytes(n);
            valid = false;
        }
        // All of it as literals, in one block: of the input's size only
        // without matches, and then perhaps larger than a block.
        8 => {
            seqs = vec![Sequence {
                offset: 0,
                lit_length: literals.len() as u32,
                match_length: 0,
                rep: 0,
            }];
            valid = false;
        }
        _ => {}
    }
    if valid && rng.range(0, 6) != 0 {
        steps.extend([28, 0, 0]);
    }
    let bound = zstd_compress_bound(src.len()).unwrap_or(0) as i64;
    let room = match rng.range(0, 8) {
        0 => rng.range(18, (bound as u64).max(19)) as i64,
        _ => bound + 64,
    };
    steps.extend([22, lit_count, room]);
    let mut input = literals[..(lit_count.max(0) as usize).min(literals.len())].to_vec();
    input.extend(&src);
    let capacity = bound + 200;
    format!(
        "cstream {capacity} {} {} - {}",
        list(steps),
        hex(&input),
        sequences_list(&seqs)
    )
}

/// A request that compresses with the oracle's sequence producer
/// registered: through `ZSTD_compress2`, streaming, or
/// `ZSTD_generateSequences`; with failures and the fallback, long distance
/// matching and workers (refused), dictionaries (for the fallback), and a
/// producer registered while a frame is streamed.
fn producer_request(rng: &mut Rng, i: usize, small: bool) -> String {
    let len = match i % 6 {
        0 => rng.range(0, 40),
        1 => rng.range(100_000, 400_000),
        _ => rng.range(40, 30_000),
    } as usize;
    let len = if small { len.min(SMALL) } else { len };
    let src = frame_data(rng, len);
    let mut steps: Vec<i64> = Vec::new();
    frame_parameter_steps(rng, &mut steps);
    let validate = rng.range(0, 1) == 0;
    steps.extend([7, 1009, i64::from(validate)]);
    let fallback = rng.range(0, 1) == 0;
    steps.extend([7, 1014, i64::from(fallback)]);
    let repcodes = rng.range(0, 2) as i64;
    steps.extend([7, 1016, repcodes]);
    let split = rng.range(0, 2);
    steps.extend([7, 1010, split as i64]);
    if rng.range(0, 3) == 0 {
        steps.extend([7, 1015, [1024, 4096, 30_000][rng.range(0, 2) as usize]]);
    }
    if rng.range(0, 4) == 0 {
        steps.extend([7, 101, rng.range(10, 18) as i64]);
    }
    if rng.range(0, 4) == 0 {
        steps.extend([7, 1017, rng.range(0, 6) as i64]);
    }
    let mut valid = true;
    match rng.range(0, 14) {
        // Long distance matching, or workers: refused.
        0 => {
            steps.extend([7, 160, 1]);
            valid = false;
        }
        1 => {
            steps.extend([7, 400, rng.range(1, 3) as i64]);
            valid = false;
        }
        _ => {}
    }
    let mut dict = if rng.range(0, 4) == 0 && !src.is_empty() {
        cstream_dict(rng, &src)
    } else {
        Vec::new()
    };
    if small {
        dict.truncate(SMALL);
    }
    if !dict.is_empty() {
        steps.extend(cstream_dict_steps(rng, dict.len(), false));
    }

    // The producer: the parse it makes, and how often it fails.
    let mut kind = rng.range(0, 3) as i64;
    if rng.range(0, 1) == 0 {
        kind |= 4;
    }
    if rng.range(0, 7) == 0 {
        // A parse that does not add up, matches too short (only checked,
        // or without the block splitter: libzstd's then reads past the
        // block), or offsets too far.
        kind |= [8, 16, 32][rng.range(0, 2) as usize];
        if kind & 16 != 0 && !validate {
            steps.extend([7, 1010, 2]);
        }
        valid = false;
    }
    let error_every = match rng.range(0, 3) {
        0 => 0,
        _ => rng.range(1, 5) as i64,
    };
    if error_every != 0 && !fallback {
        valid = false;
    }
    // A block the context compresses itself, with the strategies up to
    // btlazy2, leaves the third repeat offset as it was, where the decoder
    // has another: a repeat code of the next block the producer gives can
    // then stand for another offset, as in libzstd (see
    // CCtx::register_sequence_producer).
    if error_every != 0 && fallback && repcodes != 2 {
        valid = false;
    }
    steps.extend([19, kind, error_every]);
    if valid && rng.range(0, 5) != 0 {
        steps.extend([28, 0, 0]);
    }

    let bound = zstd_compress_bound(len).unwrap_or(0) as i64;
    match rng.range(0, 6) {
        // Streaming, a producer registered (or none) in the middle of the
        // frame: for the next.
        0 | 1 => {
            let mut given = 0i64;
            for _ in 0..rng.range(1, 8) {
                let piece = rng.range(0, 60_000) as i64;
                given += piece;
                let directive = if rng.range(0, 4) == 0 { 1 } else { 0 };
                steps.extend([directive, piece, rng.range(0, 200_000) as i64]);
                if rng.range(0, 5) == 0 {
                    if rng.range(0, 1) == 0 {
                        steps.extend([19, rng.range(0, 7) as i64, rng.range(0, 4) as i64]);
                    } else {
                        steps.extend([20, 0, 0]);
                    }
                }
            }
            for _ in 0..rng.range(1, 3) {
                steps.extend([2, len as i64 - given.min(len as i64) + 1, 1 << 30]);
            }
            // The next frame, with the producer registered last.
            steps.extend([6, 5000, bound + 64]);
        }
        // The sequences of the producer, gathered.
        2 => {
            steps.extend([25, len as i64, -1]);
        }
        _ => {
            let room = match rng.range(0, 8) {
                0 => rng.range(0, bound as u64) as i64,
                _ => bound + 64,
            };
            steps.extend([6, len as i64, room]);
        }
    }
    let capacity = 2 * bound + 10_000;
    format!(
        "cstream {capacity} {} {} {} -",
        list(steps),
        hex(&src),
        hex(&dict)
    )
}

/// The largest input and dictionary of the requests recorded, for a small
/// file: the large ones are for the live comparison.
const SMALL: usize = 700;

/// Requests for the sequence API, `count` of each kind; `small` ones for
/// the file of recorded answers.
fn requests(rng: &mut Rng, count: usize, small: bool) -> Vec<String> {
    let mut requests = Vec::new();
    for i in 0..count {
        requests.push(generated_request(rng, i, small));
        requests.push(built_request(rng, i, small));
        requests.push(literals_request(rng, i, small));
        requests.push(producer_request(rng, i, small));
    }
    requests
}

#[test]
fn port_matches_libzstd_sequences() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng::new(0x5EED_5E05);
    let count = if cfg!(debug_assertions) { 100 } else { 400 };
    let requests = requests(&mut rng, count, false);
    let mut problems = Vec::new();
    // How the steps went: each kind's results, by libzstd's answers.
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
        let steps = unlist(request.split(' ').nth(2).unwrap_or("-"));
        let ops: Vec<i64> = steps.chunks(3).map(|step| step[0]).collect();
        let words: Vec<&str> = want.split(' ').collect();
        for (op, word) in ops.iter().zip(&words[1..]) {
            let name = match op {
                6 => "compress2",
                19 => "register",
                21 => "compressSequences",
                22 => "compressSequencesAndLiterals",
                25 => "generateSequences",
                27 => "mergeBlockDelimiters",
                _ => continue,
            };
            let result = match word.split_once('/') {
                Some((code, _)) if code.starts_with('e') => code.to_string(),
                _ => "ok".to_string(),
            };
            *outcomes.entry(format!("{name} {result}")).or_default() += 1;
        }
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
        problems[..problems.len().min(10)].join("\n")
    );
}

#[test]
fn port_matches_recorded_sequence_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/sequences.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked >= 400, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/sequences.txt from the oracle"]
fn record_sequence_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng::new(0x5EED_5E06);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle) about the sequence API, replayed\n\
         # by crates/hivepack/src/zstd/oracle_sequences.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features record_sequence_answers -- --ignored\n",
    );
    for request in requests(&mut rng, 100, true) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}
