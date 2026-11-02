//! Comparison with libzstd's internal functions.
//!
//! `tools/zstd-oracle` is a small C program, built with libzstd 1.5.7's
//! sources by `scripts/testdata.py`. It answers requests such as
//! `ncount 255 <hex>` by calling the C function, one line per request.
//! [`answer`] answers the same requests with the port, in the same format,
//! so the two can be compared as text.
//!
//! Two kinds of test use it:
//! - With the oracle built, thousands of generated requests are compared
//!   with libzstd directly. Valid inputs come from libzstd's own encoder
//!   (`mkncount`, `mkhuf`), then are mutated; random bytes cover the rest.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/common.txt` replays
//!   answers libzstd gave earlier. `cargo test record_oracle_answers --
//!   --ignored` rewrites that file.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::zstd::common::bitstream::BitDStream;
use crate::zstd::common::entropy_common::{
    HUF_READ_STATS_WORKSPACE_SIZE, fse_read_ncount, huf_read_stats_wksp,
};
use crate::zstd::common::error_private::Error;
use crate::zstd::common::error_private::ErrorCode;
use crate::zstd::common::fse::{
    FSE_MAX_SYMBOL_VALUE, FSE_MAX_TABLELOG, FseDTable, fse_build_dtable_wksp_size_u32,
    fse_decompress_wksp_size_u32,
};
use crate::zstd::common::fse_decompress::{
    FseBuildDTableWksp, FseDecompressWksp, fse_build_dtable_internal, fse_decompress_wksp,
};
use crate::zstd::common::huf::{HUF_FLAGS_DISABLE_FAST, HUF_TABLELOG_MAX};
use crate::zstd::common::xxhash::xxh64;
use crate::zstd::decompress::huf_decompress::{
    HufDTable, HufDecompressWksp, HufReadDTableX1Workspace, HufReadDTableX2Workspace,
    huf_decompress1x_dctx_wksp, huf_decompress1x_using_dtable, huf_decompress4x_huf_only_wksp,
    huf_decompress4x_using_dtable, huf_read_dtable_x1_wksp, huf_read_dtable_x2_wksp,
};
use crate::zstd::decompress::zstd_decompress::{DParameter, InBuffer, OutBuffer};
use crate::zstd::decompress::zstd_decompress_block::{BlockOut, decompress_block};
use crate::zstd::decompress::zstd_decompress_internal::{DCtx, ExtDict};

/// The largest workspace the oracle gives `FSE_decompress_wksp_bmi2`.
const FSE_DECOMPRESS_MAX_WKSP: usize =
    fse_decompress_wksp_size_u32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE) * 4;

pub(crate) fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/common.txt")
}

/// The oracle program, running.
pub(crate) struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    pub(crate) fn spawn() -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join("zstd-oracle");
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            eprintln!(
                "skipping: the oracle is not built (scripts/testdata.py fetch --group generated)"
            );
            return None;
        }
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    /// The answer to `request`, "bad" included: for a request an oracle
    /// built from older sources does not know.
    pub(crate) fn try_ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        line.trim_end().to_string()
    }

    pub(crate) fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            line != "bad" && !line.is_empty(),
            "the oracle answered {line:?} to {request:.200}"
        );
        line
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

pub(crate) fn list<T: std::fmt::Display>(values: impl IntoIterator<Item = T>) -> String {
    let text: Vec<String> = values.into_iter().map(|v| v.to_string()).collect();
    if text.is_empty() {
        "-".into()
    } else {
        text.join(",")
    }
}

pub(crate) fn unlist(text: &str) -> Vec<i64> {
    if text == "-" {
        return Vec::new();
    }
    text.split(',')
        .map(|v| v.parse().expect("number"))
        .collect()
}

pub(crate) fn failed(error: Error) -> String {
    format!("err {}", error.code().number())
}

/// The port's answer to an oracle request, in the oracle's format.
pub(crate) fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["ncount", max_sv, src] => {
            let mut counts = [0i16; FSE_MAX_SYMBOL_VALUE as usize + 1];
            let mut max_sv: u32 = max_sv.parse().expect("maxSV");
            let mut table_log = 0;
            match fse_read_ncount(&mut counts, &mut max_sv, &mut table_log, &unhex(src)) {
                Ok(size) => format!(
                    "ok {size} {max_sv} {table_log} {}",
                    list(&counts[..=max_sv as usize])
                ),
                Err(error) => failed(error),
            }
        }
        ["fsedtable", max_sv, table_log, counts] => {
            let counts: Vec<i16> = unlist(counts).into_iter().map(|c| c as i16).collect();
            let table_log: u32 = table_log.parse().expect("tableLog");
            let mut dt = Box::new(FseDTable::<4096>::default());
            let mut wksp = Box::new(FseBuildDTableWksp::default());
            let wksp_size =
                fse_build_dtable_wksp_size_u32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE) * 4;
            match fse_build_dtable_internal(
                &mut dt,
                &counts,
                max_sv.parse().expect("maxSV"),
                table_log,
                &mut wksp,
                wksp_size,
            ) {
                Ok(()) => {
                    let mut text = format!("ok {} {}", dt.table_log, u8::from(dt.fast_mode));
                    for cell in &dt.table[..1 << table_log] {
                        let _ =
                            write!(text, " {}:{}:{}", cell.new_state, cell.symbol, cell.nb_bits);
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["fsedecompress", max_log, wksp_size, capacity, src] => {
            let mut output = vec![0u8; capacity.parse().expect("capacity")];
            let mut wksp = Box::new(FseDecompressWksp::<4096>::default());
            match fse_decompress_wksp(
                &mut output,
                &unhex(src),
                max_log.parse().expect("maxLog"),
                &mut wksp,
                wksp_size.parse().expect("wkspSize"),
            ) {
                Ok(size) => format!("ok {size} {}", hex(&output[..size])),
                Err(error) => failed(error),
            }
        }
        ["readstats", src] => {
            let mut weights = [0u8; 256];
            let mut rank_stats = [0u32; HUF_TABLELOG_MAX as usize + 1];
            let (mut nb_symbols, mut table_log) = (0, 0);
            let mut wksp = Box::new(FseDecompressWksp::<64>::default());
            match huf_read_stats_wksp(
                &mut weights,
                &mut rank_stats,
                &mut nb_symbols,
                &mut table_log,
                &unhex(src),
                &mut wksp,
            ) {
                Ok(size) => format!(
                    "ok {size} {nb_symbols} {table_log} {} {}",
                    list(&weights[..nb_symbols as usize]),
                    list(rank_stats)
                ),
                Err(error) => failed(error),
            }
        }
        ["hufx1", src] => {
            let mut dtable = Box::new(HufDTable::new(12));
            let mut wksp = Box::new(HufReadDTableX1Workspace::default());
            match huf_read_dtable_x1_wksp(&mut dtable, &unhex(src), &mut wksp) {
                Ok(size) => {
                    let mut text = format!("ok {size} {}", dtable.desc.table_log);
                    for cell in &dtable.x1[..1 << dtable.desc.table_log] {
                        let _ = write!(text, " {}:{}", cell.nb_bits(), cell.byte());
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["hufx2", src] => {
            let mut dtable = Box::new(HufDTable::new(12));
            let mut wksp = Box::new(HufReadDTableX2Workspace::default());
            match huf_read_dtable_x2_wksp(&mut dtable, &unhex(src), &mut wksp) {
                Ok(size) => {
                    let mut text = format!("ok {size} {}", dtable.desc.table_log);
                    for cell in &dtable.x2[..1 << dtable.desc.table_log] {
                        let _ = write!(
                            text,
                            " {}:{}:{}",
                            cell.sequence(),
                            cell.nb_bits(),
                            cell.length()
                        );
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["bits", fast, src, reads] => {
            let src = unhex(src);
            match BitDStream::new(&src) {
                Ok(mut bit_d) => {
                    let mut text = String::from("ok");
                    for nb_bits in unlist(reads) {
                        let nb_bits = nb_bits as u32;
                        let value = if fast == "1" {
                            bit_d.read_bits_fast(nb_bits)
                        } else {
                            bit_d.read_bits(nb_bits)
                        };
                        let status = bit_d.reload();
                        let _ = write!(text, " {value}/{}", status as u8);
                    }
                    let _ = write!(text, " end:{}", u8::from(bit_d.end_of_dstream()));
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["hufdec", table, streams, fast, dst_size, src] => {
            let src = unhex(src);
            let mut output = vec![0u8; dst_size.parse().expect("dstSize")];
            let mut dtable = Box::new(HufDTable::new(12));
            let mut wksp = Box::new(HufDecompressWksp::default());
            let flags = if fast == "1" {
                0
            } else {
                HUF_FLAGS_DISABLE_FAST
            };
            let result = match (table, streams) {
                ("auto", "1") => {
                    huf_decompress1x_dctx_wksp(&mut dtable, &mut output, &src, &mut wksp, flags)
                }
                ("auto", _) => {
                    huf_decompress4x_huf_only_wksp(&mut dtable, &mut output, &src, &mut wksp, flags)
                }
                (table, streams) => {
                    let h_size = if table == "x2" {
                        huf_read_dtable_x2_wksp(&mut dtable, &src, &mut wksp.x2)
                    } else {
                        huf_read_dtable_x1_wksp(&mut dtable, &src, &mut wksp.x1)
                    };
                    match h_size {
                        Err(error) => Err(error),
                        Ok(h_size) if h_size >= src.len() => Err(ErrorCode::SrcSizeWrong.into()),
                        Ok(h_size) if streams == "1" => huf_decompress1x_using_dtable(
                            &mut output,
                            &src[h_size..],
                            &dtable,
                            flags,
                        ),
                        Ok(h_size) => huf_decompress4x_using_dtable(
                            &mut output,
                            &src[h_size..],
                            &dtable,
                            flags,
                        ),
                    }
                }
            };
            match result {
                Ok(size) => format!("ok {size} {}", hex(&output[..size])),
                Err(error) => failed(error),
            }
        }
        ["blocks", capacity, blocks] => {
            let capacity: usize = capacity.parse().expect("capacity");
            let mut out = vec![0u8; capacity];
            // ZSTD_decompressBegin
            let mut dctx = Box::new(DCtx::new());
            dctx.reset_entropy();
            let mut pos = 0;
            for (index, block) in blocks.split(',').enumerate() {
                let data = unhex(&block[1..]);
                if block.starts_with('c') {
                    let mut bo = BlockOut {
                        out: &mut out,
                        dst: pos,
                        dst_capacity: capacity - pos,
                        prefix_start: 0,
                        ext: ExtDict::None,
                        dict: None,
                    };
                    match decompress_block(&mut dctx, &mut bo, &data) {
                        Ok(size) => pos += size,
                        Err(error) => return format!("err {} {index}", error.code().number()),
                    }
                } else {
                    // ZSTD_insertBlock, after copying the block in.
                    if data.len() > capacity - pos {
                        return format!("short {index}");
                    }
                    out[pos..pos + data.len()].copy_from_slice(&data);
                    pos += data.len();
                }
            }
            format!("ok {pos} {}", hex(&out[..pos]))
        }
        [
            "stream",
            max_block_size,
            stable,
            window_log_max,
            capacity,
            steps,
            src,
        ] => {
            let capacity: usize = capacity.parse().expect("capacity");
            let stable = stable == "1";
            let steps: Vec<usize> = unlist(steps).into_iter().map(|v| v as usize).collect();
            let src = unhex(src);
            let mut dctx = DCtx::new();
            let set = dctx
                .set_parameter(DParameter::MaxBlockSize(
                    max_block_size.parse().expect("block size"),
                ))
                .and_then(|()| dctx.set_parameter(DParameter::StableOutBuffer(stable)))
                .and_then(|()| {
                    dctx.set_parameter(DParameter::WindowLogMax(
                        window_log_max.parse().expect("window log"),
                    ))
                });
            if let Err(error) = set {
                return failed(error);
            }
            let mut out = vec![0u8; capacity];
            let (mut in_pos, mut out_pos) = (0usize, 0usize);
            let mut text = String::from("ok");
            for step in steps.chunks(2) {
                let in_end = (in_pos + step[0]).min(src.len());
                let out_end = if stable {
                    capacity
                } else {
                    (out_pos + step[1]).min(capacity)
                };
                let mut input = InBuffer {
                    src: &src[..in_end],
                    pos: in_pos,
                };
                let mut output = OutBuffer {
                    dst: &mut out[..out_end],
                    pos: out_pos,
                };
                let result = dctx.decompress_stream_internal(&mut output, &mut input);
                in_pos = input.pos;
                out_pos = output.pos;
                let _ = match result {
                    Ok(hint) => write!(text, " {hint}/{in_pos}/{out_pos}"),
                    Err(error) => write!(text, " e{}/{in_pos}/{out_pos}", error.code().number()),
                };
            }
            let _ = write!(text, " {:016x}", fnv64(&out[..out_pos]));
            text
        }
        ["bufferless", mode, room, kind, dict, steps, src] => {
            let steps: Vec<usize> = unlist(steps).into_iter().map(|v| v as usize).collect();
            let dict = if dict == "-" { Vec::new() } else { unhex(dict) };
            bufferless(
                mode.parse().expect("mode"),
                room.parse().expect("room"),
                kind.parse().expect("dictionary kind"),
                &dict,
                &steps,
                &unhex(src),
            )
        }
        ["frames", max_block_size, capacity, src] => {
            let capacity: usize = capacity.parse().expect("capacity");
            let mut out = vec![0u8; capacity];
            let mut dctx = DCtx::new();
            let max_block_size = max_block_size.parse().expect("block size");
            match dctx
                .set_parameter(DParameter::MaxBlockSize(max_block_size))
                .and_then(|()| dctx.decompress(&mut out, &unhex(src)))
            {
                Ok(size) => format!("ok {size} {:016x}", fnv64(&out[..size])),
                Err(error) => failed(error),
            }
        }
        ["xxh64", seed, src] => format!(
            "ok {:016x}",
            xxh64(&unhex(src), seed.parse().expect("seed"))
        ),
        // The encoder's requests.
        _ => crate::zstd::oracle_compress::answer(request),
    }
}

/// The oracle's `bufferless`: the frames of `src` through
/// [`DCtx::decompress_continue`], each begun without a dictionary (`kind`
/// 0), with `dict` loaded (1; 3 with it at the start of the output, which
/// follows it) or as a `DDict` (2); the output after the last (`mode` 0), in
/// a round buffer of `room` bytes (1), or in a buffer of its own each call
/// (2), all within one buffer of the oracle's size, laid out as the
/// oracle's. Each call takes the input asked for or the step's, and the
/// step's room; once the steps are used up, the input asked for and the
/// last room.
fn bufferless(
    mode: usize,
    room: usize,
    kind: u32,
    dict: &[u8],
    steps: &[usize],
    src: &[u8],
) -> String {
    const MAX_BYTES: usize = 1 << 20;
    if !steps.len().is_multiple_of(2)
        || room == 0
        || room > MAX_BYTES / 2
        || mode > 2
        || kind > 3
        || (kind == 3 && (mode != 0 || dict.is_empty()))
    {
        return "bad".into();
    }
    let ddict = match kind {
        2 => match crate::zstd::DDict::new(dict) {
            Ok(ddict) => Some(std::sync::Arc::new(ddict)),
            Err(_) => return "nodict".into(),
        },
        _ => None,
    };
    let mut output = vec![0u8; MAX_BYTES];
    let mut pos = 0;
    if kind == 3 {
        output[..dict.len()].copy_from_slice(dict);
        pos = dict.len();
    }
    let mut dctx = DCtx::new();
    let mut text = String::from("ok");
    let mut hash = FNV_OFFSET;
    let (mut in_pos, mut begin) = (0, true);
    let mut call = 0;
    while call < 100_000 && (in_pos < src.len() || !begin) {
        let step = (2 * call < steps.len()).then_some(2 * call);
        // Once the steps are used up, the last room.
        let last = step.or_else(|| steps.len().checked_sub(2));
        let want = match last.map_or(0, |s| steps[s + 1]) {
            0 => 1 << 17,
            want => want,
        };
        if begin {
            let begun = match (kind, &ddict) {
                (1, _) => dctx.decompress_begin_using_dict(dict),
                (3, _) => dctx.decompress_begin_using_dict(&output[..dict.len()]),
                (2, Some(ddict)) => {
                    dctx.decompress_begin_using_ddict(ddict.clone());
                    Ok(())
                }
                _ => {
                    dctx.decompress_begin();
                    Ok(())
                }
            };
            if let Err(error) = begun {
                let _ = write!(text, " b{}", error.code().number());
                break;
            }
        }
        let next = dctx.next_src_size_to_decompress();
        let size = match step.map_or(0, |s| steps[s]) {
            0 => next,
            size => size,
        }
        .min(src.len() - in_pos);
        let (start, cap) = match mode {
            0 => (pos, (MAX_BYTES - pos).min(want)),
            1 => {
                if room - pos < want {
                    pos = 0;
                }
                (pos, (room - pos).min(want))
            }
            _ => {
                let slots = MAX_BYTES / (room + 1);
                ((call % slots) * (room + 1), room.min(want))
            }
        };
        match dctx.decompress_continue(&mut output[start..start + cap], &src[in_pos..in_pos + size])
        {
            Err(error) => {
                let _ = write!(text, " e{}", error.code().number());
                break;
            }
            Ok(written) => {
                hash = fnv64_from(hash, &output[start..start + written]);
                in_pos += size;
                if mode != 2 {
                    pos += written;
                }
                let next = dctx.next_src_size_to_decompress();
                let _ = write!(text, " {written}/{next}/{}", dctx.next_input_type() as u32);
                begin = next == 0;
            }
        }
        call += 1;
    }
    let _ = write!(text, " {hash:016x}");
    text
}

/// Small, fast and reproducible: SplitMix64.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `low..=high`.
    pub(crate) fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// Bytes for Huffman coding: text-like, a small alphabet, one dominant
    /// symbol, or a skew over all 256 values.
    pub(crate) fn huffman_data(&mut self, len: usize) -> Vec<u8> {
        let kind = self.range(0, 3);
        let alphabet = self.range(2, 64);
        (0..len)
            .map(|_| match kind {
                // The smaller of two draws favours the low symbols.
                0 => b' ' + self.range(0, alphabet - 1).min(self.range(0, alphabet - 1)) as u8,
                1 => self.range(0, alphabet.min(16) - 1) as u8,
                2 => {
                    if self.range(0, 9) == 0 {
                        self.next() as u8
                    } else {
                        b'a'
                    }
                }
                _ => (self.next().trailing_zeros() * 8 + self.range(0, 7) as u32) as u8,
            })
            .collect()
    }

    /// Data with the structure LZ77 finds: runs of literals, and copies of
    /// earlier data from near and far, some overlapping themselves.
    pub(crate) fn lz_data(&mut self, len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len + 2000);
        let alphabet = self.range(4, 64);
        let binary = self.range(0, 4) == 0;
        while data.len() < len {
            if data.len() > 8 && self.range(0, 2) != 0 {
                let offset = match self.range(0, 3) {
                    0 => self.range(1, 8),
                    1 => self.range(1, 64),
                    _ => self.range(1, data.len() as u64),
                } as usize;
                let offset = offset.min(data.len());
                let longest = if self.range(0, 9) == 0 { 2000 } else { 40 };
                let length = self.range(3, longest) as usize;
                for _ in 0..length {
                    let byte = data[data.len() - offset];
                    data.push(byte);
                }
            } else {
                for _ in 0..self.range(1, 30) {
                    let byte = if binary {
                        self.next() as u8
                    } else {
                        b'a' + self.range(0, alphabet - 1) as u8
                    };
                    data.push(byte);
                }
            }
        }
        data.truncate(len);
        data
    }

    /// Symbol counts as real data tends to have them: a few frequent
    /// symbols, many rare ones, some absent.
    pub(crate) fn histogram(&mut self, symbols: usize) -> Vec<u64> {
        let mut counts: Vec<u64> = (0..symbols)
            .map(|_| match self.range(0, 9) {
                0 | 1 => 0,
                2..=5 => self.range(1, 8),
                6..=8 => self.range(1, 300),
                _ => self.range(1, 20_000),
            })
            .collect();
        // At least two symbols present, and the last one too, so that the
        // largest symbol is the one named.
        counts[0] = counts[0].max(1);
        let last = symbols - 1;
        counts[last] = counts[last].max(1);
        counts
    }
}

/// A copy of `bytes` with one bit flipped, a byte changed, or cut short.
pub(crate) fn mutate(rng: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    match rng.range(0, 2) {
        0 => {
            let at = rng.range(0, bytes.len() as u64 - 1) as usize;
            bytes[at] ^= 1 << rng.range(0, 7);
        }
        1 => {
            let at = rng.range(0, bytes.len() as u64 - 1) as usize;
            bytes[at] = rng.next() as u8;
        }
        _ => {
            bytes.truncate(rng.range(0, bytes.len() as u64 - 1) as usize);
        }
    }
    bytes
}

/// Valid table descriptions from libzstd's own encoder.
pub(crate) fn made(oracle: &mut Oracle, request: &str) -> Option<Vec<u8>> {
    let reply = oracle.ask(request);
    reply.strip_prefix("ok ").map(unhex)
}

/// Requests for every command, `per_command` of each kind.
pub(crate) fn requests(oracle: &mut Oracle, rng: &mut Rng, per_command: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // FSE table descriptions: valid, mutated and random.
    let mut valid_counts = Vec::new();
    for i in 0..per_command {
        let max_sv_choices = [255u64, 52, 35, 31, 28, 12];
        match i % 4 {
            0 => {
                let len = rng.range(0, 24) as usize;
                let src = rng.bytes(len);
                let max_sv = max_sv_choices[rng.range(0, 5) as usize];
                requests.push(format!("ncount {max_sv} {}", hex(&src)));
            }
            _ => {
                let symbols = if rng.range(0, 3) == 0 {
                    rng.range(2, 256)
                } else {
                    rng.range(2, 53)
                } as usize;
                let table_log = rng.range(5, 12);
                let request = format!("mkncount {table_log} {}", list(rng.histogram(symbols)));
                let Some(header) = made(oracle, &request) else {
                    continue;
                };
                let max_sv = if rng.range(0, 4) == 0 {
                    symbols as u64 - 2
                } else {
                    255
                };
                let src = if i % 4 == 3 {
                    mutate(rng, &header)
                } else {
                    header
                };
                let request = format!("ncount {max_sv} {}", hex(&src));
                let reply = oracle.ask(&request);
                if let Some(ok) = reply.strip_prefix("ok ") {
                    valid_counts.push(ok.to_string());
                }
                requests.push(request);
            }
        }
    }

    // FSE decoding tables, for the counts that were read.
    for ok in valid_counts.iter().take(per_command) {
        let [_, max_sv, table_log, counts] = ok.split(' ').collect::<Vec<_>>()[..] else {
            continue;
        };
        requests.push(format!("fsedtable {max_sv} {table_log} {counts}"));
    }

    // Huffman tree descriptions: valid, mutated and random; and the
    // FSE-compressed weights inside them.
    for i in 0..per_command {
        let tree = if i % 5 == 0 {
            let len = rng.range(0, 40) as usize;
            rng.bytes(len)
        } else {
            let symbols = if rng.range(0, 2) == 0 {
                rng.range(2, 256)
            } else {
                rng.range(2, 40)
            } as usize;
            let counts = rng.histogram(symbols);
            // HUF_minTableLog: libzstd never asks for shorter codes.
            let cardinality = counts.iter().filter(|&&c| c > 0).count() as u32;
            let min_table_log = u64::from(31 - cardinality.leading_zeros() + 1);
            let max_nb_bits = rng.range(min_table_log.max(6), 12);
            let request = format!("mkhuf {max_nb_bits} {}", list(counts));
            let Some(tree) = made(oracle, &request) else {
                continue;
            };
            if i % 5 == 4 { mutate(rng, &tree) } else { tree }
        };
        let tree_hex = hex(&tree);
        requests.push(format!("readstats {tree_hex}"));
        requests.push(format!("hufx1 {tree_hex}"));
        requests.push(format!("hufx2 {tree_hex}"));
        if let Some(&size) = tree.first()
            && size < 128
            && tree.len() > 1
        {
            let payload = &tree[1..tree.len().min(1 + usize::from(size))];
            let (max_log, wksp, capacity) = match rng.range(0, 3) {
                0 => (6, HUF_READ_STATS_WORKSPACE_SIZE, 255),
                1 => (rng.range(5, 12), FSE_DECOMPRESS_MAX_WKSP, 255),
                2 => (6, HUF_READ_STATS_WORKSPACE_SIZE, rng.range(0, 40) as usize),
                _ => (
                    rng.range(0, 12),
                    rng.range(0, FSE_DECOMPRESS_MAX_WKSP as u64) as usize,
                    255,
                ),
            };
            requests.push(format!(
                "fsedecompress {max_log} {wksp} {capacity} {}",
                hex(payload)
            ));
        }
    }

    // Huffman-coded streams from libzstd's encoder, decoded with every table
    // and loop, at the right size and wrong ones, and damaged.
    for i in 0..per_command {
        let len = if i % 20 == 0 {
            rng.range(1, 128 * 1024)
        } else {
            rng.range(1, 3000)
        } as usize;
        let data = rng.huffman_data(len);
        let streams = if rng.range(0, 3) == 0 { 1 } else { 4 };
        let max_nb_bits = rng.range(9, 12);
        let request = format!("mkhufstream {streams} {max_nb_bits} {}", hex(&data));
        let Some(made) = made(oracle, &request) else {
            continue;
        };
        let (src, dst_size) = match i % 8 {
            0 => (mutate(rng, &made), len),
            1 => (
                made,
                (len as u64 + rng.range(0, 2)).saturating_sub(1) as usize,
            ),
            _ => (made, len),
        };
        let src = hex(&src);
        let table = ["auto", "x1", "x2"][rng.range(0, 2) as usize];
        let fast = rng.range(0, 3).min(1);
        requests.push(format!("hufdec {table} {streams} {fast} {dst_size} {src}"));
        if i % 4 == 0 {
            let other = if table == "x1" { "x2" } else { "x1" };
            requests.push(format!("hufdec {other} {streams} {fast} {dst_size} {src}"));
        }
    }

    // Blocks from libzstd's compressor, decoded one after the other into
    // outputs of various sizes, which move the literals between the extra
    // buffer, the output, and both; and damaged.
    for i in 0..per_command / 2 {
        let len = if i % 10 == 0 || i % 5 == 3 {
            rng.range(1, 400_000)
        } else {
            rng.range(1, 20_000)
        } as usize;
        // Mostly matches; or mostly literals, with large literal sections
        // that libzstd splits between the output and its extra buffer; or
        // incompressible bytes, which make stored blocks.
        let data = match i % 5 {
            0..=2 => rng.lz_data(len),
            3 => rng.huffman_data(len),
            _ => rng.bytes(len),
        };
        let level = [-5i64, 1, 3, 7, 12, 19][rng.range(0, 5) as usize];
        let block_size = [
            1024u64,
            4096,
            32 * 1024,
            128 * 1024,
            rng.range(1, 128 * 1024),
        ][rng.range(0, 4) as usize];
        // Literal-heavy data in full-size blocks, decoded into an output just
        // large enough, is what makes libzstd split the literals.
        let split_prone = i % 5 == 3 && rng.range(0, 1) == 0;
        let block_size = if split_prone { 128 * 1024 } else { block_size };
        let request = format!("mkblocks {level} {block_size} {}", hex(&data));
        let Some(reply) = oracle.ask(&request).strip_prefix("ok ").map(str::to_string) else {
            continue;
        };
        let mut blocks: Vec<String> = reply.split(',').map(str::to_string).collect();
        if i % 6 == 0 {
            // Damage one compressed block.
            if let Some(block) = blocks.iter_mut().find(|b| b.starts_with('c')) {
                *block = format!("c{}", hex(&mutate(rng, &unhex(&block[1..]))));
            }
        }
        // Room: exactly enough, a lot more (up to the oracle's 1 MiB), or
        // a little less.
        let capacity = match if split_prone { 0 } else { rng.range(0, 3) } {
            0 => len,
            1 => (len + 300_000).min(1 << 20),
            2 => len.saturating_sub(rng.range(1, 100) as usize),
            _ => (len + rng.range(0, 200_000) as usize).min(1 << 20),
        };
        requests.push(format!("blocks {capacity} {}", blocks.join(",")));
    }

    // Whole frames with blocks up to some size, decoded with a block size
    // limit below, at or above it, or none (ZSTD_d_maxBlockSize, which the
    // tests against libzstd's public API cannot set); some damaged.
    for i in 0..per_command / 10 {
        let level = [-5i64, 1, 3, 9, 19][rng.range(0, 4) as usize];
        let len = rng.range(0, if level == 19 { 50_000 } else { 300_000 }) as usize;
        let data = if i % 3 == 0 {
            rng.huffman_data(len)
        } else {
            rng.lz_data(len)
        };
        let block_size = [
            1024u64,
            1500,
            4096,
            65_536,
            128 * 1024,
            rng.range(1024, 128 * 1024),
        ][rng.range(0, 5) as usize];
        let Some(frame) = made(
            oracle,
            &format!("mkframe {level} {block_size} {}", hex(&data)),
        ) else {
            continue;
        };
        let limit = match rng.range(0, 7) {
            0 => 0,
            1 => block_size,
            2..=4 => rng.range(1024, block_size),
            5 => rng.range(block_size, 128 * 1024),
            // Out of bounds.
            6 => [1, 1023, 128 * 1024 + 1][rng.range(0, 2) as usize],
            _ => 1024,
        };
        let frame = if i % 5 == 0 {
            mutate(rng, &frame)
        } else {
            frame
        };
        requests.push(format!("frames {limit} {len} {}", hex(&frame)));
    }

    // Bitstreams, read in random steps.
    for i in 0..per_command {
        let len = rng.range(if i % 10 == 0 { 0 } else { 1 }, 24) as usize;
        let mut src = rng.bytes(len);
        if let Some(last) = src.last_mut() {
            // The last byte holds the end mark; without one the stream is
            // refused, differently below and above 8 bytes.
            if i % 8 == 1 {
                *last = 0
            } else {
                *last |= 1 << rng.range(0, 7)
            }
        }
        let fast = rng.range(0, 1);
        let reads: Vec<u64> = (0..rng.range(1, 24)).map(|_| rng.range(fast, 31)).collect();
        requests.push(format!("bits {fast} {} {}", hex(&src), list(reads)));
    }

    // XXH64.
    for i in 0..per_command {
        let len = if i % 20 == 0 {
            rng.range(0, 3000)
        } else {
            rng.range(0, 100)
        } as usize;
        let seed = match rng.range(0, 2) {
            0 => 0,
            1 => rng.range(0, 1000),
            _ => rng.next(),
        };
        let src = rng.bytes(len);
        requests.push(format!("xxh64 {seed} {}", hex(&src)));
    }

    // Frames streamed in random steps, with a block size limit, a stable
    // output buffer and a window limit (ZSTD_d_maxBlockSize, which the
    // tests against libzstd's public API cannot set), sometimes damaged.
    // libzstd goes on after errors, and so does the request.
    for i in 0..per_command / 10 {
        let level = [-5i64, 1, 3, 9, 19][rng.range(0, 4) as usize];
        let mut src = Vec::new();
        let mut len = 0;
        let mut block_size = 128 * 1024;
        for _ in 0..rng.range(1, 2) {
            // Half of them small enough for the replay file.
            let frame_len = if i % 2 == 0 {
                rng.range(0, 4000)
            } else {
                rng.range(0, if level == 19 { 50_000 } else { 200_000 })
            } as usize;
            let data = if i % 3 == 0 {
                rng.huffman_data(frame_len)
            } else {
                rng.lz_data(frame_len)
            };
            block_size = [
                1024u64,
                4096,
                65_536,
                128 * 1024,
                rng.range(1024, 128 * 1024),
            ][rng.range(0, 4) as usize];
            let Some(frame) = made(
                oracle,
                &format!("mkframe {level} {block_size} {}", hex(&data)),
            ) else {
                continue;
            };
            if rng.range(0, 3) == 0 {
                // A skippable frame first.
                let content_len = rng.range(0, 300) as usize;
                let content = rng.bytes(content_len);
                src.extend_from_slice(&(0x184D_2A50u32 + rng.range(0, 15) as u32).to_le_bytes());
                src.extend_from_slice(&(content.len() as u32).to_le_bytes());
                src.extend_from_slice(&content);
            }
            src.extend_from_slice(&frame);
            len += frame_len;
        }
        if i % 4 == 0 {
            src = mutate(rng, &src);
        }
        let limit = match rng.range(0, 5) {
            0 | 1 => 0,
            2 => block_size,
            3 => rng.range(1024, block_size),
            _ => rng.range(block_size, 128 * 1024),
        };
        let stable = u64::from(rng.range(0, 3) == 0);
        let window_log_max = if rng.range(0, 4) == 0 {
            rng.range(10, 20)
        } else {
            0
        };
        let capacity = match rng.range(0, 3) {
            0 => len,
            1 => (len + 300_000).min(1 << 20),
            _ => len.saturating_sub(rng.range(1, 100) as usize),
        };
        let mut steps = Vec::new();
        for _ in 0..rng.range(1, 60) {
            for _ in 0..2 {
                steps.push(match rng.range(0, 3) {
                    0 => rng.range(0, 8),
                    1 => rng.range(0, 300),
                    2 => rng.range(0, 20_000),
                    _ => rng.range(0, 2 * 131_075),
                });
            }
        }
        if rng.range(0, 2) == 0 {
            // Then all the rest, a few times.
            steps.extend([1 << 20, 1 << 20, 1 << 20, 1 << 20, 0, 0, 0, 0]);
        }
        requests.push(format!(
            "stream {limit} {stable} {window_log_max} {capacity} {} {}",
            list(steps),
            hex(&src)
        ));
    }

    for i in 0..per_command / 10 {
        requests.push(bufferless_request(rng, i));
    }

    requests
}

/// A `bufferless` request: frames made by the port's encoder (libzstd's
/// frames), with a dictionary for some, a skippable frame before some, and
/// damaged now and then; decoded into one buffer, a round buffer as
/// libzstd's documentation describes it, or a buffer for each call. Every
/// fifth one is frames longer than twice their window and 1 MB, in a
/// round buffer, through which the port drops the oldest part of its copy.
fn bufferless_request(rng: &mut Rng, i: usize) -> String {
    use crate::zstd::{CCtx, CParameter, FrameHeaderState};
    let kind = rng.range(0, 3);
    let big = i % 5 == 4;
    let mode = match kind {
        3 => 0,
        _ if big => 1,
        _ => rng.range(0, 2),
    };
    let dict = if kind == 0 {
        Vec::new()
    } else {
        let size = rng.range(1, 30_000) as usize;
        let content = rng.lz_data(size);
        let mut trained = vec![0u8; 8192];
        let sizes = vec![content.len() / 64; 64];
        match crate::zstd::train_from_buffer(&mut trained, &content, &sizes) {
            Ok(size) if rng.range(0, 2) != 0 => {
                trained.truncate(size);
                if rng.range(0, 9) == 0 {
                    // Tables that do not read.
                    trained = mutate(rng, &trained);
                }
                trained
            }
            _ => content,
        }
    };
    let level = [-5i32, 1, 3, 9, 19][rng.range(0, 4) as usize];
    let (mut window_max, mut block_max) = (0u64, 1usize);
    let mut src = Vec::new();
    for _ in 0..rng.range(1, 2) {
        let len = if big {
            rng.range(1 << 20, 3 << 20)
        } else if i.is_multiple_of(2) {
            rng.range(0, 4000)
        } else {
            rng.range(0, 200_000)
        } as usize;
        let mut data = Vec::with_capacity(len);
        let piece = rng.lz_data(20_000);
        while data.len() < len {
            // Pieces of the dictionary, of a piece repeated, and new data.
            match rng.range(0, 2) {
                0 if !dict.is_empty() => {
                    let at = rng.range(0, dict.len() as u64 - 1) as usize;
                    let end = (at + rng.range(1, 3000) as usize).min(dict.len());
                    data.extend_from_slice(&dict[at..end]);
                }
                1 => {
                    let at = rng.range(0, piece.len() as u64 - 1) as usize;
                    let end = (at + rng.range(1, 5000) as usize).min(piece.len());
                    data.extend_from_slice(&piece[at..end]);
                }
                _ => {
                    let size = rng.range(1, if big { 50 } else { 3000 }) as usize;
                    data.extend(rng.lz_data(size));
                }
            }
        }
        data.truncate(len);
        let mut cctx = CCtx::new();
        let mut set = cctx
            .set_parameter(CParameter::CompressionLevel(level))
            .and_then(|()| cctx.set_parameter(CParameter::ChecksumFlag(rng.range(0, 1) == 1)));
        if big || rng.range(0, 3) == 0 {
            let window_log = rng.range(10, 18) as u32;
            set = set.and_then(|()| cctx.set_parameter(CParameter::WindowLog(window_log)));
        }
        if !dict.is_empty() && rng.range(0, 4) != 0 {
            // A damaged dictionary is refused: the frame goes without.
            let _ = cctx.load_dictionary(&dict);
        }
        let mut frame = vec![0u8; crate::zstd::compress_bound(len).expect("a bound")];
        let Ok(size) = set.and_then(|()| cctx.compress2(&mut frame, &data)) else {
            continue;
        };
        frame.truncate(size);
        if let Ok(FrameHeaderState::Complete(header)) = crate::zstd::get_frame_header(&frame) {
            window_max = window_max.max(header.window_size);
            block_max = block_max.max(header.block_size_max as usize);
        }
        if rng.range(0, 3) == 0 {
            // A skippable frame first.
            let size = rng.range(0, 300) as usize;
            let content = rng.bytes(size);
            src.extend_from_slice(&(0x184D_2A50u32 + rng.range(0, 15) as u32).to_le_bytes());
            src.extend_from_slice(&(content.len() as u32).to_le_bytes());
            src.extend_from_slice(&content);
        }
        src.extend_from_slice(&frame);
    }
    if i.is_multiple_of(4) && !big {
        src = mutate(rng, &src);
    }
    let room = match mode {
        // Enough for the window and a block, as libzstd's documentation
        // asks, and some.
        1 => crate::zstd::decoding_buffer_size_min(window_max, crate::zstd::CONTENTSIZE_UNKNOWN)
            .unwrap_or(1 << 19)
            .saturating_add(rng.range(0, 1000) as usize)
            .min(1 << 19),
        2 => rng.range(block_max as u64 / 2, block_max as u64 * 2).max(1) as usize,
        _ => 1000,
    };
    let mut steps = Vec::new();
    for _ in 0..rng.range(0, 60) {
        // The input asked for, but now and then a size of the step's own;
        // the room: in a round buffer, a block's, from its start again when
        // less is left; otherwise any.
        steps.push(if rng.range(0, 79) == 0 {
            rng.range(1, 300)
        } else {
            0
        });
        steps.push(match (mode, rng.range(0, 3)) {
            (1, _) => block_max as u64,
            (_, 0) => 0,
            (_, 1) => block_max as u64,
            _ => rng.range(1, 2 * block_max as u64),
        });
    }
    if mode == 1 && steps.is_empty() {
        steps.extend([0, block_max as u64]);
    }
    format!(
        "bufferless {mode} {room} {kind} {} {} {}",
        if dict.is_empty() {
            "-".to_string()
        } else {
            hex(&dict)
        },
        list(steps),
        hex(&src)
    )
}

/// Requests made from zstd's fuzzing corpora for the same functions, when
/// they have been fetched (`scripts/testdata.py fetch --group fuzz`). The
/// corpora's inputs are made for libzstd's own fuzzers; here they are just
/// bytes to read, which is all the comparison needs.
fn corpus_requests() -> Vec<String> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let mut requests = Vec::new();
    let mut read = |set: &str, make: &dyn Fn(&str) -> Vec<String>| {
        let Ok(entries) = std::fs::read_dir(cache.join(set)) else {
            eprintln!("not using {set}: not fetched (scripts/testdata.py fetch --group fuzz)");
            return;
        };
        let mut files: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        files.sort();
        for file in files {
            if file.file_name() == Some(".complete".as_ref()) {
                continue;
            }
            let mut bytes = std::fs::read(&file).expect("corpus file");
            bytes.truncate(4096);
            requests.extend(make(&hex(&bytes)));
        }
    };
    read("zstd-fuzz-fse-read-ncount", &|src| {
        vec![format!("ncount 255 {src}"), format!("ncount 35 {src}")]
    });
    read("zstd-fuzz-huf-decompress", &|src| {
        vec![
            format!("readstats {src}"),
            format!("hufx1 {src}"),
            format!("hufx2 {src}"),
        ]
    });
    requests
}

/// FNV-1a, to record long answers by their hash, and to answer with outputs
/// briefly.
pub(crate) fn fnv64(bytes: &[u8]) -> u64 {
    fnv64_from(FNV_OFFSET, bytes)
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a over `bytes`, continuing `hash`.
fn fnv64_from(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What the replay file keeps of an answer: all of it, or the hash of a long one.
pub(crate) fn recorded_form(answer: &str) -> String {
    if answer.len() <= 160 {
        answer.to_string()
    } else {
        format!("fnv64:{:016x}", fnv64(answer.as_bytes()))
    }
}

#[test]
fn port_matches_libzstd() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng::new(0x5EED_0001);
    let mut requests = requests(&mut oracle, &mut rng, 2000);
    requests.extend(corpus_requests());
    let mut problems = Vec::new();
    // The errors streamed frames ran into, by libzstd's code.
    let mut stream_errors = std::collections::BTreeMap::<String, usize>::new();
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if request.starts_with("stream ") {
            for code in want
                .split(' ')
                .filter(|call| call.contains('/'))
                .filter_map(|call| call.strip_prefix('e'))
            {
                let code = code.split('/').next().unwrap_or_default().to_string();
                *stream_errors.entry(code).or_default() += 1;
            }
        }
        // Blocks libzstd decodes must decode the same with every loop.
        if request.starts_with("blocks ") && want.starts_with("ok") {
            let long = answer_with_long_loop(request);
            if long != want && problems.len() < 20 {
                problems.push(format!(
                    "{request:.300}\n  libzstd: {want:.300}\n  port, long loop: {long:.300}"
                ));
            }
        }
        if got != want && problems.len() < 20 {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
    }
    eprintln!("compared {} requests with libzstd", requests.len());
    eprintln!("streaming calls that failed, by error code: {stream_errors:?}");
    // Both 4-stream loops, for both tables, must have been reached.
    let runs = crate::zstd::decompress::huf_decompress::LOOP_RUNS
        .each_ref()
        .map(|r| r.load(std::sync::atomic::Ordering::Relaxed));
    eprintln!("4-stream loops run (fast X1, fallback X1, fast X2, fallback X2): {runs:?}");
    assert!(
        runs.iter().all(|&n| n >= 20),
        "some 4-stream loops were barely reached: {runs:?}"
    );
    let paths = crate::zstd::decompress::zstd_decompress_block::PATH_RUNS
        .each_ref()
        .map(|r| r.load(std::sync::atomic::Ordering::Relaxed));
    eprintln!(
        "literals (extra, input, output, split), then sequence loops (plain, split, long): {paths:?}"
    );

    // With the `unsafe-fast` feature, the plain loop always runs unchecked:
    // the decoder's buffers always meet the limits it checks.
    #[cfg(all(feature = "zstd-unsafe-fast", target_pointer_width = "64"))]
    {
        let [unchecked, checked] = crate::zstd::decompress::zstd_decompress_block::UNCHECKED_RUNS
            .each_ref()
            .map(|r| r.load(std::sync::atomic::Ordering::Relaxed));
        eprintln!("plain loops run unchecked, then checked: {unchecked}, {checked}");
        assert!(
            unchecked > 0 && checked == 0,
            "the plain loop ran checked {checked} times, unchecked {unchecked}"
        );
    }
    assert!(
        problems.is_empty(),
        "{} requests checked, differences:\n{}",
        requests.len(),
        problems.join("\n")
    );
}

#[test]
fn the_prefetching_loop_decodes_valid_blocks_like_libzstd() {
    // libzstd takes this loop after loading a dictionary, or with over
    // 16 MiB of history; here it is forced, on the blocks libzstd decodes.
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/common.txt");
    let blocks: Vec<(&str, &str)> = text
        .lines()
        .filter(|l| l.starts_with("blocks "))
        .filter_map(|l| l.split_once('\t'))
        .filter(|(_, want)| want.starts_with("ok") || want.starts_with("fnv64"))
        .collect();
    assert!(
        blocks.len() > 30,
        "only {} valid block requests recorded",
        blocks.len()
    );
    for (request, want) in blocks {
        assert_eq!(
            recorded_form(&answer_with_long_loop(request)),
            want,
            "{request:.200}"
        );
    }
}

/// The port's answer with the prefetching sequence loop forced, on this
/// thread only.
fn answer_with_long_loop(request: &str) -> String {
    use crate::zstd::decompress::zstd_decompress_block::FORCE_LONG_LOOP;
    FORCE_LONG_LOOP.with(|force| force.set(true));
    let answer = answer(request);
    FORCE_LONG_LOOP.with(|force| force.set(false));
    answer
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/common.txt");
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
#[ignore = "rewrites testdata/oracle/common.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng::new(0x5EED_0002);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle), replayed by crates/zstd/src/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 300) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 12_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

#[test]
fn xxh64_streaming_matches_one_call() {
    use crate::zstd::common::xxhash::Xxh64State;
    let mut rng = Rng::new(0x5EED_0003);
    for _ in 0..500 {
        let len = rng.range(0, 700) as usize;
        let data = rng.bytes(len);
        let seed = rng.next();
        let mut state = Xxh64State::new(seed);
        let mut at = 0;
        while at < len {
            let step = (rng.range(0, 70) as usize).min(len - at);
            state.update(&data[at..at + step]);
            at += step;
        }
        assert_eq!(state.digest(), xxh64(&data, seed), "{len} bytes");
    }
}

#[test]
fn xxh64_matches_published_values() {
    assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
    assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
}
