//! The test data described by `testdata/manifest.json`, for the tests in this
//! folder.

// Test helpers: a broken data set should stop the test with its name.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub about: String,
    pub upstream: Upstream,
    pub sets: Vec<Set>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub version: String,
    pub commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Set {
    pub name: String,
    /// Where a committed set is, under `testdata/`.
    pub path: Option<String>,
    /// How `scripts/testdata.py` downloads the set.
    pub fetch: Option<serde_json::Value>,
    /// How `scripts/testdata.py` generates the set.
    pub generate: Option<serde_json::Value>,
    pub source: String,
    pub license: String,
    pub kind: Kind,
    /// Only these files, relative to the set's folder, when given.
    #[serde(default)]
    pub files: Vec<String>,
    /// `beside`: the original of `x.zst` is `x`, when that file exists.
    pub originals: Option<String>,
    /// Frames that decode to this many zero bytes.
    #[serde(default)]
    pub zeros: BTreeMap<String, usize>,
    /// The dictionary every frame needs, relative to the set's folder.
    pub dictionary: Option<String>,
    /// For a dictionaries set: the inputs, relative to `testdata/`, to
    /// compress with each dictionary.
    #[serde(default)]
    pub inputs: BTreeMap<String, Vec<String>>,
    /// Frames whose content is a dataset of zstd's `tests/regression`.
    #[serde(default)]
    pub regression: BTreeMap<String, String>,
    /// Files whose outcome differs from what the set's kind says.
    #[serde(default)]
    pub expect: BTreeMap<String, Expect>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Every `.zst` file decodes.
    Frames,
    /// Every `.zst` file fails to decode.
    BadFrames,
    /// Every file is data to compress.
    Inputs,
    /// Every file is a dictionary.
    Dictionaries,
    /// `.dict` files are dictionaries; each `.zst` file decodes with the
    /// one its header names.
    DictFrames,
    /// Arbitrary bytes found by fuzzers; nothing is expected of them.
    Fuzz,
    /// Source code that the script builds tools from.
    Source,
    /// A program the script builds, such as the oracle.
    Tool,
    /// Benchmark inputs, too big for the tests.
    Bench,
    /// Archives for hivepack::extract's tests, never unpacked here.
    Archives,
    /// Test vectors of another format, such as hivepack::age's.
    Vectors,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub result: Outcome,
    pub why: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Decodes,
    Fails,
}

pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` puts the sets it fetches and generates.
pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

pub fn manifest() -> Manifest {
    let path = repository().join("testdata/manifest.json");
    let text = std::fs::read_to_string(&path).expect("manifest readable");
    serde_json::from_str(&text).expect("manifest parses")
}

impl Set {
    pub fn committed(&self) -> bool {
        self.path.is_some()
    }

    pub fn folder(&self) -> PathBuf {
        match &self.path {
            Some(path) => repository().join("testdata").join(path),
            None => cache().join(&self.name),
        }
    }

    /// The group `scripts/testdata.py` fetches or generates the set in.
    pub fn group(&self) -> Option<&str> {
        self.fetch
            .as_ref()
            .or(self.generate.as_ref())?
            .get("group")?
            .as_str()
    }

    /// Whether the set is on disk. A missing set fails the test when its
    /// group is listed in `HIVEPACK_TESTDATA_REQUIRED` (for example
    /// `core,generated` in CI, or `all`), and is skipped with a note otherwise.
    pub fn present(&self) -> bool {
        if self.committed() || self.folder().join(".complete").exists() {
            return true;
        }
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        let group = self.group().unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == group),
            "{} is missing: run `python3 scripts/testdata.py fetch --group {group}`",
            self.name
        );
        eprintln!(
            "skipping {}: not fetched (scripts/testdata.py fetch --group {group})",
            self.name
        );
        false
    }

    /// The set's files, relative to its folder, sorted.
    pub fn list(&self) -> Vec<PathBuf> {
        if !self.files.is_empty() {
            return self.files.iter().map(PathBuf::from).collect();
        }
        let root = self.folder();
        let mut found = Vec::new();
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("set folder readable") {
                let path = entry.expect("folder entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.file_name() != Some(".complete".as_ref()) {
                    found.push(
                        path.strip_prefix(&root)
                            .expect("inside the set")
                            .to_path_buf(),
                    );
                }
            }
        }
        found.sort();
        found
    }

    pub fn frames(&self) -> Vec<PathBuf> {
        self.list()
            .into_iter()
            .filter(|p| p.extension() == Some("zst".as_ref()))
            .collect()
    }

    pub fn read(&self, file: &Path) -> Vec<u8> {
        let path = self.folder().join(file);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// What `file` should decode to, when the set says.
    pub fn original(&self, frame: &Path) -> Option<Vec<u8>> {
        let key = frame.to_string_lossy();
        if let Some(&zeros) = self.zeros.get(key.as_ref()) {
            return Some(vec![0; zeros]);
        }
        if self.originals.as_deref() == Some("beside") {
            let original = self.folder().join(frame.with_extension(""));
            if original.exists() {
                return Some(std::fs::read(original).expect("original readable"));
            }
        }
        None
    }

    pub fn expected(&self, file: &Path) -> Option<Outcome> {
        self.expect
            .get(file.to_string_lossy().as_ref())
            .map(|e| e.result)
    }
}

/// Collects every mismatch so a run reports all of them, not just the first.
#[derive(Default)]
pub struct Problems(Vec<String>);

impl Problems {
    pub fn add(&mut self, problem: String) {
        self.0.push(problem);
    }

    pub fn check(self) {
        assert!(
            self.0.is_empty(),
            "{} problems:\n{}",
            self.0.len(),
            self.0.join("\n")
        );
    }
}

/// SplitMix64.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    pub fn chance(&mut self, one_in: u64) -> bool {
        self.range(1, one_in) == 1
    }

    /// [`Rng::data`] of a length from `low` to `high`.
    pub fn data_between(&mut self, low: u64, high: u64, base: &[u8]) -> Vec<u8> {
        let len = self.range(low, high) as usize;
        self.data(len, base)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.range(0, i as u64) as usize);
        }
    }

    /// A zstd dictionary trained on samples drawn from `base`, if training
    /// works out.
    pub fn trained_dict(&mut self, base: &[u8]) -> Option<Vec<u8>> {
        let samples: Vec<Vec<u8>> = (0..200).map(|_| self.data_between(50, 400, base)).collect();
        zstd::dict::from_samples(&samples, self.range(1024, 16 * 1024) as usize).ok()
    }

    /// A piece of `base`, as raw content.
    pub fn raw_dict(&mut self, base: &[u8]) -> Vec<u8> {
        let at = self.range(0, base.len() as u64 / 2) as usize;
        let len = self.range(1, (base.len() - at) as u64) as usize;
        base[at..at + len].to_vec()
    }

    /// Text-like data with repeats near and far, drawn from `base` when
    /// given, so that a dictionary built from it helps.
    pub fn data(&mut self, len: usize, base: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(len + 64);
        while data.len() < len {
            match self.range(0, 3) {
                0 if !base.is_empty() => {
                    let at = self.range(0, base.len() as u64 - 1) as usize;
                    let n = (self.range(4, 60) as usize).min(base.len() - at);
                    data.extend_from_slice(&base[at..at + n]);
                }
                1 if data.len() > 8 => {
                    let offset = self.range(1, data.len() as u64) as usize;
                    for _ in 0..self.range(3, 50) {
                        let byte = data[data.len() - offset];
                        data.push(byte);
                    }
                }
                _ => {
                    for _ in 0..self.range(1, 12) {
                        data.push(b'a' + self.range(0, 25) as u8);
                    }
                }
            }
        }
        data.truncate(len);
        data
    }
}

/// A skippable frame, as `ZSTD_writeSkippableFrame` writes it.
pub fn skippable_frame(variant: u32, content: &[u8]) -> Vec<u8> {
    let mut frame = (0x184D_2A50 + variant).to_le_bytes().to_vec();
    frame.extend_from_slice(&(content.len() as u32).to_le_bytes());
    frame.extend_from_slice(content);
    frame
}

/// FNV-1a, to compare outputs briefly.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_from(0xcbf2_9ce4_8422_2325, bytes)
}

/// FNV-1a, continued from `hash`.
pub fn fnv1a_from(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// How a streaming comparison cuts the input and the output into pieces.
#[derive(Clone, Copy, Debug)]
pub enum Pieces {
    /// All the input at once, and all the room there is for output: libzstd
    /// then decodes whole frames in one go when it can.
    Whole,
    /// `ZSTD_DStreamInSize` and `ZSTD_DStreamOutSize` at a time, as the zstd
    /// command line reads and writes.
    Blocks,
    /// Random sizes, from one byte to two blocks.
    Random(u64),
    /// One byte of input and one of output per call.
    Bytes,
    /// A stable output buffer (`ZSTD_d_stableOutBuffer`), all of it at each
    /// call, and the input in random pieces.
    Stable(u64),
}

impl Pieces {
    fn seed(self) -> u64 {
        match self {
            Pieces::Random(seed) | Pieces::Stable(seed) => seed,
            _ => 0,
        }
    }
}

/// A random piece size: mostly small ones, sometimes blocks.
fn piece(rng: &mut Rng) -> usize {
    let size = match rng.range(0, 3) {
        0 => rng.range(1, 8),
        1 => rng.range(1, 300),
        2 => rng.range(1, 20_000),
        _ => rng.range(1, 2 * 131_075),
    };
    size as usize
}

/// Calls more than this mean a decoder makes no progress.
const MAX_CALLS: usize = 4_000_000;

/// Streams `src` through libzstd's `ZSTD_decompressStream` and the port's,
/// in the same pieces, with at most `capacity` bytes of output. Every call
/// must return the same and move the positions as far, and the output must
/// be the same.
///
/// It stops at the end of the input, after a call that returns 0, or at the
/// first error: the `zstd` crate keeps reporting an error until the context
/// is reset. Returns how it ended, or what differed.
pub fn stream_both(
    c: &mut zstd::zstd_safe::DCtx<'_>,
    p: &mut hivepack::zstd::DCtx,
    src: &[u8],
    capacity: usize,
    pieces: Pieces,
) -> Result<String, String> {
    use zstd::zstd_safe::{self, DParameter, InBuffer, OutBuffer};

    let stable = matches!(pieces, Pieces::Stable(_));
    let want = c
        .set_parameter(DParameter::StableOutBuffer(stable))
        .map_err(|code| zstd_safe::get_error_name(code).to_string());
    let got = p
        .set_parameter(hivepack::zstd::DParameter::StableOutBuffer(stable))
        .map_err(|error| error.code().message().to_string());
    if want != got.clone().map(|()| 0) {
        return Err(format!(
            "setting the buffer mode: libzstd {want:?}, port {got:?}"
        ));
    }
    if let Err(name) = want {
        return Ok(format!("err {name} setting the buffer mode"));
    }

    let mut rng = Rng(pieces.seed());
    let mut c_out = vec![0u8; capacity];
    let mut p_out = vec![0u8; capacity];
    let (mut in_pos, mut out_pos) = (0usize, 0usize);
    let mut hash = 0xcbf2_9ce4_8422_2325;
    let mut stalled = 0;
    for call in 0..MAX_CALLS {
        let (in_end, out_end) = match pieces {
            Pieces::Whole => (src.len(), capacity),
            Pieces::Blocks => (
                src.len().min(in_pos + hivepack::zstd::dstream_in_size()),
                capacity.min(out_pos + hivepack::zstd::dstream_out_size()),
            ),
            Pieces::Random(_) => (
                src.len().min(in_pos + piece(&mut rng)),
                capacity.min(out_pos + piece(&mut rng)),
            ),
            Pieces::Bytes => (src.len().min(in_pos + 1), capacity.min(out_pos + 1)),
            Pieces::Stable(_) => (src.len().min(in_pos + piece(&mut rng)), capacity),
        };

        let (want, ci, co) = {
            let mut output = OutBuffer::around_pos(&mut c_out[..out_end], out_pos);
            let mut input = InBuffer::around(&src[..in_end]);
            input.set_pos(in_pos);
            let result = c.decompress_stream(&mut output, &mut input);
            (
                result.map_err(|code| zstd_safe::get_error_name(code).to_string()),
                input.pos(),
                output.pos(),
            )
        };
        let (mut pi, mut po) = (in_pos, out_pos);
        let got = p
            .decompress_stream_simple_args(&mut p_out[..out_end], &mut po, &src[..in_end], &mut pi)
            .map_err(|error| error.code().message().to_string());

        if (&want, ci, co) != (&got, pi, po) {
            return Err(format!(
                "call {call} (input {in_pos}..{in_end}, output {out_pos}..{out_end}): \
                 libzstd {want:?} read to {ci} wrote to {co}, port {got:?} read to {pi} wrote to {po}"
            ));
        }
        if c_out[out_pos..co] != p_out[out_pos..po] {
            let at = (out_pos..co)
                .find(|&i| c_out[i] != p_out[i])
                .unwrap_or(out_pos);
            return Err(format!("call {call}: the output differs at byte {at}"));
        }
        hash = fnv1a_from(hash, &c_out[out_pos..co]);
        // Given all the input, and room for output, and still no progress:
        // a frame cut short. libzstd fails after 16 such calls, except while
        // the header is incomplete, where it keeps asking for more.
        if (ci, co) == (in_pos, out_pos) && in_end == src.len() {
            stalled += 1;
        } else {
            stalled = 0;
        }
        in_pos = ci;
        out_pos = co;
        match want {
            Err(name) => return Ok(format!("err {name} at call {call}, after {out_pos} bytes")),
            Ok(0) if in_pos == src.len() => {
                return Ok(format!("ok {out_pos} {hash:016x}"));
            }
            Ok(hint) if stalled > 20 => {
                return Ok(format!(
                    "wants {hint} more at call {call}, after {out_pos} bytes"
                ));
            }
            Ok(_) => {}
        }
    }
    Err(format!("no end after {MAX_CALLS} calls"))
}
