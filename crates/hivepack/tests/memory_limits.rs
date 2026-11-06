//! The memory the multi-threaded coders take, against what their estimates
//! say: 7z's LZMA2 in blocks (`WriteOptions::memory_usage`), zstd's workers
//! (`CCtx::estimate_memory`), bzip2's `CompressMt` (`MtOptions::memory_usage`)
//! and bzip2's threads in `Opener`. An allocator that counts what is
//! allocated gives the most each held at once: it must be no more than the
//! estimate, and the estimate no more than twice it. Under a memory limit,
//! the threads are lowered, what is made is the same, and it takes no more
//! than the limit.
//!
//! The default run takes the small presets and levels. The rest takes up
//! to 13 GB at once and 20 minutes on 32 threads, and prints the ratios:
//!
//! ```sh
//! cargo test --release -p hivepack --test memory_limits -- --ignored --nocapture
//! ```

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The allocator that counts: the one `unsafe` here, in a test, outside the
// library, which forbids it. It hands every call to the system's.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hivepack::Threads;
use hivepack::bzip2::{
    Action, CompressMt, InBuffer as BzIn, MtOptions, OutBuffer as BzOut, Status,
};
use hivepack::open::{Limits, Opener};
use hivepack::sevenz::{Lzma2Blocks, Method, NewEntry, WriteOptions, Writer};
use hivepack::zstd::{CCtx, CParameter, EndDirective, InBuffer, OutBuffer, ParamSwitch};

/// The bytes allocated now, and the most since the last [`measure`].
static CURRENT: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

struct Counting;

fn grew(by: u64) {
    let now = CURRENT.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn shrank(by: u64) {
    CURRENT.fetch_sub(by, Ordering::Relaxed);
}

// SAFETY: each call is the system allocator's, with the same arguments;
// the counts beside it touch no memory.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller's.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size() as u64);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller's.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size() as u64);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: as the caller's.
        unsafe { System.dealloc(p, layout) };
        shrank(layout.size() as u64);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as the caller's.
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            // Counted as if in place, as large blocks are moved by
            // remapping their pages: the old size, then the new.
            let (old, new) = (layout.size() as u64, new_size as u64);
            if new > old {
                grew(new - old);
            } else {
                shrank(old - new);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One measure at a time: the tests of this file each take it whole.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The most bytes `work` held at once beyond what was held before it, and
/// what it gave. Threads a coder leaves to end on their own are waited for
/// after, so that the next measure does not count them.
fn measure<T>(work: impl FnOnce() -> T) -> (u64, T) {
    let before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = work();
    let peak = PEAK.load(Ordering::Relaxed) - before;
    let start = Instant::now();
    while CURRENT.load(Ordering::Relaxed) > before + (1 << 20)
        && start.elapsed() < Duration::from_secs(10)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    (peak, out)
}

/// Text of a kind, `len` bytes: words of a vocabulary of 4096, picked at
/// random, so that it compresses about as text does, 3 to 4 times.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let words: Vec<Vec<u8>> = (0..4096)
        .map(|_| {
            let n = 2 + next() % 9;
            (0..n).map(|_| b'a' + (next() % 26) as u8).collect()
        })
        .collect();
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        let r = next();
        out.extend_from_slice(&words[(r % 4096) as usize]);
        out.push(if r >> 60 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

/// An output that keeps nothing, but where it is: a 7z writer seeks back
/// to its start at the end.
#[derive(Default)]
struct Discard {
    pos: u64,
    len: u64,
}

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pos += buf.len() as u64;
        self.len = self.len.max(self.pos);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for Discard {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::Current(by) => self.pos.checked_add_signed(by).unwrap(),
            SeekFrom::End(by) => self.len.checked_add_signed(by).unwrap(),
        };
        Ok(self.pos)
    }
}

/// A hash of what an output gets, to compare outputs without keeping them.
#[derive(Default)]
struct Hash {
    discard: Discard,
    sum: u64,
}

impl Write for Hash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &b in buf {
            self.sum = (self.sum ^ u64::from(b)).wrapping_mul(0x100_0000_01B3);
        }
        self.discard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for Hash {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.discard.seek(to)
    }
}

const MIB: f64 = (1 << 20) as f64;

/// A measure against its estimate: actual no more, and the estimate no
/// more than twice it. Printed with `--nocapture`.
fn check(what: &str, actual: u64, estimate: u64) {
    let ratio = estimate as f64 / actual as f64;
    println!(
        "{what}: {:.1} MiB held, {:.1} MiB estimated, {ratio:.2}x",
        actual as f64 / MIB,
        estimate as f64 / MIB,
    );
    assert!(
        actual <= estimate,
        "{what}: {actual} held, {estimate} estimated"
    );
    assert!(ratio <= 2.0, "{what}: {actual} held, {estimate} estimated");
}

/// `data` written as one file of a 7z archive with `options`, in pieces of
/// 1 MiB, as a hash.
fn write_7z(data: &[u8], options: &WriteOptions) -> u64 {
    let mut writer = Writer::with_options(Hash::default(), options.clone()).unwrap();
    writer.start_file(NewEntry::new("data")).unwrap();
    for piece in data.chunks(1 << 20) {
        writer.write_all(piece).unwrap();
    }
    writer.finish().unwrap().sum
}

fn sevenz_options(preset: u32, blocks: Lzma2Blocks, threads: u32) -> WriteOptions {
    WriteOptions {
        method: Method::Lzma2 { preset },
        lzma2_blocks: blocks,
        threads: Threads::of(threads),
        ..WriteOptions::default()
    }
}

/// 7z with `preset`, in blocks, with `threads`, on enough data for each
/// thread to have blocks and some to wait.
fn sevenz_case(preset: u32, blocks: Lzma2Blocks, block: usize, threads: u32) {
    let data = text(
        block * (threads as usize + 2),
        u64::from(preset * 100 + threads),
    );
    let options = sevenz_options(preset, blocks, threads);
    let estimate = options.memory_usage(threads).unwrap();
    let (actual, _) = measure(|| write_7z(&data, &options));
    check(
        &format!(
            "7z preset {preset}, blocks of {} MiB, {threads} threads",
            block >> 20
        ),
        actual,
        estimate,
    );
}

/// `data` compressed by `cctx` as one frame of unknown size, given and
/// written out 1 MiB at a time, as a hash.
fn zstd_stream(cctx: &mut CCtx, data: &[u8]) -> u64 {
    let mut out = [0u8; 1 << 16];
    let mut hash = Hash::default();
    for piece in data.chunks(1 << 20) {
        let mut input = InBuffer::new(piece);
        while input.pos < piece.len() {
            let mut output = OutBuffer::new(&mut out);
            cctx.compress_stream2(&mut output, &mut input, EndDirective::Continue)
                .unwrap();
            let n = output.pos;
            hash.write_all(&out[..n]).unwrap();
        }
    }
    loop {
        let mut output = OutBuffer::new(&mut out);
        let left = cctx.end_stream(&mut output).unwrap();
        let n = output.pos;
        hash.write_all(&out[..n]).unwrap();
        if left == 0 {
            return hash.sum;
        }
    }
}

fn zstd_cctx(level: i32, workers: u32) -> CCtx {
    let mut cctx = CCtx::new();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers)).unwrap();
    cctx
}

/// zstd at `level` with `workers` (none for 0), on enough data for each
/// worker to have jobs and some to wait: `job` bytes each.
fn zstd_case(level: i32, workers: u32, job: usize, ldm: bool) {
    let jobs = workers.max(1) as usize + 3;
    let data = text(job * jobs, u64::from(level.unsigned_abs() * 100 + workers));
    let (actual, estimate) = measure(|| {
        let mut cctx = zstd_cctx(level, workers);
        if ldm {
            cctx.set_parameter(CParameter::EnableLongDistanceMatching(ParamSwitch::Enable))
                .unwrap();
            cctx.set_parameter(CParameter::WindowLog(24)).unwrap();
        }
        let estimate = cctx.estimate_memory(workers).unwrap();
        zstd_stream(&mut cctx, &data);
        estimate
    });
    let ldm = if ldm { ", long distance matching" } else { "" };
    check(
        &format!("zstd level {level}{ldm}, {workers} workers"),
        actual,
        estimate,
    );
}

/// `data` through `CompressMt` with `options`, 1 MiB at a time in and out,
/// as a hash, and the streams if `keep`.
fn bzip2_mt(data: &[u8], options: &MtOptions, keep: bool) -> (u64, Vec<u8>) {
    let mut c = CompressMt::with_options(options).unwrap();
    let mut out = [0u8; 1 << 16];
    let mut hash = Hash::default();
    let mut kept = Vec::new();
    let mut at = 0;
    loop {
        let end = (at + (1 << 20)).min(data.len());
        let mut input = BzIn::new(&data[at..end]);
        let mut output = BzOut::new(&mut out);
        let action = if end == data.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let status = c.compress(&mut output, &mut input, action).unwrap();
        at += input.pos;
        let n = output.pos;
        hash.write_all(&out[..n]).unwrap();
        if keep {
            kept.extend_from_slice(&out[..n]);
        }
        if status == Status::StreamEnd {
            return (hash.sum, kept);
        }
    }
}

fn bzip2_options(threads: u32) -> MtOptions {
    MtOptions {
        block_size_100k: 9,
        threads: Threads::of(threads),
        ..MtOptions::default()
    }
}

fn bzip2_case(threads: u32) {
    let options = bzip2_options(threads);
    let data = text(855_000 * (2 * threads as usize + 4), u64::from(threads));
    let estimate = options.memory_usage(threads).unwrap();
    let (actual, _) = measure(|| bzip2_mt(&data, &options, false));
    check(
        &format!("bzip2 level 9, {threads} threads"),
        actual,
        estimate,
    );
}

/// What `Opener` reads of `file`, with `threads` and `limits`, as a hash.
fn open_bzip2(file: &[u8], threads: u32, limits: Limits) -> u64 {
    let mut opener = Opener::new(|| Ok(Cursor::new(file)))
        .threads(Threads::of(threads))
        .limits(limits);
    let mut opened = opener.open().unwrap();
    let mut hash = Hash::default();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = opened.read(&mut buf).unwrap();
        if n == 0 {
            return hash.sum;
        }
        hash.write_all(&buf[..n]).unwrap();
    }
}

/// bzip2 read in threads by `Opener`, against the bound `docs/memory.md`
/// gives: 21 MiB a thread and 13 MiB more. Not twice what is held: the
/// bound takes pieces of the most the threads take, 2 MiB packed and 4
/// MiB unpacked, where those of `CompressMt` are a quarter of that.
fn bzip2_read_case(threads: u32) {
    let data = text(855_000 * (2 * threads as usize + 4), 7);
    let (_, file) = bzip2_mt(&data, &bzip2_options(4), true);
    let bound = u64::from(threads) * (21 << 20) + (13 << 20);
    let (actual, _) = measure(|| open_bzip2(&file, threads, Limits::default()));
    println!(
        "bzip2 read, {threads} threads: {:.1} MiB held, bound {:.1} MiB",
        actual as f64 / MIB,
        bound as f64 / MIB
    );
    assert!(actual <= bound, "{actual} held, bound {bound}");
}

#[test]
fn sevenz_small_presets() {
    let _one = lock();
    for threads in [1, 4] {
        sevenz_case(1, Lzma2Blocks::Auto, 4 << 20, threads);
    }
    // Blocks smaller than the dictionary make it their size.
    sevenz_case(6, Lzma2Blocks::Size(1 << 20), 1 << 20, 4);
}

/// Bytes that do not compress, `len` of them.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}

/// The methods of one thread fit their estimates too, which are not tight
/// for those that take little: 1 MiB is counted for the writer's own.
#[test]
fn sevenz_other_methods() {
    let _one = lock();
    let data = text(6 << 20, 22);
    for method in [
        Method::Copy,
        Method::Lzma { preset: 1 },
        Method::Lzma2 { preset: 6 },
        Method::Deflate { level: 9 },
        Method::BZip2 { level: 9 },
    ] {
        let options = WriteOptions {
            method,
            threads: Threads::of(4),
            ..WriteOptions::default()
        };
        let estimate = options.memory_usage(4).unwrap();
        assert_eq!(options.threads_used(), Ok(1));
        let (actual, _) = measure(|| write_7z(&data, &options));
        println!(
            "7z {method:?}: {:.1} MiB held, {:.1} MiB estimated",
            actual as f64 / MIB,
            estimate as f64 / MIB
        );
        assert!(
            actual <= estimate,
            "{method:?}: {actual} held, {estimate} estimated"
        );
    }
}

/// What does not compress grows a little: the room for it is still enough.
#[test]
fn data_that_does_not_compress() {
    let _one = lock();
    let data = noise(6 << 20, 21);
    let options = sevenz_options(1, Lzma2Blocks::Size(1 << 20), 3);
    let estimate = options.memory_usage(3).unwrap();
    let (actual, _) = measure(|| write_7z(&data, &options));
    check("7z preset 1, noise, 3 threads", actual, estimate);
    let (actual, estimate) = measure(|| {
        let mut cctx = zstd_cctx(1, 2);
        cctx.set_parameter(CParameter::JobSize(1 << 20)).unwrap();
        let estimate = cctx.estimate_memory(2).unwrap();
        zstd_stream(&mut cctx, &data);
        estimate
    });
    check("zstd level 1, noise, 2 workers", actual, estimate);
    let options = MtOptions {
        block_size_100k: 1,
        ..bzip2_options(3)
    };
    let estimate = options.memory_usage(3).unwrap();
    let (actual, _) = measure(|| bzip2_mt(&data, &options, false));
    check("bzip2 level 1, noise, 3 threads", actual, estimate);
}

#[test]
fn zstd_small_levels() {
    let _one = lock();
    for workers in [0, 1, 4] {
        zstd_case(3, workers, 8 << 20, false);
    }
    zstd_case(1, 0, 1 << 20, false);
}

#[test]
fn bzip2_threads() {
    let _one = lock();
    for threads in [1, 4] {
        bzip2_case(threads);
    }
    bzip2_read_case(4);
}

#[test]
fn estimates_grow_with_threads() {
    let _one = lock();
    let options = sevenz_options(6, Lzma2Blocks::Auto, 1);
    let one = options.memory_usage(1).unwrap();
    let two = options.memory_usage(2).unwrap();
    // An encoder of 94 MiB and two blocks of 32 MiB a thread.
    assert!(
        (150 << 20..170 << 20).contains(&(two - one)),
        "{}",
        two - one
    );
    assert_eq!(options.memory_usage(0).unwrap(), one);
    // One stream, other methods: one thread whatever is asked.
    let stream = sevenz_options(6, Lzma2Blocks::None, 8);
    assert_eq!(stream.memory_usage(8), stream.memory_usage(1));
    assert_eq!(stream.threads_used(), Ok(1));
    assert!(
        WriteOptions {
            method: Method::Lzma2 { preset: 10 },
            ..options.clone()
        }
        .memory_usage(1)
        .is_err()
    );
    let bzip2 = bzip2_options(1);
    assert!(bzip2.memory_usage(2).unwrap() > bzip2.memory_usage(1).unwrap());
    let cctx = zstd_cctx(19, 4);
    let workers = [1, 2, 4, 16].map(|n| cctx.estimate_memory(n).unwrap());
    assert!(workers.windows(2).all(|w| w[0] < w[1]), "{workers:?}");
    assert!(cctx.estimate_memory(0).unwrap() < workers[0]);
}

#[test]
fn sevenz_limit_lowers_threads() {
    let _one = lock();
    let data = text(30 << 20, 11);
    let wide = sevenz_options(1, Lzma2Blocks::Auto, 8);
    let want = write_7z(&data, &sevenz_options(1, Lzma2Blocks::Auto, 1));
    for threads in [1, 3, 8] {
        let limit = wide.memory_usage(threads).unwrap();
        let options = WriteOptions {
            memory_limit: limit,
            ..wide.clone()
        };
        assert_eq!(options.threads_used(), Ok(threads));
        let (actual, got) = measure(|| write_7z(&data, &options));
        assert_eq!(got, want, "{threads} threads");
        assert!(
            actual <= limit,
            "{threads} threads: {actual} held, {limit} allowed"
        );
    }
    // Below one thread's memory: one thread all the same.
    let tight = WriteOptions {
        memory_limit: 1 << 20,
        ..wide
    };
    assert_eq!(tight.threads_used(), Ok(1));
    assert_eq!(write_7z(&data, &tight), want);
}

#[test]
fn zstd_limit_lowers_workers() {
    let _one = lock();
    let data = text(24 << 20, 12);
    let want = zstd_stream(&mut zstd_cctx(3, 1), &data);
    let mut cctx = zstd_cctx(3, 6);
    assert_eq!(cctx.nb_workers_within_limit(), Ok(6));
    for workers in [6, 2, 4, 1] {
        let limit = cctx.estimate_memory(workers).unwrap();
        cctx.set_workers_memory_limit(limit);
        assert_eq!(cctx.nb_workers_within_limit(), Ok(workers));
        let (actual, got) = measure(|| zstd_stream(&mut cctx, &data));
        assert_eq!(got, want, "{workers} workers");
        assert!(
            actual <= limit,
            "{workers} workers: {actual} held, {limit} allowed"
        );
    }
    cctx.set_workers_memory_limit(1);
    assert_eq!(cctx.nb_workers_within_limit(), Ok(1));
    assert_eq!(zstd_stream(&mut cctx, &data), want);
    // No workers: no limit to them.
    let none = zstd_cctx(3, 0);
    assert_eq!(none.nb_workers_within_limit(), Ok(0));
}

#[test]
fn bzip2_limit_lowers_threads() {
    let _one = lock();
    let data = text(855_000 * 12, 13);
    let wide = bzip2_options(6);
    let (want, file) = bzip2_mt(&data, &bzip2_options(1), true);
    for threads in [1, 2, 6] {
        let limit = wide.memory_usage(threads).unwrap();
        let options = MtOptions {
            memory_limit: limit,
            ..wide
        };
        assert_eq!(options.threads_used(), Ok(threads));
        let (actual, (got, _)) = measure(|| bzip2_mt(&data, &options, false));
        assert_eq!(got, want, "{threads} threads");
        assert!(
            actual <= limit,
            "{threads} threads: {actual} held, {limit} allowed"
        );
    }
    // Reading: the same whatever the limit, and within it.
    let plain = open_bzip2(&file, 1, Limits::default());
    for (limit, most) in [(0, 8 << 20), (60 << 20, 60 << 20), (u64::MAX, u64::MAX)] {
        let mut limits = Limits::default();
        limits.bzip2_memlimit = limit;
        let (actual, got) = measure(|| open_bzip2(&file, 8, limits));
        assert_eq!(got, plain, "limit {limit}");
        assert!(actual <= most, "limit {limit}: {actual} held");
    }
}

/// The presets, levels and threads the estimates are checked at, with the
/// ratios printed: up to 13 GB at once, and 20 minutes on 32 threads.
#[test]
#[ignore = "takes 13 GB and 20 minutes: run with --release -- --ignored --nocapture"]
fn every_preset_and_level() {
    let _one = lock();
    for threads in [1, 4, 16] {
        sevenz_case(1, Lzma2Blocks::Auto, 4 << 20, threads);
        sevenz_case(6, Lzma2Blocks::Auto, 32 << 20, threads);
    }
    // Preset 9's blocks of 256 MiB in 4 threads; in 16, blocks of 64 MiB,
    // the dictionary's size, keep its encoder of 674 MiB in a third of the
    // memory.
    for threads in [1, 4] {
        sevenz_case(9, Lzma2Blocks::Auto, 256 << 20, threads);
    }
    sevenz_case(9, Lzma2Blocks::Size(64 << 20), 64 << 20, 16);
    for workers in [0, 1, 4, 16] {
        zstd_case(3, workers, 8 << 20, false);
        zstd_case(19, workers, 32 << 20, false);
    }
    zstd_case(3, 4, 64 << 20, true);
    for threads in [1, 4, 16] {
        bzip2_case(threads);
    }
    for threads in [4, 16] {
        bzip2_read_case(threads);
    }
}

/// RAR extracted in threads, each holding what it decompresses with, against
/// the bound `docs/memory.md` gives for each thread, counted for the entry
/// that takes the most: its window, as large as the entry asks and no larger
/// than twice its size and 8 MiB more, PPMd's 257 MiB for RAR 2.9 to 4, and 5
/// MiB; and 8 MiB more for the caller's, its list of entries and the archive's
/// buffers. Under a memory limit of two threads, no more than two are held.
#[cfg(all(feature = "extract", feature = "rar"))]
mod rar {
    use std::path::{Path, PathBuf};

    use hivepack::Threads;
    use hivepack::extract::{Options, extract_rar};
    use hivepack::rar::{Archive, Format, HEAD_FILE};

    use super::{MIB, lock, measure};

    /// The most a thread holds for one entry of `data`, as the bound says.
    fn each(data: &[u8]) -> u64 {
        let mut arc = Archive::open_with_password(data, false, "hivepack").unwrap();
        let mut most = 0;
        while arc.read_header().unwrap() != 0 {
            let head = &arc.file_head;
            if arc.cur_header_type == HEAD_FILE && !head.dir && head.method != 0 {
                let largest = head.win_size.max(0x4_0000);
                let reached = (head.unp_size.max(0) as u64) + (8 << 20) + (64 << 10);
                let window = largest.min((2 * reached).max(1 << 20));
                let ppmd = if arc.format != Format::Rar50 && head.unp_ver == 29 {
                    257 << 20
                } else {
                    0
                };
                most = most.max(window + ppmd + (5 << 20));
            }
            arc.seek_to_next();
        }
        most
    }

    fn scratch(name: &str, threads: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hivepack-memory-rar-{}-{name}-{threads}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn extract(data: &[u8], out: &Path, threads: u32, limit: Option<u64>) {
        let mut options = Options::default();
        options.threads = Threads::of(threads);
        options.memory_limit = limit;
        options.password = Some(b"hivepack".to_vec());
        options.limits.max_ratio = u64::MAX;
        extract_rar(
            |password| Archive::open_with_password(data, false, password),
            out,
            &options,
        )
        .unwrap();
    }

    fn case(name: &str, threads: u32) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/rar")
            .join(name);
        let data = std::fs::read(path).unwrap();
        let each = each(&data);
        for (limit, most) in [(None, threads), (Some(2 * each), threads.min(2))] {
            let out = scratch(name, threads);
            let (actual, ()) = measure(|| extract(&data, &out, threads, limit));
            let _ = std::fs::remove_dir_all(&out);
            let bound = u64::from(most) * each + (8 << 20);
            println!(
                "{name}, {threads} threads, limit {limit:?}: {:.1} MiB held, bound {:.1} MiB",
                actual as f64 / MIB,
                bound as f64 / MIB
            );
            assert!(actual <= bound, "{name}: {actual} held, bound {bound}");
        }
    }

    #[test]
    fn rar_threads_hold_no_more_than_their_bound() {
        let _one = lock();
        for name in [
            "rar5-m3.rar",
            "rar5-m5.rar",
            "rar4-m3.rar",
            "rar4-m3-ppmd.rar",
        ] {
            for threads in [1, 4, 8] {
                case(name, threads);
            }
        }
    }
}
