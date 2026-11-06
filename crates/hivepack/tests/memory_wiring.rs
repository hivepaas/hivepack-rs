//! The example of `docs/memory.md`, "Wiring it to the coders": an
//! application measures what is available, gives its jobs half of it, and
//! each job holds the threads its coder takes, and their memory, until it
//! is done. Nothing in hivepack does this on its own. Built and run here,
//! so that the example stays right.

use std::io::{self, Cursor, Read, Seek, Write};

use hivepack::Threads;
use hivepack::memory::{Budget, Held};
use hivepack::{bzip2, open, sevenz, xz, zip, zstd};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// The example begins.

/// What the application gives its jobs, between them: half of what is
/// available now, as packwing does, or 1 GiB where it is not measured.
fn budget() -> Budget {
    Budget::of_available(1, 2).unwrap_or_else(|| Budget::new(1 << 30))
}

/// 7z with LZMA2 in blocks, in the most threads, `wanted` or fewer, that
/// fit. An estimate that fails is of options the writer refuses: counted
/// as too much, it gives one thread, and the writer tells the error.
fn sevenz_writer<W: Write + Seek>(
    out: W,
    budget: &Budget,
    preset: u32,
    wanted: u32,
) -> Result<(sevenz::Writer<W>, Held)> {
    let mut options = sevenz::WriteOptions {
        method: sevenz::Method::Lzma2 { preset },
        lzma2_blocks: sevenz::Lzma2Blocks::Auto,
        ..Default::default()
    };
    let (threads, held) =
        budget.hold_threads(wanted, |n| options.memory_usage(n).unwrap_or(u64::MAX));
    options.threads = Threads::of(threads);
    options.memory_limit = held.bytes();
    Ok((sevenz::Writer::with_options(out, options)?, held))
}

/// zstd with workers: each frame takes the workers held, fewer where it
/// would take more than the limit (a frame of another size).
fn zstd_cctx(budget: &Budget, level: i32, wanted: u32) -> Result<(zstd::CCtx, Held)> {
    let mut cctx = zstd::CCtx::new();
    cctx.set_parameter(zstd::CParameter::CompressionLevel(level))?;
    let (workers, held) =
        budget.hold_threads(wanted, |n| cctx.estimate_memory(n).unwrap_or(u64::MAX));
    cctx.set_parameter(zstd::CParameter::NbWorkers(workers))?;
    cctx.set_workers_memory_limit(held.bytes());
    Ok((cctx, held))
}

/// bzip2 in threads, as pbzip2 compresses.
fn bzip2_compressor(budget: &Budget, level: i32, wanted: u32) -> Result<(bzip2::CompressMt, Held)> {
    let mut options = bzip2::MtOptions {
        block_size_100k: level,
        ..Default::default()
    };
    let (threads, held) =
        budget.hold_threads(wanted, |n| options.memory_usage(n).unwrap_or(u64::MAX));
    options.threads = Threads::of(threads);
    options.memory_limit = held.bytes();
    Ok((bzip2::CompressMt::with_options(&options)?, held))
}

/// xz in threads: liblzma's encoder has no limit of its own, so the
/// threads held are all it is told.
fn xz_encoder(budget: &Budget, preset: u32, wanted: u32) -> Result<(xz::Stream, Held)> {
    let mut options = xz::MtOptions {
        preset,
        ..Default::default()
    };
    let (threads, held) = budget.hold_threads(wanted, |n| {
        xz::stream_encoder_mt_memusage(&xz::MtOptions {
            threads: n,
            ..options.clone()
        })
    });
    options.threads = threads;
    Ok((xz::Stream::stream_encoder_mt(&options)?, held))
}

/// What each thread of `zip::Archive::set_threads` takes: up to 32 MiB of
/// entries compressed ahead, waiting to be written, and its compressor:
/// Deflate's, 512 KiB at most (bzip2's 7 MiB, LZMA's and XZ's 94 MiB at
/// preset 6). ZIP's threads take no limit: the threads are all it is told.
fn zip_threads<R>(archive: &mut zip::Archive<R>, budget: &Budget, wanted: u32) -> Held {
    let (threads, held) =
        budget.hold_threads(wanted, |n| u64::from(n) * ((32 << 20) + (512 << 10)));
    archive.set_threads(Threads::of(threads));
    held
}

/// Reading through `open::Opener`, bzip2 in threads: 20.5 MiB a thread, and
/// 13 MiB (`docs/memory.md`, "Readers"). xz's threads are bounded by
/// `Limits::xz_memlimit`, which is also the most one Block may take before
/// it fails: it is left as it is.
fn opener<F, R>(open: F, budget: &Budget, wanted: u32) -> (open::Opener<F>, Held)
where
    F: FnMut() -> io::Result<R>,
    R: Read + Send,
{
    let (threads, held) = budget.hold_threads(wanted, |n| u64::from(n) * (41 << 19) + (13 << 20));
    let mut limits = open::Limits::default();
    limits.bzip2_memlimit = held.bytes();
    let opener = open::Opener::new(open)
        .threads(Threads::of(threads))
        .limits(limits);
    (opener, held)
}

/// The preset of 7z's LZMA2 in blocks to compress with: `preset`, or the
/// highest below it whose one thread fits what is left, as packwing lowers
/// a level the machine has no room for, and says so. `None` where not even
/// preset 0 fits: the application may wait for other jobs to end, refuse,
/// or go on past the budget with one thread.
fn sevenz_preset_that_fits(budget: &Budget, preset: u32) -> Option<u32> {
    (0..=preset).rev().find(|&preset| {
        let options = sevenz::WriteOptions {
            method: sevenz::Method::Lzma2 { preset },
            lzma2_blocks: sevenz::Lzma2Blocks::Auto,
            ..Default::default()
        };
        options
            .memory_usage(1)
            .is_ok_and(|one| one <= budget.left())
    })
}

/// A job: `data` in a 7z archive, at preset 9 or the highest that fits,
/// and said so, in as many threads as the machine runs at once, or as fit.
/// What it holds is given back when it ends, for the jobs after it.
fn compress_job<W: Write + Seek>(budget: &Budget, out: W, name: &str, data: &[u8]) -> Result<W> {
    let preset = match sevenz_preset_that_fits(budget, 9) {
        Some(9) => 9,
        Some(lower) => {
            eprintln!("{name}: preset 9 does not fit in the memory left: made at preset {lower}");
            lower
        }
        // Not even preset 0 fits: the least there is, past the budget.
        None => 0,
    };
    let (mut writer, _held) = sevenz_writer(out, budget, preset, Threads::Auto.count())?;
    writer.start_file(sevenz::NewEntry::new(name))?;
    writer.write_all(data)?;
    Ok(writer.finish()?)
}

// The example ends.

const MIB: u64 = 1 << 20;

/// Text of a kind, which compresses about as text does.
fn text(len: usize) -> Vec<u8> {
    let words = ["memory ", "thread ", "budget ", "held ", "zstd ", "bzip2\n"];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(words[(state % 6) as usize].as_bytes());
    }
    out.truncate(len);
    out
}

/// `data` through an xz or bzip2 coder, with `run` called until it ends.
fn through(data: &[u8], mut run: impl FnMut(&[u8], &mut [u8]) -> (usize, usize, bool)) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut at = 0;
    loop {
        let (read, written, end) = run(&data[at..], &mut buf);
        at += read;
        out.extend_from_slice(&buf[..written]);
        if end {
            return out;
        }
    }
}

#[test]
fn each_coder_under_a_budget_of_half() {
    let budget = budget();
    let data = text(3 << 20);

    let (mut writer, held) = sevenz_writer(Cursor::new(Vec::new()), &budget, 1, 4).unwrap();
    assert!(held.bytes() > 0 && budget.held() >= held.bytes());
    writer
        .start_file(sevenz::NewEntry::new("notes.txt"))
        .unwrap();
    writer.write_all(&data).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    drop(held);
    assert_eq!(
        sevenz::Archive::open(Cursor::new(archive)).unwrap().len(),
        1
    );

    let (mut cctx, held) = zstd_cctx(&budget, 3, 4).unwrap();
    assert!(cctx.nb_workers_within_limit().unwrap() <= 4);
    let mut frame = vec![0; zstd::compress_bound(data.len()).unwrap()];
    let n = cctx.compress2(&mut frame, &data).unwrap();
    drop((cctx, held));
    let mut back = vec![0; data.len()];
    assert_eq!(
        zstd::decompress(&mut back, &frame[..n]).unwrap(),
        data.len()
    );
    assert_eq!(back, data);

    let (mut bz, held) = bzip2_compressor(&budget, 9, 4).unwrap();
    let file = through(&data, |input, out| {
        let mut input = bzip2::InBuffer::new(input);
        let mut output = bzip2::OutBuffer::new(out);
        let status = bz
            .compress(&mut output, &mut input, bzip2::Action::Finish)
            .unwrap();
        (input.pos, output.pos, status == bzip2::Status::StreamEnd)
    });
    drop((bz, held));
    let (mut opener, held) = opener(|| Ok(Cursor::new(file.clone())), &budget, 4);
    let mut back = Vec::new();
    opener.open().unwrap().read_to_end(&mut back).unwrap();
    drop(held);
    assert_eq!(back, data);

    let (mut xz, held) = xz_encoder(&budget, 1, 4).unwrap();
    let file = through(&data, |input, out| {
        let mut input = xz::InBuffer::new(input);
        let mut output = xz::OutBuffer::new(out);
        let status = xz
            .code(&mut output, &mut input, xz::Action::Finish)
            .unwrap();
        (input.pos, output.pos, status == xz::Status::StreamEnd)
    });
    drop((xz, held));
    let mut back = Vec::new();
    open::Opener::new(|| Ok(Cursor::new(file.clone())))
        .open()
        .unwrap()
        .read_to_end(&mut back)
        .unwrap();
    assert_eq!(back, data);

    let mut archive = zip::Archive::open(&[][..], zip::OpenFlags(0)).unwrap();
    let held = zip_threads(&mut archive, &budget, 4);
    for i in 0..4 {
        archive
            .file_add(
                format!("notes-{i}.txt").as_bytes(),
                zip::BufferSource::new(data.clone()),
                zip::Flags::NONE,
            )
            .unwrap();
    }
    let mut out = Cursor::new(Vec::new());
    archive.close_to(&mut out).unwrap();
    drop((archive, held));
    assert!(out.into_inner().len() < data.len());

    assert_eq!(budget.held(), 0);
}

#[test]
fn under_a_small_budget_fewer_threads_and_a_lower_level() {
    let usage = |preset, threads| {
        sevenz::WriteOptions {
            method: sevenz::Method::Lzma2 { preset },
            lzma2_blocks: sevenz::Lzma2Blocks::Auto,
            ..Default::default()
        }
        .memory_usage(threads)
        .unwrap()
    };
    let budget = Budget::new(400 * MIB);
    // Preset 9 takes 1.4 GiB for one thread: the highest that fits.
    let preset = sevenz_preset_that_fits(&budget, 9).unwrap();
    assert!(preset < 9);
    assert!(usage(preset, 1) <= 400 * MIB && usage(preset + 1, 1) > 400 * MIB);
    // Preset 6 takes 190 MiB, and 157 MiB a thread more: two threads.
    let (_, held) = sevenz_writer(Cursor::new(Vec::new()), &budget, 6, 16).unwrap();
    assert_eq!(held.bytes(), usage(6, 2));
    // The job after it finds a lower preset, and zstd's level 19 no room
    // for its one worker (373 MiB), which it is given all the same.
    assert!(sevenz_preset_that_fits(&budget, 9).unwrap() < preset);
    let (cctx, zstd_held) = zstd_cctx(&budget, 19, 16).unwrap();
    assert_eq!(cctx.nb_workers_within_limit().unwrap(), 1);
    assert!(budget.held() > budget.bytes());
    drop((held, zstd_held));
    // Alone, level 19 fits one worker, not two (656 MiB).
    let (cctx, held) = zstd_cctx(&budget, 19, 16).unwrap();
    assert_eq!(cctx.nb_workers_within_limit().unwrap(), 1);
    assert!(held.bytes() <= 400 * MIB);
    drop((cctx, held));
    // Nothing fits in 1 MiB.
    assert_eq!(sevenz_preset_that_fits(&Budget::new(MIB), 9), None);
    // Jobs at a lower preset, and at the least past the budget.
    let data = text(1 << 20);
    for budget in [Budget::new(400 * MIB), Budget::new(MIB)] {
        let archive = compress_job(&budget, Cursor::new(Vec::new()), "notes.txt", &data).unwrap();
        let archive = sevenz::Archive::open(Cursor::new(archive.into_inner())).unwrap();
        assert_eq!(archive.len(), 1);
        assert_eq!(budget.held(), 0);
    }
}
