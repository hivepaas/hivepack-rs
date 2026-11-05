//! `--threads`: an archive of files on disk written with
//! `Archive::set_threads`, in one thread and in more, in place of the rest.
//! Two sets of files are cut from the text files of DATA (Silesia's dickens,
//! nci, reymont, samba, webster and xml), `--limit-mb` of each: many small
//! files, of 1 KiB to 64 KiB, and eight large ones. Each is written to a file
//! as `close_to` writes it, deflated at libzip's default level (`ZIP_CM_DEFAULT`,
//! level 9), at level 6, and at level 6 with WinZip AES-256, and to a stream
//! as `close_to_stream` writes it. Each row says how long the best of
//! `--rounds` took, and the size written; every archive must be the same,
//! byte for byte, as the one thread's.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hivepack::Threads;
use hivepack::zip::{Archive, FileSource, Flags, OpenFlags, RandomSource, cm, em};

use crate::{PASSWORD, Result, best};

/// Silesia's files of text.
const TEXT: [&str; 6] = ["dickens", "nci", "reymont", "samba", "webster", "xml"];

/// Pieces of Silesia's text under `dir/name`, `limit` bytes in all, each of
/// `size()` bytes: their names, and paths.
fn make_text(
    sources: &[Vec<u8>],
    dir: &Path,
    name: &str,
    limit: usize,
    mut size: impl FnMut(u64) -> usize,
) -> Result<Vec<(String, PathBuf)>> {
    let root = dir.join(name);
    let _ = std::fs::remove_dir_all(&root);
    let mut state = 0x7ead_5bec_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut files, mut total) = (Vec::new(), 0);
    while total < limit {
        let source = &sources[next() as usize % sources.len()];
        let len = size(next()).min(limit - total);
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let n = (len - data.len()).min(source.len());
            let start = next() as usize % (source.len() - n + 1);
            data.extend_from_slice(&source[start..start + n]);
        }
        let name = format!(
            "d{:02}/s{:02}/file{:05}.txt",
            files.len() % 37,
            files.len() % 11,
            files.len()
        );
        let path = root.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, &data).map_err(|e| e.to_string())?;
        files.push((name, path));
        total += len;
    }
    Ok(files)
}

/// Random bytes that are the same each time an archive is written.
fn counting() -> RandomSource {
    let next = Arc::new(AtomicU64::new(1));
    Arc::new(move |buf: &mut [u8]| {
        for b in buf {
            *b = next.fetch_add(1, Ordering::Relaxed) as u8;
        }
        Ok(())
    })
}

/// How the entries are compressed: the method, the level, and whether they
/// are encrypted.
type How = (i32, u32, bool);

/// Writes the files to `out` with `threads`, to a file, or to a stream: the
/// time it took, from adding the first entry to the end of the archive.
fn write(
    files: &[(String, PathBuf)],
    out: &Path,
    how: How,
    threads: Threads,
    stream: bool,
) -> Result<Duration> {
    let error = |e: hivepack::zip::Error| e.to_string();
    let start = Instant::now();
    let mut archive = Archive::open(&[][..], OpenFlags(0)).map_err(error)?;
    archive.set_threads(threads);
    archive.set_random_source(Some(counting()));
    let (method, level, encrypt) = how;
    for (name, path) in files {
        let index = archive
            .file_add(
                name.as_bytes(),
                FileSource::new(path, 0, None).map_err(error)?,
                Flags::NONE,
            )
            .map_err(error)?;
        archive
            .set_file_compression(index, method, level)
            .map_err(error)?;
        if encrypt {
            archive
                .file_set_encryption(index, em::AES_256, Some(PASSWORD.as_bytes()))
                .map_err(error)?;
        }
    }
    let file = File::create(out).map_err(|e| e.to_string())?;
    let mut file = BufWriter::with_capacity(1 << 20, file);
    if stream {
        archive.close_to_stream(&mut file).map_err(error)?;
    } else {
        archive.close_to(&mut file).map_err(error)?;
    }
    file.flush().map_err(|e| e.to_string())?;
    Ok(start.elapsed())
}

/// Times `files` written each way, in one thread and in more.
pub(crate) fn bench(data: &Path, dir: &Path, limit: usize, rounds: usize) -> Result<()> {
    let mut sources = Vec::new();
    for name in TEXT {
        let path = data.join(name);
        sources.push(std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    // From 1 KiB to 64 KiB, most of them small; eight of an eighth each.
    let small = make_text(&sources, dir, "small", limit, |n| 1024 << (n % 7))?;
    let large = make_text(&sources, dir, "large", limit, |_| limit.div_ceil(8))?;
    let all = Threads::Auto.count();
    let mut counts = vec![Threads::One];
    for n in [2, 4, 8] {
        if n < all {
            counts.push(Threads::Exactly(
                NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN),
            ));
        }
    }
    counts.push(Threads::Auto);
    let ways: [(&str, How, bool); 4] = [
        ("default level", (cm::DEFAULT, 0, false), false),
        ("level 6", (i32::from(cm::DEFLATE), 6, false), false),
        ("level 6, AES-256", (i32::from(cm::DEFLATE), 6, true), false),
        (
            "level 6, to a stream",
            (i32::from(cm::DEFLATE), 6, false),
            true,
        ),
    ];
    let out = dir.join("out.zip");
    let first = dir.join("first.zip");
    println!("| Files | Written | Threads | Time | Speed | Size |");
    println!("|---|---|---|---|---|---|");
    for (set, files) in [("small", &small), ("large", &large)] {
        let bytes: u64 = files
            .iter()
            .map(|(_, path)| std::fs::metadata(path).map_or(0, |m| m.len()))
            .sum();
        let set = format!("{} {set}, {:.1} MB", files.len(), bytes as f64 / 1e6);
        for (way, how, stream) in ways {
            for (k, &threads) in counts.iter().enumerate() {
                let mut times = Vec::new();
                for _ in 0..rounds.max(1) {
                    times.push(write(files, &out, how, threads, stream)?.as_secs_f64());
                }
                if k == 0 {
                    std::fs::rename(&out, &first).map_err(|e| e.to_string())?;
                } else if std::fs::read(&out).map_err(|e| e.to_string())?
                    != std::fs::read(&first).map_err(|e| e.to_string())?
                {
                    return Err(format!("{set}, {way}, {threads:?}: not the same archive"));
                }
                let size = std::fs::metadata(&first).map_or(0, |m| m.len());
                let time = best(&times);
                let name = match threads {
                    Threads::One => "1".to_string(),
                    Threads::Auto => format!("all ({all})"),
                    threads => threads.count().to_string(),
                };
                println!(
                    "| {set} | {way} | {name} | {time:.2} s | {:.1} MB/s | {:.2} MB |",
                    bytes as f64 / 1e6 / time,
                    size as f64 / 1e6
                );
                let _ = std::io::stdout().flush();
            }
        }
    }
    Ok(())
}
