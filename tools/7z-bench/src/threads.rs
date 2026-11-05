//! `--threads`: LZMA2 cut in blocks (`Lzma2Blocks::Auto`, of 32 MiB for preset
//! 6), written in one thread and in all, against one stream as before, and
//! extracted in one thread and in all, on many text files: `--limit-mb` of
//! them, cut from the text files of DATA (Silesia's dickens, nci, reymont,
//! samba, webster and xml), of 1 KiB to 1 MiB each. Each row says how long the
//! best of `--rounds` took, and what size was written. `7zz`, where it is
//! built, tests the archive in blocks in one thread and in all, for the
//! reference.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hivepack::Threads;
use hivepack::sevenz::{Archive, Lzma2Blocks, NewEntry, WriteOptions, Writer};

use crate::{BUF_SIZE, Result, best};

/// Silesia's files of text.
const TEXT: [&str; 6] = ["dickens", "nci", "reymont", "samba", "webster", "xml"];

/// The files of text under `dir/text`, `limit` bytes in all: their names, and
/// paths.
fn make_text(data: &Path, dir: &Path, limit: usize) -> Result<Vec<(String, PathBuf)>> {
    let mut sources = Vec::new();
    for name in TEXT {
        let path = data.join(name);
        sources.push(std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    let root = dir.join("text");
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
        // From 1 KiB to 1 MiB, most of them small.
        let len = (1024usize << (next() % 11))
            .min(source.len())
            .min(limit - total);
        let start = next() as usize % (source.len() - len + 1);
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
        std::fs::write(&path, &source[start..start + len]).map_err(|e| e.to_string())?;
        files.push((name, path));
        total += len;
    }
    Ok(files)
}

/// Writes the files to `out`: the time it took, and the size.
fn write(
    files: &[(String, PathBuf)],
    out: &Path,
    options: &WriteOptions,
) -> Result<(Duration, u64)> {
    let error = |e: hivepack::sevenz::Error| e.name().to_string();
    let start = Instant::now();
    let file = File::create(out).map_err(|e| e.to_string())?;
    let mut w = Writer::with_options(BufWriter::with_capacity(BUF_SIZE, file), options.clone())
        .map_err(error)?;
    for (name, path) in files {
        let mut input = File::open(path).map_err(|e| e.to_string())?;
        w.add_file(NewEntry::new(name), &mut input)
            .map_err(|e| e.to_string())?;
    }
    w.finish().map_err(error)?;
    let time = start.elapsed();
    Ok((
        time,
        std::fs::metadata(out).map_err(|e| e.to_string())?.len(),
    ))
}

/// Extracts `archive` into `out`, emptied first: the time it took.
fn extract(archive: &Path, out: &Path, threads: Threads) -> Result<Duration> {
    let _ = std::fs::remove_dir_all(out);
    let start = Instant::now();
    let reader =
        BufReader::with_capacity(BUF_SIZE, File::open(archive).map_err(|e| e.to_string())?);
    let mut archive = Archive::open(reader).map_err(|e| e.name().to_string())?;
    let mut options = hivepack::extract::Options::default();
    options.threads = threads;
    hivepack::extract::extract_7z(&mut archive, out, &options).map_err(|e| e.to_string())?;
    Ok(start.elapsed())
}

/// Reads every file of `archive`, writing nothing: the time it took.
fn read(archive: &Path, threads: Threads) -> Result<Duration> {
    let start = Instant::now();
    let reader =
        BufReader::with_capacity(BUF_SIZE, File::open(archive).map_err(|e| e.to_string())?);
    let mut archive = Archive::open(reader).map_err(|e| e.name().to_string())?;
    archive.set_threads(threads);
    let mut files = archive.files();
    let mut buf = vec![0; 1 << 16];
    while files.next().map_err(|e| e.name().to_string())?.is_some() {
        while files.read(&mut buf).map_err(|e| e.to_string())? > 0 {}
    }
    Ok(start.elapsed())
}

/// `7zz t` of `archive` with `-mmt=threads`: the time it took.
fn tool_test(tool: &Path, archive: &Path, threads: &str) -> Result<Duration> {
    let start = Instant::now();
    let status = Command::new(tool)
        .args([
            "t",
            &format!("-mmt={threads}"),
            "-bd",
            "-bso0",
            "-bse0",
            "-bsp0",
        ])
        .arg(archive)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("7zz t {}: {status}", archive.display()));
    }
    Ok(start.elapsed())
}

fn row(name: &str, bytes: u64, times: &[f64], size: Option<u64>) {
    let time = best(times);
    let size = size.map_or(String::new(), |s| format!("{:.2} MB", s as f64 / 1e6));
    println!(
        "| {name} | {time:.2} s | {:.1} MB/s | {size} |",
        bytes as f64 / 1e6 / time
    );
    let _ = std::io::stdout().flush();
}

/// The table of `--threads`.
pub(crate) fn bench(
    data: &Path,
    dir: &Path,
    limit: usize,
    rounds: usize,
    tool: Option<&Path>,
) -> Result<()> {
    let files = make_text(data, dir, limit)?;
    let bytes: u64 = files
        .iter()
        .map(|(_, p)| std::fs::metadata(p).map_or(0, |m| m.len()))
        .sum();
    let threads = Threads::Auto.count();
    println!(
        "{} files of text, {:.1} MB; LZMA2 of preset 6; {threads} threads for \"all\".\n",
        files.len(),
        bytes as f64 / 1e6
    );
    println!("| Workload | Time | Speed | Size |\n|---|---|---|---|");
    println!("| **Writing** | | | |");
    let one_stream = dir.join("one-stream.7z");
    let blocks = dir.join("blocks.7z");
    let rows = [
        (
            "One stream, as before",
            Lzma2Blocks::None,
            Threads::One,
            &one_stream,
        ),
        (
            "Blocks, one thread",
            Lzma2Blocks::Auto,
            Threads::One,
            &blocks,
        ),
        (
            "Blocks, all threads",
            Lzma2Blocks::Auto,
            Threads::Auto,
            &blocks,
        ),
    ];
    for (name, lzma2_blocks, threads, out) in rows {
        let options = WriteOptions {
            lzma2_blocks,
            threads,
            ..WriteOptions::default()
        };
        let (mut times, mut size) = (Vec::new(), 0);
        for _ in 0..rounds {
            let (time, made) = write(&files, out, &options)?;
            times.push(time.as_secs_f64());
            size = made;
        }
        row(name, bytes, &times, Some(size));
    }
    let out = dir.join("out");
    for (what, archive) in [("one stream", &one_stream), ("blocks", &blocks)] {
        println!("| **Reading {what}** | | | |");
        for (name, threads) in [("one thread", Threads::One), ("all threads", Threads::Auto)] {
            let (mut extracting, mut reading) = (Vec::new(), Vec::new());
            for _ in 0..rounds {
                extracting.push(extract(archive, &out, threads)?.as_secs_f64());
                reading.push(read(archive, threads)?.as_secs_f64());
            }
            row(&format!("`extract_7z`, {name}"), bytes, &extracting, None);
            row(&format!("`Archive::files`, {name}"), bytes, &reading, None);
        }
        if let Some(tool) = tool {
            for (name, threads) in [("one thread", "1"), ("all threads", "on")] {
                let mut times = Vec::new();
                for _ in 0..rounds {
                    times.push(tool_test(tool, archive, threads)?.as_secs_f64());
                }
                row(&format!("`7zz t`, {name}"), bytes, &times, None);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    Ok(())
}
