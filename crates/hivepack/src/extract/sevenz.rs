//! Extracting a 7z archive that `hivepack::sevenz` opened.
//!
//! A 7z archive lists all its entries in its headers, as a ZIP archive
//! does, so every entry is checked before anything is written. Its data is
//! in folders, streams that may each hold many files (a solid block), read
//! once from start to end: the files are written in the archive's order as
//! their folder is decoded, each checked against its CRC when its data
//! ends, and each folder's checks made when its last file is read.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::sevenz::{Archive, Entry, Files, FolderFiles, Lzma2Threads, Spare};

use crate::extract::destination::Target;
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::{Item, Kind, Links, Options, check, fold};
use crate::extract::plan::{LinkChecked, LinkTo, link_to, named, settle, settle_links};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::write_with;
use crate::extract::zip::{Room, Summary, open_destination, set_dir_times};

/// `FILE_ATTRIBUTE_UNIX_EXTENSION`: 7-Zip keeps a Unix mode in the high 16
/// bits of the attributes when this bit is set.
const UNIX_EXTENSION: u32 = 0x8000;

/// The type bits of a Unix mode.
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

/// The longest link target read, as Linux's `PATH_MAX`.
const MAX_LINK_TARGET: u64 = 4096;

/// Seconds from 1601, where NTFS times start, to 1970.
const NTFS_TO_UNIX: i64 = 11_644_473_600;

/// An NTFS time, in 100 ns since 1601, as a `SystemTime`.
fn system_time(ntfs: u64) -> Option<SystemTime> {
    let secs = (ntfs / 10_000_000) as i64 - NTFS_TO_UNIX;
    let nanos = Duration::from_nanos((ntfs % 10_000_000) * 100);
    let at = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))?
    };
    at.checked_add(nanos)
}

/// What the archive says of `entry`. `folders` holds each folder's packed
/// and unpacked sizes, for the share of its compressed data a file is
/// counted with.
fn item(entry: &Entry, folders: &[(u64, u64)], options: &Options) -> Item {
    let index = entry.index as u64;
    let raw_name = entry.name.as_bytes().to_vec();
    // A name that is not UTF-16 decodes to U+FFFD: refused, not guessed.
    let (text, name) = if String::from_utf16(&entry.name_utf16).is_err() {
        (entry.name.clone(), Err(NameError::NotUtf8))
    } else {
        // 7-Zip writes `/` between components on every system, and keeps
        // a `\` of a Unix name as it is.
        named(&entry.name, options)
    };
    let unix_mode = entry
        .attributes
        .filter(|attributes| attributes & UNIX_EXTENSION != 0)
        .map(|attributes| attributes >> 16);
    // A device, FIFO or socket is only its mode with data, as in ZIP: it
    // is written as a file, never created as what the mode says.
    let kind = if entry.is_dir {
        Kind::Dir
    } else if unix_mode.is_some_and(|mode| mode & S_IFMT == S_IFLNK) {
        Kind::Link
    } else {
        Kind::File
    };
    let size = if kind == Kind::Dir { 0 } else { entry.size };
    // A file's share of its folder's compressed data, so that the ratio of
    // what it writes to it is its folder's.
    let compressed = match entry.folder.and_then(|folder| folders.get(folder)) {
        Some(&(packed, unpacked)) if unpacked > 0 => {
            let share = u128::from(size) * u128::from(packed) / u128::from(unpacked);
            u64::try_from(share).unwrap_or(u64::MAX).max(1)
        }
        _ => size,
    };
    Item {
        index,
        raw_name,
        text,
        name,
        kind,
        size,
        compressed,
        // Folders do not share packed streams: no two files' data overlap.
        data: None,
        mode: unix_mode.map(|mode| mode & 0o7777),
        mtime: entry.mtime.and_then(system_time),
        owner: None,
        xattrs: Vec::new(),
    }
}

/// A read's error: the archive's, or another.
fn seven_zip_error(e: io::Error) -> ErrorKind {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<crate::sevenz::Error>())
    {
        Some(&error) => ErrorKind::SevenZip(error),
        None => ErrorKind::Io(e),
    }
}

/// A link to create, once every other entry is written.
struct Link<'a> {
    item: &'a Item,
    target: String,
    to_dir: bool,
}

/// The data of the current file of `files`, read to its end so that its
/// CRC is checked: at most [`MAX_LINK_TARGET`] bytes.
fn read_target<R: Read + Seek>(
    files: &mut Files<'_, R>,
    item: &Item,
    run: &Run<'_>,
) -> Result<Vec<u8>, ErrorKind> {
    if item.size > MAX_LINK_TARGET {
        return Err(ErrorKind::LinkTarget(NameError::TooLong));
    }
    let mut target = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        run.check()?;
        match files.read(&mut buffer) {
            Ok(0) => return Ok(target),
            Ok(n) => {
                target.extend_from_slice(&buffer[..n]);
                if target.len() as u64 > MAX_LINK_TARGET {
                    return Err(ErrorKind::LinkTarget(NameError::TooLong));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(seven_zip_error(e)),
        }
    }
}

/// The links to create, with [`Links::Inside`] or [`Links::Any`]: their
/// targets read, which takes decoding the folders up to the last link,
/// checked ([`link_to`]) and settled ([`settle_links`]). Those refused and
/// skipped go to `skipped`.
fn links<'a, R: Read + Seek>(
    archive: &mut Archive<R>,
    kept: &[&'a Item],
    run: &Run<'_>,
    options: &Options,
    skipped: &mut Vec<Error>,
) -> Result<Vec<Link<'a>>, Error> {
    let wanted: HashMap<u64, &'a Item> = kept
        .iter()
        .filter(|item| item.kind == Kind::Link)
        .map(|&item| (item.index, item))
        .collect();
    let Some(&last) = wanted.keys().max() else {
        return Ok(Vec::new());
    };
    let fold_of = |kind: Kind| {
        kept.iter()
            .filter(move |item| item.kind == kind)
            .filter_map(|item| {
                item.name
                    .as_ref()
                    .ok()
                    .map(|name| (fold(&name.components), item.index))
            })
    };
    let paths: HashMap<String, u64> = fold_of(Kind::Link).collect();
    let dirs: HashMap<String, u64> = fold_of(Kind::Dir).collect();

    // The targets, read in the archive's order.
    let mut targets: Vec<(&'a Item, Result<Vec<u8>, ErrorKind>)> = Vec::new();
    let mut files = archive.files();
    for index in 0..=last {
        run.check().map_err(Error::global)?;
        match files.next() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => return Err(Error::global(ErrorKind::SevenZip(e))),
        }
        if let Some(&item) = wanted.get(&index) {
            targets.push((item, read_target(&mut files, item, run)));
        }
    }
    drop(files);

    let checked = targets
        .into_iter()
        .filter_map(|(item, read)| {
            let name = item.name.as_ref().ok()?;
            let parent = &name.components[..name.components.len().saturating_sub(1)];
            Some((
                item,
                match read {
                    Ok(target) => link_to(&target, parent, options, &paths, &dirs),
                    Err(kind) => LinkChecked::unread(kind),
                },
            ))
        })
        .collect();
    Ok(settle_links(checked, options, skipped)?
        .into_iter()
        .map(|(item, LinkTo { target, to_dir })| Link {
            item,
            target,
            to_dir,
        })
        .collect())
}

/// Extracts the 7z archive `archive` into `destination`, which is created
/// if it is not there, with `options`.
///
/// Every entry is checked before anything is written, as a ZIP archive's
/// are: its name (UTF-16 that does not decode is refused, and so is a `\`,
/// which 7-Zip keeps in a Unix name), that no two entries name the same
/// path, links, and what the headers say of the sizes against the limits.
/// Then the folders are decoded from start to end, and each file written
/// as its data comes, counted against the limits and checked against its
/// CRC when it ends; a file whose data fails is removed, and the
/// extraction stops there. A wrong password shows as a CRC that fails
/// ([`crate::sevenz::Error::WrongPassword`]): 7z has nothing else to check
/// it with.
///
/// Besides ZIP's rules: a symbolic link is an entry whose attributes hold
/// the Unix mode of a link (7-Zip's `-snl`), its target its data; with
/// [`Links::Inside`] the targets are read first, which decodes the folders
/// up to the last link once more. A file's compressed size is its share of
/// its folder's, so that the ratio a file is held to is its folder's.
/// Devices and FIFOs are written as files, as in ZIP. Files get their Unix
/// permissions when the archive has them, and their modification time.
///
/// [`Options::password`] is the password of encrypted data, taken as UTF-8
/// (it replaces one the archive was opened with); an archive whose headers
/// are encrypted needs it to be opened, with
/// [`crate::sevenz::Options::password`].
///
/// With [`Options::threads`], that many folders (each a solid block, or a
/// file of an archive that is not solid) are decoded at once, each by a thread
/// of its own, which writes its files in the archive's order; the largest
/// folders are started first. The directories and the files without data are
/// made first, on the caller's thread, which reads the archive for the others,
/// a piece at a time: `R` needs no more than [`Read`] and [`Seek`]. Each thread
/// holds its folder's decoder, whose dictionaries and models the archive says:
/// the threads are lowered until they fit [`Options::memory_limit`] and
/// `Options::memory_budget`, one always allowed. The threads left over, and
/// those whose folders are done as the last ones are decoded, decode LZMA2
/// whose stream resets its dictionary on the way, as 7-Zip writes it in
/// threads and [`crate::sevenz::Lzma2Blocks`] does, a block in each, in place
/// of what [`Archive::set_threads`] said, for this extraction: all of them
/// where one folder is decoded at a time. What is written is the same whatever
/// the threads, and so is the summary. The first error stops the other
/// threads, which remove the files they were writing, and is the one returned;
/// files after it in the archive may have been written.
pub fn extract_7z<R: Read + Seek>(
    archive: &mut Archive<R>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(
        archive,
        || open_destination(destination, options),
        options,
        true,
        |archive, writing, summary| match writing.threading.workers {
            1 => write_in_order(archive, writing, summary),
            _ => write_at_once(archive, writing, summary),
        },
    )
}

/// Extracts `archive` into `sink`, with the checks and in the order of
/// [`extract_7z`], each folder decoded once: see [`Sink`]. The sink is given
/// one entry at a time, on the caller's thread, the folders decoded one after
/// another, whatever [`Options::threads`] says; it decodes LZMA2 in blocks.
pub fn extract_7z_to<R: Read + Seek>(
    archive: &mut Archive<R>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(
        archive,
        || Ok(state.target(options)),
        options,
        false,
        write_in_order,
    )
}

/// Entries one after another whose data is in the same folder, or which have
/// none: what one thread writes, as [`Files`] reads them. A folder has one,
/// unless entries without data are put between its files.
struct Span {
    files: Range<usize>,
    folder: Option<usize>,
}

/// The spans of `folders`, each entry's folder, in order.
fn spans(folders: &[Option<usize>]) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    for (index, &folder) in folders.iter().enumerate() {
        match spans.last_mut() {
            Some(last) if last.folder == folder => last.files.end = index + 1,
            _ => spans.push(Span {
                files: index..index + 1,
                folder,
            }),
        }
    }
    spans
}

/// How the folders are decoded: how many at once, and LZMA2 in blocks in
/// each, its threads and what their jobs may hold.
struct Threading {
    workers: u32,
    lzma2: Lzma2Threads,
    /// LZMA2 in blocks where one folder is decoded at a time: to read the links'
    /// targets, and with one worker.
    alone: Lzma2Threads,
    /// What is held of [`Options::memory_budget`] until the extraction is done.
    _held: Option<Box<dyn std::any::Any + Send + Sync>>,
}

/// The threads to decode the folders of `spans` with, one at a time unless
/// `at_once`. Each holds its folder's decoder, counted for the folder that
/// takes the most (`Archive::folder_memory`): the threads are lowered until
/// they fit the memory limit and budget, one always allowed. The threads left
/// over are shared ([`Spare`]) by the folders whose LZMA2 is in blocks, and
/// those of the folders done as the last are decoded; their jobs share what is
/// left of the limit, and of
/// [`decoder_memory_limit`](crate::sevenz::Options::decoder_memory_limit),
/// once the decoders are counted, an equal part for each folder.
fn threading<R: Read + Seek>(
    archive: &Archive<R>,
    spans: &[Span],
    options: &Options,
    at_once: bool,
) -> Threading {
    let threads = options.threads.count().max(1);
    let folders = spans.iter().filter_map(|span| span.folder);
    let wanted = match at_once {
        true => threads.min(u32::try_from(folders.clone().count()).unwrap_or(u32::MAX)),
        false => 1,
    };
    let each = folders
        .map(|folder| archive.folder_memory(folder, threads > 1))
        .max()
        .unwrap_or(0);
    let need = |n: u32| u64::from(n).saturating_mul(each);
    let limit = options.memory_limit.unwrap_or(u64::MAX);
    let workers = (1..=wanted).rev().find(|&n| need(n) <= limit).unwrap_or(1);
    #[cfg(feature = "memory")]
    let (workers, limit, held) = match &options.memory_budget {
        Some(budget) if threads > 1 => {
            let left = budget.left();
            let (fit, holds) = budget.hold_threads(workers, need);
            (
                fit,
                limit.min(left),
                Some(Box::new(holds) as Box<dyn std::any::Any + Send + Sync>),
            )
        }
        _ => (workers, limit, None),
    };
    #[cfg(not(feature = "memory"))]
    let held = None;
    let jobs = |n: u32| {
        limit
            .saturating_sub(need(n))
            .min(archive.decoder_memory_limit())
            / u64::from(n.max(1))
    };
    Threading {
        workers,
        lzma2: Lzma2Threads {
            threads,
            jobs: jobs(workers),
            spare: Some(Spare::new(threads.saturating_sub(workers))),
        },
        alone: Lzma2Threads {
            threads,
            jobs: jobs(1),
            spare: None,
        },
        _held: held,
    }
}

/// What the entries are written by, once checked.
struct Writing<'a, T> {
    items: &'a [Item],
    spans: &'a [Span],
    written_now: &'a HashSet<u64>,
    destination: &'a T,
    run: &'a Run<'a>,
    options: &'a Options,
    threading: &'a Threading,
}

/// [`extract_7z`] into the target `make` makes, once the archive is checked,
/// the entries written by `write`, folders decoded at once if `at_once`; LZMA2
/// decoded in [`Options::threads`] for this extraction only.
fn extract_into<R: Read + Seek, T: Target>(
    archive: &mut Archive<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
    at_once: bool,
    write: impl FnOnce(&mut Archive<R>, &Writing<'_, T>, &mut Summary) -> Result<(), Error>,
) -> Result<Summary, Error> {
    let before = archive.swap_lzma2(Lzma2Threads {
        threads: options.threads.count(),
        jobs: u64::MAX,
        spare: None,
    });
    let extracted = extract_with(archive, make, options, at_once, write);
    archive.swap_lzma2(before);
    extracted
}

/// [`extract_into`], with the archive's threads set.
fn extract_with<R: Read + Seek, T: Target>(
    archive: &mut Archive<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
    at_once: bool,
    write: impl FnOnce(&mut Archive<R>, &Writing<'_, T>, &mut Summary) -> Result<(), Error>,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);
    if let Some(password) = &options.password {
        archive.set_password(&String::from_utf8_lossy(password));
    }
    let n = archive.len();
    if n as u64 > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let folders: Vec<(u64, u64)> = (0..archive.folders())
        .map(|folder| {
            (
                archive.folder_packed_size(folder),
                archive.folder_size(folder),
            )
        })
        .collect();
    let mut items = Vec::with_capacity(n);
    let mut folder_of = Vec::with_capacity(n);
    for index in 0..n {
        run.check().map_err(Error::global)?;
        let entry = archive.entry(index);
        folder_of.push(entry.folder);
        items.push(item(&entry, &folders, options));
    }
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    let spans = spans(&folder_of);
    let threading = threading(archive, &spans, options, at_once);
    archive.swap_lzma2(threading.alone.clone());
    let links = match options.links {
        Links::Inside | Links::Any => links(archive, &kept, &run, options, &mut skipped)?,
        _ => Vec::new(),
    };
    // Links to create are written after the rest; with `AsFile` they are
    // files.
    let created_later = |item: &Item| {
        item.kind == Kind::Link && matches!(options.links, Links::Inside | Links::Any)
    };
    let written_now: HashSet<u64> = kept
        .iter()
        .filter(|item| !created_later(item))
        .map(|item| item.index)
        .collect();
    run.start(
        written_now.len() as u64 + links.len() as u64,
        kept.iter()
            .filter(|item| item.kind != Kind::Dir && !created_later(item))
            .map(|item| item.size)
            .fold(0, u64::saturating_add),
    );
    let destination = make()?;
    let mut summary = Summary {
        skipped,
        renamed: settled.renamed,
        ..Summary::default()
    };
    let writing = Writing {
        items: &items,
        spans: &spans,
        written_now: &written_now,
        destination: &destination,
        run: &run,
        options,
        threading: &threading,
    };
    write(archive, &writing, &mut summary)?;
    for link in &links {
        let error = |kind| link.item.error(kind);
        let Ok(name) = &link.item.name else {
            continue;
        };
        run.check().map_err(error)?;
        destination
            .symlink(link.item, &name.components, &link.target, link.to_dir)
            .map_err(error)?;
        summary.links += 1;
        run.entry_done();
    }
    set_dir_times(&destination, &kept, &run)?;
    summary.damaged = run.take_damaged();
    // In the archive's order, as one thread meets them, whatever the threads.
    summary.damaged.sort_by_key(|damaged| damaged.error.index);
    Ok(summary)
}

/// What a thread wrote.
#[derive(Default)]
struct Tally {
    files: u64,
    directories: u64,
    bytes: u64,
}

impl Tally {
    fn add_to(&self, summary: &mut Summary) {
        summary.files += self.files;
        summary.directories += self.directories;
        summary.bytes += self.bytes;
    }
}

/// The directories and files of `writing.written_now`, in the archive's
/// order, on this thread, the folders decoded one after another.
fn write_in_order<R: Read + Seek, T: Target>(
    archive: &mut Archive<R>,
    writing: &Writing<'_, T>,
    summary: &mut Summary,
) -> Result<(), Error> {
    let (folders, reader) = archive.apart();
    let mut tally = Tally::default();
    for span in writing.spans {
        let mut files = folders.files(span.files.clone(), &mut *reader);
        write_span(&mut files, span, writing, &mut tally, None)?;
    }
    tally.add_to(summary);
    Ok(())
}

/// [`write_in_order`] with folders decoded at once, in `writing.threading`'s
/// workers: the directories and the files without data first, in order, on
/// this thread; then the folders, the largest first, each taken by the next
/// thread that is free, which writes its files, reading the archive through
/// this thread ([`serve`]).
///
/// The threads share `writing.run`, which tells [`Options::progress`] and
/// asks [`Options::on_damaged`] one at a time, and what all files have
/// written, held to the limit on it. The first to fail keeps its error and
/// halts the others, which stop as if cancelled and remove the file they were
/// writing.
fn write_at_once<R: Read + Seek, T: Target + Sync>(
    archive: &mut Archive<R>,
    writing: &Writing<'_, T>,
    summary: &mut Summary,
) -> Result<(), Error> {
    let total = AtomicU64::new(0);
    let mut tally = Tally::default();
    let mut by_size: Vec<(&Span, u64)> = writing
        .spans
        .iter()
        .filter_map(|span| Some((span, archive.folder_size(span.folder?))))
        .collect();
    by_size.sort_by_key(|&(_, size)| std::cmp::Reverse(size));
    let spare = writing.threading.lzma2.spare.clone();
    archive.swap_lzma2(writing.threading.lzma2.clone());
    let (folders, reader) = archive.apart();
    for span in writing.spans.iter().filter(|span| span.folder.is_none()) {
        let mut files = folders.files(span.files.clone(), &mut *reader);
        write_span(&mut files, span, writing, &mut tally, Some(&total))?;
    }

    let next = AtomicUsize::new(0);
    let failed: Mutex<Option<Error>> = Mutex::new(None);
    let workers = usize::try_from(writing.threading.workers)
        .unwrap_or(usize::MAX)
        .min(by_size.len());
    let (requests, asked) = mpsc::sync_channel::<Request>(workers);
    let tallies = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let mut remote = Remote::new(requests.clone());
                let (folders, by_size, next, failed, total, spare) =
                    (&folders, &by_size, &next, &failed, &total, &spare);
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    while let Some(&(span, _)) = by_size.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let written = writing.run.check().map_err(Error::global).and_then(|()| {
                            let mut files = folders.files(span.files.clone(), &mut remote);
                            write_span(&mut files, span, writing, &mut tally, Some(total))
                        });
                        if let Err(e) = written {
                            // Kept before the others are halted: their errors
                            // come after it.
                            failed
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .get_or_insert(e);
                            writing.run.halt();
                            break;
                        }
                    }
                    // Its thread, for the folders still decoded.
                    if let Some(spare) = spare {
                        spare.give(1);
                    }
                    tally
                })
            })
            .collect();
        drop(requests);
        serve(reader, &asked);
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    tally.add_to(summary);
    for each in tallies {
        // A thread that panicked: its panic goes on to the caller.
        each.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            .add_to(summary);
    }
    match failed.into_inner().unwrap_or_else(PoisonError::into_inner) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A piece of the archive a thread asks for: `buf.len()` bytes at `pos`, and
/// where to send them.
struct Request {
    pos: u64,
    buf: Vec<u8>,
    reply: SyncSender<Reply>,
}

/// The buffer of a [`Request`], filled with as many bytes as there were, or
/// the error reading them.
type Reply = (Vec<u8>, io::Result<usize>);

/// Reads what the threads ask of `reader`, one piece at a time, until none of
/// them is left to ask.
fn serve<R: Read + Seek>(reader: &mut R, asked: &Receiver<Request>) {
    for Request {
        pos,
        mut buf,
        reply,
    } in asked
    {
        let read = read_at(reader, pos, &mut buf);
        // A thread that is gone needs no answer.
        let _ = reply.send((buf, read));
    }
}

/// Fills `buf` from `pos` in `reader`, as far as it goes.
fn read_at<R: Read + Seek>(reader: &mut R, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
    reader.seek(SeekFrom::Start(pos))?;
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// The archive, read by a thread through the one that [`serve`]s it.
struct Remote {
    pos: u64,
    requests: SyncSender<Request>,
    reply: SyncSender<Reply>,
    replies: Receiver<Reply>,
    /// The buffer sent with each request, kept between them.
    buf: Vec<u8>,
}

impl Remote {
    fn new(requests: SyncSender<Request>) -> Remote {
        let (reply, replies) = mpsc::sync_channel(1);
        Remote {
            pos: 0,
            requests,
            reply,
            replies,
            buf: Vec::new(),
        }
    }
}

impl Read for Remote {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = std::mem::take(&mut self.buf);
        buf.resize(out.len(), 0);
        let gone = || io::Error::other("the archive's reader is gone");
        let request = Request {
            pos: self.pos,
            buf,
            reply: self.reply.clone(),
        };
        self.requests.send(request).map_err(|_| gone())?;
        let (buf, read) = self.replies.recv().map_err(|_| gone())?;
        self.buf = buf;
        let n = read?.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for Remote {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(by) => self.pos.checked_add_signed(by),
            SeekFrom::End(_) => None,
        }
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

/// The entries of `span` that `writing` writes now, in order, read by `files`:
/// at most `writing.options.limits.max_total_size` bytes in all, with those
/// `tally` wrote, or with `total`, what all threads wrote. Its folder's checks
/// are made once its last file is read, or after it if it is not, as the
/// entry after it is read with one thread: they fail as that entry, if any.
fn write_span<S: Read + Seek, T: Target>(
    files: &mut FolderFiles<'_, '_, S>,
    span: &Span,
    writing: &Writing<'_, T>,
    tally: &mut Tally,
    total: Option<&AtomicU64>,
) -> Result<(), Error> {
    let Writing {
        items,
        written_now,
        destination,
        run: progress,
        options,
        ..
    } = *writing;
    // Whether the last file written was damaged, and gone on from.
    let mut gone_on = false;
    // The files of a folder whose data failed, after what failed, and why.
    let mut lost: Option<(Range<usize>, crate::sevenz::Error)> = None;
    for item in &items[span.files.clone()] {
        progress.check().map_err(Error::global)?;
        let index = item.index as usize;
        if let Some((range, e)) = &lost
            && range.contains(&index)
        {
            // Nothing of it can be read: left out, unless to stop.
            if written_now.contains(&item.index) && item.kind != Kind::Dir {
                let (_, damage) = progress.decide(item, ErrorKind::SevenZip(*e))?;
                progress.damaged(damage, None);
                progress.entry_done();
            }
            continue;
        }
        let mut next = files.next();
        if let (Err(e), true) = (&next, gone_on) {
            // The folder of the file gone on from cannot be read past it.
            let e = *e;
            let range = files.skip_folder();
            let in_it = range.contains(&index);
            lost = Some((range, e));
            if in_it {
                if written_now.contains(&item.index) && item.kind != Kind::Dir {
                    let (_, damage) = progress.decide(item, ErrorKind::SevenZip(e))?;
                    progress.damaged(damage, None);
                    progress.entry_done();
                }
                gone_on = false;
                continue;
            }
            next = files.next();
        }
        gone_on = false;
        match next {
            Ok(Some(_)) => {}
            Ok(None) => return Err(item.error(ErrorKind::SizeMismatch)),
            // What was skipped before it failed its checks.
            Err(e) => return Err(item.error(ErrorKind::SevenZip(e))),
        }
        if !written_now.contains(&item.index) {
            continue;
        }
        let Ok(name) = &item.name else {
            continue;
        };
        let error = |kind| item.error(kind);
        let components = &name.components;
        if item.kind == Kind::Dir {
            destination.directory(item, components).map_err(error)?;
            tally.directories += 1;
            progress.entry_done();
            continue;
        }
        let room = match total {
            Some(total) => Room::Shared(total),
            None => Room::Left(options.limits.max_total_size.saturating_sub(tally.bytes)),
        };
        let mut failed = false;
        let written = write_with(
            item,
            Some(item.size),
            destination,
            progress,
            options,
            |file| {
                let written = write_data(files, item, file, room, progress, options);
                failed = written.is_err();
                written
            },
        )?;
        // Its data failed, and the file was left out or kept.
        gone_on = failed;
        if let Some(written) = written {
            tally.files += 1;
            tally.bytes += written;
        }
        progress.entry_done();
    }
    // Past its last file: its folder's checks, if that file was skipped, as
    // the next entry is read; none to make of a folder gone on from.
    let after = items.get(span.files.end);
    if after.is_some() {
        progress.check().map_err(Error::global)?;
    }
    match files.next() {
        Ok(_) => Ok(()),
        Err(_) if gone_on => Ok(()),
        Err(e) => {
            let kind = ErrorKind::SevenZip(e);
            Err(match after {
                Some(after) => after.error(kind),
                None => Error::global(kind),
            })
        }
    }
}

/// Writes the current file of `files` into `file`, for `item`, at most as
/// many bytes as `room` leaves: the bytes written. Its data is read to its
/// end, where its CRC is checked.
fn write_data<S: Read + Seek>(
    files: &mut FolderFiles<'_, '_, S>,
    item: &Item,
    file: &mut impl Write,
    room: Room<'_>,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let limits = &options.limits;
    let mut written: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        run.check()?;
        let n = match files.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(seven_zip_error(e)),
        };
        written += n as u64;
        if written > limits.max_entry_size {
            return Err(ErrorKind::EntryTooLarge);
        }
        if !room.fits(written, n as u64, limits.max_total_size) {
            return Err(ErrorKind::TotalTooLarge);
        }
        if written > item.size {
            return Err(ErrorKind::SizeMismatch);
        }
        if written > limits.ratio_threshold
            && written > item.compressed.saturating_mul(limits.max_ratio)
        {
            return Err(ErrorKind::Ratio);
        }
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    if written != item.size {
        return Err(ErrorKind::SizeMismatch);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntfs_times() {
        // 1970-01-01, and 100 ns either side of it.
        let epoch = 116_444_736_000_000_000;
        assert_eq!(system_time(epoch), Some(UNIX_EPOCH));
        let tick = Duration::from_nanos(100);
        assert_eq!(system_time(epoch + 1), UNIX_EPOCH.checked_add(tick));
        assert_eq!(system_time(epoch - 1), UNIX_EPOCH.checked_sub(tick));
        // 2026-09-01 12:00:00 UTC.
        assert_eq!(
            system_time(epoch + 1_788_264_000 * 10_000_000),
            UNIX_EPOCH.checked_add(Duration::from_secs(1_788_264_000))
        );
        // 1601 itself.
        assert_eq!(
            system_time(0),
            UNIX_EPOCH.checked_sub(Duration::from_secs(NTFS_TO_UNIX as u64))
        );
    }
}
