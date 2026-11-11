//! Extracting a SquashFS image that `hivepack::squashfs` opens: snap
//! packages, AppImages' images.
//!
//! An image is read by random access, as a ZIP archive and a UDF volume
//! are: its tree is walked first, every inode read and every file's data
//! checked to be on the image, and every entry checked before anything is
//! written; then the files are written, their data read where it is, with
//! [`Options::threads`] several at once.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::squashfs::{
    Block, BlockIndex, Compression, DataAhead, DataPlace, Inode, InodeId, Squashfs,
};

use crate::extract::destination::{Destination, Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::settle;
use crate::extract::plan::{Item, Kind, OnRefused, Options, check};
use crate::extract::progress::Run;
use crate::extract::remote::{Remote, Request, serve};
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, copy_of, plan_links, write_with};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// A SquashFS time, seconds since 1970, as a `SystemTime`.
fn system_time(sec: i64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(sec).ok()?))
}

/// What the walk found: the entries (each with its inode, for its data),
/// those to extract, and the errors of those refused for what could not
/// be read, to skip.
type Walk = (Vec<Entry<Option<Inode>>>, Vec<Item>, Vec<Error>);

/// Walks the image's tree, parents before what they hold: every entry
/// listed, its inode read, and its data checked to read, a file's, or its
/// target, a link's. What cannot be read is refused.
fn walk<R: Read + Seek>(
    fs: &mut Squashfs<R>,
    run: &Run<'_>,
    options: &Options,
    mut places: Option<&mut Places>,
) -> Result<Walk, Error> {
    let mut entries: Vec<Entry<Option<Inode>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    // The entry each inode was first met as: a file's again is a hard link,
    // a directory's again is refused.
    let mut met: HashMap<InodeId, (u64, Vec<u8>)> = HashMap::new();
    let root = fs
        .root()
        .map_err(|e| Error::global(ErrorKind::Squashfs(e)))?;
    met.insert(fs.root_id(), (0, Vec::new()));

    // Directories still to list, the next last: their inode, path, and
    // index (the root has none). Each is listed after its parent's
    // entries, so that a parent comes before what it holds.
    let mut dirs: Vec<(Inode, Vec<u8>, Option<u64>)> = vec![(root, Vec::new(), None)];
    while let Some((dir, path, dir_index)) = dirs.pop() {
        run.check().map_err(Error::global)?;
        let mut listed = Vec::new();
        let mut broken = None;
        match fs.read_dir(&dir) {
            Ok(list) => {
                for entry in list {
                    match entry {
                        Ok(entry) => listed.push(entry),
                        Err(e) => broken = Some(e),
                    }
                }
            }
            Err(e) => broken = Some(e),
        }
        if let Some(e) = broken {
            // What the directory holds after a broken entry is missing.
            let error = Error {
                index: dir_index,
                name: dir_index.map(|_| path.clone()),
                kind: ErrorKind::Squashfs(e),
            };
            match (options.on_refused, dir_index) {
                (OnRefused::Skip, Some(_)) => refused.push(error),
                _ => return Err(error),
            }
        }
        let mut children = Vec::new();
        for listed in listed {
            let index = entries.len() as u64;
            run.check().map_err(Error::global)?;
            // Every entry counts, as in tar.
            if index >= options.limits.max_entries {
                return Err(Error::global(ErrorKind::TooManyEntries));
            }
            let mut raw = path.clone();
            if !raw.is_empty() {
                raw.push(b'/');
            }
            raw.extend_from_slice(&listed.name);
            let refuse = |kind, refused: &mut Vec<Error>| {
                let error = Error::new(index, &raw, kind);
                match options.on_refused {
                    OnRefused::Stop => Err(error),
                    OnRefused::Skip => {
                        refused.push(error);
                        Ok(())
                    }
                }
            };
            let mut entry = Entry {
                seen: None,
                item: None,
                target: Vec::new(),
            };
            let read = fs
                .inode(listed.inode)
                .and_then(|inode| Ok((inode, fs.stat(&inode)?)));
            let (inode, stat) = match read {
                Ok(read) => read,
                Err(e) => {
                    refuse(ErrorKind::Squashfs(e), &mut refused)?;
                    entries.push(entry);
                    continue;
                }
            };
            let key = listed.inode;
            let first = met.get(&key).cloned();
            let met_before = first.is_some();
            let kind = match (&first, inode) {
                (Some(_), inode) if inode.is_dir() => {
                    refuse(ErrorKind::DirectoryAgain, &mut refused)?;
                    entries.push(entry);
                    continue;
                }
                (None, inode) if inode.is_dir() => Kind::Dir,
                (Some(_), inode) if inode.is_file() => Kind::HardLink,
                (None, inode) if inode.is_file() => Kind::File,
                (_, inode) if inode.is_symlink() => Kind::Link,
                _ => Kind::Special,
            };
            match kind {
                Kind::Link => match fs.read_link(&inode) {
                    Ok(target) => entry.target = target,
                    Err(e) => {
                        refuse(ErrorKind::Squashfs(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                },
                Kind::HardLink => {
                    entry.target = first.map(|(_, path)| path).unwrap_or_default();
                }
                // The data, unless the checks are to stop it for its size.
                Kind::File if inode.file_size() <= options.limits.max_entry_size => {
                    let checked = match places.as_deref_mut().filter(|places| places.apart) {
                        Some(places) => fs
                            .check_data_with(&inode, &mut |place| places.add(place))
                            .map(|()| places.index(fs.block_index(&inode))),
                        None => fs.check_data(&inode),
                    };
                    if let Err(e) = checked {
                        refuse(ErrorKind::Squashfs(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                }
                _ => {}
            }
            if !met_before {
                met.insert(key, (index, raw.clone()));
            }
            let (text, name) = named_of(&raw, options).unwrap_or_else(|| {
                (
                    String::from_utf8_lossy(&raw).into_owned(),
                    Err(NameError::Empty),
                )
            });
            let size = if kind == Kind::File {
                inode.file_size()
            } else {
                0
            };
            items.push(Item {
                index,
                raw_name: raw.clone(),
                text,
                name,
                kind,
                size,
                // Its blocks are compressed apart, and a hole takes nothing:
                // the limits on sizes stand.
                compressed: size,
                data: None,
                mode: Some(stat.mode & 0o7777),
                mtime: system_time(stat.mtime),
                owner: None,
                xattrs: Vec::new(),
            });
            entry.item = Some(items.len() - 1);
            if kind == Kind::Dir {
                children.push((inode, raw, Some(index)));
            }
            entry.seen = Some(inode);
            entries.push(entry);
        }
        // Depth first, in the order listed.
        dirs.extend(children.into_iter().rev());
    }
    Ok((entries, items, refused))
}

/// Extracts the SquashFS image `fs` into `destination`, which is created
/// if it is not there, with `options`.
///
/// The image is walked first, parents before what they hold, each
/// directory in its order, which is by name: every inode is read, every
/// file's data checked to be on the image ([`Squashfs::check_data`]), and
/// every link's target read, and every entry checked as a ZIP archive's
/// are, before anything is written. What cannot be read is refused
/// ([`ErrorKind::Squashfs`]): an entry whose inode, data or target does not
/// read, and a directory with a broken entry, whose entries after it are
/// missing; or left out with [`OnRefused::Skip`] (but a broken root
/// directory, which stops the extraction). A block that does not
/// decompress is found as it is written, as damage.
///
/// Besides tar's rules: an inode that two entries name is a hard link, to
/// the first; a directory named twice, or its own ancestor, is refused
/// ([`ErrorKind::DirectoryAgain`]), and its tree is not walked again.
/// Devices, FIFOs and sockets are not created. A hole in a file is written
/// as zeros.
///
/// With [`Options::threads`], once the directories are made, on the
/// caller's thread, the files are written that many at once, the largest
/// first, each by a thread that reads it through caches of its own; the
/// files whose data is all in one fragment block are taken together, a
/// fragment block at a time, so that it is decompressed once. The threads
/// with no file left to take decompress the blocks of the files still being
/// written ahead of them. Every thread reads the image through the caller's,
/// which reads what they ask, a block at a time: `R` needs no more than
/// [`Read`] and [`Seek`]. Each thread holds a few blocks and its decoder's
/// dictionary: the threads are lowered until they fit
/// [`Options::memory_limit`] and `Options::memory_budget`, one always
/// allowed. Hard links, and links as files, are written after the files.
/// What is written is the same whatever the threads, and so is the summary:
/// an image whose files would not read the same through caches of their
/// own (a damaged one, whose blocks are read with different sizes at one
/// place), or whose files and copies would pass
/// [`Limits::max_total_size`](crate::extract::Limits::max_total_size), is
/// written on one thread. The first error stops the other threads, which
/// remove the files they were writing, and is the one returned; files after
/// it in the image may have been written.
pub fn extract_squashfs<R: Read + Seek>(
    fs: &mut Squashfs<R>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(fs, || open_destination(destination, options), options, true)
}

/// Extracts the SquashFS image `fs` into `sink`, with the checks and in the
/// order of [`extract_squashfs`]: see [`Sink`]. The sink is given one entry
/// at a time, on the caller's thread, whatever [`Options::threads`] says.
pub fn extract_squashfs_to<R: Read + Seek>(
    fs: &mut Squashfs<R>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(fs, || Ok(state.target(options)), options, false)
}

/// What the entries are written with, once they are checked.
struct Writing<'a, T> {
    entries: &'a [Entry<Option<Inode>>],
    items: &'a [Item],
    kept: &'a HashSet<u64>,
    plans: &'a HashMap<u64, LinkPlan>,
    destination: &'a T,
    run: &'a Run<'a>,
    options: &'a Options,
}

impl<T> Writing<'_, T> {
    /// A symbolic link created after every other entry.
    fn created_later(&self, item: &Item) -> bool {
        matches!(self.plans.get(&item.index), Some(LinkPlan::Symlink(..)))
    }

    /// The item of `entry`, if it is written now, with its name.
    fn written_now(&self, entry: &Entry<Option<Inode>>) -> Option<&Item> {
        let item = &self.items[entry.item?];
        (self.kept.contains(&item.index) && !self.created_later(item) && item.name.is_ok())
            .then_some(item)
    }
}

/// [`extract_squashfs`] into the target `make` makes, once the image is
/// checked; in threads if `at_once` and [`Options::threads`] say so, and the
/// target is a folder.
fn extract_into<R: Read + Seek, T: Target>(
    fs: &mut Squashfs<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
    at_once: bool,
) -> Result<Summary, Error> {
    let run = Run::new(options);

    let mut places = (at_once && options.threads.count() > 1).then(Places::new);
    let (entries, mut items, refused) = walk(fs, &run, options, places.as_mut())?;
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    skipped.splice(0..0, refused);
    skipped.sort_by_key(|e| e.index);
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    let to_write = bytes_to_write(&entries, &items, &kept_indexes, &plans, options);
    run.start(kept_indexes.len() as u64, to_write);

    let destination = make()?;
    let mut summary = Summary {
        skipped,
        renamed: settled.renamed,
        ..Summary::default()
    };
    let writing = Writing {
        entries: &entries,
        items: &items,
        kept: &kept_indexes,
        plans: &plans,
        destination: &destination,
        run: &run,
        options,
    };
    let threading = places.and_then(|places| threading(fs, &writing, &places, to_write));
    match (threading, destination.folder()) {
        (Some(threading), Some(folder)) => {
            let folder_writing = Writing {
                destination: folder,
                entries: writing.entries,
                items: writing.items,
                kept: writing.kept,
                plans: writing.plans,
                run: writing.run,
                options,
            };
            write_at_once(fs, &folder_writing, &threading, &mut summary)?;
        }
        _ => write_in_order(fs, &writing, &mut summary)?,
    }

    for &item in kept.iter().filter(|item| writing.created_later(item)) {
        let error = |kind| item.error(kind);
        let (Ok(name), Some(LinkPlan::Symlink(target, to_dir))) =
            (&item.name, plans.get(&item.index))
        else {
            continue;
        };
        run.check().map_err(error)?;
        destination
            .symlink(item, &name.components, target, *to_dir)
            .map_err(error)?;
        summary.links += 1;
        run.entry_done();
    }

    set_dir_times(&destination, &kept, &run)?;
    summary.damaged = run.take_damaged();
    // In the image's order, as one thread meets them, whatever the threads.
    summary.damaged.sort_by_key(|damaged| damaged.error.index);
    Ok(summary)
}

/// Writes the directories, files and hard links of `writing`, one at a time,
/// in the image's order; the symbolic links created later are left.
fn write_in_order<R: Read + Seek, T: Target>(
    fs: &mut Squashfs<R>,
    writing: &Writing<'_, T>,
    summary: &mut Summary,
) -> Result<(), Error> {
    let Writing {
        destination,
        run,
        options,
        ..
    } = *writing;
    for entry in writing.entries {
        run.check().map_err(Error::global)?;
        let Some(item) = writing.written_now(entry) else {
            continue;
        };
        if item.kind == Kind::Dir {
            write_directory(item, destination, run, summary)?;
            continue;
        }
        if write_link(entry, item, writing, summary)? {
            continue;
        }
        let Some(inode) = &entry.seen else {
            return Err(item.error(ErrorKind::HardLinkTarget));
        };
        let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
        let written = write_data(
            &mut fs.file(inode),
            item,
            item.size,
            destination,
            remaining,
            run,
            options,
        )?;
        if let Some(written) = written {
            summary.files += 1;
            summary.bytes += written;
        }
        run.entry_done();
    }
    Ok(())
}

/// Makes the directory `item`.
fn write_directory<T: Target>(
    item: &Item,
    destination: &T,
    run: &Run<'_>,
    summary: &mut Summary,
) -> Result<(), Error> {
    let Ok(name) = &item.name else {
        return Ok(());
    };
    destination
        .directory(item, &name.components)
        .map_err(|kind| item.error(kind))?;
    summary.directories += 1;
    run.entry_done();
    Ok(())
}

/// Writes `item` if it is a link written now: a hard link, or a copy of
/// its file with [`Links::AsFile`](crate::extract::Links::AsFile), or a
/// symbolic link as a file holding its target. Whether it was one.
fn write_link<T: Target>(
    entry: &Entry<Option<Inode>>,
    item: &Item,
    writing: &Writing<'_, T>,
    summary: &mut Summary,
) -> Result<bool, Error> {
    let Writing {
        destination,
        run,
        options,
        ..
    } = *writing;
    let Ok(name) = &item.name else {
        return Ok(false);
    };
    let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
    let written = match writing.plans.get(&item.index) {
        Some(LinkPlan::Hard(target)) if !destination.copies_hard_links(options) => {
            destination
                .hard_link(item, &name.components, target)
                .map_err(|kind| item.error(kind))?;
            summary.files += 1;
            run.entry_done();
            return Ok(true);
        }
        // A copy of the file it names, with Links::AsFile.
        Some(LinkPlan::Hard(target)) => {
            copy_of(destination, target, item, remaining, run, options)?
        }
        Some(LinkPlan::SymlinkAsFile) => write_data(
            &mut &entry.target[..],
            item,
            entry.target.len() as u64,
            destination,
            remaining,
            run,
            options,
        )?,
        _ => return Ok(false),
    };
    if let Some(written) = written {
        summary.files += 1;
        summary.bytes += written;
    }
    run.entry_done();
    Ok(true)
}

/// Writes `size` bytes of `r` into `file`, for `item`, at most `remaining`
/// in all, then its time and permissions: the bytes written. Data that
/// ends before `size` is an error ([`ErrorKind::SizeMismatch`]).
fn write_data<T: Target>(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    destination: &T,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<Option<u64>, Error> {
    let limits = &options.limits;
    if size > limits.max_entry_size {
        return Err(item.error(ErrorKind::EntryTooLarge));
    }
    if size > remaining {
        return Err(item.error(ErrorKind::TotalTooLarge));
    }
    write_with(item, Some(size), destination, run, options, |file| {
        write_into(r, size, file, run)
    })
}

fn write_into(
    r: &mut impl Read,
    size: u64,
    file: &mut impl TargetFile,
    run: &Run<'_>,
) -> Result<u64, ErrorKind> {
    let mut written: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while written < size {
        run.check()?;
        let want = buffer.len().min((size - written) as usize);
        let n = match r.read(&mut buffer[..want]) {
            Ok(0) => return Err(ErrorKind::SizeMismatch),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(squashfs_error(e)),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}

/// A read's error: the image's.
fn squashfs_error(e: io::Error) -> ErrorKind {
    ErrorKind::Squashfs(crate::squashfs::Error::from(e))
}

/// The marker of a data block stored as it is, in its header; the rest is
/// its size in the image (`SQUASHFS_COMPRESSED_BIT_BLOCK`).
const STORED: u32 = 1 << 24;

/// Where the files' data is read from, as the walk found it: whether each
/// file reads the same through caches of its own as through those one
/// thread shares between them, so that threads write what one does.
///
/// squashfuse's caches are keyed by where a block is, not by the header it
/// is read with, and its block indexes by the file's inode number: in an
/// image where a place is read with two headers, or two files of one number
/// have different indexes, what a file reads depends on what was read
/// before it. mksquashfs makes no such image; a damaged one is written on
/// one thread.
struct Places {
    /// Each data block's place, and its header.
    blocks: HashMap<u64, u32>,
    /// Each fragment block's place, and its header.
    fragments: HashMap<u64, u32>,
    /// Each block index a read makes, by its key.
    indexes: HashMap<u64, BlockIndex>,
    /// Whether the files read apart as together, so far.
    apart: bool,
}

impl Places {
    fn new() -> Places {
        Places {
            blocks: HashMap::new(),
            fragments: HashMap::new(),
            indexes: HashMap::new(),
            apart: true,
        }
    }

    /// A place a file's data is read from.
    fn add(&mut self, place: DataPlace) {
        let (map, pos, hdr) = match place {
            DataPlace::Block { pos, hdr } => (&mut self.blocks, pos, hdr),
            DataPlace::Fragment { pos, hdr } => (&mut self.fragments, pos, hdr),
        };
        if *map.entry(pos).or_insert(hdr) != hdr {
            self.apart_no_more();
        }
    }

    /// A file's block index.
    fn index(&mut self, index: BlockIndex) {
        match &index {
            BlockIndex::None => {}
            BlockIndex::Irregular => self.apart_no_more(),
            &BlockIndex::Regular(key, _) => {
                if *self.indexes.entry(key).or_insert_with(|| index.clone()) != index {
                    self.apart_no_more();
                }
            }
        }
    }

    /// The files do not read apart as together: what was gathered is let go.
    fn apart_no_more(&mut self) {
        *self = Places {
            apart: false,
            ..Places::new()
        };
    }
}

/// The threads to write the files with, and what they hold of
/// [`Options::memory_budget`] until they are done.
struct Threading {
    workers: u32,
    /// The image's block size.
    block: u64,
    /// What is held of [`Options::memory_budget`] until the extraction is done.
    _held: Option<Box<dyn std::any::Any>>,
}

/// What a thread writing files holds at most, for an image of blocks of
/// `block` bytes compressed with `compression`: its caches (a data block,
/// three fragment blocks, and eight metadata blocks of 8 KiB), a block read
/// and the block it decompresses to, two blocks decoded ahead, and its
/// decoder: xz's and LZMA's dictionary, which a block's data fills no more
/// than its size, and what each decoder keeps besides, with its buffer to
/// write from, within 512 KiB.
fn thread_memory(block: u64, compression: Compression) -> u64 {
    let dictionary = match compression {
        Compression::Xz | Compression::Lzma => block,
        _ => 0,
    };
    block
        .saturating_mul(8)
        .saturating_add(dictionary)
        .saturating_add(512 << 10)
}

/// The least blocks a file has for the threads with nothing left to take to
/// decode them ahead of the one writing it.
const AHEAD_LEAST: u64 = 4;

/// The threads to write the files of `writing` with, if more than one: none
/// where the files would not read apart as together ([`Places`]), or what
/// the files and the copies of hard links write would pass the limit on all
/// (`to_write`): there, which file the limit stops at depends on what was
/// written before it. [`Options::threads`], lowered until each thread's
/// memory ([`thread_memory`]) fits [`Options::memory_limit`] and
/// `Options::memory_budget`, and to the files and their blocks.
fn threading<R: Read + Seek, T>(
    fs: &Squashfs<R>,
    writing: &Writing<'_, T>,
    places: &Places,
    to_write: u64,
) -> Option<Threading> {
    let options = writing.options;
    if !places.apart || to_write > options.limits.max_total_size {
        return None;
    }
    let block = u64::from(fs.superblock().block_size);
    // A file each, and its blocks for the threads decoding ahead.
    let mut work: u64 = 0;
    for entry in writing.entries {
        let Some(item) = writing.written_now(entry) else {
            continue;
        };
        if item.kind == Kind::File && entry.seen.is_some() {
            let blocks = item.size / block.max(1);
            work = work.saturating_add(1);
            if blocks >= AHEAD_LEAST {
                work = work.saturating_add(blocks);
            }
        }
    }
    let wanted = options
        .threads
        .count()
        .min(u32::try_from(work).unwrap_or(u32::MAX));
    if wanted < 2 {
        return None;
    }
    let each = thread_memory(block, fs.compression());
    let need = |n: u32| u64::from(n).saturating_mul(each);
    let limit = options.memory_limit.unwrap_or(u64::MAX);
    let workers = (1..=wanted).rev().find(|&n| need(n) <= limit).unwrap_or(1);
    #[cfg(feature = "memory")]
    let (workers, held) = match &options.memory_budget {
        Some(budget) if workers > 1 => {
            let (fit, holds) = budget.hold_threads(workers, need);
            (fit, Some(Box::new(holds) as Box<dyn std::any::Any>))
        }
        _ => (workers, None),
    };
    #[cfg(not(feature = "memory"))]
    let held = None;
    (workers > 1).then_some(Threading {
        workers,
        block,
        _held: held,
    })
}

/// Files a thread writes one after another, in the image's order: one, or
/// those whose data is all in one fragment block.
struct Unit {
    /// Their entries' places.
    entries: Vec<usize>,
    /// The bytes they hold.
    size: u64,
}

/// The files of `writing` to write in threads, the largest units first, as
/// ZIP's files are taken: one taken last would be written by its thread
/// alone, after the others are done. The files whose data is all in one
/// fragment block are taken together, in the image's order, so that their
/// block, which one thread keeps, is decompressed once: taken one at a time,
/// by their size, each would decompress it again.
fn units<T>(writing: &Writing<'_, T>, block: u64) -> Vec<Unit> {
    let mut units: Vec<Unit> = Vec::new();
    let mut by_fragment: HashMap<u32, usize> = HashMap::new();
    for (at, entry) in writing.entries.iter().enumerate() {
        let (Some(item), Some(inode)) = (writing.written_now(entry), &entry.seen) else {
            continue;
        };
        if item.kind != Kind::File {
            continue;
        }
        let (fragment, _) = inode.fragment();
        let together = fragment != u32::MAX && item.size < block;
        match by_fragment.get(&fragment).filter(|_| together) {
            Some(&unit) => {
                units[unit].entries.push(at);
                units[unit].size = units[unit].size.saturating_add(item.size);
            }
            None => {
                if together {
                    by_fragment.insert(fragment, units.len());
                }
                units.push(Unit {
                    entries: vec![at],
                    size: item.size,
                });
            }
        }
    }
    // Stable: units of one size in the image's order.
    units.sort_by_key(|unit| std::cmp::Reverse(unit.size));
    units
}

/// What a thread wrote.
#[derive(Default)]
struct Tally {
    files: u64,
    bytes: u64,
}

/// [`write_in_order`] in `threading.workers` threads: the directories first,
/// on this thread, in order; then the files ([`units`]), each unit taken by
/// the next thread that is free, which reads the image through this thread
/// ([`serve`]) and its own caches; the threads with no unit left to take
/// decode the blocks of the files still written ahead of them ([`Ahead`]).
/// Then, on this thread, in order, the hard links and the links written as
/// files.
///
/// The threads share `writing.run`, which tells [`Options::progress`] and
/// asks [`Options::on_damaged`] one at a time. The first to fail keeps its
/// error and halts the others, which stop as if cancelled and remove the
/// file they were writing.
fn write_at_once<R: Read + Seek>(
    fs: &mut Squashfs<R>,
    writing: &Writing<'_, Destination<'_>>,
    threading: &Threading,
    summary: &mut Summary,
) -> Result<(), Error> {
    let Writing {
        destination, run, ..
    } = *writing;
    for entry in writing.entries {
        let Some(item) = writing.written_now(entry) else {
            continue;
        };
        if item.kind == Kind::Dir {
            run.check().map_err(|kind| item.error(kind))?;
            write_directory(item, destination, run, summary)?;
        }
    }

    let units = units(writing, threading.block);
    let workers = usize::try_from(threading.workers).unwrap_or(usize::MAX);
    let ahead = Arc::new(Ahead::new(units.len(), 2 * workers, threading.block));
    let failed: Mutex<Option<Error>> = Mutex::new(None);
    let (requests, asked) = mpsc::sync_channel::<Request>(workers);
    let views: Vec<Squashfs<Remote>> = (0..workers)
        .map(|_| fs.with_reader(Remote::new(requests.clone())))
        .collect();
    drop(requests);
    let tallies = std::thread::scope(|scope| {
        let handles: Vec<_> = views
            .into_iter()
            .map(|mut view| {
                let (units, ahead, failed) = (&units, &ahead, &failed);
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    while let Some(unit) = ahead.take_unit() {
                        let taken = Taken { ahead, run };
                        let written =
                            write_unit(&mut view, &units[unit], writing, ahead, &mut tally);
                        drop(taken);
                        if let Err(e) = written {
                            // Kept before the others are halted: their errors
                            // come after it.
                            lock(failed).get_or_insert(e);
                            run.halt();
                            ahead.wake();
                            return tally;
                        }
                    }
                    ahead.help(&mut view, run);
                    tally
                })
            })
            .collect();
        serve(fs.reader_mut(), &asked);
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    for tally in tallies {
        // A thread that panicked: its panic goes on to the caller.
        let tally = tally.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        summary.files += tally.files;
        summary.bytes += tally.bytes;
    }
    if let Some(e) = failed.into_inner().unwrap_or_else(PoisonError::into_inner) {
        return Err(e);
    }

    for entry in writing.entries {
        let Some(item) = writing.written_now(entry) else {
            continue;
        };
        if matches!(item.kind, Kind::Link | Kind::HardLink) {
            run.check().map_err(|kind| item.error(kind))?;
            write_link(entry, item, writing, summary)?;
        }
    }
    Ok(())
}

/// Writes the files of `unit` with `view`, in order, each file of
/// [`AHEAD_LEAST`] blocks or more given to `ahead` to have its blocks
/// decoded ahead.
fn write_unit(
    view: &mut Squashfs<Remote>,
    unit: &Unit,
    writing: &Writing<'_, Destination<'_>>,
    ahead: &Arc<Ahead>,
    tally: &mut Tally,
) -> Result<(), Error> {
    let Writing {
        destination,
        run,
        options,
        ..
    } = *writing;
    for &at in &unit.entries {
        let entry = &writing.entries[at];
        let (Some(item), Some(inode)) = (writing.written_now(entry), &entry.seen) else {
            continue;
        };
        run.check().map_err(|kind| item.error(kind))?;
        let id = ahead.start(view, inode, at);
        if let Some(id) = id {
            view.set_ahead(Some(Box::new(Taker {
                ahead: Arc::clone(ahead),
                id,
            })));
        }
        // What the files and copies write was checked to fit the limit.
        let written = write_data(
            &mut view.file(inode),
            item,
            item.size,
            destination,
            options.limits.max_total_size,
            run,
            options,
        );
        if let Some(id) = id {
            view.set_ahead(None);
            ahead.end(id);
        }
        if let Some(written) = written? {
            tally.files += 1;
            tally.bytes += written;
        }
        run.entry_done();
    }
    Ok(())
}

/// What `mutex` holds, even if a thread panicked holding it: the panic goes on
/// to the caller anyway.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The units the threads take, and the blocks of the files being written
/// that the threads with no unit left to take decode ahead of the ones
/// writing them: at most `most` blocks decoding or decoded and not yet read,
/// in all, each no larger than a block.
struct Ahead {
    state: Mutex<AheadState>,
    changed: Condvar,
    units: usize,
    most: usize,
    block: u64,
}

struct AheadState {
    /// The next unit to take.
    next: usize,
    /// The units taken and not yet written.
    writing: usize,
    /// The files whose blocks may be decoded ahead, by the place of their
    /// entry.
    files: HashMap<usize, Planned>,
    /// The blocks decoding or decoded, of the files in `files`.
    held: usize,
}

/// A file's blocks, decoded ahead.
struct Planned {
    /// Its data blocks, in the order a read takes them: where and of what
    /// header.
    blocks: Vec<(u64, u32)>,
    /// The next the file's thread reads.
    next: usize,
    /// The first not taken yet, by its thread or another.
    claimed: usize,
    /// Those taken by other threads: decoding (`None`) or decoded.
    slots: HashMap<usize, Option<Result<Block, crate::squashfs::Error>>>,
}

impl Ahead {
    fn new(units: usize, most: usize, block: u64) -> Ahead {
        Ahead {
            state: Mutex::new(AheadState {
                next: 0,
                writing: 0,
                files: HashMap::new(),
                held: 0,
            }),
            changed: Condvar::new(),
            units,
            most,
            block,
        }
    }

    /// The next unit to write, if any is left.
    fn take_unit(&self) -> Option<usize> {
        let mut state = lock(&self.state);
        (state.next < self.units).then(|| {
            state.next += 1;
            state.writing += 1;
            state.next - 1
        })
    }

    /// A unit taken is written, or failed.
    fn unit_done(&self) {
        lock(&self.state).writing -= 1;
        self.changed.notify_all();
    }

    /// Wakes the threads waiting, for them to look again.
    fn wake(&self) {
        self.changed.notify_all();
    }

    /// The file of `inode`, of the entry at `at`, is about to be read with
    /// `view`: its blocks are given to decode ahead if it has
    /// [`AHEAD_LEAST`] or more, read and no larger than a block, and the
    /// key they are given under is returned.
    fn start(&self, view: &mut Squashfs<Remote>, inode: &Inode, at: usize) -> Option<usize> {
        if inode.file_size() / self.block.max(1) < AHEAD_LEAST {
            return None;
        }
        let mut blocks = Vec::new();
        view.check_data_with(inode, &mut |place| {
            if let DataPlace::Block { pos, hdr } = place
                && u64::from(hdr & !STORED) <= self.block
            {
                blocks.push((pos, hdr));
            }
        })
        .ok()?;
        if (blocks.len() as u64) < AHEAD_LEAST {
            return None;
        }
        lock(&self.state).files.insert(
            at,
            Planned {
                blocks,
                next: 0,
                claimed: 0,
                slots: HashMap::new(),
            },
        );
        self.changed.notify_all();
        Some(at)
    }

    /// The file given as `id` is read: its blocks still held are let go.
    fn end(&self, id: usize) {
        let mut state = lock(&self.state);
        if let Some(planned) = state.files.remove(&id) {
            state.held -= planned.slots.len();
        }
        drop(state);
        self.changed.notify_all();
    }

    /// The block at `pos` of header `hdr` of the file given as `id`, if it
    /// is the next its thread reads and another thread took it: what that
    /// thread read, once it has. Otherwise none, for the file's thread to
    /// read it, and no other thread will.
    fn take(&self, id: usize, pos: i64, hdr: u32) -> Option<Result<Block, crate::squashfs::Error>> {
        let mut state = lock(&self.state);
        let planned = state.files.get_mut(&id)?;
        let at = planned.next;
        if planned.blocks.get(at) != Some(&(pos as u64, hdr)) {
            return None;
        }
        planned.next += 1;
        if planned.claimed <= at {
            planned.claimed = at + 1;
            drop(state);
            // Room for one more ahead.
            self.changed.notify_all();
            return None;
        }
        loop {
            let planned = state.files.get_mut(&id)?;
            match planned.slots.remove(&at) {
                Some(Some(block)) => {
                    state.held -= 1;
                    drop(state);
                    self.changed.notify_all();
                    return Some(block);
                }
                Some(None) => {
                    planned.slots.insert(at, None);
                    state = self
                        .changed
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                // Let go by the thread that took it: read here.
                None => return None,
            }
        }
    }

    /// Decodes blocks of the files being written, ahead of the threads
    /// writing them, with `view`, until every unit is written, or the
    /// extraction stops.
    fn help(&self, view: &mut Squashfs<Remote>, run: &Run<'_>) {
        let mut state = lock(&self.state);
        loop {
            if run.check().is_err() || (state.next >= self.units && state.writing == 0) {
                return;
            }
            let Some((id, at, pos, hdr)) = self.claim(&mut state) else {
                state = self
                    .changed
                    .wait_timeout(state, Duration::from_millis(50))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
                continue;
            };
            drop(state);
            let mut decoding = Decoding {
                ahead: self,
                id,
                at,
                done: false,
            };
            let block = view.data_block(pos, hdr);
            state = lock(&self.state);
            decoding.done = true;
            if let Some(slot) = state
                .files
                .get_mut(&id)
                .and_then(|planned| planned.slots.get_mut(&at))
            {
                *slot = Some(block);
            }
            self.changed.notify_all();
        }
    }

    /// The next block to decode ahead, if there is room for one: of the file
    /// whose thread is nearest to it.
    fn claim(&self, state: &mut AheadState) -> Option<(usize, usize, u64, u32)> {
        if state.held >= self.most {
            return None;
        }
        let most = self.most;
        let (&id, planned) = state
            .files
            .iter_mut()
            .filter(|(_, planned)| {
                planned.claimed < planned.blocks.len() && planned.claimed < planned.next + most
            })
            .min_by_key(|(id, planned)| (planned.claimed - planned.next, **id))?;
        let at = planned.claimed;
        planned.claimed += 1;
        planned.slots.insert(at, None);
        let (pos, hdr) = planned.blocks[at];
        state.held += 1;
        Some((id, at, pos, hdr))
    }
}

/// A unit taken: done once its thread is done with it, or panics, which
/// stops the others too, as an error does.
struct Taken<'a> {
    ahead: &'a Ahead,
    run: &'a Run<'a>,
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.run.halt();
        }
        self.ahead.unit_done();
    }
}

/// A block taken to decode ahead: let go if its thread panics before it is
/// decoded, for the file's thread to read it.
struct Decoding<'a> {
    ahead: &'a Ahead,
    id: usize,
    at: usize,
    done: bool,
}

impl Drop for Decoding<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut state = lock(&self.ahead.state);
        let gone = state
            .files
            .get_mut(&self.id)
            .and_then(|planned| planned.slots.remove(&self.at))
            .is_some();
        if gone {
            state.held -= 1;
        }
        drop(state);
        self.ahead.changed.notify_all();
    }
}

/// Where a file's thread takes the blocks decoded ahead of it.
struct Taker {
    ahead: Arc<Ahead>,
    id: usize,
}

impl DataAhead for Taker {
    fn take(&mut self, pos: i64, hdr: u32) -> Option<Result<Block, crate::squashfs::Error>> {
        self.ahead.take(self.id, pos, hdr)
    }
}
