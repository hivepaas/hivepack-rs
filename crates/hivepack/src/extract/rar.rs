//! RAR archives: `hivepack::rar` reads them as UnRAR does, and this writes what
//! it reads by this crate's rules. Only with the feature `rar`, as it takes
//! UnRAR's license, which the rest of this crate does not.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::rar::{
    Archive, ExitCode, Extract, FileHeader, Format, HEAD_FILE, HostSystem, ReadAt, Redirection,
    WideString, name,
};

use crate::extract::destination::Target;
use crate::extract::error::{Error, ErrorKind, RarProblem};
use crate::extract::name::{Name, NameError};
use crate::extract::plan::{Item, Kind, Links, OnDamaged, Options, check, fold};
use crate::extract::plan::{named, settle};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, copy_of, plan_links, write_from};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// What the second reading must see again of an entry.
#[derive(PartialEq, Eq)]
struct Seen {
    name: WideString,
    unp_size: i64,
    pack_size: i64,
    unknown_size: bool,
    dir: bool,
    redir_type: Redirection,
    redir_name: WideString,
}

impl Seen {
    fn of(head: &FileHeader) -> Seen {
        Seen {
            name: head.file_name.clone(),
            unp_size: head.unp_size,
            pack_size: head.pack_size,
            unknown_size: head.unknown_unp_size,
            dir: head.dir,
            redir_type: head.redir_type,
            // A header that is no link can keep the target of one before it:
            // a thread going straight to it does not see that.
            redir_name: if head.redir_type == Redirection::None {
                WideString::new()
            } else {
                head.redir_name.clone()
            },
        }
    }
}

fn rar_error(e: crate::rar::Error) -> ErrorKind {
    ErrorKind::Rar(e)
}

/// What [`Extract`] said of the entry last gone through, but for its data's
/// hash: what stops an extraction whatever becomes of the entry.
fn problem(extract: &Extract) -> Option<RarProblem> {
    if extract.missing_password {
        Some(RarProblem::MissingPassword)
    } else if extract.bad_password {
        Some(RarProblem::BadPassword)
    } else if extract.missing_volume {
        Some(RarProblem::MissingVolume)
    } else if extract.needs_previous_volume {
        Some(RarProblem::NeedsPreviousVolume)
    } else if extract.dictionary_too_large {
        Some(RarProblem::DictionaryTooLarge)
    } else if extract.unknown_format {
        Some(RarProblem::UnknownFormat)
    } else if extract.bad_link_target {
        Some(RarProblem::BrokenLink)
    } else {
        None
    }
}

/// A link's target as bytes: one that is not text is not UTF-8 either, which
/// the checks refuse.
fn wide_target(target: &[u32]) -> Vec<u8> {
    name::to_string(target).map_or_else(|| vec![0xff], String::into_bytes)
}

/// What the archive says of the current entry, its place `index`.
fn item_of<R: ReadAt>(arc: &Archive<R>, index: u64, options: &Options) -> Item {
    let head = &arc.file_head;
    let text = name::to_string(&head.file_name);
    let raw_name = name::to_string_lossy(&head.file_name).into_bytes();
    let (text, name) = match &text {
        None => (
            String::from_utf8_lossy(&raw_name).into_owned(),
            Err(NameError::NotUtf8),
        ),
        Some(text) => named(text, options),
    };
    let kind = if head.dir {
        Kind::Dir
    } else {
        match head.redir_type {
            Redirection::None => Kind::File,
            Redirection::UnixSymlink | Redirection::WindowsSymlink | Redirection::Junction => {
                Kind::Link
            }
            Redirection::HardLink | Redirection::FileCopy => Kind::HardLink,
            _ => Kind::Special,
        }
    };
    // A size not known says nothing to check before writing: what is written
    // is what counts.
    let size = if kind == Kind::File && !head.unknown_unp_size {
        head.unp_size.max(0) as u64
    } else {
        0
    };
    Item {
        index,
        raw_name,
        text,
        name,
        kind,
        size,
        compressed: head.pack_size.max(0) as u64,
        // Headers follow one another, and data its header: none overlaps.
        data: None,
        mode: (head.hs_type == HostSystem::Unix).then_some(head.file_attr & 0o7777),
        mtime: head
            .mtime
            .is_set()
            .then(|| head.mtime.system_time())
            .flatten(),
        owner: None,
        xattrs: Vec::new(),
    }
}

/// Whether the current entry goes on from the one before in a solid stream.
fn is_solid<R: ReadAt>(arc: &Archive<R>) -> bool {
    let head = &arc.file_head;
    // RAR 1.3 to 1.5 archives do not set a solid flag per file.
    head.solid || arc.solid && arc.format != Format::Rar50 && head.unp_ver <= 15
}

/// Makes each entry of a solid stream's compressed size its share of the
/// stream's, so that the ratio it is held to is the stream's, as with 7z's
/// folders: an entry that repeats one before it takes next to nothing.
fn share_solid(items: &mut [Item], solid: &[bool]) {
    let mut start = 0;
    while start < items.len() {
        let mut end = start + 1;
        while end < items.len() && solid[end] {
            end += 1;
        }
        let group = &mut items[start..end];
        let packed: u128 = group.iter().map(|item| u128::from(item.compressed)).sum();
        let unpacked: u128 = group.iter().map(|item| u128::from(item.size)).sum();
        if group.len() > 1 && unpacked > 0 {
            for item in group {
                let share = u128::from(item.size) * packed / unpacked;
                item.compressed = u64::try_from(share).unwrap_or(u64::MAX).max(1);
            }
        }
        start = end;
    }
}

type Entries = Vec<Entry<Seen>>;

/// Where each entry is in the archive, and what decompressing it takes, as
/// the first reading found them: what files written at once go by.
struct Layout {
    /// Whether an entry goes on from the one before it, in a solid stream:
    /// then every entry's data is read, in order, as what follows needs it.
    solid: bool,
    /// Whether the archive is one of many volumes: an entry's place is in its
    /// own volume, which a thread reading from the first cannot go to.
    volumes: bool,
    /// Where each entry's header starts, in the archive (or its volume).
    places: Vec<u64>,
    /// What a thread holds to decompress each entry, at most: see
    /// [`thread_memory`].
    memory: Vec<u64>,
}

/// What a thread holds, at most, to decompress the entry whose header was
/// just read: its window, as large as the entry asks and no larger than its
/// data needs; PPMd's model, which RAR 2.9 to 4 may switch to within any
/// entry, of up to 256 MiB; and its filters and buffers. A thread keeps the
/// largest window it has had, for the entries after.
fn thread_memory(head: &FileHeader, format: Format) -> u64 {
    // Filters' blocks (4 MiB), RAR 3's VM, the input and the archive's buffers.
    const FIXED: u64 = 5 << 20;
    if head.method == 0 {
        return FIXED;
    }
    // At least 256 KiB, as `Unpack::Init` asks.
    let largest = head.win_size.max(0x4_0000);
    // The window grows to twice what a match reaches, from 1 MiB; a stream is
    // stopped once past its size, which it can be by a write of 4 MiB and a
    // filter's block of 4 MiB.
    let window = if head.unknown_unp_size {
        largest
    } else {
        let reached = (head.unp_size.max(0) as u64).saturating_add((8 << 20) + (64 << 10));
        largest.min(reached.saturating_mul(2).max(1 << 20))
    };
    let ppmd = if format != Format::Rar50 && head.unp_ver == 29 {
        257 << 20
    } else {
        0
    };
    window.saturating_add(ppmd).saturating_add(FIXED)
}

/// What file copies write, which a hard link does not unless it is written as
/// a copy: those [`bytes_to_write`] counts already.
fn bytes_of_copies(
    entries: &[Entry<Seen>],
    items: &[Item],
    kept: &HashSet<u64>,
    plans: &HashMap<u64, LinkPlan>,
    options: &Options,
) -> u64 {
    if options.links == Links::AsFile {
        return 0;
    }
    // What each file written so far holds, for the copies after it.
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;
    for entry in entries {
        let Some(item) = entry.item.map(|at| &items[at]) else {
            continue;
        };
        let (true, Ok(name)) = (kept.contains(&item.index), &item.name) else {
            continue;
        };
        let bytes = match plans.get(&item.index) {
            Some(LinkPlan::Hard(target)) => {
                let bytes = sizes.get(&fold(target)).copied().unwrap_or(0);
                if entry.seen.redir_type == Redirection::FileCopy {
                    total = total.saturating_add(bytes);
                }
                bytes
            }
            _ => item.size,
        };
        sizes.insert(fold(&name.components), bytes);
    }
    total
}

/// The first reading: every entry, with what is read and passed over just as
/// the second reading's, no data decompressed.
fn read_headers<R: ReadAt>(
    arc: &mut Archive<R>,
    run: &Run<'_>,
    options: &Options,
) -> Result<(Entries, Vec<Item>, Layout), Error> {
    let mut extract = Extract::new();
    extract.headers_only = true;
    extract.link_targets = true;
    let (mut entries, mut items, mut solid) = (Vec::new(), Vec::new(), Vec::new());
    let (mut places, mut memory) = (Vec::new(), Vec::new());
    loop {
        run.check().map_err(Error::global)?;
        let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
        let mut added = false;
        if size != 0 && arc.cur_header_type == HEAD_FILE {
            if arc.file_head.split_before {
                // The part in this volume of the entry before.
                if let Some(item) = items.last_mut() {
                    let item: &mut Item = item;
                    let part = arc.file_head.pack_size.max(0) as u64;
                    item.compressed = item.compressed.saturating_add(part);
                }
            } else {
                if items.len() as u64 >= options.limits.max_entries {
                    return Err(Error::global(ErrorKind::TooManyEntries));
                }
                let item = item_of(arc, items.len() as u64, options);
                entries.push(Entry {
                    seen: Seen::of(&arc.file_head),
                    item: Some(items.len()),
                    target: wide_target(&arc.file_head.redir_name),
                });
                solid.push(is_solid(arc));
                places.push(arc.cur_block_pos.max(0) as u64);
                memory.push(thread_memory(&arc.file_head, arc.format));
                items.push(item);
                added = true;
            }
        }
        let go = extract
            .current_file(arc, size, &mut |_| Ok(()))
            .map_err(|e| Error::global(rar_error(e)))?;
        if let Some(found) = problem(&extract) {
            let kind = ErrorKind::RarEntry(found);
            return Err(match (added, items.last()) {
                (true, Some(item)) => item.error(kind),
                _ => Error::global(kind),
            });
        }
        if added
            && arc.format != Format::Rar50
            && extract.link_targets
            && let (Some(entry), Some(item)) = (entries.last_mut(), items.last())
            && item.kind == Kind::Link
        {
            entry.target = std::mem::take(&mut extract.link_target);
        }
        if extract.broken_file
            && let Some(item) = items.last()
        {
            return Err(item.error(ErrorKind::RarEntry(RarProblem::BrokenLink)));
        }
        if !go {
            break;
        }
    }
    // Damage that left the headers short of the end.
    if arc.broken_header || arc.exit_code() != ExitCode::Success {
        return Err(Error::global(ErrorKind::RarEntry(
            RarProblem::BrokenArchive,
        )));
    }
    share_solid(&mut items, &solid);
    let layout = Layout {
        solid: arc.solid || solid.contains(&true),
        volumes: arc.volume,
        places,
        memory,
    };
    Ok((entries, items, layout))
}

/// What the entries read may still give of
/// [`Limits::max_total_size`](crate::extract::Limits::max_total_size).
#[derive(Clone, Copy)]
enum Room<'a> {
    /// These many bytes, for one entry read at a time.
    Left(u64),
    /// What the files written at once have written in all, shared by their
    /// threads. A file left out for its damage stays counted.
    Shared(&'a AtomicU64),
}

/// Where an entry's data goes as [`Extract`] gives it out: a file, or nowhere
/// for what is only read through, as a solid stream's data before what is wanted.
struct Out<'a, W> {
    file: Option<W>,
    item: &'a Item,
    /// A size that is not known cannot be compared.
    known_size: bool,
    room: Room<'a>,
    written: u64,
    run: &'a Run<'a>,
    options: &'a Options,
    /// Why writing stopped.
    failed: Option<ErrorKind>,
}

impl<W: Write> Out<'_, W> {
    fn check(&self, written: u64, n: u64) -> Result<(), ErrorKind> {
        let limits = &self.options.limits;
        self.run.check()?;
        let fits = match self.room {
            Room::Left(left) => written <= left,
            Room::Shared(total) => {
                total.fetch_add(n, Ordering::Relaxed).saturating_add(n) <= limits.max_total_size
            }
        };
        if !fits {
            return Err(ErrorKind::TotalTooLarge);
        }
        if self.file.is_none() {
            return Ok(());
        }
        if written > limits.max_entry_size {
            return Err(ErrorKind::EntryTooLarge);
        }
        if self.known_size && written > self.item.size {
            return Err(ErrorKind::SizeMismatch);
        }
        if written > limits.ratio_threshold
            && written > self.item.compressed.saturating_mul(limits.max_ratio)
        {
            return Err(ErrorKind::Ratio);
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let written = self.written.saturating_add(data.len() as u64);
        self.check(written, data.len() as u64).map_err(|kind| {
            self.failed = Some(kind);
            io::Error::other("stopped")
        })?;
        self.written = written;
        if self.file.is_some() && !self.known_size {
            self.run.more_to_write(data.len() as u64);
        }
        if let Some(file) = &mut self.file {
            if let Err(e) = file.write_all(data) {
                self.failed = Some(ErrorKind::Io(e));
                return Err(io::Error::other("stopped"));
            }
            self.run.wrote(data.len() as u64);
        }
        Ok(())
    }
}

/// The file `item` at `place`, whose data failed with `kind` after `written`
/// bytes: the error to stop with, unless it is damage that
/// [`Options::on_damaged`] goes on from, the file then kept as it is or removed.
/// With no file, nothing to go on from: the error.
#[allow(clippy::too_many_arguments)]
fn damaged_file<T: Target>(
    destination: &T,
    item: Option<&Item>,
    place: Option<&[String]>,
    file: Option<T::File<'_>>,
    written: u64,
    kind: ErrorKind,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error> {
    let (Some(item), Some(place), Some(file)) = (item, place, file) else {
        if let Some(place) = place {
            destination.remove_file(place);
        }
        return Err(match item {
            Some(item) => item.error(kind),
            None => Error::global(kind),
        });
    };
    match run.decide(item, kind) {
        Ok((OnDamaged::Keep, damage)) => {
            destination.damaged(&damage);
            if let Err(kind) = destination.finish_file(file, item, options) {
                destination.remove_file(place);
                return Err(item.error(kind));
            }
            summary.files += 1;
            summary.bytes += written;
            run.damaged(damage, Some(written));
        }
        Ok((_, damage)) => {
            destination.damaged(&damage);
            drop(file);
            destination.remove_file(place);
            run.damaged(damage, None);
        }
        Err(e) => {
            drop(file);
            destination.remove_file(place);
            return Err(e);
        }
    }
    run.entry_done();
    Ok(())
}

/// Extracts the RAR archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`. Only with the feature `rar`.
///
/// `open` is given [`Options::password`] as UTF-8, or nothing, and is called
/// twice, and must give the same archive each time, with
/// [`Archive::open_with_password`], or [`Archive::open_volumes`] for a volume
/// of many. An archive with a broken header is best opened refusing it. With
/// [`Options::threads`], each thread calls it too, once to go through the
/// archive and once more if it takes large files first, so it is `Fn` and
/// `Sync`.
///
/// The first reading goes through the entries as the second will, without
/// decompressing, and checks them as [`extract_zip`](crate::extract::extract_zip) does
/// (names, the same path twice, links, the sizes against the limits), and also
/// that no header is broken or cut short, no volume missing, and that RAR 5's
/// check takes the password; a QuickOpen record's copies of headers are what
/// both readings see, as they are what UnRAR's library sees. The second writes
/// them, each header compared with the first reading's ([`ErrorKind::Changed`]
/// if one differs). A file whose hash fails is removed, and the extraction
/// stops there ([`ErrorKind::RarEntry`]). A wrong password that RAR 3 and
/// earlier have nothing to check with shows as that.
///
/// Besides ZIP's rules: symbolic links are RAR 5's redirections, and RAR 4's
/// Unix links, whose target is their data. A Windows link or junction goes by
/// the same rules, which refuse its absolute or `\` targets. A hard link or
/// file copy is created only from a file extracted before it
/// ([`ErrorKind::HardLinkTarget`] otherwise); a file copy, and with
/// [`Links::AsFile`] a hard link, is a copy. A kind of link not known is
/// refused ([`ErrorKind::Special`]). A file in a solid stream is held to its
/// share of the stream's compressed data. In a solid stream, data of entries
/// not written (left out with
/// [`OnRefused::Skip`](crate::extract::OnRefused::Skip), or not picked by
/// [`Options::select`]) is still decompressed, as what follows needs it, and
/// counts against the total limit; elsewhere it is passed over. Files get
/// their Unix permissions when the archive was made on Unix, and their
/// modification time. Recovery records are not used, and comments are left in
/// the archive.
///
/// With [`Options::threads`], an archive that is not solid has its files
/// written that many at once, each read and decompressed by a thread of its
/// own, which goes through the archive itself: the directories are made
/// first, and hard links, file copies and links written as files after the
/// files, in the archive's order. The largest files are started first, where
/// the archive is not of many volumes. Each thread holds a window as large as
/// the archive's dictionary asks, as one thread does: the threads are lowered
/// until they fit [`Options::memory_limit`]. What is written is the same, and
/// so is the summary. The first error stops the other threads, which remove
/// the files they were writing, and is the one returned; files after it in
/// the archive may have been written. A solid archive is read on the caller's
/// thread, as its entries go on from one another.
pub fn extract_rar<R, F>(open: F, destination: &Path, options: &Options) -> Result<Summary, Error>
where
    R: ReadAt,
    F: Fn(&str) -> Result<Archive<R>, crate::rar::Error> + Sync,
{
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(
        &open,
        || open_destination(destination, options),
        options,
        |opener, destination, plan, run, summary| {
            let threads = threads_for(plan, options);
            match threads {
                Some((threads, _held)) => {
                    write_at_once(*opener, destination, plan, run, options, summary, threads)
                }
                None => write_in_order(opener, destination, plan, run, options, summary),
            }
        },
    )
}

/// Extracts the RAR archive that `open` gives into `sink`, with the checks and in
/// the order of [`extract_rar`], reading it twice as it does: see [`Sink`]. A file
/// copy fails here, as what the sink was given cannot be read back. The sink
/// is given one entry at a time, on the caller's thread, whatever
/// [`Options::threads`] says.
pub fn extract_rar_to<R, F>(
    open: F,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error>
where
    R: ReadAt,
    F: FnMut(&str) -> Result<Archive<R>, crate::rar::Error>,
{
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(
        open,
        || Ok(state.target(options)),
        options,
        |opener, target, plan, run, summary| {
            write_in_order(opener, target, plan, run, options, summary)
        },
    )
}

/// What the first reading found, for the second to write by.
struct Plan<'a> {
    entries: &'a [Entry<Seen>],
    items: &'a [Item],
    kept: &'a [&'a Item],
    /// The entries written, links to create later among them.
    kept_indexes: &'a HashSet<u64>,
    plans: &'a HashMap<u64, LinkPlan>,
    layout: &'a Layout,
    password: &'a str,
}

impl Plan<'_> {
    /// Whether `item` is a link created after every other entry.
    fn created_later(&self, item: &Item) -> bool {
        matches!(self.plans.get(&item.index), Some(LinkPlan::Symlink(..)))
    }

    /// The entry at `at`, with its name, if it is written as it is read:
    /// links created later are not.
    fn wanted(&self, at: usize) -> Option<(&Item, &Name)> {
        let item = &self.items[at];
        if !self.kept_indexes.contains(&item.index) || self.created_later(item) {
            return None;
        }
        item.name.as_ref().ok().map(|name| (item, name))
    }

    /// Whether the entry at `at` is a file written from its data: not a
    /// directory, a hard link, a copy, or a link written as a file.
    fn writes_data(&self, at: usize) -> bool {
        self.wanted(at).is_some_and(|(item, name)| {
            item.kind != Kind::Dir
                && !name.components.is_empty()
                && !matches!(
                    self.plans.get(&item.index),
                    Some(LinkPlan::Hard(_) | LinkPlan::SymlinkAsFile)
                )
        })
    }
}

/// [`extract_rar`] into the target `make` makes, once the archive is checked,
/// the entries written by `write`, given `open` to read it again.
fn extract_into<R, F, T>(
    mut open: F,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
    write: impl FnOnce(&mut F, &T, &Plan<'_>, &Run<'_>, &mut Summary) -> Result<(), Error>,
) -> Result<Summary, Error>
where
    R: ReadAt,
    F: FnMut(&str) -> Result<Archive<R>, crate::rar::Error>,
    T: Target,
{
    let run = Run::new(options);
    let password = options
        .password
        .as_ref()
        .map(|password| String::from_utf8_lossy(password).into_owned())
        .unwrap_or_default();

    let mut first = open(&password).map_err(|e| Error::global(rar_error(e)))?;
    let (entries, mut items, layout) = read_headers(&mut first, &run, options)?;
    drop(first);
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    run.start(
        kept_indexes.len() as u64,
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options).saturating_add(
            bytes_of_copies(&entries, &items, &kept_indexes, &plans, options),
        ),
    );

    let destination = make()?;
    let mut summary = Summary {
        skipped,
        renamed: settled.renamed,
        ..Summary::default()
    };
    let plan = Plan {
        entries: &entries,
        items: &items,
        kept: &kept,
        kept_indexes: &kept_indexes,
        plans: &plans,
        layout: &layout,
        password: &password,
    };
    write(&mut open, &destination, &plan, &run, &mut summary)?;

    for &item in kept.iter().filter(|item| plan.created_later(item)) {
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
    // In the archive's order, as one thread meets them, whatever the threads.
    summary.damaged.sort_by_key(|damaged| damaged.error.index);
    Ok(summary)
}

/// The threads to write files at once with, and what they hold of
/// [`Options::memory_budget`] until they are done: none where the archive is
/// solid, or fewer than two files are written, or one thread is all there is.
fn threads_for(
    plan: &Plan<'_>,
    options: &Options,
) -> Option<(u32, Option<Box<dyn std::any::Any>>)> {
    let layout = plan.layout;
    if layout.solid {
        return None;
    }
    let files: Vec<usize> = (0..plan.items.len())
        .filter(|&at| plan.writes_data(at))
        .collect();
    let wanted = options
        .threads
        .count()
        .min(u32::try_from(files.len()).unwrap_or(u32::MAX));
    if wanted < 2 {
        return None;
    }
    // A thread keeps the largest window it has had: each is counted for the
    // largest of all.
    let each = files.iter().map(|&at| layout.memory[at]).max().unwrap_or(0);
    let need = |n: u32| u64::from(n).saturating_mul(each);
    let limit = options.memory_limit.unwrap_or(u64::MAX);
    let threads = (1..=wanted).rev().find(|&n| need(n) <= limit).unwrap_or(1);
    #[cfg(feature = "memory")]
    let (threads, held) = match &options.memory_budget {
        Some(budget) => {
            let (fit, holds) = budget.hold_threads(threads, need);
            (fit, Some(Box::new(holds) as Box<dyn std::any::Any>))
        }
        None => (threads, None),
    };
    #[cfg(not(feature = "memory"))]
    let held = None;
    (threads > 1).then_some((threads, held))
}

/// Goes through the archive once more, as the first reading did, and writes
/// what `plan` says, one entry at a time, in order.
fn write_in_order<R, F, T>(
    open: &mut F,
    destination: &T,
    plan: &Plan<'_>,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error>
where
    R: ReadAt,
    F: FnMut(&str) -> Result<Archive<R>, crate::rar::Error>,
    T: Target,
{
    let mut arc = open(plan.password).map_err(|e| Error::global(rar_error(e)))?;
    let mut extract = Extract::new();
    extract.link_targets = true;
    let mut next = 0;
    // What the entries not written read through.
    let mut read_through = 0u64;
    loop {
        run.check().map_err(Error::global)?;
        let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
        let current = entry_read(&arc, size, plan, &mut next)?;
        let go = step(
            &mut arc,
            &mut extract,
            size,
            current,
            Turn::All,
            None,
            destination,
            plan,
            run,
            options,
            summary,
            &mut read_through,
        )?;
        if !go {
            break;
        }
    }
    gone_through(&arc, next, plan)
}

/// The place of the entry whose header was just read, if it is one, after
/// `next`'s, which it moves on; compared with what the first reading saw there.
fn entry_read<R: ReadAt>(
    arc: &Archive<R>,
    size: usize,
    plan: &Plan<'_>,
    next: &mut usize,
) -> Result<Option<usize>, Error> {
    if size == 0 || arc.cur_header_type != HEAD_FILE || arc.file_head.split_before {
        return Ok(None);
    }
    let at = *next;
    *next += 1;
    let changed = || {
        let raw = name::to_string_lossy(&arc.file_head.file_name);
        Error::new(at as u64, raw.as_bytes(), ErrorKind::Changed)
    };
    let entry = plan.entries.get(at).ok_or_else(changed)?;
    if entry.seen != Seen::of(&arc.file_head) {
        return Err(changed());
    }
    Ok(Some(at))
}

/// After the last header: every entry met, and nothing broken.
fn gone_through<R: ReadAt>(arc: &Archive<R>, next: usize, plan: &Plan<'_>) -> Result<(), Error> {
    if next != plan.entries.len() {
        return Err(Error::global(ErrorKind::Changed));
    }
    if arc.broken_header {
        return Err(Error::global(ErrorKind::RarEntry(
            RarProblem::BrokenArchive,
        )));
    }
    Ok(())
}

/// What a reading does with an entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// Everything, as one reading in order does.
    All,
    /// Its data, written into its file: a thread's file.
    File,
    /// Only its checks: what another does, or what has no data of its own,
    /// done before or after the threads.
    Pass,
}

/// The entry whose header was just read, at `current` if it is one of the
/// first reading's, gone through as `turn` says: whether to go on.
#[allow(clippy::too_many_arguments)]
fn step<R: ReadAt, T: Target>(
    arc: &mut Archive<R>,
    extract: &mut Extract,
    size: usize,
    current: Option<usize>,
    turn: Turn,
    shared: Option<&AtomicU64>,
    destination: &T,
    plan: &Plan<'_>,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
    read_through: &mut u64,
) -> Result<bool, Error> {
    let items = plan.items;
    let item = current.map(|at| &items[at]);
    let link_plan = item.and_then(|item| plan.plans.get(&item.index));
    let wanted = current.and_then(|at| plan.wanted(at));

    // What has no data here comes first: only files are written as read.
    let mut file = None;
    // Where the file being written is, or the link written as a file.
    let mut place: Option<&[String]> = None;
    let mut link_place = None;
    if let Some((item, name)) = wanted {
        let error = |kind| item.error(kind);
        if item.kind == Kind::Dir {
            if turn == Turn::All {
                destination
                    .directory(item, &name.components)
                    .map_err(error)?;
                summary.directories += 1;
                run.entry_done();
            }
        } else if name.components.is_empty() {
            return Err(error(ErrorKind::Name(NameError::Empty)));
        } else if let Some(LinkPlan::Hard(target)) = link_plan {
            if turn == Turn::All {
                let copy = current.is_some_and(|at| is_copy(plan, at));
                write_hard_link(destination, item, name, target, copy, run, options, summary)?;
            }
        } else if matches!(link_plan, Some(LinkPlan::SymlinkAsFile)) {
            link_place = Some(&name.components);
        } else if turn != Turn::Pass {
            let size = (!arc.file_head.unknown_unp_size).then_some(item.size);
            file = Some(
                destination
                    .create_file(item, &name.components, size, options)
                    .map_err(error)?,
            );
            place = Some(&name.components);
        }
    }

    let as_file = file.is_some();
    let remove = |place: &Option<&[String]>| {
        if let Some(components) = place {
            destination.remove_file(components);
        }
    };
    let fallback = Item {
        index: u64::MAX,
        raw_name: Vec::new(),
        text: String::new(),
        name: Err(NameError::Empty),
        kind: Kind::Special,
        size: 0,
        compressed: 0,
        data: None,
        mode: None,
        mtime: None,
        owner: None,
        xattrs: Vec::new(),
    };
    let about = item.unwrap_or(&fallback);
    let total_left = options.limits.max_total_size;
    let room = match (as_file, shared) {
        (true, Some(total)) => Room::Shared(total),
        (true, None) => Room::Left(total_left.saturating_sub(summary.bytes)),
        (false, _) => Room::Left(total_left.saturating_sub(*read_through)),
    };
    let mut sink = Out {
        file,
        item: about,
        known_size: !arc.file_head.unknown_unp_size,
        room,
        written: 0,
        run,
        options,
        failed: None,
    };
    let link_file = link_place.is_some();
    // Outside a solid stream, data that is not written is passed over.
    extract.headers_only = !plan.layout.solid && !as_file;
    let result = extract.current_file(arc, size, &mut |data| sink.write(data));
    extract.headers_only = false;
    let at_error = |kind| match item {
        Some(item) => item.error(kind),
        None => Error::global(kind),
    };
    let go = match result {
        Ok(go) => go,
        Err(e) => {
            let kind = sink.failed.take().unwrap_or_else(|| rar_error(e));
            let (file, written) = (sink.file.take(), sink.written);
            damaged_file(
                destination,
                item.filter(|_| as_file),
                place,
                file,
                written,
                kind,
                run,
                options,
                summary,
            )?;
            // What follows may still be read: the next header says.
            true
        }
    };
    let Out { file, written, .. } = sink;
    if let Some(found) = problem(extract) {
        remove(&place);
        return Err(at_error(ErrorKind::RarEntry(found)));
    }
    if link_file && extract.broken_file {
        return Err(at_error(ErrorKind::RarEntry(RarProblem::BrokenData)));
    }
    if as_file && file.is_some() && extract.broken_file {
        damaged_file(
            destination,
            item,
            place,
            file,
            written,
            ErrorKind::RarEntry(RarProblem::BrokenData),
            run,
            options,
            summary,
        )?;
        return Ok(go);
    }
    if let (Some(at), true) = (current, arc.format != Format::Rar50)
        && items[at].kind == Kind::Link
        && extract.link_target != plan.entries[at].target
    {
        remove(&place);
        return Err(at_error(ErrorKind::Changed));
    }
    if as_file {
        let Some(file) = file else {
            return Err(at_error(ErrorKind::SizeMismatch));
        };
        if !arc.file_head.unknown_unp_size && written != about.size && !arc.file_head.split_after {
            damaged_file(
                destination,
                item,
                place,
                Some(file),
                written,
                ErrorKind::SizeMismatch,
                run,
                options,
                summary,
            )?;
            return Ok(go);
        }
        destination
            .finish_file(file, about, options)
            .inspect_err(|_| remove(&place))
            .map_err(at_error)?;
        summary.files += 1;
        summary.bytes += written;
        run.entry_done();
    } else if link_file {
        if turn == Turn::All
            && let Some(at) = current
        {
            write_link_file(destination, plan, at, run, options, summary)?;
        }
    } else {
        *read_through = read_through.saturating_add(written);
    }
    Ok(go)
}

/// Whether the entry at `at` is a file copy, written as a copy whatever the
/// destination does with hard links.
fn is_copy(plan: &Plan<'_>, at: usize) -> bool {
    plan.entries[at].seen.redir_type == Redirection::FileCopy
}

/// A hard link or file copy of `target`, a file written before it.
#[allow(clippy::too_many_arguments)]
fn write_hard_link<T: Target>(
    destination: &T,
    item: &Item,
    name: &Name,
    target: &[String],
    copy: bool,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error> {
    if !destination.copies_hard_links(options) && !copy {
        destination
            .hard_link(item, &name.components, target)
            .map_err(|kind| item.error(kind))?;
        summary.files += 1;
    } else {
        let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
        if let Some(written) = copy_of(destination, target, item, remaining, run, options)? {
            summary.files += 1;
            summary.bytes += written;
        }
    }
    run.entry_done();
    Ok(())
}

/// The link at `at` written as a file holding its target, with
/// [`Links::AsFile`].
fn write_link_file<T: Target>(
    destination: &T,
    plan: &Plan<'_>,
    at: usize,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error> {
    let target = &plan.entries[at].target;
    let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
    if let Some(written) = write_from(
        &mut &target[..],
        &plan.items[at],
        target.len() as u64,
        destination,
        remaining,
        false,
        run,
        options,
    )? {
        summary.files += 1;
        summary.bytes += written;
    }
    run.entry_done();
    Ok(())
}

/// [`write_in_order`] in `threads` threads: the directories first, on this
/// thread, in order; then the files, each taken by the next thread that is
/// free, which goes through the archive itself and writes the file whole;
/// then, on this thread, in order, what has no data of its own: hard links,
/// copies, and links written as files, once the files they are of are there.
///
/// Each thread opens the archive and goes through its headers, as the first
/// reading did, passing over what other threads take. The largest files,
/// each more than a share of what all write, are taken first, a thread going
/// to each one's header where the archive is not of many volumes: so that
/// one met last is not left to one thread at the end.
///
/// The threads share `run`, which tells [`Options::progress`] and asks
/// [`Options::on_damaged`] one at a time, and what all files have written,
/// held to the limit on it. The first to fail keeps its error and halts the
/// others, which stop as if cancelled and remove the file they were writing.
fn write_at_once<R, G, T>(
    open: &G,
    destination: &T,
    plan: &Plan<'_>,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
    threads: u32,
) -> Result<(), Error>
where
    R: ReadAt,
    G: Fn(&str) -> Result<Archive<R>, crate::rar::Error> + Sync,
    T: Target + Sync,
{
    for &item in plan.kept {
        if item.kind != Kind::Dir || plan.created_later(item) {
            continue;
        }
        let Ok(name) = &item.name else {
            continue;
        };
        let error = |kind| item.error(kind);
        run.check().map_err(error)?;
        destination
            .directory(item, &name.components)
            .map_err(error)?;
        summary.directories += 1;
        run.entry_done();
    }

    let n = plan.items.len();
    let files: Vec<usize> = (0..n).filter(|&at| plan.writes_data(at)).collect();
    let taken: Vec<AtomicBool> = (0..n).map(|_| AtomicBool::new(false)).collect();
    // The largest files first, each by a thread going to its header: those
    // over a share of all the threads write.
    let all: u64 = files
        .iter()
        .map(|&at| plan.items[at].size)
        .fold(0, u64::saturating_add);
    let share = all / (2 * u64::from(threads)).max(1);
    let mut large: Vec<usize> = files
        .iter()
        .copied()
        .filter(|&at| !plan.layout.volumes && plan.items[at].size > share)
        .collect();
    large.sort_by_key(|&at| std::cmp::Reverse(plan.items[at].size));
    for &at in &large {
        taken[at].store(true, Ordering::Relaxed);
    }
    let next_large = AtomicUsize::new(0);
    let total = AtomicU64::new(0);
    let failed: Mutex<Option<Error>> = Mutex::new(None);

    // Files and bytes written by one thread.
    let worker = || {
        let mut tally = Summary::default();
        let result = (|| -> Result<(), Error> {
            let mut extract = Extract::new();
            extract.link_targets = true;
            let mut no_read = 0u64;
            let mut to_large: Option<Archive<R>> = None;
            while let Some(&at) = large.get(next_large.fetch_add(1, Ordering::Relaxed)) {
                let item = &plan.items[at];
                run.check().map_err(|kind| item.error(kind))?;
                let arc = match &mut to_large {
                    Some(arc) => arc,
                    None => to_large
                        .insert(open(plan.password).map_err(|e| Error::global(rar_error(e)))?),
                };
                arc.seek(plan.layout.places[at]);
                let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
                let mut next = at;
                if entry_read(arc, size, plan, &mut next)? != Some(at) {
                    return Err(item.error(ErrorKind::Changed));
                }
                step(
                    arc,
                    &mut extract,
                    size,
                    Some(at),
                    Turn::File,
                    Some(&total),
                    destination,
                    plan,
                    run,
                    options,
                    &mut tally,
                    &mut no_read,
                )?;
            }
            drop(to_large);

            let mut arc = open(plan.password).map_err(|e| Error::global(rar_error(e)))?;
            let mut next = 0;
            loop {
                run.check().map_err(Error::global)?;
                let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
                let current = entry_read(&arc, size, plan, &mut next)?;
                let mine = current.is_some_and(|at| {
                    plan.writes_data(at) && !taken[at].swap(true, Ordering::Relaxed)
                });
                let go = step(
                    &mut arc,
                    &mut extract,
                    size,
                    current,
                    if mine { Turn::File } else { Turn::Pass },
                    Some(&total),
                    destination,
                    plan,
                    run,
                    options,
                    &mut tally,
                    &mut no_read,
                )?;
                if !go {
                    break;
                }
            }
            gone_through(&arc, next, plan)
        })();
        if let Err(e) = result {
            // Kept before the others are halted: their errors come after it.
            failed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_or_insert(e);
            run.halt();
        }
        tally
    };
    let workers = usize::try_from(threads)
        .unwrap_or(usize::MAX)
        .min(files.len());
    let tallies = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers).map(|_| scope.spawn(worker)).collect();
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

    for at in 0..n {
        let Some((item, name)) = plan.wanted(at) else {
            continue;
        };
        match plan.plans.get(&item.index) {
            Some(LinkPlan::Hard(target)) => {
                run.check().map_err(|kind| item.error(kind))?;
                write_hard_link(
                    destination,
                    item,
                    name,
                    target,
                    is_copy(plan, at),
                    run,
                    options,
                    summary,
                )?;
            }
            Some(LinkPlan::SymlinkAsFile) => {
                run.check().map_err(|kind| item.error(kind))?;
                write_link_file(destination, plan, at, run, options, summary)?;
            }
            _ => {}
        }
    }
    Ok(())
}
