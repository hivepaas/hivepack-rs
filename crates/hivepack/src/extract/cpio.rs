//! Extracting a cpio archive that `hivepack::cpio` reads.
//!
//! A cpio archive is a run of entries, each header before its data, as in
//! tar: it is read twice, once for the headers, the data skipped, and once
//! to write, each header compared with the first reading's. The caller
//! gives a function that opens it again, which for a compressed archive or
//! an RPM package's payload decompresses it again.
//!
//! A file with several names is an entry for each name, and its data comes
//! with any of them: with the last in newc, as GNU cpio and RPM write it,
//! the others empty; with each in odc. libarchive's extraction writes the
//! data of each into the file the names share, which ends with the last
//! data written. Here the file is written once, when the last of its
//! entries with data comes, under its first name; its other names are
//! linked to it then, or as they come after.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cpio::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFSOCK, Header, Reader,
};

use crate::extract::destination::Target;
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::{Item, Kind, OnRefused, Options, check};
use crate::extract::plan::{Renamed, settle};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{
    Entry, LinkPlan, bytes_to_write, copy_of, cut_short, plan_links, read_rest, write_with,
};
use crate::extract::writers::{Writers, with_writers, writer_threads};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// An entry's error, by its index and its path.
fn entry_error(index: u64, h: &Header, kind: ErrorKind) -> Error {
    Error::new(index, &h.path, kind)
}

/// Seconds since 1970 as a `SystemTime`.
fn system_time(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// A file with several names.
#[derive(Debug, Default)]
struct Group {
    /// The entry whose data the file holds: the last with data, if any.
    data: Option<u64>,
    /// Whether the file is written.
    written: bool,
    /// Its other names that came before it was written, by their place in
    /// the items, to link to it once it is.
    waiting: Vec<usize>,
}

/// What the first reading found.
#[derive(Default)]
struct FirstReading {
    entries: Vec<Entry<Header>>,
    items: Vec<Item>,
    /// The errors of the entries refused for a warning, to skip.
    refused: Vec<Error>,
    /// The files with several names, by their first entry's index.
    groups: HashMap<u64, Group>,
    /// The first entry of the file each hard link is a name of.
    first_of: HashMap<u64, u64>,
    /// Whether the stream is cut short after the entries, which
    /// [`Options::on_damaged`](crate::extract::Options::on_damaged) may go on from.
    cut: bool,
}

/// The first reading: every header, the data skipped (which reading it
/// through does). An entry that comes with a warning, after bytes that are
/// not a header were passed over, is refused: what was passed over is lost.
fn read_headers<R: Read>(r: R, run: &Run<'_>, options: &Options) -> Result<FirstReading, Error> {
    let mut cpio = Reader::new(r);
    let mut first = FirstReading::default();
    // The entry each path was given by, for the hard links that name it.
    let mut by_path: HashMap<Vec<u8>, u64> = HashMap::new();
    loop {
        let index = first.entries.len() as u64;
        run.check().map_err(Error::global)?;
        let h = match cpio.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let kind = ErrorKind::Cpio(e);
                if run.may_be_cut(&kind) {
                    first.cut = true;
                    return Ok(first);
                }
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind,
                });
            }
        };
        // Every entry counts, as in tar.
        if first.entries.len() as u64 >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let mut entry = Entry {
            seen: h.clone(),
            item: None,
            target: Vec::new(),
        };
        if let Some(warning) = &h.warning {
            let error = entry_error(index, &h, ErrorKind::CpioEntry(warning.clone()));
            match options.on_refused {
                OnRefused::Stop => return Err(error),
                OnRefused::Skip => first.refused.push(error),
            }
            first.entries.push(entry);
            continue;
        }
        // The file a hard link is a name of, by an earlier entry's path:
        // its own, if it has the path of the file's first name, is not one.
        let target = h.hardlink.as_ref().and_then(|t| by_path.get(t)).copied();
        by_path.insert(h.path.clone(), index);
        // The root directory, ".", is not an entry.
        let Some((text, name)) = named_of(&h.path, options) else {
            first.entries.push(entry);
            continue;
        };
        let kind = if h.hardlink.is_some() {
            Kind::HardLink
        } else {
            match h.mode & AE_IFMT {
                AE_IFDIR => Kind::Dir,
                AE_IFLNK => Kind::Link,
                AE_IFCHR | AE_IFBLK | AE_IFIFO | AE_IFSOCK => Kind::Special,
                _ => Kind::File,
            }
        };
        if let Some(target) = target {
            first.first_of.insert(index, target);
            let target_size = first.entries[target as usize].seen.size;
            let group = first.groups.entry(target).or_insert_with(|| Group {
                data: (target_size > 0).then_some(target),
                ..Group::default()
            });
            if h.size > 0 {
                group.data = Some(index);
            }
        }
        entry.target = match kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        let size = match kind {
            Kind::File => h.size,
            _ => 0,
        };
        first.items.push(Item {
            index,
            raw_name: h.path.clone(),
            text,
            name,
            kind,
            size,
            compressed: size,
            data: None,
            mode: Some(h.mode & 0o7777),
            mtime: system_time(h.mod_time),
        });
        entry.item = Some(first.items.len() - 1);
        first.entries.push(entry);
    }
    read_rest(cpio.into_inner(), run, options)?;
    // A file with several names holds the data of its last entry with
    // data, which its first name is written with.
    for (&target, group) in &first.groups {
        let (Some(data), Some(at)) = (group.data, first.entries[target as usize].item) else {
            continue;
        };
        let size = first.entries[data as usize].seen.size;
        let item = &mut first.items[at];
        if item.kind == Kind::File {
            item.size = size;
            item.compressed = size;
        }
    }
    Ok(first)
}

/// Extracts the cpio archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`: Linux's initramfs images,
/// RPM packages' payloads (`hivepack::open::Opener` takes the package and
/// its compression off), and what `cpio` writes.
///
/// `open` is called twice, and must give the same archive each time, as
/// for [`extract_tar`](crate::extract::extract_tar): the first reading checks every
/// entry before anything is written, the second writes them, each header
/// compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs). Each reading goes on to the end of the stream.
///
/// Besides tar's rules: the root directory, `.`, is not an entry. An entry
/// found after bytes that are not a header were passed over comes with a
/// warning ([`crate::cpio::Warning`]), and is refused
/// ([`ErrorKind::CpioEntry`]), or left out with [`OnRefused::Skip`]: what
/// was passed over is lost. A hard link names the first entry of its file,
/// which holds the data of the last of their entries with data, as
/// libarchive's extraction leaves it; the file is written when that data
/// comes, and its names linked to it. An archive cut short, or without
/// `TRAILER!!!`, fails the first reading.
///
/// With [`Options::threads`], the files are written by threads while the
/// archive is read on the caller's thread, as
/// [`extract_tar`](crate::extract::extract_tar) does: what is written is the
/// same, and so is the summary; after an error, files after it in the
/// archive may have been written.
pub fn extract_cpio<R: Read, F: FnMut() -> io::Result<R>>(
    open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(open, || open_destination(destination, options), options)
}

/// Extracts the cpio archive that `open` gives into `sink`, with the checks and
/// in the order of [`extract_cpio`], reading it twice as it does: see [`Sink`].
/// The sink is given one entry at a time, on the caller's thread, whatever
/// [`Options::threads`] says.
pub fn extract_cpio_to<R: Read, F: FnMut() -> io::Result<R>>(
    open: F,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(open, || Ok(state.target(options)), options)
}

/// [`extract_cpio`] into the target `make` makes, once the archive is checked.
fn extract_into<R: Read, F: FnMut() -> io::Result<R>, T: Target>(
    mut open: F,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let run = Run::new(options);
    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut plan = plan(first, &run, options)?;
    run.start(plan.entries_to_write(), plan.bytes_to_write(options));

    let destination = make()?;
    let mut summary = Summary {
        skipped: std::mem::take(&mut plan.skipped),
        renamed: std::mem::take(&mut plan.renamed),
        ..Summary::default()
    };
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    write(second, &mut plan, &destination, &run, options, &mut summary)?;
    summary.damaged = run.take_damaged();
    Ok(summary)
}

/// A cpio archive read once and checked: what the second reading writes.
pub(crate) struct Plan {
    entries: Vec<Entry<Header>>,
    items: Vec<Item>,
    groups: HashMap<u64, Group>,
    first_of: HashMap<u64, u64>,
    plans: HashMap<u64, LinkPlan>,
    /// The places of the entries to extract in `items`.
    kept: Vec<usize>,
    kept_indexes: HashSet<u64>,
    /// The errors of the entries left out, with [`OnRefused::Skip`].
    pub(crate) skipped: Vec<Error>,
    /// The entries renamed, as [`Options::on_unnamable`] said.
    pub(crate) renamed: Vec<Renamed>,
    /// Whether the stream is cut short after the entries.
    cut: bool,
}

impl Plan {
    /// How many entries the second reading writes.
    pub(crate) fn entries_to_write(&self) -> u64 {
        self.kept_indexes.len() as u64
    }

    /// How many bytes it writes.
    pub(crate) fn bytes_to_write(&self, options: &Options) -> u64 {
        bytes_to_write(
            &self.entries,
            &self.items,
            &self.kept_indexes,
            &self.plans,
            options,
        )
    }
}

/// The first reading of the archive `r`, and the checks on all of it.
pub(crate) fn plan<R: Read>(r: R, run: &Run<'_>, options: &Options) -> Result<Plan, Error> {
    let FirstReading {
        entries,
        mut items,
        refused,
        groups,
        first_of,
        cut,
    } = read_headers(r, run, options)?;
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
    // An item's index is its entry's, and items come in their order.
    let place: HashMap<u64, usize> = items
        .iter()
        .enumerate()
        .map(|(at, item)| (item.index, at))
        .collect();
    let kept = kept
        .iter()
        .filter_map(|item| place.get(&item.index).copied())
        .collect();
    Ok(Plan {
        entries,
        items,
        groups,
        first_of,
        plans,
        kept,
        kept_indexes,
        skipped,
        renamed: settled.renamed,
        cut,
    })
}

/// The second reading of the archive `r`, which must be the one `plan`
/// read: its entries written into `destination`, then its symbolic links
/// and its directories' times. With [`Options::threads`], into a folder, the
/// files are written by threads while `r` is read on this thread.
pub(crate) fn write<R: Read, T: Target>(
    r: R,
    plan: &mut Plan,
    destination: &T,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error> {
    let Plan {
        entries,
        items,
        groups,
        first_of,
        plans,
        kept,
        kept_indexes,
        cut,
        ..
    } = plan;
    let kept: Vec<&Item> = kept.iter().map(|&at| &items[at]).collect();
    let created_later = |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
    let reading = Reading {
        entries,
        items,
        first_of,
        kept: kept_indexes,
        cut: *cut,
    };
    let files = kept.iter().filter(|item| item.kind == Kind::File).count() as u64;
    let writers = destination
        .folder()
        .and_then(|folder| Some((folder, writer_threads(options, files)?)));
    let data_error = |e| ErrorKind::Cpio(crate::cpio::Error::from(e));
    match writers {
        Some((folder, writing)) => {
            with_writers(folder, run, options, &writing, |writers| {
                let writer = Writer {
                    destination: folder,
                    plans,
                    run,
                    options,
                    data_error,
                    writers: Some(writers),
                };
                reading.write(r, groups, &writer, summary)
            })?;
        }
        None => {
            let writer = Writer {
                destination,
                plans,
                run,
                options,
                data_error,
                writers: None,
            };
            reading.write(r, groups, &writer, summary)?;
        }
    }

    for &item in kept.iter().filter(|item| created_later(item)) {
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

    set_dir_times(destination, &kept, run)?;
    Ok(())
}

/// What the first reading found and the checks kept, for the second reading.
struct Reading<'p> {
    entries: &'p [Entry<Header>],
    items: &'p [Item],
    first_of: &'p HashMap<u64, u64>,
    /// The entries to write.
    kept: &'p HashSet<u64>,
    /// Whether the stream is cut short after the entries.
    cut: bool,
}

impl<'p> Reading<'p> {
    /// The second reading, of `r`: each entry written with `writer` but the
    /// symbolic links.
    fn write<R: Read, T: Target>(
        &self,
        r: R,
        groups: &mut HashMap<u64, Group>,
        writer: &Writer<'_, 'p, T>,
        summary: &mut Summary,
    ) -> Result<(), Error> {
        let Reading {
            entries,
            items,
            first_of,
            kept: kept_indexes,
            cut,
        } = *self;
        let (plans, run, options) = (writer.plans, writer.run, writer.options);
        let created_later =
            |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
        let mut cpio = Reader::new(r);
        for (index, entry) in entries.iter().enumerate() {
            let index = index as u64;
            run.check().map_err(Error::global)?;
            let h = match cpio.next() {
                Ok(Some(h)) => h,
                Ok(None) => return Err(Error::global(ErrorKind::Changed)),
                Err(e) => return Err(Error::global(ErrorKind::Cpio(e))),
            };
            if h != entry.seen {
                return Err(entry_error(index, &h, ErrorKind::Changed));
            }
            // The data of a file with several names, which its first name is
            // written with, whichever of them it comes with.
            if let Some(target) = first_of.get(&index).copied().or(Some(index))
                && let Some(group) = groups.get_mut(&target)
                && group.data == Some(index)
            {
                let first_entry = &entries[target as usize];
                if let Some(at) = first_entry.item
                    && items[at].kind == Kind::File
                    && kept_indexes.contains(&target)
                {
                    writer.file(&mut cpio, &items[at], h.size, summary)?;
                    for &waiting in &group.waiting {
                        writer.hard_link(&items[waiting], summary)?;
                    }
                    group.waiting.clear();
                }
                group.written = true;
            }
            let Some(at) = entry.item else {
                continue;
            };
            let item = &items[at];
            if !kept_indexes.contains(&item.index) || created_later(item) {
                continue;
            }
            if item.name.is_err() {
                continue;
            }
            if item.kind == Kind::Dir {
                writer.directory(item, summary)?;
                continue;
            }
            match plans.get(&item.index) {
                Some(LinkPlan::Hard(_)) => {
                    match first_of
                        .get(&index)
                        .and_then(|target| groups.get_mut(target))
                    {
                        Some(group) if !group.written => group.waiting.push(at),
                        _ => writer.hard_link(item, summary)?,
                    }
                    continue;
                }
                Some(LinkPlan::SymlinkAsFile) => {
                    writer.file(
                        &mut &entry.target[..],
                        item,
                        entry.target.len() as u64,
                        summary,
                    )?;
                    continue;
                }
                _ => {}
            }
            match groups.get(&index) {
                // Written with its data, which comes with a later name.
                Some(group) if group.data.is_some() => {}
                // A file with several names and no data at all.
                Some(_) => {
                    writer.file(&mut io::empty(), item, 0, summary)?;
                    if let Some(group) = groups.get_mut(&index) {
                        group.written = true;
                    }
                }
                None => writer.file(&mut cpio, item, item.size, summary)?,
            }
        }
        // The second reading must end where the first did.
        match cpio.next() {
            Ok(None) if !cut => read_rest(cpio.into_inner(), run, options)?,
            Ok(None) => return Err(Error::global(ErrorKind::Changed)),
            Ok(Some(h)) => {
                return Err(entry_error(entries.len() as u64, &h, ErrorKind::Changed));
            }
            Err(e) if cut => cut_short(entries, ErrorKind::Cpio(e), run)?,
            Err(e) => return Err(Error::global(ErrorKind::Cpio(e))),
        }
        Ok(())
    }
}

/// What a second reading writes with: the threads writing files, if there
/// are, whose items live for `'w`.
pub(crate) struct Writer<'a, 'w, T> {
    pub(crate) destination: &'a T,
    pub(crate) plans: &'a HashMap<u64, LinkPlan>,
    pub(crate) run: &'a Run<'a>,
    pub(crate) options: &'a Options,
    /// The archive's error, from a read of an entry's data that failed.
    pub(crate) data_error: fn(io::Error) -> ErrorKind,
    pub(crate) writers: Option<&'a Writers<'w>>,
}

impl<'w, T: Target> Writer<'_, 'w, T> {
    /// Makes the directory `item`.
    pub(crate) fn directory(&self, item: &'w Item, summary: &mut Summary) -> Result<(), Error> {
        let name = item
            .name
            .as_ref()
            .map_err(|e| item.error(ErrorKind::Name(*e)))?;
        match self.writers {
            Some(writers) => writers.directory(item),
            None => {
                self.destination
                    .directory(item, &name.components)
                    .map_err(|kind| item.error(kind))?;
                self.run.entry_done();
            }
        }
        summary.directories += 1;
        Ok(())
    }

    /// Writes `item` as a file of the `size` bytes `r` gives.
    pub(crate) fn file(
        &self,
        r: &mut impl Read,
        item: &'w Item,
        size: u64,
        summary: &mut Summary,
    ) -> Result<(), Error> {
        let limits = &self.options.limits;
        let remaining = limits.max_total_size.saturating_sub(summary.bytes);
        let written = match self.writers {
            // Within the limits, as `write_data` checks them first.
            Some(writers) if size <= limits.max_entry_size && size <= remaining => {
                match writers.file(r, item, size, remaining, false)? {
                    // Counted as written: if it is not, the extraction fails.
                    None => {
                        summary.files += 1;
                        summary.bytes += size;
                        return Ok(());
                    }
                    Some(mut replay) => write_data(
                        &mut replay,
                        item,
                        size,
                        self.destination,
                        remaining,
                        self.run,
                        self.options,
                        self.data_error,
                    ),
                }
            }
            _ => write_data(
                r,
                item,
                size,
                self.destination,
                remaining,
                self.run,
                self.options,
                self.data_error,
            ),
        };
        if let Some(written) = written? {
            summary.files += 1;
            summary.bytes += written;
        }
        self.run.entry_done();
        Ok(())
    }

    /// Makes `item` a hard link to the file its plan names, which is
    /// written: a copy of it, with [`Links::AsFile`](crate::extract::Links::AsFile).
    pub(crate) fn hard_link(&self, item: &Item, summary: &mut Summary) -> Result<(), Error> {
        let error = |kind| item.error(kind);
        if let Some(writers) = self.writers {
            // Its file is to be there, if a thread has it.
            writers.wait(item)?;
        }
        let Some(LinkPlan::Hard(target)) = self.plans.get(&item.index) else {
            return Err(error(ErrorKind::HardLinkTarget));
        };
        let name = item.name.as_ref().map_err(|e| error(ErrorKind::Name(*e)))?;
        if name.components.is_empty() {
            return Err(error(ErrorKind::Name(NameError::Empty)));
        }
        if !self.destination.copies_hard_links(self.options) {
            self.destination
                .hard_link(item, &name.components, target)
                .map_err(error)?;
            summary.files += 1;
            self.run.entry_done();
            return Ok(());
        }
        let remaining = self
            .options
            .limits
            .max_total_size
            .saturating_sub(summary.bytes);
        if let Some(written) = copy_of(
            self.destination,
            target,
            item,
            remaining,
            self.run,
            self.options,
        )? {
            summary.files += 1;
            summary.bytes += written;
        }
        self.run.entry_done();
        Ok(())
    }
}

/// Writes the `size` bytes of `r` into `file`, for `item`, at most
/// `remaining` in all, then its time and permissions: the bytes written.
#[allow(clippy::too_many_arguments)]
fn write_data<T: Target>(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    destination: &T,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
    data_error: fn(io::Error) -> ErrorKind,
) -> Result<Option<u64>, Error> {
    let limits = &options.limits;
    if size > limits.max_entry_size {
        return Err(item.error(ErrorKind::EntryTooLarge));
    }
    if size > remaining {
        return Err(item.error(ErrorKind::TotalTooLarge));
    }
    write_with(item, Some(size), destination, run, options, |file| {
        write_into(r, size, file, run, data_error)
    })
}

fn write_into(
    r: &mut impl Read,
    size: u64,
    file: &mut impl std::io::Write,
    run: &Run<'_>,
    data_error: fn(io::Error) -> ErrorKind,
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
            Err(e) => return Err(data_error(e)),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}
