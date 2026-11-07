//! Extracting a tar archive that `hivepack::tar` reads.
//!
//! A tar archive has no index: its entries come one after the other, each
//! header before its data. To check every entry before anything is
//! written, as for ZIP, the archive is read twice: once for the headers,
//! skipping the data, and once to write, each header compared with the
//! first reading's. The caller gives a function that opens it again, which
//! for a compressed or encrypted archive decompresses or decrypts it again.
//! Each reading goes on past the archive's end to the end of the stream,
//! so that what checks the stream there is made.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::tar::{
    Header, Reader, TYPE_BLOCK, TYPE_CHAR, TYPE_DIR, TYPE_FIFO, TYPE_LINK, TYPE_SYMLINK,
    TYPE_X_GLOBAL_HEADER, Time,
};

use crate::extract::destination::{Counted, Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::{Name, NameError};
use crate::extract::plan::{Item, Kind, Links, OnDamaged, OnRefused, Options, check, fold};
use crate::extract::plan::{LinkTo, link_to, named, settle, settle_links, skips_links};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::writers::{Writers, with_writers, writer_threads};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// GNU's volume label, which names the archive, not a file.
const TYPE_GNU_VOLUME: u8 = b'V';
/// GNU's dump directory: a directory, whose data lists what was in it.
const TYPE_GNU_DUMPDIR: u8 = b'D';

/// What the first reading saw of an entry, for the second to compare.
#[derive(PartialEq, Eq)]
struct Seen {
    typeflag: u8,
    name: Vec<u8>,
    linkname: Vec<u8>,
    size: i64,
}

impl Seen {
    fn of(h: &Header) -> Seen {
        Seen {
            typeflag: h.typeflag,
            name: h.name.clone(),
            linkname: h.linkname.clone(),
            size: h.size,
        }
    }
}

/// An entry of the archive, as the first reading saw it: what the second
/// reading must see again (`S`), and what it is to become.
pub(crate) struct Entry<S> {
    pub(crate) seen: S,
    /// Its place in `items`, if it is to be extracted at all (global PAX
    /// headers, volume labels and `./` are not).
    pub(crate) item: Option<usize>,
    /// A link's target: a symbolic link's as written, a hard link's as a
    /// name in the archive.
    pub(crate) target: Vec<u8>,
}

/// The name of an entry or of a hard link's target as the options take
/// it, a leading `./` dropped (`tar -cf x.tar .` writes every name so):
/// `None` for the archive's root, `./` itself.
pub(crate) fn name_of(raw: &[u8], options: &Options) -> Option<Result<Name, NameError>> {
    named_of(raw, options).map(|(_, name)| name)
}

/// [`name_of`], with the name as text (see [`Item::text`]).
pub(crate) fn named_of(raw: &[u8], options: &Options) -> Option<(String, Result<Name, NameError>)> {
    let lossy = || String::from_utf8_lossy(raw).into_owned();
    if raw.iter().any(u8::is_ascii_control) {
        return Some((lossy(), Err(NameError::Control)));
    }
    let by_decoder;
    let mut text = match std::str::from_utf8(raw) {
        Ok(text) => text,
        Err(_) => match options
            .decode_names
            .as_ref()
            .and_then(|d| d.decode(raw, None))
        {
            Some(text) => {
                by_decoder = text;
                by_decoder.as_str()
            }
            None => return Some((lossy(), Err(NameError::NotUtf8))),
        },
    };
    while let Some(rest) = text.strip_prefix("./") {
        text = rest.trim_start_matches('/');
    }
    if text.is_empty() || text == "." {
        return None;
    }
    Some(named(text, options))
}

/// A tar time as a `SystemTime`.
fn system_time(t: Option<Time>) -> Option<SystemTime> {
    let t = t?;
    let at = if t.secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.secs as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.secs.unsigned_abs()))?
    };
    at.checked_add(Duration::from_nanos(u64::from(t.nanos)))
}

/// The first reading: every header, the data skipped.
/// What the first reading found: the entries and the items to write, and
/// whether the stream is cut short after them, which
/// [`Options::on_damaged`](crate::extract::Options::on_damaged) may go on from.
type FirstReading = (Vec<Entry<Seen>>, Vec<Item>, bool);

/// The first reading.
fn read_headers<R: Read>(r: R, run: &Run<'_>, options: &Options) -> Result<FirstReading, Error> {
    let mut tr = Reader::new(r);
    let mut entries = Vec::new();
    let mut items = Vec::new();
    loop {
        let index = entries.len() as u64;
        run.check().map_err(Error::global)?;
        let h = match tr.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let kind = ErrorKind::Tar(e);
                if run.may_be_cut(&kind) {
                    return Ok((entries, items, true));
                }
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind,
                });
            }
        };
        // Every entry counts, metadata too, so that an archive of them
        // does not grow this list without end.
        if entries.len() as u64 >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let seen = Seen::of(&h);
        let name = match h.typeflag {
            // The archive's own metadata, not entries to write.
            TYPE_X_GLOBAL_HEADER | TYPE_GNU_VOLUME => None,
            _ => named_of(&h.name, options),
        };
        let Some((text, name)) = name else {
            entries.push(Entry {
                seen,
                item: None,
                target: Vec::new(),
            });
            continue;
        };
        let named_dir = name.as_ref().is_ok_and(|name| name.is_dir);
        let kind = match h.typeflag {
            TYPE_DIR | TYPE_GNU_DUMPDIR => Kind::Dir,
            TYPE_SYMLINK => Kind::Link,
            TYPE_LINK => Kind::HardLink,
            TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO => Kind::Special,
            _ if named_dir => Kind::Dir,
            // Regular files, sparse files, and the types GNU and Python
            // tar take for regular files.
            _ => Kind::File,
        };
        let size = match kind {
            Kind::File => u64::try_from(h.size).unwrap_or(0),
            _ => 0,
        };
        let target = match kind {
            Kind::Link | Kind::HardLink => h.linkname.clone(),
            _ => Vec::new(),
        };
        items.push(Item {
            index,
            raw_name: h.name.clone(),
            text,
            name,
            kind,
            size,
            // tar does not compress: the ratio is a compressor's to check.
            compressed: size,
            data: None,
            mode: Some((h.mode & 0o7777) as u32),
            mtime: system_time(h.mod_time),
        });
        entries.push(Entry {
            seen,
            item: Some(items.len() - 1),
            target,
        });
    }
    read_rest(tr.into_inner(), run, options)?;
    Ok((entries, items, false))
}

/// A stream cut short after `entries`, as the first reading found, met again
/// with `kind`: gone on from, unless [`Options::on_damaged`](crate::extract::Options::on_damaged)
/// says to stop, asked of the last entry if its data was not asked about already.
pub(crate) fn cut_short<S>(
    entries: &[Entry<S>],
    kind: ErrorKind,
    run: &Run<'_>,
) -> Result<(), Error> {
    let last = entries.len().checked_sub(1).map(|at| at as u64);
    if last.is_some() && run.last_damaged() == last {
        return Ok(());
    }
    let error = Error {
        index: Some(entries.len() as u64),
        name: None,
        kind,
    };
    let (_, damage) = run.decide_on(error)?;
    run.damaged(damage, None);
    Ok(())
}

/// After the archive's end, the rest of the stream, read to its end: a
/// compressor checks its data there (gzip's and bzip2's CRC-32, xz's and
/// zstd's checks), and an age file's last chunk is authenticated, as GNU
/// tar reads its compressor's output to the end. The tar reader stops at
/// the archive's end, which comes before. A compressed stream can go on
/// far past it: what is read is limited to
/// [`Limits::max_total_size`](crate::extract::Limits::max_total_size), or 1 MiB if
/// that is less, the largest record tar pads an archive to (`-b 2048`).
pub(crate) fn read_rest<R: Read>(mut r: R, run: &Run<'_>, options: &Options) -> Result<(), Error> {
    let limit = options.limits.max_total_size.max(1 << 20);
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        run.check().map_err(Error::global)?;
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                total += n as u64;
                if total > limit {
                    return Err(Error::global(ErrorKind::TotalTooLarge));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::global(ErrorKind::Io(e))),
        }
    }
}

/// What to do with a link once the entries are checked.
pub(crate) enum LinkPlan {
    /// A symbolic link to create last, with its target, and whether it
    /// leads to a directory.
    Symlink(String, bool),
    /// A file holding the target, with [`Links::AsFile`].
    SymlinkAsFile,
    /// A hard link to the file with these components.
    Hard(Vec<String>),
}

/// The links' plans, checked: a symbolic link's target as [`link_to`] and
/// [`settle_links`] take it (with [`Links::Inside`] or [`Links::Any`]); a hard
/// link's must name a file extracted before it. Those refused and skipped
/// go to `skipped`.
pub(crate) fn plan_links<S>(
    entries: &[Entry<S>],
    items: &[Item],
    kept: &[&Item],
    options: &Options,
    skipped: &mut Vec<Error>,
) -> Result<HashMap<u64, LinkPlan>, Error> {
    let kept_of = |kind: Kind| {
        kept.iter()
            .filter(move |item| item.kind == kind)
            .filter_map(|item| {
                item.name
                    .as_ref()
                    .ok()
                    .map(|name| (fold(&name.components), item.index))
            })
    };
    let symlinks: HashMap<String, u64> = kept_of(Kind::Link).collect();
    let dirs: HashMap<String, u64> = kept_of(Kind::Dir).collect();
    let files: HashMap<String, u64> = kept_of(Kind::File).chain(kept_of(Kind::HardLink)).collect();
    let kept_indexes: std::collections::HashSet<u64> = kept.iter().map(|item| item.index).collect();

    let mut plans = HashMap::new();
    let mut symlinks_checked = Vec::new();
    // Those left out here, in the archive's order once the symbolic links are.
    let mut left = Vec::new();
    for entry in entries {
        let Some(at) = entry.item else {
            continue;
        };
        let item = &items[at];
        if !kept_indexes.contains(&item.index) {
            continue;
        }
        let Ok(name) = &item.name else {
            continue;
        };
        let checked = match item.kind {
            Kind::Link => match options.links {
                Links::AsFile => Ok(LinkPlan::SymlinkAsFile),
                _ => {
                    let parent = &name.components[..name.components.len().saturating_sub(1)];
                    symlinks_checked.push((
                        item,
                        link_to(&entry.target, parent, options, &symlinks, &dirs),
                    ));
                    continue;
                }
            },
            Kind::HardLink => match name_of(&entry.target, options) {
                Some(Ok(target)) => match files.get(&fold(&target.components)) {
                    Some(&first) if first < item.index => Ok(LinkPlan::Hard(target.components)),
                    _ => Err(ErrorKind::HardLinkTarget),
                },
                Some(Err(e)) => Err(ErrorKind::LinkTarget(e)),
                None => Err(ErrorKind::HardLinkTarget),
            },
            _ => continue,
        };
        let skip = |kind: &ErrorKind| match kind {
            ErrorKind::LinkTarget(_) | ErrorKind::LinkChain { .. } => skips_links(options),
            _ => options.on_refused,
        };
        match checked {
            Ok(plan) => {
                plans.insert(item.index, plan);
            }
            Err(kind) if skip(&kind) == OnRefused::Skip => left.push(item.error(kind)),
            Err(kind) => return Err(item.error(kind)),
        }
    }
    for (item, LinkTo { target, to_dir }) in settle_links(symlinks_checked, options, &mut left)? {
        plans.insert(item.index, LinkPlan::Symlink(target, to_dir));
    }
    left.sort_by_key(|error| error.index);
    skipped.extend(left);
    Ok(plans)
}

/// Extracts the tar archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`.
///
/// `open` is called twice, and must give the same archive each time: the
/// first reading checks every entry before anything is written, as
/// [`extract_zip`](crate::extract::extract_zip) does (names, the same path twice,
/// links, the sizes against the limits), and the second writes them, each
/// header compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs). For a compressed or encrypted archive, `open` decompresses or
/// decrypts it again (`hivepack::open::Opener` does). Each reading goes on
/// past the archive's end to the end of the stream, so that a compressor's
/// check there, or age's last chunk, fails the first reading before
/// anything is written ([`ErrorKind::Io`]); what follows the end is
/// limited to [`Limits::max_total_size`](crate::extract::Limits::max_total_size),
/// or 1 MiB if that is less.
///
/// Besides ZIP's rules: a leading `./` is dropped from names, and `./`
/// itself, the archive's root, is not an entry; a hard link is created
/// only to a file extracted before it ([`ErrorKind::HardLinkTarget`]
/// otherwise), as a copy with [`Links::AsFile`]; devices and FIFOs are
/// refused ([`ErrorKind::Special`]); global PAX headers and GNU volume
/// labels are the archive's, not entries. A sparse file's holes stay holes
/// where the file system has them, and count against the limits.
///
/// With [`Options::threads`], the archive is read on the caller's thread, and
/// the directories and files are made by the others, as many at once: each
/// file's data read whole and handed to the next thread free, 32 MiB at most
/// held ([`Options::memory_limit`] if less); a file larger than an eighth of
/// that, or sparse, is written on the caller's thread. A hard link waits for
/// the files handed before it to be written, and symbolic links are created
/// once every thread is done. What is written is the same, and so is the
/// summary. The first error stops the other threads, which remove the files
/// they were writing, and is the one returned; files after it in the archive
/// may have been written.
pub fn extract_tar<R: Read, F: FnMut() -> io::Result<R>>(
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

/// Extracts the tar archive that `open` gives into `sink`, with the checks and
/// in the order of [`extract_tar`], reading it twice as it does: see [`Sink`].
/// The sink is given one entry at a time, on the caller's thread, whatever
/// [`Options::threads`] says.
pub fn extract_tar_to<R: Read, F: FnMut() -> io::Result<R>>(
    open: F,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(open, || Ok(state.target(options)), options)
}

/// [`extract_tar`] into the target `make` makes, once the archive is checked.
fn extract_into<R: Read, F: FnMut() -> io::Result<R>, T: Target>(
    mut open: F,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let run = Run::new(options);

    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let (entries, mut items, cut) = read_headers(first, &run, options)?;
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let kept_indexes: std::collections::HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    let created_later = |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
    run.start(
        kept_indexes.len() as u64,
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options),
    );

    let destination = make()?;
    let mut summary = Summary {
        skipped,
        renamed: settled.renamed,
        ..Summary::default()
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let reading = Reading {
        entries: &entries,
        items: &items,
        kept: &kept_indexes,
        plans: &plans,
        cut,
    };
    let files = kept.iter().filter(|item| item.kind == Kind::File).count() as u64;
    let writers = destination
        .folder()
        .and_then(|folder| Some((folder, writer_threads(options, files)?)));
    match writers {
        Some((folder, writing)) => {
            with_writers(folder, &run, options, &writing, |writers| {
                reading.write(second, folder, &run, options, &mut summary, Some(writers))
            })?;
        }
        None => reading.write(second, &destination, &run, options, &mut summary, None)?,
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

    set_dir_times(&destination, &kept, &run)?;
    summary.damaged = run.take_damaged();
    Ok(summary)
}

/// What the first reading found and the checks kept, for the second reading.
struct Reading<'p> {
    entries: &'p [Entry<Seen>],
    items: &'p [Item],
    /// The entries to write.
    kept: &'p std::collections::HashSet<u64>,
    plans: &'p HashMap<u64, LinkPlan>,
    /// Whether the stream is cut short after the entries.
    cut: bool,
}

impl<'p> Reading<'p> {
    fn created_later(&self, item: &Item) -> bool {
        matches!(self.plans.get(&item.index), Some(LinkPlan::Symlink(..)))
    }

    /// The second reading, of `r`: each entry written into `destination` but
    /// the symbolic links, the files by `writers` where there are, or here.
    fn write<R: Read, T: Target>(
        &self,
        r: R,
        destination: &T,
        run: &Run<'_>,
        options: &Options,
        summary: &mut Summary,
        writers: Option<&Writers<'p>>,
    ) -> Result<(), Error> {
        let limits = &options.limits;
        let entries = self.entries;
        let mut tr = Reader::new(r);
        for (index, entry) in entries.iter().enumerate() {
            run.check().map_err(Error::global)?;
            let h = match tr.next() {
                Ok(Some(h)) => h,
                Ok(None) => return Err(Error::global(ErrorKind::Changed)),
                Err(e) => return Err(Error::global(ErrorKind::Tar(e))),
            };
            if Seen::of(&h) != entry.seen {
                return Err(Error::new(index as u64, &h.name, ErrorKind::Changed));
            }
            let Some(at) = entry.item else {
                continue;
            };
            let item = &self.items[at];
            if !self.kept.contains(&item.index) || self.created_later(item) {
                continue;
            }
            let Ok(name) = &item.name else {
                continue;
            };
            let error = |kind| item.error(kind);
            let components = &name.components;
            if item.kind == Kind::Dir {
                match writers {
                    Some(writers) => writers.directory(item),
                    None => {
                        destination.directory(item, components).map_err(error)?;
                        run.entry_done();
                    }
                }
                summary.directories += 1;
                continue;
            }
            let plan = self.plans.get(&item.index);
            if let (Some(LinkPlan::Hard(_)), Some(writers)) = (plan, writers) {
                // Its file is to be there, if a thread has it.
                writers.wait(item)?;
            }
            match plan {
                Some(LinkPlan::Hard(target)) if !destination.copies_hard_links(options) => {
                    destination
                        .hard_link(item, components, target)
                        .map_err(error)?;
                    summary.files += 1;
                    run.entry_done();
                    continue;
                }
                _ => {}
            }
            let remaining = limits.max_total_size.saturating_sub(summary.bytes);
            let written = match plan {
                Some(LinkPlan::SymlinkAsFile) => write_from(
                    &mut &entry.target[..],
                    item,
                    entry.target.len() as u64,
                    destination,
                    remaining,
                    false,
                    run,
                    options,
                ),
                Some(LinkPlan::Hard(target)) => {
                    // A copy of the file it names, with Links::AsFile.
                    copy_of(destination, target, item, remaining, run, options)
                }
                _ => {
                    let holes = tr.is_sparse();
                    match writers.filter(|_| !holes) {
                        Some(writers) => {
                            match writers.file(&mut tr, item, item.size, remaining, true)? {
                                // Counted as written: if it is not, the
                                // extraction fails.
                                None => {
                                    summary.files += 1;
                                    summary.bytes += item.size;
                                    continue;
                                }
                                Some(mut replay) => write_from(
                                    &mut replay,
                                    item,
                                    item.size,
                                    destination,
                                    remaining,
                                    false,
                                    run,
                                    options,
                                ),
                            }
                        }
                        None => write_from(
                            &mut tr,
                            item,
                            item.size,
                            destination,
                            remaining,
                            holes,
                            run,
                            options,
                        ),
                    }
                }
            };
            if let Some(written) = written? {
                summary.files += 1;
                summary.bytes += written;
            }
            run.entry_done();
        }
        // The second reading must end where the first did.
        match tr.next() {
            Ok(None) if !self.cut => read_rest(tr.into_inner(), run, options),
            Ok(None) => Err(Error::global(ErrorKind::Changed)),
            Ok(Some(h)) => Err(Error::new(
                entries.len() as u64,
                &h.name,
                ErrorKind::Changed,
            )),
            Err(e) if self.cut => cut_short(entries, ErrorKind::Tar(e), run),
            Err(e) => Err(Error::global(ErrorKind::Tar(e))),
        }
    }
}

/// The bytes the second reading is to write: the files' data, and with
/// [`Links::AsFile`] the targets of symbolic links and the copies of hard
/// links, which tar's sizes do not count.
pub(crate) fn bytes_to_write<S>(
    entries: &[Entry<S>],
    items: &[Item],
    kept: &std::collections::HashSet<u64>,
    plans: &HashMap<u64, LinkPlan>,
    options: &Options,
) -> u64 {
    // What each file written so far holds, for the copies after it.
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;
    for entry in entries {
        let Some(item) = entry.item.map(|at| &items[at]) else {
            continue;
        };
        let Ok(name) = &item.name else {
            continue;
        };
        if !kept.contains(&item.index) {
            continue;
        }
        let bytes = match (item.kind, plans.get(&item.index)) {
            (Kind::File, _) => item.size,
            (Kind::Link, Some(LinkPlan::SymlinkAsFile)) => entry.target.len() as u64,
            (Kind::HardLink, Some(LinkPlan::Hard(target))) if options.links == Links::AsFile => {
                sizes.get(&fold(target)).copied().unwrap_or(0)
            }
            _ => 0,
        };
        sizes.insert(fold(&name.components), bytes);
        total = total.saturating_add(bytes);
    }
    total
}

/// Writes `item` as a file of `size` bytes, if they are known, whose data `data`
/// writes into it, then its time and permissions: the bytes `data` says it wrote.
/// A file whose data fails is not left, unless it is damaged and
/// [`Options::on_damaged`](crate::extract::Options::on_damaged) says to go on:
/// none if it is left out, or the bytes kept of it.
pub(crate) fn write_with<T: Target>(
    item: &Item,
    size: Option<u64>,
    destination: &T,
    run: &Run<'_>,
    options: &Options,
    data: impl FnOnce(&mut Counted<T::File<'_>>) -> Result<u64, ErrorKind>,
) -> Result<Option<u64>, Error> {
    let error = |kind| item.error(kind);
    let components = &item
        .name
        .as_ref()
        .map_err(|e| error(ErrorKind::Name(*e)))?
        .components;
    let file = destination
        .create_file(item, components, size, options)
        .map_err(error)?;
    let mut file = Counted { file, len: 0 };
    let failed = match data(&mut file) {
        Ok(written) => match destination.finish_file(file.file, item, options) {
            Ok(()) => return Ok(Some(written)),
            Err(kind) => kind,
        },
        Err(kind) => match run.decide(item, kind) {
            Ok((OnDamaged::Keep, damage)) => {
                destination.damaged(&damage);
                let kept = file.len;
                match destination.finish_file(file.file, item, options) {
                    Ok(()) => {
                        run.damaged(damage, Some(kept));
                        return Ok(Some(kept));
                    }
                    Err(kind) => kind,
                }
            }
            Ok((_, damage)) => {
                destination.damaged(&damage);
                destination.remove_file(components);
                run.damaged(damage, None);
                return Ok(None);
            }
            Err(e) => {
                destination.remove_file(components);
                return Err(e);
            }
        },
    };
    destination.remove_file(components);
    Err(error(failed))
}

/// Writes `item` as a file of the `size` bytes of `r`, at most `remaining` in
/// all, then its time and permissions: the bytes written. With `holes`, what
/// reads as zeros is not written where the target has holes: the file is new or
/// emptied, so it reads as zeros, and takes no room where the file system has
/// holes. A file whose data fails is not left.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_from<T: Target>(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    destination: &T,
    remaining: u64,
    holes: bool,
    run: &Run<'_>,
    options: &Options,
) -> Result<Option<u64>, Error> {
    write_with(item, Some(size), destination, run, options, |file| {
        write_into(r, size, file, remaining, holes, run, options)
    })
}

fn write_into(
    r: &mut impl Read,
    size: u64,
    file: &mut impl TargetFile,
    remaining: u64,
    holes: bool,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let limits = &options.limits;
    let holes = holes && file.has_holes();
    let mut written: u64 = 0;
    // Zeros not written yet, which the next write goes past.
    let mut pending: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        run.check()?;
        let n = match r.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ErrorKind::Tar(crate::tar::Error::from(e))),
        };
        written += n as u64;
        if written > limits.max_entry_size {
            return Err(ErrorKind::EntryTooLarge);
        }
        if written > remaining {
            return Err(ErrorKind::TotalTooLarge);
        }
        if written > size {
            return Err(ErrorKind::SizeMismatch);
        }
        if holes && buffer[..n].iter().all(|&byte| byte == 0) {
            pending += n as u64;
        } else {
            if pending > 0 {
                if i64::try_from(pending).is_err() {
                    return Err(ErrorKind::SizeMismatch);
                }
                file.skip(pending).map_err(ErrorKind::Io)?;
                pending = 0;
            }
            file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        }
        run.wrote(n as u64);
    }
    if written != size {
        return Err(ErrorKind::SizeMismatch);
    }
    if pending > 0 {
        // Zeros to the end: the file's length says so.
        file.set_len(written).map_err(ErrorKind::Io)?;
    }
    Ok(written)
}

/// Writes `item` as a copy of the file at `target`, for a hard link with
/// [`Links::AsFile`]: its bytes count as written.
pub(crate) fn copy_of<T: Target>(
    destination: &T,
    target: &[String],
    item: &Item,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<Option<u64>, Error> {
    let (mut source, size) = destination
        .open_file(target)
        .map_err(|kind| item.error(kind))?;
    write_from(
        &mut source,
        item,
        size,
        destination,
        remaining,
        false,
        run,
        options,
    )
}
