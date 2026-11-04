//! Extracting an ISO 9660 image that `hivepack::iso` reads.
//!
//! An image is read in order, as libarchive reads it: each directory's
//! records when the image gets to them, each file's data where it is. As
//! for tar, there is nothing to read the entries from before the data, so
//! the image is read twice: once for the headers, the data skipped, and
//! once to write, each header compared with the first reading's. The
//! caller gives a function that opens it again, which for a compressed
//! image (`.iso.xz`) decompresses it again.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::iso::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFSOCK, Format, Header, Reader,
};

use crate::extract::destination::{Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::plan::{Item, Kind, OnRefused, Options, check};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::{
    Entry, LinkPlan, bytes_to_write, copy_of, name_of, plan_links, read_rest, write_with,
};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// An entry's error, by its index and its path, if it has one.
fn entry_error(index: u64, h: &Header, kind: ErrorKind) -> Error {
    Error {
        index: Some(index),
        name: h.path.clone(),
        kind,
    }
}

/// Seconds since 1970 as a `SystemTime`.
fn system_time(secs: Option<i64>) -> Option<SystemTime> {
    let secs = secs?;
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// What the first reading found: the entries, those to extract, and the
/// errors of those refused for a warning, to skip.
type FirstReading = (Vec<Entry<Header>>, Vec<Item>, Vec<Error>);

/// The first reading: every header, and each file's data, read up to its
/// size and dropped, so that data cut short or damaged stops here, before
/// anything is written (reading past it would read it anyway, from an
/// input that cannot seek). Entries that come with a warning, which have
/// something missing, are refused.
fn read_headers<R: Read>(r: R, run: &Run<'_>, options: &Options) -> Result<FirstReading, Error> {
    let mut iso = Reader::new(r);
    let mut entries = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    loop {
        let index = entries.len() as u64;
        run.check().map_err(Error::global)?;
        let h = match iso.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind: ErrorKind::Iso(e),
                });
            }
        };
        // Every entry counts, as in tar.
        if entries.len() as u64 >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        // An image without Rock Ridge has no permissions: libarchive's
        // 0400 and 0700 are its own.
        let rock_ridge = iso.format() == Some(Format::Iso9660RockRidge);
        let mut entry = Entry {
            seen: h.clone(),
            item: None,
            target: Vec::new(),
        };
        if let Some(warning) = &h.warning {
            let error = entry_error(index, &h, ErrorKind::IsoEntry(warning.clone()));
            match options.on_refused {
                OnRefused::Stop => return Err(error),
                OnRefused::Skip => refused.push(error),
            }
            entries.push(entry);
            continue;
        }
        let raw = h.path.clone().unwrap_or_default();
        // The root directory, ".", is not an entry.
        let Some(name) = name_of(&raw, options) else {
            entries.push(entry);
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
        let size = match kind {
            Kind::File => h.size.unwrap_or(0),
            _ => 0,
        };
        entry.target = match kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        items.push(Item {
            index,
            raw_name: raw,
            name,
            kind,
            size,
            // zisofs compresses, a block at a time, but an image does not
            // say how much: the limits on sizes stand.
            compressed: size,
            data: None,
            mode: rock_ridge.then_some(h.mode & 0o7777),
            mtime: system_time(h.mod_time),
        });
        // The data, unless the checks are to stop it for its size.
        if kind == Kind::File && size <= options.limits.max_entry_size {
            check_data(&mut iso, size, run).map_err(|kind| entry_error(index, &h, kind))?;
        }
        entry.item = Some(items.len() - 1);
        entries.push(entry);
    }
    read_rest(iso.into_inner(), run, options)?;
    Ok((entries, items, refused))
}

/// Reads up to `size` bytes of the current entry's data, and drops them.
fn check_data(r: &mut impl Read, size: u64, run: &Run<'_>) -> Result<(), ErrorKind> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut left = size;
    while left > 0 {
        run.check()?;
        let want = buffer.len().min(left as usize);
        match r.read(&mut buffer[..want]) {
            // Zeros to the end (see write_data).
            Ok(0) => return Ok(()),
            Ok(n) => left -= n as u64,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(iso_error(e)),
        }
    }
    Ok(())
}

/// A read's error: the image's, or a warning that data is missing.
fn iso_error(e: io::Error) -> ErrorKind {
    match crate::iso::Error::from(e) {
        crate::iso::Error::Warning(w) => ErrorKind::IsoEntry(w),
        e => ErrorKind::Iso(e),
    }
}

/// Extracts the ISO 9660 image that `open` gives into `destination`,
/// which is created if it is not there, with `options`.
///
/// `open` is called twice, and must give the same image each time, as for
/// [`extract_tar`](crate::extract::extract_tar): the first reading checks every
/// entry before anything is written, the second writes them, each header
/// compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs). For a compressed image, `open` decompresses it again
/// (`hivepack::open::Opener` does). Each reading goes on to the end of the
/// stream.
///
/// The first reading reads each file's data too, which an input that
/// cannot seek reads to skip it anyway: data cut short or damaged (a
/// zisofs block that does not decompress) stops it before anything is
/// written.
///
/// Besides tar's rules: the root directory, `.`, is not an entry. An entry
/// that comes with a warning ([`crate::iso::Warning`]: a directory left
/// out with what it holds, a file past the image's end or whose data is
/// before its directory, a Joliet name that is not UTF-16) has something
/// missing, and is refused ([`ErrorKind::IsoEntry`]), or left out with
/// [`OnRefused::Skip`]. A hard link is to the entry before it, which
/// hivepack::iso gives as its target. An image without Rock Ridge has no
/// permissions, and its files get the system's defaults. A file's data is
/// written to its size, as libarchive's extraction writes it: zisofs leaves
/// out the blocks of zeros at a file's end, which come out as zeros.
pub fn extract_iso<R: Read, F: FnMut() -> io::Result<R>>(
    open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    extract_into(open, || open_destination(destination, options), options)
}

/// Extracts the ISO 9660 image that `open` gives into `sink`, with the checks and
/// in the order of [`extract_iso`], reading it twice as it does: see [`Sink`].
pub fn extract_iso_to<R: Read, F: FnMut() -> io::Result<R>>(
    open: F,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    extract_into(open, || Ok(state.target(options)), options)
}

/// [`extract_iso`] into the target `make` makes, once the image is checked.
fn extract_into<R: Read, F: FnMut() -> io::Result<R>, T: Target>(
    mut open: F,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);

    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let (entries, items, refused) = read_headers(first, &run, options)?;
    let (kept, mut skipped) = check(&items, options)?;
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
    let created_later = |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
    run.start(
        kept_indexes.len() as u64,
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options),
    );

    let destination = make()?;
    let mut summary = Summary {
        skipped,
        ..Summary::default()
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut iso = Reader::new(second);
    for (index, entry) in entries.iter().enumerate() {
        run.check().map_err(Error::global)?;
        let h = match iso.next() {
            Ok(Some(h)) => h,
            Ok(None) => return Err(Error::global(ErrorKind::Changed)),
            Err(e) => return Err(Error::global(ErrorKind::Iso(e))),
        };
        if h != entry.seen {
            return Err(entry_error(index as u64, &h, ErrorKind::Changed));
        }
        let Some(at) = entry.item else {
            continue;
        };
        let item = &items[at];
        if !kept_indexes.contains(&item.index) || created_later(item) {
            continue;
        }
        let Ok(name) = &item.name else {
            continue;
        };
        let error = |kind| item.error(kind);
        let components = &name.components;
        if item.kind == Kind::Dir {
            destination.directory(item, components).map_err(error)?;
            summary.directories += 1;
            run.entry_done();
            continue;
        }
        match plans.get(&item.index) {
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
        let written = match plans.get(&item.index) {
            Some(LinkPlan::SymlinkAsFile) => write_data(
                &mut &entry.target[..],
                item,
                entry.target.len() as u64,
                &destination,
                remaining,
                &run,
                options,
            ),
            Some(LinkPlan::Hard(target)) => {
                // A copy of the file it names, with Links::AsFile.
                copy_of(&destination, target, item, remaining, &run, options)
            }
            _ => write_data(
                &mut iso,
                item,
                item.size,
                &destination,
                remaining,
                &run,
                options,
            ),
        }?;
        summary.files += 1;
        summary.bytes += written;
        run.entry_done();
    }
    // The second reading must end where the first did.
    match iso.next() {
        Ok(None) => {}
        Ok(Some(h)) => {
            return Err(entry_error(entries.len() as u64, &h, ErrorKind::Changed));
        }
        Err(e) => return Err(Error::global(ErrorKind::Iso(e))),
    }
    read_rest(iso.into_inner(), &run, options)?;

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
    Ok(summary)
}

/// Writes `size` bytes of `r` into `file`, for `item`, at most `remaining`
/// in all, then its time and permissions: the bytes written. As
/// libarchive's extraction does, what `r` has past `size` is left, and a
/// file whose data ends before is made `size` long with zeros: zisofs
/// leaves out the blocks of zeros at a file's end, which libarchive does
/// not give, where the data of any other file is all there, or fails.
fn write_data<T: Target>(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    destination: &T,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, Error> {
    let limits = &options.limits;
    if size > limits.max_entry_size {
        return Err(item.error(ErrorKind::EntryTooLarge));
    }
    if size > remaining {
        return Err(item.error(ErrorKind::TotalTooLarge));
    }
    write_with(item, Some(size), destination, options, |file| {
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
            Ok(0) => {
                file.set_len(size).map_err(ErrorKind::Io)?;
                run.wrote(size - written);
                written = size;
                break;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(iso_error(e)),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}
