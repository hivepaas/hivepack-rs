//! Extracting a 7z archive that `hivepack::sevenz` opened.
//!
//! A 7z archive lists all its entries in its headers, as a ZIP archive
//! does, so every entry is checked before anything is written. Its data is
//! in folders, streams that may each hold many files (a solid block), read
//! once from start to end: the files are written in the archive's order as
//! their folder is decoded, each checked against its CRC when its data
//! ends, and each folder's checks made when its last file is read.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::sevenz::{Archive, Entry, Files};

use crate::extract::destination::Target;
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::{NameError, check_name, link_on_the_way, link_target, prepare};
use crate::extract::plan::{Item, Kind, Links, Names, OnRefused, Options, check, fold};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::write_with;
use crate::extract::zip::{Summary, open_destination, set_dir_times};

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
    let name = if String::from_utf16(&entry.name_utf16).is_err() {
        Err(NameError::NotUtf8)
    } else {
        // 7-Zip writes `/` between components on every system, and keeps
        // a `\` of a Unix name as it is.
        let prepared = prepare(
            &entry.name,
            options.backslash_separator,
            options.names == Names::Sanitize,
        );
        check_name(prepared.as_bytes())
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
        name,
        kind,
        size,
        compressed,
        // Folders do not share packed streams: no two files' data overlap.
        data: None,
        mode: unix_mode.map(|mode| mode & 0o7777),
        mtime: entry.mtime.and_then(system_time),
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

/// The links to create, with [`Links::Inside`]: their targets read, which
/// takes decoding the folders up to the last link, and checked to stay
/// inside the destination and not to pass through another link of the
/// archive. Those refused and skipped go to `skipped`.
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

    let mut links = Vec::new();
    for (item, read) in targets {
        let Ok(name) = &item.name else {
            continue;
        };
        let parent = &name.components[..name.components.len().saturating_sub(1)];
        let checked = read.and_then(|target| {
            let resolved = link_target(&target, parent).map_err(ErrorKind::LinkTarget)?;
            // A link on the way, which the system would follow.
            let link_at = |walked: &[String]| paths.get(&fold(walked)).copied();
            if let Some(other) = link_on_the_way(&target, parent, link_at) {
                return Err(ErrorKind::LinkChain { other });
            }
            let to_dir = dirs.contains_key(&fold(&resolved));
            // It was resolved, so it is UTF-8.
            let target = String::from_utf8_lossy(&target).into_owned();
            Ok((target, to_dir))
        });
        match (checked, options.on_refused) {
            (Ok((target, to_dir)), _) => links.push(Link {
                item,
                target,
                to_dir,
            }),
            (
                Err(kind @ (ErrorKind::LinkTarget(_) | ErrorKind::LinkChain { .. })),
                OnRefused::Skip,
            ) => skipped.push(item.error(kind)),
            (Err(kind), _) => return Err(item.error(kind)),
        }
    }
    Ok(links)
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
    extract_into(archive, || open_destination(destination, options), options)
}

/// Extracts `archive` into `sink`, with the checks and in the order of
/// [`extract_7z`], each folder decoded once: see [`Sink`].
pub fn extract_7z_to<R: Read + Seek>(
    archive: &mut Archive<R>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    extract_into(archive, || Ok(state.target(options)), options)
}

/// [`extract_7z`] into the target `make` makes, once the archive is checked.
fn extract_into<R: Read + Seek, T: Target>(
    archive: &mut Archive<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
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
    for index in 0..n {
        run.check().map_err(Error::global)?;
        items.push(item(&archive.entry(index), &folders, options));
    }
    let (kept, mut skipped) = check(&items, options)?;
    let links = match options.links {
        Links::Inside => links(archive, &kept, &run, options, &mut skipped)?,
        _ => Vec::new(),
    };
    // Links to create are written after the rest; with `AsFile` they are
    // files.
    let created_later = |item: &Item| item.kind == Kind::Link && options.links == Links::Inside;
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
        ..Summary::default()
    };
    write_entries(
        archive,
        &items,
        &written_now,
        &destination,
        &run,
        options,
        &mut summary,
    )?;
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
    Ok(summary)
}

/// The directories and files of `written_now`, in the archive's order, the
/// folders decoded once from start to end; the last folder's checks made,
/// whether its last files were written or skipped.
fn write_entries<R: Read + Seek, T: Target>(
    archive: &mut Archive<R>,
    items: &[Item],
    written_now: &HashSet<u64>,
    destination: &T,
    run: &Run<'_>,
    options: &Options,
    summary: &mut Summary,
) -> Result<(), Error> {
    let mut files = archive.files();
    // Whether the last file written was damaged, and gone on from.
    let mut gone_on = false;
    // The files of a folder whose data failed, after what failed, and why.
    let mut lost: Option<(std::ops::Range<usize>, crate::sevenz::Error)> = None;
    for item in items {
        run.check().map_err(Error::global)?;
        let index = item.index as usize;
        if let Some((range, e)) = &lost
            && range.contains(&index)
        {
            // Nothing of it can be read: left out, unless to stop.
            if written_now.contains(&item.index) && item.kind != Kind::Dir {
                let (_, damage) = run.decide(item, ErrorKind::SevenZip(*e))?;
                run.damaged(damage, None);
                run.entry_done();
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
                    let (_, damage) = run.decide(item, ErrorKind::SevenZip(e))?;
                    run.damaged(damage, None);
                    run.entry_done();
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
            summary.directories += 1;
            run.entry_done();
            continue;
        }
        let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
        let before = run.damaged_count();
        let written = write_with(item, Some(item.size), destination, run, options, |file| {
            write_data(&mut files, item, file, remaining, run, options)
        })?;
        gone_on = run.damaged_count() > before;
        if let Some(written) = written {
            summary.files += 1;
            summary.bytes += written;
        }
        run.entry_done();
    }
    // Past the last file: its folder's checks, if it was skipped; none to make
    // of a folder gone on from.
    match files.next() {
        Ok(_) => Ok(()),
        Err(_) if gone_on => Ok(()),
        Err(e) => Err(Error::global(ErrorKind::SevenZip(e))),
    }
}

/// Writes the current file of `files` into `file`, for `item`, at most
/// `remaining` bytes in all: the bytes written. Its data is read to its end,
/// where its CRC is checked.
fn write_data<R: Read + Seek>(
    files: &mut Files<'_, R>,
    item: &Item,
    file: &mut impl Write,
    remaining: u64,
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
        if written > remaining {
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
