//! Extracting a ZIP archive that `hivepack::zip` opened.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::zip::{Archive, Flags, ReadAt, opsys, stat};

use crate::extract::destination::{Destination, Target};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::{NameError, link_on_the_way, link_target};
use crate::extract::plan::{Item, Kind, Links, OnRefused, Options, Permissions, check, fold};
use crate::extract::plan::{Renamed, named, settle, skips_links};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::write_with;

/// What was extracted.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Summary {
    pub files: u64,
    pub directories: u64,
    pub links: u64,
    /// Bytes written.
    pub bytes: u64,
    /// The entries left out with [`OnRefused::Skip`], and why.
    pub skipped: Vec<Error>,
    /// The entries extracted under another name, as
    /// [`Options::on_unnamable`](crate::extract::Options::on_unnamable) said.
    pub renamed: Vec<Renamed>,
    /// The entries whose data was damaged, gone on from with
    /// [`Options::on_damaged`](crate::extract::Options::on_damaged), in the
    /// order met.
    pub damaged: Vec<Damaged>,
}

/// An entry whose data was damaged, gone on from.
#[derive(Debug)]
#[non_exhaustive]
pub struct Damaged {
    /// The entry, and what was wrong with its data.
    pub error: Error,
    /// The bytes of its data kept, with [`OnDamaged::Keep`](crate::extract::OnDamaged::Keep);
    /// none if it was left out.
    pub kept: Option<u64>,
}

/// The type bits of a Unix mode.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// The longest link target read, as Linux's `PATH_MAX`.
const MAX_LINK_TARGET: usize = 4096;

/// What the archive says of entry `i`.
fn item<R: ReadAt>(archive: &Archive<R>, i: u64, options: &Options) -> Result<Item, Error> {
    let archive_error = |e| Error {
        index: Some(i),
        name: None,
        kind: ErrorKind::Archive(e),
    };
    // The name as the archive has it, for errors and for the control
    // characters a CP437 name decodes to symbols (0x01 to ☺): an extractor
    // that takes the bytes as they are sees them.
    let raw_name = archive
        .get_name(i, Flags::ENC_RAW)
        .map_err(archive_error)?
        .to_vec();
    // The name as it is written: UTF-8, or decoded from CP437, or as the
    // caller's decoder says.
    let decoded = archive.get_name(i, Flags::NONE).map_err(archive_error)?;
    let as_read = std::str::from_utf8(decoded).ok();
    let text = match &options.decode_names {
        Some(decoder) if std::str::from_utf8(&raw_name).is_err() => {
            decoder.decode(&raw_name, as_read)
        }
        _ => as_read.map(str::to_owned),
    };
    let lossy = || String::from_utf8_lossy(&raw_name).into_owned();
    let (text, name) = if raw_name.iter().any(u8::is_ascii_control) {
        (text.unwrap_or_else(lossy), Err(NameError::Control))
    } else {
        match text {
            Some(text) => named(&text, options),
            None => (lossy(), Err(NameError::NotUtf8)),
        }
    };
    let error = |e| Error::new(i, &raw_name, ErrorKind::Archive(e));
    let st = archive.stat_index(i, Flags::NONE).map_err(error)?;
    let (system, attributes) = archive
        .file_get_external_attributes(i, Flags::NONE)
        .map_err(error)?;

    // Unix keeps the mode in the high half of the external attributes.
    let unix_mode = (system == opsys::UNIX).then_some(attributes >> 16);
    let named_dir = name.as_ref().is_ok_and(|name| name.is_dir);
    // A device, FIFO or socket in a ZIP archive is only its mode with
    // data, as Info-ZIP's zip records what it reads from a pipe: it is
    // written as a file, never created as what the mode says.
    let kind = match unix_mode.map(|mode| mode & S_IFMT) {
        Some(S_IFLNK) => Kind::Link,
        Some(S_IFDIR) => Kind::Dir,
        _ if named_dir => Kind::Dir,
        _ => Kind::File,
    };
    let data = if st.valid & stat::COMP_SIZE != 0 && st.comp_size > 0 {
        let start = archive.file_get_offset(i).map_err(error)?;
        Some(start..start.saturating_add(st.comp_size))
    } else {
        None
    };
    let mtime = if st.valid & stat::MTIME == 0 {
        None
    } else if st.mtime >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(st.mtime as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(st.mtime.unsigned_abs()))
    };
    Ok(Item {
        index: i,
        raw_name,
        text,
        name,
        kind,
        size: if st.valid & stat::SIZE != 0 {
            st.size
        } else {
            0
        },
        compressed: st.comp_size,
        data,
        mode: unix_mode.map(|mode| mode & 0o7777),
        mtime,
    })
}

/// A link to create, once every other entry is written.
struct Link<'a> {
    item: &'a Item,
    target: String,
    to_dir: bool,
}

/// Reads the data of `item` with `f`, a piece at a time, checked as any
/// entry's data is, and stopping if `run` is to stop: what `f` returns, or
/// why it stopped.
fn read_entry<R: ReadAt>(
    archive: &Archive<R>,
    item: &Item,
    run: &Run<'_>,
    options: &Options,
    mut f: impl FnMut(&[u8]) -> Result<(), ErrorKind>,
) -> Result<(), ErrorKind> {
    let mut zf = archive
        .fopen_index_encrypted(item.index, Flags::NONE, options.password.as_deref())
        .map_err(ErrorKind::Archive)?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        run.check()?;
        let n = match zf.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                return Err(match zf.fclose() {
                    Err(error) => ErrorKind::Archive(error),
                    Ok(()) => ErrorKind::Io(e),
                });
            }
        };
        f(&buffer[..n])?;
    }
    zf.fclose().map_err(ErrorKind::Archive)
}

/// The data of a link entry: its target, at most [`MAX_LINK_TARGET`]
/// bytes.
fn read_target<R: ReadAt>(
    archive: &Archive<R>,
    item: &Item,
    run: &Run<'_>,
    options: &Options,
) -> Result<Vec<u8>, ErrorKind> {
    let mut target = Vec::new();
    read_entry(archive, item, run, options, |piece| {
        target.extend_from_slice(piece);
        if target.len() > MAX_LINK_TARGET {
            return Err(ErrorKind::LinkTarget(NameError::TooLong));
        }
        Ok(())
    })?;
    Ok(target)
}

/// The links to create, with [`Links::Inside`]: their targets read, and
/// checked to stay inside the destination and not to pass through another
/// link of the archive. Those refused and skipped go to `skipped`.
fn links<'a, R: ReadAt>(
    archive: &Archive<R>,
    kept: &[&'a Item],
    run: &Run<'_>,
    options: &Options,
    skipped: &mut Vec<Error>,
) -> Result<Vec<Link<'a>>, Error> {
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
    let mut links = Vec::new();
    for &item in kept.iter().filter(|item| item.kind == Kind::Link) {
        let Ok(name) = &item.name else {
            continue;
        };
        let parent = &name.components[..name.components.len().saturating_sub(1)];
        let checked = read_target(archive, item, run, options).and_then(|target| {
            let resolved =
                link_target(&target, parent, options.checks()).map_err(ErrorKind::LinkTarget)?;
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
        match (checked, skips_links(options)) {
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

/// Extracts `archive` into `destination`, which is created if it is not
/// there, with `options`.
///
/// Every entry is checked before anything is written: its name (see
/// [`check_name`](crate::extract::check_name)), that no two entries name the same path (ignoring
/// case), links (refused unless [`Options::links`] says otherwise, their
/// targets read and checked first), that no two share
/// compressed data, and what the archive says of the sizes against the
/// limits. Then each is written, its data counted against the limits as it
/// comes and checked when it ends (the CRC-32, or WinZip AES's
/// authentication code); a file whose data fails is removed, and the
/// extraction stops there. Links are created last, then the directories
/// get their times. Nothing is overwritten unless [`Options::overwrite`]
/// says so, and nothing is written through a link.
///
/// Files and directories get the time the archive has, and files on Unix
/// their permission bits, as [`Options::permissions`] says.
///
/// [`Options::time_limit`] and [`Options::cancel`] stop the extraction
/// between pieces of data and between entries; a file cut off is removed,
/// and what was written before stays. [`Options::progress`] is told how
/// far it is.
///
/// Open the archive with
/// [`OpenFlags::CHECKCONS`](crate::zip::OpenFlags::CHECKCONS), so that
/// local headers that disagree with the central directory are refused.
pub fn extract_zip<R: ReadAt>(
    archive: &Archive<R>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(archive, || open_destination(destination, options), options)
}

/// Extracts `archive` into `sink`, with the checks and in the order of
/// [`extract_zip`], whose limits count what is given to it: see [`Sink`].
pub fn extract_zip_to<R: ReadAt>(
    archive: &Archive<R>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(archive, || Ok(state.target(options)), options)
}

/// The folder at `destination`, created if it is not there, for an extraction to
/// write into.
pub(crate) fn open_destination<'a>(
    destination: &Path,
    options: &'a Options,
) -> Result<Destination<'a>, Error> {
    Destination::open(destination, options.origin.as_ref())
        .map_err(|e| Error::global(ErrorKind::Io(e)))
}

/// [`extract_zip`] into the target `make` makes, once the archive is checked.
fn extract_into<R: ReadAt, T: Target>(
    archive: &Archive<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);
    let n = archive.get_num_entries(Flags::NONE);
    if n > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let mut items = (0..n)
        .map(|i| {
            run.check().map_err(Error::global)?;
            item(archive, i, options)
        })
        .collect::<Result<Vec<Item>, Error>>()?;
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    let links = match options.links {
        Links::Inside => links(archive, &kept, &run, options, &mut skipped)?,
        _ => Vec::new(),
    };
    // Links to create are written after the rest; the others are files.
    let created_later = |item: &Item| item.kind == Kind::Link && options.links == Links::Inside;
    run.start(
        kept.iter().filter(|item| !created_later(item)).count() as u64 + links.len() as u64,
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
    for &item in &kept {
        let Ok(name) = &item.name else {
            continue;
        };
        let error = |kind| item.error(kind);
        let components = &name.components;
        if created_later(item) {
            continue;
        }
        run.check().map_err(error)?;
        if item.kind == Kind::Dir {
            destination.directory(item, components).map_err(error)?;
            summary.directories += 1;
            run.entry_done();
            continue;
        }
        let remaining = limits.max_total_size.saturating_sub(summary.bytes);
        let written = write_with(item, Some(item.size), &destination, &run, options, |file| {
            write_file(archive, item, file, remaining, &run, options)
        })?;
        if let Some(written) = written {
            summary.files += 1;
            summary.bytes += written;
        }
        run.entry_done();
    }

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

/// The directories' times, the deepest first, once nothing more is
/// written in them.
pub(crate) fn set_dir_times<T: Target>(
    destination: &T,
    kept: &[&Item],
    run: &Run<'_>,
) -> Result<(), Error> {
    let mut dirs: Vec<(&[String], std::time::SystemTime, &Item)> = kept
        .iter()
        .filter(|item| item.kind == Kind::Dir)
        .filter_map(|&item| match (&item.name, item.mtime) {
            (Ok(name), Some(mtime)) => Some((name.components.as_slice(), mtime, item)),
            _ => None,
        })
        .collect();
    dirs.sort_by_key(|(components, _, _)| std::cmp::Reverse(components.len()));
    for (components, mtime, item) in dirs {
        if components.is_empty() {
            continue;
        }
        let error = |kind| item.error(kind);
        run.check().map_err(error)?;
        destination.set_time(components, mtime).map_err(error)?;
    }
    Ok(())
}

/// Writes the data of `item` into `file`, at most `remaining` bytes in
/// all: the bytes written.
fn write_file<R: ReadAt>(
    archive: &Archive<R>,
    item: &Item,
    file: &mut impl Write,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let limits = &options.limits;
    let mut written: u64 = 0;
    read_entry(archive, item, run, options, |piece| {
        written += piece.len() as u64;
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
        file.write_all(piece).map_err(ErrorKind::Io)?;
        run.wrote(piece.len() as u64);
        Ok(())
    })?;
    if written != item.size {
        return Err(ErrorKind::SizeMismatch);
    }
    Ok(written)
}

/// Sets `file`'s modification time, unless the system cannot hold it: a
/// 32-bit system's `time_t` ends in January 2038, and a file dated after
/// keeps the time it is written at, rather than stop the extraction.
pub(crate) fn set_modified(
    file: &std::fs::File,
    mtime: std::time::SystemTime,
) -> Result<(), ErrorKind> {
    match file.set_times(std::fs::FileTimes::new().set_modified(mtime)) {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        result => result.map_err(ErrorKind::Io),
    }
}

/// The permission bits of `mode`, as `permissions` says, on Unix.
#[cfg(unix)]
pub(crate) fn set_permissions(
    file: &std::fs::File,
    mode: Option<u32>,
    permissions: Permissions,
) -> Result<(), ErrorKind> {
    use std::os::unix::fs::PermissionsExt;
    let mode = match (mode, permissions) {
        // No setuid, setgid or sticky bit, no writing by group or others,
        // and reading and writing by the owner.
        (Some(mode), Permissions::Masked) => (mode & 0o755) | 0o600,
        (Some(mode), Permissions::Preserve) => mode & 0o777,
        (None, _) | (_, Permissions::Ignore) => return Ok(()),
    };
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(ErrorKind::Io)
}

/// Windows has no permission bits.
#[cfg(not(unix))]
pub(crate) fn set_permissions(
    _file: &std::fs::File,
    _mode: Option<u32>,
    _permissions: Permissions,
) -> Result<(), ErrorKind> {
    Ok(())
}
