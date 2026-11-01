//! Extracting a tar archive that `hivepack-tar` reads.
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
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hivepack_tar::{
    Header, Reader, TYPE_BLOCK, TYPE_CHAR, TYPE_DIR, TYPE_FIFO, TYPE_LINK, TYPE_SYMLINK,
    TYPE_X_GLOBAL_HEADER, Time,
};

use crate::destination::Destination;
use crate::error::{Error, ErrorKind};
use crate::name::{Name, NameError, check_name, link_on_the_way, link_target, prepare};
use crate::plan::{Item, Kind, Links, Names, OnRefused, Options, check, fold};
use crate::progress::Run;
use crate::zip::{Summary, set_dir_times, set_modified, set_permissions};

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
    if raw.iter().any(u8::is_ascii_control) {
        return Some(Err(NameError::Control));
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
            None => return Some(Err(NameError::NotUtf8)),
        },
    };
    while let Some(rest) = text.strip_prefix("./") {
        text = rest.trim_start_matches('/');
    }
    if text.is_empty() || text == "." {
        return None;
    }
    let prepared = prepare(
        text,
        options.backslash_separator,
        options.names == Names::Sanitize,
    );
    Some(check_name(prepared.as_bytes()))
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
fn read_headers<R: Read>(
    r: R,
    run: &Run<'_>,
    options: &Options,
) -> Result<(Vec<Entry<Seen>>, Vec<Item>), Error> {
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
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind: ErrorKind::Tar(e),
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
            _ => name_of(&h.name, options),
        };
        let Some(name) = name else {
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
    Ok((entries, items))
}

/// After the archive's end, the rest of the stream, read to its end: a
/// compressor checks its data there (gzip's and bzip2's CRC-32, xz's and
/// zstd's checks), and an age file's last chunk is authenticated, as GNU
/// tar reads its compressor's output to the end. The tar reader stops at
/// the archive's end, which comes before. A compressed stream can go on
/// far past it: what is read is limited to
/// [`Limits::max_total_size`](crate::Limits::max_total_size), or 1 MiB if
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

/// The links' plans, checked: a symbolic link's target must stay inside
/// and not pass through another link (with [`Links::Inside`]); a hard
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
                    link_target(&entry.target, parent)
                        .map_err(ErrorKind::LinkTarget)
                        .and_then(|resolved| {
                            // A link on the way, which the system would follow.
                            let link_at = |walked: &[String]| symlinks.get(&fold(walked)).copied();
                            if let Some(other) = link_on_the_way(&entry.target, parent, link_at) {
                                return Err(ErrorKind::LinkChain { other });
                            }
                            let to_dir = dirs.contains_key(&fold(&resolved));
                            Ok(LinkPlan::Symlink(
                                String::from_utf8_lossy(&entry.target).into_owned(),
                                to_dir,
                            ))
                        })
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
        match (checked, options.on_refused) {
            (Ok(plan), _) => {
                plans.insert(item.index, plan);
            }
            (Err(kind), OnRefused::Skip) => skipped.push(item.error(kind)),
            (Err(kind), OnRefused::Stop) => return Err(item.error(kind)),
        }
    }
    Ok(plans)
}

/// Extracts the tar archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`.
///
/// `open` is called twice, and must give the same archive each time: the
/// first reading checks every entry before anything is written, as
/// [`extract_zip`](crate::extract_zip) does (names, the same path twice,
/// links, the sizes against the limits), and the second writes them, each
/// header compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs). For a compressed or encrypted archive, `open` decompresses or
/// decrypts it again (`hivepack_open::Opener` does). Each reading goes on
/// past the archive's end to the end of the stream, so that a compressor's
/// check there, or age's last chunk, fails the first reading before
/// anything is written ([`ErrorKind::Io`]); what follows the end is
/// limited to [`Limits::max_total_size`](crate::Limits::max_total_size),
/// or 1 MiB if that is less.
///
/// Besides ZIP's rules: a leading `./` is dropped from names, and `./`
/// itself, the archive's root, is not an entry; a hard link is created
/// only to a file extracted before it ([`ErrorKind::HardLinkTarget`]
/// otherwise), as a copy with [`Links::AsFile`]; devices and FIFOs are
/// refused ([`ErrorKind::Special`]); global PAX headers and GNU volume
/// labels are the archive's, not entries. A sparse file's holes stay holes
/// where the file system has them, and count against the limits.
pub fn extract_tar<R: Read, F: FnMut() -> io::Result<R>>(
    mut open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }

    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let (entries, items) = read_headers(first, &run, options)?;
    let (kept, mut skipped) = check(&items, options)?;
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

    let destination = Destination::open(destination, options.origin.as_ref())
        .map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut summary = Summary {
        skipped,
        ..Summary::default()
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut tr = Reader::new(second);
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
            destination.directory(components).map_err(error)?;
            summary.directories += 1;
            run.entry_done();
            continue;
        }
        let (last, parents) = components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
        let dir = destination.directory(parents).map_err(error)?;
        match plans.get(&item.index) {
            Some(LinkPlan::Hard(target)) if options.links != Links::AsFile => {
                let (target_last, target_parents) = target
                    .split_last()
                    .ok_or_else(|| error(ErrorKind::HardLinkTarget))?;
                let target_dir = destination.directory(target_parents).map_err(error)?;
                Destination::hard_link(&target_dir, target_last, &dir, last).map_err(error)?;
                summary.files += 1;
                run.entry_done();
                continue;
            }
            _ => {}
        }
        let file = Destination::create_file(&dir, last, options.overwrite).map_err(error)?;
        let remaining = limits.max_total_size.saturating_sub(summary.bytes);
        let written = match plans.get(&item.index) {
            Some(LinkPlan::SymlinkAsFile) => write_from(
                &mut &entry.target[..],
                item,
                entry.target.len() as u64,
                file,
                remaining,
                false,
                &run,
                options,
            ),
            Some(LinkPlan::Hard(target)) => {
                // A copy of the file it names, with Links::AsFile.
                copy_of(&destination, target, item, file, remaining, &run, options)
            }
            _ => {
                let holes = tr.is_sparse();
                write_from(
                    &mut tr, item, item.size, file, remaining, holes, &run, options,
                )
            }
        };
        match written {
            Ok(written) => {
                summary.files += 1;
                summary.bytes += written;
                run.entry_done();
            }
            Err(kind) => {
                // A file whose data failed is not left.
                let _ = dir.remove_file(last);
                return Err(error(kind));
            }
        }
    }
    // The second reading must end where the first did.
    match tr.next() {
        Ok(None) => {}
        Ok(Some(h)) => {
            return Err(Error::new(
                entries.len() as u64,
                &h.name,
                ErrorKind::Changed,
            ));
        }
        Err(e) => return Err(Error::global(ErrorKind::Tar(e))),
    }
    read_rest(tr.into_inner(), &run, options)?;

    for &item in kept.iter().filter(|item| created_later(item)) {
        let error = |kind| item.error(kind);
        let (Ok(name), Some(LinkPlan::Symlink(target, to_dir))) =
            (&item.name, plans.get(&item.index))
        else {
            continue;
        };
        let (last, parents) = name
            .components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
        run.check().map_err(error)?;
        let dir = destination.directory(parents).map_err(error)?;
        Destination::symlink(&dir, last, target, *to_dir).map_err(error)?;
        summary.links += 1;
        run.entry_done();
    }

    set_dir_times(&destination, &kept, &run)?;
    Ok(summary)
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

/// Writes `size` bytes of `r` into `file`, for `item`, at most `remaining`
/// in all, then its time and permissions: the bytes written. With `holes`, what
/// reads as zeros is not written: the file is new or emptied, so it reads as
/// zeros, and takes no room where the file system has holes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_from(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    file: cap_std::fs::File,
    remaining: u64,
    holes: bool,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let limits = &options.limits;
    let mut file = file.into_std();
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
            Err(e) => return Err(ErrorKind::Tar(hivepack_tar::Error::from(e))),
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
                let ahead = i64::try_from(pending).map_err(|_| ErrorKind::SizeMismatch)?;
                file.seek(SeekFrom::Current(ahead)).map_err(ErrorKind::Io)?;
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
    finish_file(&file, item, options)?;
    Ok(written)
}

/// Writes a copy of the file at `target` into `file`, for a hard link
/// with [`Links::AsFile`]: its bytes count as written.
pub(crate) fn copy_of(
    destination: &Destination<'_>,
    target: &[String],
    item: &Item,
    file: cap_std::fs::File,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let (last, parents) = target.split_last().ok_or(ErrorKind::HardLinkTarget)?;
    let dir = destination.directory(parents)?;
    let source = Destination::open_file(&dir, last)?;
    let size = source.metadata().map_err(ErrorKind::Io)?.len();
    write_from(
        &mut source.into_std(),
        item,
        size,
        file,
        remaining,
        false,
        run,
        options,
    )
}

/// A file's mark of origin, time and permissions, once its data is
/// written.
pub(crate) fn finish_file(
    file: &std::fs::File,
    item: &Item,
    options: &Options,
) -> Result<(), ErrorKind> {
    // The mark first: writing a stream can change the file's time.
    if let Some(origin) = &options.origin {
        origin.write_file(file).map_err(ErrorKind::Origin)?;
    }
    if let Some(mtime) = item.mtime {
        set_modified(file, mtime)?;
    }
    set_permissions(file, item.mode, options.permissions)?;
    let mut file = file;
    file.flush().map_err(ErrorKind::Io)
}
