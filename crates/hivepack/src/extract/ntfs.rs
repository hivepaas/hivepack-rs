//! Extracting an NTFS file system that `hivepack::ntfs` reads.
//!
//! A file system is read by random access, as an ext one is: its tree is
//! walked first, every entry listed and every file's data reached for, and
//! every entry checked before anything is written; then the files are
//! written, their data read where it is.
//!
//! **What NTFS keeps and this does not give back is said rather than
//! guessed at.** A Windows volume holds four things nothing here can turn
//! into a file on this side: data NTFS compressed itself, data the
//! encrypting file system holds the key to, reparse points (a symbolic
//! link, a junction, a file kept through Windows' overlay filter), and the
//! streams beside a file. The first three are refused, each as its own
//! reason ([`crate::ntfs::Error`]), so a file that cannot come out whole
//! does not come out at all; the streams are left where they are, as
//! nothing outside Windows keeps them. The security descriptor every file
//! carries is not a Unix owner or mode and is not turned into one: what
//! the files get is [`Options::permissions`].

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::image::Disk;
use crate::ntfs::{Entry as Record, Ntfs, Time};

use crate::extract::destination::{Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::settle;
use crate::extract::plan::{Item, Kind, OnRefused, Options, check};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, copy_of, plan_links, write_with};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// An NTFS time as a `SystemTime`.
///
/// Unlike a FAT time, this is an instant: NTFS counts hundreds of
/// nanoseconds from 1601 in UTC, so there is nothing to choose and the
/// hundreds of nanoseconds are kept.
fn system_time(t: Time) -> Option<SystemTime> {
    let (seconds, nanoseconds) = t.unix();
    let at = if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))?
    };
    at.checked_add(Duration::from_nanos(u64::from(nanoseconds)))
}

/// What the walk found: the entries (each with its record, for its data),
/// those to extract, and the errors of those refused, to skip.
type Walk = (Vec<Entry<Option<Record>>>, Vec<Item>, Vec<Error>);

/// Walks the file system's tree, parents before what they hold, in the
/// order each directory holds its entries.
///
/// Files are kept to the master file table records they are: a record met
/// again under a second name is a hard link, which a Windows volume has
/// plenty of, and a directory met again is a chain leading back on itself,
/// which a hostile image can write and Windows cannot. It is refused
/// rather than followed for ever.
fn walk<D: Disk>(fs: &Ntfs<D>, run: &Run<'_>, options: &Options) -> Result<Walk, Error> {
    let mut entries: Vec<Entry<Option<Record>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    // The entry each record was first met as: a file's again is a hard
    // link to the first, which is what `Entry::links` greater than one
    // means; a directory's again is refused.
    let mut met: HashMap<u64, (u64, Vec<u8>)> = HashMap::new();

    let root = fs
        .read_root()
        .map_err(|e| Error::global(ErrorKind::Ntfs(e)))?;
    // Directories still to list, the next last: their entries, and the
    // path to them.
    let mut dirs: Vec<(Vec<Record>, Vec<u8>)> = vec![(root, Vec::new())];
    while let Some((listed, path)) = dirs.pop() {
        run.check().map_err(Error::global)?;
        let mut children = Vec::new();
        for record in listed {
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
            raw.extend_from_slice(record.name.as_bytes());
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
            // An entry of a directory is one name, not a path: Windows
            // allows neither a separator nor a NUL in one, so an entry
            // holding either did not come from Windows. Cut into
            // components by the rules that read an archive's paths, it
            // would be written somewhere other than where this file system
            // says it is.
            if record.name.as_bytes().contains(&b'/') || record.name.as_bytes().contains(&0) {
                refuse(ErrorKind::Name(NameError::Separator), &mut refused)?;
                entries.push(entry);
                continue;
            }
            let first = met.get(&record.record()).cloned();
            let kind = match (record.is_dir(), &first) {
                (true, Some(_)) => {
                    refuse(ErrorKind::DirectoryAgain, &mut refused)?;
                    entries.push(entry);
                    continue;
                }
                (true, None) => Kind::Dir,
                (false, Some(_)) => Kind::HardLink,
                (false, None) => Kind::File,
            };
            if kind == Kind::HardLink {
                entry.target = first.clone().map(|(_, path)| path).unwrap_or_default();
            }
            // That the data can be read at all, unless the checks are to
            // stop it for its size: data NTFS compressed or encrypted, a
            // reparse point, a file whose runs do not cover its length, and
            // one whose runs are in an attribute list are all refused here
            // rather than part way through writing a file. The flags of the
            // record say most of it; opening the stream is what tells a
            // file holding a compressed stream beside a plain one, and what
            // reads where the bytes are.
            if kind == Kind::File
                && record.size <= options.limits.max_entry_size
                && let Err(e) = record
                    .readable()
                    .and_then(|()| fs.file(&record).map(|_| ()))
            {
                refuse(ErrorKind::Ntfs(e), &mut refused)?;
                entries.push(entry);
                continue;
            }
            met.entry(record.record()).or_insert((index, raw.clone()));
            let (text, name) = named_of(&raw, options).unwrap_or_else(|| {
                (
                    String::from_utf8_lossy(&raw).into_owned(),
                    Err(NameError::Empty),
                )
            });
            let size = if kind == Kind::File { record.size } else { 0 };
            items.push(Item {
                index,
                raw_name: raw.clone(),
                text,
                name,
                kind,
                size,
                // Nothing is held back: a hole of a sparse file reads as
                // the zeros it stands for, and compressed data is refused
                // rather than decompressed, so what is read is what is
                // written.
                compressed: size,
                data: None,
                // NTFS keeps a security descriptor and not a Unix mode,
                // and one is not made up from the other: what the files
                // get is `Options::permissions`.
                mode: None,
                mtime: record.modified.and_then(system_time),
                // Nor an owner that means anything on this side, nor
                // extended attributes: the streams beside a file are not
                // attributes and are not written.
                owner: None,
                xattrs: Vec::new(),
            });
            entry.item = Some(items.len() - 1);
            if kind == Kind::Dir {
                match fs.read_dir(&record) {
                    Ok(inside) => children.push((inside, raw)),
                    Err(e) => {
                        // What the directory holds could not be read, and
                        // its own entry stands: a folder with nothing in
                        // it.
                        let error = Error::new(index, &raw, ErrorKind::Ntfs(e));
                        match options.on_refused {
                            OnRefused::Skip => refused.push(error),
                            OnRefused::Stop => return Err(error),
                        }
                    }
                }
            }
            entry.seen = Some(record);
            entries.push(entry);
        }
        // Depth first, in the order the directory holds its entries.
        dirs.extend(children.into_iter().rev());
    }
    Ok((entries, items, refused))
}

/// Extracts the NTFS file system `fs` into `destination`, which is created
/// if it is not there, with `options`.
///
/// The tree is walked first, parents before what they hold, in the order
/// each directory holds its entries: every file's data is reached for and
/// every entry checked as a ZIP archive's are, before anything is written.
/// What cannot be read is refused ([`ErrorKind::Ntfs`]): a file whose data
/// is compressed ([`crate::ntfs::Error::Compressed`]) or encrypted, a
/// reparse point, a file whose runs do not cover the length it says, and a
/// directory whose entries do not read, which then comes out empty; or
/// left out with [`OnRefused::Skip`] (but a root directory that does not
/// read, which stops the extraction).
///
/// **A compressed file is refused rather than written.** NTFS compresses
/// with LZNT1, which the library underneath does not decompress and does
/// not refuse either: it hands back the compressed bytes as if they were
/// the file's. Writing those would be writing a file that is not the one
/// in the image, so this stops instead; `docs/ntfs.md` has the
/// measurement.
///
/// Besides tar's rules: a record that two names point at is a hard link to
/// the first, as [`Options::links`] says ([`Links::AsFile`] copies it); a
/// directory met again is refused ([`ErrorKind::DirectoryAgain`]), as a
/// volume Windows wrote has none. **A reparse point is not a link here** —
/// what it stands for is in its reparse data, which `hivepack::ntfs` does
/// not read — so it is refused rather than created pointing at nothing.
///
/// **The streams beside a file are not written.** A file's own data is
/// what comes out; an alternate data stream (`file.txt:stream`) is left
/// where it is, as nothing outside Windows keeps one and a colon is a name
/// this crate refuses anyway.
///
/// **A name is text**, as NTFS keeps names in UTF-16, and goes through the
/// same checks a tar archive's does ([`crate::extract::check_name`]): one
/// that holds a separator, a `..`, or anything else that would land
/// outside the destination is refused or renamed there, not here. An entry
/// of a directory holding a separator or a NUL is refused
/// ([`NameError::Separator`]): an entry is one name, not a path.
///
/// Times are kept as NTFS holds them — an instant in UTC, to a hundred
/// nanoseconds — so unlike FAT there is nothing to choose. What NTFS keeps
/// that does not come out is said above: no mode, no owner, no extended
/// attributes.
///
/// [`Links::AsFile`]: crate::extract::Links::AsFile
pub fn extract_ntfs<D: Disk>(
    fs: &Ntfs<D>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(fs, || open_destination(destination, options), options)
}

/// Extracts the NTFS file system `fs` into `sink`, with the checks and in
/// the order of [`extract_ntfs`]: see [`Sink`].
pub fn extract_ntfs_to<D: Disk>(
    fs: &Ntfs<D>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(fs, || Ok(state.target(options)), options)
}

/// [`extract_ntfs`] into the target `make` makes, once the tree is checked.
fn extract_into<D: Disk, T: Target>(
    fs: &Ntfs<D>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);

    let (entries, mut items, refused) = walk(fs, &run, options)?;
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    skipped.splice(0..0, refused);
    skipped.sort_by_key(|e| e.index);
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    // A hard link whose first name was left out is left out with it: there
    // is nothing on disk for it to point at.
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| item.kind != Kind::HardLink || plans.contains_key(&item.index))
        .map(|item| item.index)
        .collect();
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

    for entry in &entries {
        run.check().map_err(Error::global)?;
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
        let written = match (plans.get(&item.index), &entry.seen) {
            // A copy of the file it names, with Links::AsFile.
            (Some(LinkPlan::Hard(target)), _) => {
                copy_of(&destination, target, item, remaining, &run, options)
            }
            (_, Some(record)) => {
                let mut file = fs.file(record).map_err(|e| error(ErrorKind::Ntfs(e)))?;
                write_data(
                    &mut file,
                    item,
                    item.size,
                    &destination,
                    remaining,
                    &run,
                    options,
                )
            }
            (_, None) => Err(error(ErrorKind::HardLinkTarget)),
        }?;
        if let Some(written) = written {
            summary.files += 1;
            summary.bytes += written;
        }
        run.entry_done();
    }

    set_dir_times(&destination, &kept, &run)?;
    summary.damaged = run.take_damaged();
    Ok(summary)
}

/// Writes `size` bytes of `r` into `file`, for `item`, at most `remaining`
/// in all, then its time: the bytes written. Data that ends before `size`
/// is an error ([`ErrorKind::SizeMismatch`]).
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
            Err(e) => return Err(ErrorKind::Ntfs(crate::ntfs::Error::from(e))),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}
