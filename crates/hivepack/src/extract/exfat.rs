//! Extracting an exFAT file system that `hivepack::exfat` reads.
//!
//! A file system is read by random access, as a FAT one is: its tree is
//! walked first, every entry listed and every file's data reached for, and
//! every entry checked before anything is written; then the files are
//! written, their data read where it is.
//!
//! exFAT keeps as little beside a file as FAT does, and what it does not
//! keep is not invented here: there are no permissions, no owner, no
//! extended attributes, no symbolic links and no hard links. Only files
//! and directories come out. What it does keep and FAT does not is the
//! offset from UTC beside each time, and the length a file has been
//! written to, which is where its bytes stop and zeroes begin.

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::exfat::{Entry as Record, Exfat, Time};
use crate::image::Disk;

use crate::extract::destination::{Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::settle;
use crate::extract::plan::{Item, Kind, OnRefused, Options, check};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, bytes_to_write, plan_links, write_with};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// An exFAT time as a `SystemTime`.
///
/// **An exFAT time says where it was written**, which a FAT time does not:
/// each one carries an offset from UTC beside it, and `Time::unix` takes
/// that off, so what comes out is the moment itself. A volume written by a
/// tool that left the offset out has its parts read as UTC, as FAT's are,
/// which is a choice and not a fact.
fn system_time(t: Time) -> Option<SystemTime> {
    let at = t.unix();
    if at >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(at as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(at.unsigned_abs()))
    }
}

/// What the walk found: the entries (each with its record, for its data),
/// those to extract, and the errors of those refused, to skip.
type Walk = (Vec<Entry<Option<Record>>>, Vec<Item>, Vec<Error>);

/// Walks the file system's tree, parents before what they hold, in the
/// order each directory holds its entries.
///
/// Directories are kept to the clusters they begin at, as the reader's own
/// walk does: an entry that names a directory already walked into is a
/// chain that leads back on itself, which a hostile image can write and a
/// kernel cannot, and it is refused rather than followed for ever.
fn walk<D: Disk>(fs: &Exfat<D>, run: &Run<'_>, options: &Options) -> Result<Walk, Error> {
    let mut entries: Vec<Entry<Option<Record>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    let mut seen: BTreeSet<u32> = BTreeSet::new();

    let root = fs
        .read_root()
        .map_err(|e| Error::global(ErrorKind::ExFat(e)))?;
    // Directories still to list, the next last: their records, path, and
    // the index of the entry that named them (the root has none).
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
            let entry = Entry {
                seen: None,
                item: None,
                target: Vec::new(),
            };
            // An entry is one name, not a path. exFAT's own rules leave
            // out every character a path is made of, so a name that holds
            // one did not come from anything that writes file systems: cut
            // into components it would be written somewhere other than
            // where this file system says it is.
            if record.name.as_bytes().contains(&b'/')
                || record.name.as_bytes().contains(&b'\\')
                || record.name.as_bytes().contains(&0)
            {
                refuse(ErrorKind::Name(NameError::Separator), &mut refused)?;
                entries.push(entry);
                continue;
            }
            let mut entry = entry;
            let kind = if record.is_dir() {
                Kind::Dir
            } else {
                Kind::File
            };
            if kind == Kind::Dir {
                // There are no `.` and `..` entries to leave out: exFAT
                // keeps none, so a directory holds what is in it and
                // nothing that leads back out.
                let at = record.first_cluster();
                if at >= 2 && !seen.insert(at) {
                    refuse(ErrorKind::DirectoryAgain, &mut refused)?;
                    entries.push(entry);
                    continue;
                }
            }
            // That the data reads at all, unless the checks are to stop it
            // for its size: a file whose chain leads off the file system is
            // refused here rather than part way through writing it.
            if kind == Kind::File
                && record.size <= options.limits.max_entry_size
                && let Err(e) = fs.file(&record)
            {
                refuse(ErrorKind::ExFat(e), &mut refused)?;
                entries.push(entry);
                continue;
            }
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
                // Not compressed, and nothing is held back: the clusters
                // are the file.
                compressed: size,
                data: None,
                // An exFAT file system has no permissions to keep, so
                // none are given: the files get `Options::permissions`.
                mode: None,
                mtime: record.modified.and_then(system_time),
                // Nor an owner, nor attributes beside a file.
                owner: None,
                xattrs: Vec::new(),
            });
            entry.item = Some(items.len() - 1);
            if kind == Kind::Dir {
                match fs.read_dir(&record) {
                    Ok(inside) => children.push((inside, raw)),
                    Err(e) => {
                        // What the directory holds is missing, and its own
                        // entry stands: a folder with nothing in it.
                        let error = Error::new(index, &raw, ErrorKind::ExFat(e));
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
        // Depth first, in the order the directory holds its records.
        dirs.extend(children.into_iter().rev());
    }
    Ok((entries, items, refused))
}

/// Extracts the exFAT file system `fs` into `destination`, which is
/// created if it is not there, with `options`.
///
/// The tree is walked first, parents before what they hold, in the order
/// each directory holds its entries: every file's data is reached for and
/// every entry checked as a ZIP archive's are, before anything is written.
/// What cannot be read is refused ([`ErrorKind::ExFat`]): a file whose
/// clusters lead off the file system, a set of entries that fails its own
/// checksum, and a directory whose entries do not read, which then comes
/// out empty; or left out with [`OnRefused::Skip`] (but a root directory
/// that does not read, which stops the extraction).
///
/// **A file is written to its whole length, and the room in it that was
/// never written comes out as zeroes.** exFAT keeps both lengths, and the
/// clusters past the second hold whatever was in them before: handing that
/// back would hand back somebody else's deleted data.
///
/// An entry holding a separator or a NUL is refused
/// ([`NameError::Separator`]): an entry is one name, not a path.
///
/// exFAT keeps as little beside a file as FAT does, and what it does not
/// keep is not invented: there are no permissions, no owner, no extended
/// attributes, and neither kind of link, so only files and directories
/// come out and what they are given is [`Options::permissions`]. Its times
/// carry the offset from UTC where they were written, which is taken off,
/// so what comes out is the moment itself.
///
/// An entry that names a directory already walked into is refused
/// ([`ErrorKind::DirectoryAgain`]): a chain that leads back on itself,
/// which a hostile image can write and a kernel cannot.
pub fn extract_exfat<D: Disk>(
    fs: &Exfat<D>,
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

/// Extracts the exFAT file system `fs` into `sink`, with the checks and in
/// the order of [`extract_exfat`]: see [`Sink`].
pub fn extract_exfat_to<D: Disk>(
    fs: &Exfat<D>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(fs, || Ok(state.target(options)), options)
}

/// [`extract_exfat`] into the target `make` makes, once the tree is
/// checked.
fn extract_into<D: Disk, T: Target>(
    fs: &Exfat<D>,
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
    let kept_indexes: HashSet<u64> = kept.iter().map(|item| item.index).collect();
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
        let remaining = limits.max_total_size.saturating_sub(summary.bytes);
        let Some(record) = &entry.seen else {
            continue;
        };
        let mut file = fs.file(record).map_err(|e| error(ErrorKind::ExFat(e)))?;
        let written = write_data(
            &mut file,
            item,
            item.size,
            &destination,
            remaining,
            &run,
            options,
        )?;
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
            Err(e) => return Err(ErrorKind::ExFat(crate::exfat::Error::from(e))),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}
