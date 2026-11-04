//! Extracting a UDF volume that `hivepack::udf` mounts.
//!
//! A volume is read by random access, as a ZIP archive is: its tree is
//! walked first, every node read and every file's data checked to be on
//! the image, and every entry checked before anything is written; then the
//! files are written, their data read where it is.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::udf::{Node, Timespec, Udf, VType};

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

/// A UDF time as a `SystemTime`.
fn system_time(t: Timespec) -> Option<SystemTime> {
    let at = if t.sec >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.sec as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.sec.unsigned_abs()))?
    };
    at.checked_add(Duration::from_nanos(u64::from(t.nsec)))
}

/// What the walk found: the entries (each with its node, for its data),
/// those to extract, and the errors of those refused for what could not
/// be read, to skip.
type Walk = (Vec<Entry<Option<Node>>>, Vec<Item>, Vec<Error>);

/// Walks the volume's tree, parents before what they hold: every entry
/// listed, its node read, and its data checked to read, a file's, or its
/// target, a link's. What cannot be read is refused.
fn walk<R: Read + Seek>(udf: &mut Udf<R>, run: &Run<'_>, options: &Options) -> Result<Walk, Error> {
    let mut entries: Vec<Entry<Option<Node>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    // The entry each node was first met as: a file's again is a hard link,
    // a directory's again is refused.
    let mut met: HashMap<(u16, u32), (u64, Vec<u8>)> = HashMap::new();
    let root = udf.root().clone();
    let at_root = root.location();
    met.insert((at_root.part_num, at_root.lb_num), (0, Vec::new()));

    // Directories still to list, the next last: their node, path, and
    // index (the root has none). Each is listed after its parent's
    // entries, so that a parent comes before what it holds.
    let mut dirs: Vec<(Node, Vec<u8>, Option<u64>)> = vec![(root, Vec::new(), None)];
    while let Some((dir, path, dir_index)) = dirs.pop() {
        run.check().map_err(Error::global)?;
        let mut listed = Vec::new();
        let mut broken = None;
        match udf.read_dir(&dir) {
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
                kind: ErrorKind::Udf(e),
            };
            match (options.on_refused, dir_index) {
                (OnRefused::Skip, Some(_)) => refused.push(error),
                _ => return Err(error),
            }
        }
        let mut children = Vec::new();
        for listed in listed {
            if listed.is_parent() {
                continue;
            }
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
            let node = match udf.node(listed.icb) {
                Ok(node) => node,
                Err(e) => {
                    refuse(ErrorKind::Udf(e), &mut refused)?;
                    entries.push(entry);
                    continue;
                }
            };
            let stat = udf.stat(&node);
            let key = (listed.icb.part_num, listed.icb.lb_num);
            let first = met.get(&key).cloned();
            let met_before = first.is_some();
            let kind = match (stat.kind, &first) {
                (VType::VDIR, Some(_)) => {
                    refuse(ErrorKind::DirectoryAgain, &mut refused)?;
                    entries.push(entry);
                    continue;
                }
                (VType::VDIR, None) => Kind::Dir,
                (VType::VREG, Some(_)) => Kind::HardLink,
                (VType::VREG, None) => Kind::File,
                (VType::VLNK, _) => Kind::Link,
                _ => Kind::Special,
            };
            match kind {
                Kind::Link => match udf.read_link(&node) {
                    Ok(target) => entry.target = target,
                    Err(e) => {
                        refuse(ErrorKind::Udf(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                },
                Kind::HardLink => {
                    entry.target = first.map(|(_, path)| path).unwrap_or_default();
                }
                // The data, unless the checks are to stop it for its size.
                Kind::File if stat.size <= options.limits.max_entry_size => {
                    if let Err(e) = udf.check_data(&node) {
                        refuse(ErrorKind::Udf(e), &mut refused)?;
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
            let size = if kind == Kind::File { stat.size } else { 0 };
            items.push(Item {
                index,
                raw_name: raw.clone(),
                text,
                name,
                kind,
                size,
                // Not compressed: what is not recorded reads as zeros, and
                // the limits on sizes stand.
                compressed: size,
                data: None,
                mode: Some(stat.mode & 0o7777),
                mtime: system_time(stat.mtime),
            });
            entry.item = Some(items.len() - 1);
            if kind == Kind::Dir {
                children.push((node.clone(), raw, Some(index)));
            }
            entry.seen = Some(node);
            entries.push(entry);
        }
        // Depth first, in the order listed.
        dirs.extend(children.into_iter().rev());
    }
    Ok((entries, items, refused))
}

/// Extracts the UDF volume `udf` into `destination`, which is created if
/// it is not there, with `options`.
///
/// The volume is walked first, parents before what they hold, as NetBSD
/// lists its directories (hidden entries only if it was mounted with
/// [`crate::udf::Options::unhide`]): every node is read, every file's
/// data checked to be on the image ([`Udf::check_data`]), and every link's
/// target read, and every entry checked as a ZIP archive's are, before
/// anything is written. What cannot be read is refused
/// ([`ErrorKind::Udf`]): an entry whose node, data or target does not
/// read, and a directory with a broken entry, whose entries after it are
/// missing; or left out with [`OnRefused::Skip`] (but a broken root
/// directory, which stops the extraction).
///
/// Besides tar's rules: a node that two entries name is a hard link, to
/// the first; a directory named twice is refused
/// ([`ErrorKind::DirectoryAgain`]), as UDF does not allow it. Devices,
/// FIFOs and sockets are not created. A file's data is read as
/// hivepack::udf reads it: what is not recorded, zeros.
pub fn extract_udf<R: Read + Seek>(
    udf: &mut Udf<R>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(udf, || open_destination(destination, options), options)
}

/// Extracts the UDF volume `udf` into `sink`, with the checks and in the order of
/// [`extract_udf`]: see [`Sink`].
pub fn extract_udf_to<R: Read + Seek>(
    udf: &mut Udf<R>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(udf, || Ok(state.target(options)), options)
}

/// [`extract_udf`] into the target `make` makes, once the volume is checked.
fn extract_into<R: Read + Seek, T: Target>(
    udf: &mut Udf<R>,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);

    let (entries, mut items, refused) = walk(udf, &run, options)?;
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

    for entry in &entries {
        run.check().map_err(Error::global)?;
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
        let written = match (plans.get(&item.index), &entry.seen) {
            (Some(LinkPlan::SymlinkAsFile), _) => write_data(
                &mut &entry.target[..],
                item,
                entry.target.len() as u64,
                &destination,
                remaining,
                &run,
                options,
            ),
            (Some(LinkPlan::Hard(target)), _) => {
                // A copy of the file it names, with Links::AsFile.
                copy_of(&destination, target, item, remaining, &run, options)
            }
            (_, Some(node)) => write_data(
                &mut udf.file(node),
                item,
                item.size,
                &destination,
                remaining,
                &run,
                options,
            ),
            (_, None) => Err(error(ErrorKind::HardLinkTarget)),
        }?;
        if let Some(written) = written {
            summary.files += 1;
            summary.bytes += written;
        }
        run.entry_done();
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
            Err(e) => return Err(udf_error(e)),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}

/// A read's error: the volume's.
fn udf_error(e: io::Error) -> ErrorKind {
    ErrorKind::Udf(crate::udf::Error::from(e))
}
