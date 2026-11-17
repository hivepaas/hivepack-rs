//! Extracting an ext2, ext3 or ext4 file system that `hivepack::ext` reads.
//!
//! A file system is read by random access, as a UDF volume is: its tree is
//! walked first, every inode read, every file's data and every link's
//! target reached for, and every entry checked before anything is written;
//! then the files are written, their data read where it is.
//!
//! This is the first thing extracted here that keeps who owned a file and
//! what was beside it: a file system records the owner and the group of
//! every inode, and the extended attributes where SELinux labels and ACLs
//! live. Both are given to the same machinery a tar archive's go through,
//! so what is done with them is [`Options::owners`] and
//! [`Options::xattrs`], not this reader's own doing.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ext::{Ext, Node, Time, What};
use crate::image::Disk;

use crate::extract::destination::{Target, TargetFile};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::settle;
use crate::extract::plan::{Item, Kind, OnRefused, Options, Owner, check};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, copy_of, plan_links, write_with};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// An inode's time as a `SystemTime`, which is seconds from the epoch and
/// may be before it.
fn system_time(t: Time) -> Option<SystemTime> {
    let at = if t.seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.seconds as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.seconds.unsigned_abs()))?
    };
    at.checked_add(Duration::from_nanos(u64::from(t.nanoseconds)))
}

/// What the walk found: the entries (each with its inode, for its data),
/// those to extract, and the errors of those refused for what could not be
/// read, to skip.
type Walk = (Vec<Entry<Option<Node>>>, Vec<Item>, Vec<Error>);

/// Walks the file system's tree, parents before what they hold: every
/// record listed, its inode read, its data or its target reached for, and
/// its extended attributes read where they are wanted. What cannot be read
/// is refused.
fn walk<D: Disk>(fs: &Ext<D>, run: &Run<'_>, options: &Options) -> Result<Walk, Error> {
    let mut entries: Vec<Entry<Option<Node>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    // The entry each inode was first met as: a file's again is a hard
    // link, which is what `links` greater than one means and what a root
    // file system is full of; a directory's again is refused, as the
    // format does not allow one.
    let mut met: HashMap<u32, (u64, Vec<u8>)> = HashMap::new();
    let root = fs.root().map_err(|e| Error::global(ErrorKind::Ext(e)))?;
    met.insert(root.ino, (0, Vec::new()));

    // Directories still to list, the next last: their inode, path, and
    // index (the root has none).
    let mut dirs: Vec<(Node, Vec<u8>, Option<u64>)> = vec![(root, Vec::new(), None)];
    while let Some((dir, path, dir_index)) = dirs.pop() {
        run.check().map_err(Error::global)?;
        let listed = match fs.read_dir(&dir) {
            Ok(listed) => listed,
            Err(e) => {
                // What the directory holds is missing, and the records of a
                // directory are read whole or not at all.
                let error = Error {
                    index: dir_index,
                    name: dir_index.map(|_| path.clone()),
                    kind: ErrorKind::Ext(e),
                };
                match (options.on_refused, dir_index) {
                    (OnRefused::Skip, Some(_)) => {
                        refused.push(error);
                        continue;
                    }
                    _ => return Err(error),
                }
            }
        };
        let mut children = Vec::new();
        for listed in listed {
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
            // A record is one name, not a path: the kernel allows neither a
            // separator nor a NUL in one, so a record holding either did
            // not come from a kernel. Cut into components by the rules that
            // read an archive's paths, it would be written somewhere other
            // than where this file system says it is.
            if listed.name.contains(&b'/') || listed.name.contains(&0) {
                refuse(
                    ErrorKind::Name(crate::extract::name::NameError::Separator),
                    &mut refused,
                )?;
                entries.push(entry);
                continue;
            }
            let node = match fs.node(listed.ino) {
                Ok(node) => node,
                Err(e) => {
                    refuse(ErrorKind::Ext(e), &mut refused)?;
                    entries.push(entry);
                    continue;
                }
            };
            let first = met.get(&node.ino).cloned();
            let met_before = first.is_some();
            let kind = match (node.what, &first) {
                (What::Dir, Some(_)) => {
                    refuse(ErrorKind::DirectoryAgain, &mut refused)?;
                    entries.push(entry);
                    continue;
                }
                (What::Dir, None) => Kind::Dir,
                (What::File, Some(_)) => Kind::HardLink,
                (What::File, None) => Kind::File,
                (What::Symlink, _) => Kind::Link,
                _ => Kind::Special,
            };
            match kind {
                Kind::Link => match fs.read_link(&node) {
                    Ok(target) => entry.target = target,
                    Err(e) => {
                        refuse(ErrorKind::Ext(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                },
                Kind::HardLink => {
                    entry.target = first.clone().map(|(_, path)| path).unwrap_or_default();
                }
                // That the data reads at all, unless the checks are to stop
                // it for its size: a file whose map or extent tree leads off
                // the file system is refused here rather than part way
                // through writing it.
                Kind::File if node.size <= options.limits.max_entry_size => {
                    if let Err(e) = fs.file(&node) {
                        refuse(ErrorKind::Ext(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                }
                _ => {}
            }
            // The attributes beside it, which is where SELinux labels, ACLs
            // and capabilities are. Read only where they are wanted: for a
            // tree of thousands they are a read of their own apiece.
            let xattrs = if options.xattrs {
                match fs.xattrs(&node) {
                    Ok(found) => found.into_iter().map(|one| (one.name, one.value)).collect(),
                    Err(e) => {
                        refuse(ErrorKind::Ext(e), &mut refused)?;
                        entries.push(entry);
                        continue;
                    }
                }
            } else {
                Vec::new()
            };
            if !met_before {
                met.insert(node.ino, (index, raw.clone()));
            }
            let (text, name) = named_of(&raw, options).unwrap_or_else(|| {
                (
                    String::from_utf8_lossy(&raw).into_owned(),
                    Err(NameError::Empty),
                )
            });
            let size = if kind == Kind::File { node.size } else { 0 };
            items.push(Item {
                index,
                raw_name: raw.clone(),
                text,
                name,
                kind,
                size,
                // Not compressed: a hole reads as zeros, and the limits on
                // sizes stand whatever the file takes on the disk.
                compressed: size,
                data: None,
                mode: Some(u32::from(node.mode & 0o7777)),
                mtime: node.modified.and_then(system_time),
                // A file system keeps the numbers and not the names, which
                // is what a tar archive without them has too.
                owner: Some(Owner {
                    uid: node.uid,
                    gid: node.gid,
                    user: Vec::new(),
                    group: Vec::new(),
                }),
                xattrs,
            });
            entry.item = Some(items.len() - 1);
            if kind == Kind::Dir {
                children.push((node.clone(), raw, Some(index)));
            }
            entry.seen = Some(node);
            entries.push(entry);
        }
        // Depth first, in the order the directory holds its records.
        dirs.extend(children.into_iter().rev());
    }
    Ok((entries, items, refused))
}

/// Extracts the ext file system `fs` into `destination`, which is created
/// if it is not there, with `options`.
///
/// The tree is walked first, parents before what they hold, in the order
/// each directory holds its records: every inode is read, every file's data
/// reached for, every link's target read, and every entry checked as a ZIP
/// archive's are, before anything is written. What cannot be read is
/// refused ([`ErrorKind::Ext`]): an entry whose inode, data, target or
/// attributes do not read, and a directory whose records do not hold
/// together, whose entries are then missing; or left out with
/// [`OnRefused::Skip`] (but a root directory that does not read, which
/// stops the extraction).
///
/// Besides tar's rules: an inode that two names point at is a hard link to
/// the first, which is what a root file system is full of; a directory
/// named twice is refused ([`ErrorKind::DirectoryAgain`]), as the format
/// does not allow one. Devices, FIFOs and sockets are not created.
///
/// **A name is bytes**, as it is on the disk, and goes through the same
/// checks a tar archive's does ([`crate::extract::check_name`]): one that
/// holds a separator, a `..`, or anything else that would land outside the
/// destination is refused or renamed there, not here.
///
/// The owner and the group of every inode are kept, and the extended
/// attributes where SELinux labels and ACLs are, so that a root file system
/// comes out as it went in. What is done with either is
/// [`Options::owners`] and [`Options::xattrs`]: the attributes are not even
/// read unless they are wanted.
pub fn extract_ext<D: Disk>(
    fs: &Ext<D>,
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

/// Extracts the ext file system `fs` into `sink`, with the checks and in
/// the order of [`extract_ext`]: see [`Sink`].
pub fn extract_ext_to<D: Disk>(
    fs: &Ext<D>,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(fs, || Ok(state.target(options)), options)
}

/// [`extract_ext`] into the target `make` makes, once the tree is checked.
fn extract_into<D: Disk, T: Target>(
    fs: &Ext<D>,
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
            (_, Some(node)) => {
                let mut file = fs.file(node).map_err(|e| error(ErrorKind::Ext(e)))?;
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
/// in all, then its time and permissions: the bytes written. Data that ends
/// before `size` is an error ([`ErrorKind::SizeMismatch`]).
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
            Err(e) => return Err(ErrorKind::Ext(crate::ext::Error::from(e))),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    Ok(written)
}
