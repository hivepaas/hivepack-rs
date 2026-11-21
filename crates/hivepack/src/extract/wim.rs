//! Extracting one image of a WIM archive that `hivepack::wim` reads.
//!
//! A WIM is not an archive of files one after another. It holds
//! **resources**, each named by the SHA-1 of what it holds, and **images**
//! — whole trees of names — over them, so an archive of several Windows
//! editions is mostly one set of resources with several trees pointing at
//! it. **One image is extracted at a time**, by its number, as a disk
//! image's one partition is: putting every image of a `.wim` in one folder
//! would need a folder for each, and what those are called is for whoever
//! asks, not for this.
//!
//! The tree is read first — an image's metadata is a resource of the
//! archive, compressed like any other — and every entry is checked before
//! anything is written, as a ZIP archive's are.
//!
//! **What a WIM keeps and this does not give back is said rather than
//! guessed at.** A reparse point (a symbolic link, a junction, a file kept
//! through Windows' overlay filter) stands for something that is in its
//! reparse data, which `hivepack::wim` does not read, so it is refused
//! rather than created pointing at nothing. The streams beside a file are
//! left where they are, as nothing outside Windows keeps them. The
//! security descriptor an image carries for its files is not a Unix owner
//! or mode and is not turned into one: what the files get is
//! [`Options::permissions`], unless the archive carries a Unix mode of its
//! own, which 7-Zip writes when it makes a WIM on a Unix system.
//!
//! **Every file is held to its SHA-1.** That hash is the only check a WIM
//! gives — there is none beside a chunk and none beside a resource — and
//! `hivepack::wim` checks it as the file is read, so a file whose bytes
//! are not the bytes that went in fails and what was written of it is
//! removed, as a ZIP archive's file that fails its CRC-32 is. It is
//! damage, so [`Options::on_damaged`] can keep it and go on, which is the
//! one way such a file is left on the disk — and then it is in
//! [`Summary::damaged`] with how much of it was kept.
//!
//! [`Summary::damaged`]: crate::extract::Summary::damaged
//! [`Options::on_damaged`]: crate::extract::Options::on_damaged

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::path::Path;

use crate::wim::{Entry as Record, File as Reading, Wim};

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

/// What the walk found: the entries (each with its record, for its data),
/// those to extract, and the errors of those refused, to skip.
type Walk = (Vec<Entry<Option<Record>>>, Vec<Item>, Vec<Error>);

/// Reads the image's tree, parents before what they hold, and says what
/// comes out of it.
///
/// Files are kept to the set of names an image says share one file: the
/// second name of a set is a hard link to the first, which a Windows image
/// has plenty of — the same payload under a dozen names in `WinSxS` — and
/// without them an image of a Windows installation would be written many
/// times over.
///
/// Two names that are not a set and hold the same resource are two files,
/// and both are written: a WIM holds one resource for every file with
/// those bytes, which says nothing about whether they were one file.
fn walk<R: Read + Seek>(
    wim: &mut Wim<R>,
    image: u32,
    run: &Run<'_>,
    options: &Options,
) -> Result<Walk, Error> {
    let tree = wim
        .entries(image)
        .map_err(|e| Error::global(ErrorKind::Wim(e)))?;
    let mut entries: Vec<Entry<Option<Record>>> = Vec::new();
    let mut items = Vec::new();
    let mut refused = Vec::new();
    // The entry each set of names was first met as: a second name of the
    // set is a hard link to it.
    let mut met: HashMap<u64, (u64, Vec<u8>)> = HashMap::new();

    for record in tree {
        let index = entries.len() as u64;
        run.check().map_err(Error::global)?;
        // Every entry counts, as in tar.
        if index >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let raw = record.path.clone().into_bytes();
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
        // An entry of a directory is one name, not a path: Windows allows
        // neither a separator nor a NUL in one, so an entry holding either
        // did not come from Windows. The path here is the names of the
        // tree joined, so a name holding a separator would be written
        // somewhere other than where the tree says it is.
        let name = record.name.as_bytes();
        if name.contains(&b'/') || name.contains(&b'\\') || name.contains(&0) {
            refuse(ErrorKind::Name(NameError::Separator), &mut refused)?;
            entries.push(entry);
            continue;
        }
        let first = record
            .hard_link_group
            .and_then(|group| met.get(&group).cloned());
        let kind = match (record.is_dir(), &first) {
            (true, _) => Kind::Dir,
            (false, Some(_)) => Kind::HardLink,
            (false, None) => Kind::File,
        };
        if kind == Kind::HardLink {
            entry.target = first.clone().map(|(_, path)| path).unwrap_or_default();
        }
        // That the data can be read at all, unless the checks are to stop
        // it for its size: a reparse point, a resource in a solid block,
        // one compressed with a compression there is no decoder for, and
        // one that is not on the file are all refused here rather than
        // part way through writing a file.
        if kind == Kind::File
            && record.size <= options.limits.max_entry_size
            && let Err(e) = wim.file(&record).map(|_| ())
        {
            refuse(ErrorKind::Wim(e), &mut refused)?;
            entries.push(entry);
            continue;
        }
        if kind != Kind::Dir
            && let Some(group) = record.hard_link_group
        {
            met.entry(group).or_insert((index, raw.clone()));
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
            // **No ratio is checked here**, which is what giving the
            // uncompressed length twice says. A resource's compressed
            // length belongs to no one file: several names can hold the
            // same resource, and a chunk of it holds whatever part of the
            // file falls in that chunk. The limits that do hold are the
            // ones on each entry and on all of them.
            compressed: size,
            data: None,
            // A WIM carries Windows' attributes and a security
            // descriptor, neither of which is a Unix mode — but 7-Zip
            // writes a real one in the high half of the attributes when
            // it makes an archive on a Unix system, and where it did,
            // that is the mode the file had.
            mode: record.unix_mode,
            mtime: record.modified,
            // Nor an owner that means anything on this side, nor extended
            // attributes: the streams beside a file are not attributes and
            // are not written.
            owner: None,
            xattrs: Vec::new(),
        });
        entry.item = Some(items.len() - 1);
        entry.seen = Some(record);
        entries.push(entry);
    }
    Ok((entries, items, refused))
}

/// Extracts image `image` of the WIM archive `wim` into `destination`,
/// which is created if it is not there, with `options`.
///
/// Images are counted from 1, as every tool counts them, and
/// [`Wim::images`] says which an archive holds and what the XML calls
/// them. An image that is not there is an error
/// ([`crate::wim::Error::NoSuchImage`]).
///
/// The tree is read first — an image's metadata is a resource of the
/// archive, compressed like any other — and every entry is checked before
/// anything is written, as a ZIP archive's are. What cannot be read is
/// refused ([`ErrorKind::Wim`]): a reparse point, a resource in a solid
/// block or compressed with LZMS ([`crate::wim::Unsupported`]), and one
/// whose place is not on the file; or left out with [`OnRefused::Skip`].
///
/// **Every file is held to the SHA-1 the tree names it by**, which is the
/// only check a WIM gives. A file whose bytes do not hash to it fails
/// ([`crate::wim::Error::Hash`]) and what was written of it is removed, as
/// a ZIP archive's file that fails its CRC is.
///
/// Besides tar's rules: the names an image says share one file are a hard
/// link to the first of them, as [`Options::links`] says
/// ([`Links::AsFile`] copies it). **A reparse point is not a link here** —
/// what it stands for is in its reparse data, which `hivepack::wim` does
/// not read — so it is refused rather than created pointing at nothing.
///
/// **A name is text**, as a WIM keeps names in UTF-16, and goes through
/// the same checks a tar archive's does ([`crate::extract::check_name`]):
/// one that holds a separator, a `..`, or anything else that would land
/// outside the destination is refused or renamed there, not here. An entry
/// of a directory holding a separator or a NUL is refused
/// ([`NameError::Separator`]): an entry is one name, not a path.
///
/// Times are kept as a WIM holds them, an instant in UTC. What a WIM keeps
/// that does not come out: no owner, no extended attributes, and no mode
/// unless the archive carries a Unix one of its own, which 7-Zip writes on
/// a Unix system and Windows' own tools never do.
///
/// [`Links::AsFile`]: crate::extract::Links::AsFile
/// [`Wim::images`]: crate::wim::Wim::images
pub fn extract_wim<R: Read + Seek>(
    wim: &mut Wim<R>,
    image: u32,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    extract_into(
        wim,
        image,
        || open_destination(destination, options),
        options,
    )
}

/// Extracts image `image` of the WIM archive `wim` into `sink`, with the
/// checks and in the order of [`extract_wim`]: see [`Sink`].
pub fn extract_wim_to<R: Read + Seek>(
    wim: &mut Wim<R>,
    image: u32,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    let options = &options.for_sink();
    extract_into(wim, image, || Ok(state.target(options)), options)
}

/// [`extract_wim`] into the target `make` makes, once the tree is checked.
fn extract_into<R: Read + Seek, T: Target>(
    wim: &mut Wim<R>,
    image: u32,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);

    let (entries, mut items, refused) = walk(wim, image, &run, options)?;
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
                let mut file = wim.file(record).map_err(|e| error(ErrorKind::Wim(e)))?;
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

/// Writes `size` bytes of `file` into the destination, for `item`, at most
/// `remaining` in all, then its time: the bytes written. Data that ends
/// before `size` is an error ([`ErrorKind::SizeMismatch`]).
fn write_data<R: Read + Seek, T: Target>(
    file: &mut Reading<'_, R>,
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
    write_with(item, Some(size), destination, run, options, |into| {
        write_into(file, size, into, run)
    })
}

/// The file's bytes, a chunk of the archive at a time, into `into`.
///
/// The bytes come through [`crate::wim::File::pull`] rather than through
/// `Read`, so that what a WIM says when it fails arrives as it is: a file
/// whose SHA-1 does not match is [`crate::wim::Error::Hash`] here, and
/// through `Read` it would arrive as an `io` error carrying the words.
fn write_into<R: Read + Seek>(
    file: &mut Reading<'_, R>,
    size: u64,
    into: &mut impl TargetFile,
    run: &Run<'_>,
) -> Result<u64, ErrorKind> {
    let mut written: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while written < size {
        run.check()?;
        let want = buffer.len().min((size - written) as usize);
        let read = match file.pull(&mut buffer[..want]) {
            Ok(0) => return Err(ErrorKind::SizeMismatch),
            Ok(read) => read,
            Err(e) => return Err(ErrorKind::Wim(e)),
        };
        written += read as u64;
        into.write_all(&buffer[..read]).map_err(ErrorKind::Io)?;
        run.wrote(read as u64);
    }
    Ok(written)
}
