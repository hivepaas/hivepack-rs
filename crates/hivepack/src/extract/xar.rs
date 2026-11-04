//! Extracting a XAR archive that `hivepack::xar` reads: macOS packages
//! (`.pkg`) and `.xip` files among them.
//!
//! libarchive reads a XAR archive's table of contents, then each file's
//! data where it is in the heap, in order, as from a stream: as for tar,
//! the archive is read twice, once to check every entry and once to
//! write, each header compared with the first reading's. The first reading
//! reads each file's data to its end, so that its checksums are checked
//! before anything is written.
//!
//! A package's files are not its entries, but in its payloads: cpio
//! archives, compressed with gzip or pbzx, named `Payload` (and `Scripts`
//! for its scripts) in each component package, or `Content` in a `.xip`
//! file. With [`Packages::Expand`], each is opened through its layers
//! (`hivepack::open::Opener`) and extracted into a directory of its name,
//! as `pkgutil --expand-full` does: planned in the first reading, with the
//! checks on all of it, and written in the second.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::open::{Container, Layer, Opener};
use crate::xar::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFSOCK, Header, Reader,
};

use crate::extract::cpio::{self, Writer};
use crate::extract::destination::Target;
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::plan::{Item, Kind, OnRefused, Options, Packages, check};
use crate::extract::plan::{Renamed, settle};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, plan_links, read_rest};
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// The names of the payloads [`Packages::Expand`] extracts: a component
/// package's files and scripts, and a `.xip` file's content.
const PAYLOADS: [&str; 3] = ["Payload", "Scripts", "Content"];

/// Seconds since 1970 as a `SystemTime`.
fn system_time(secs: Option<i64>) -> Option<SystemTime> {
    let secs = secs?;
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// A payload: its layers, and the plan of the cpio archive under them.
struct Payload {
    layers: Vec<Layer>,
    plan: cpio::Plan,
}

/// What the first reading found: the entries (`None` for one lost, whose
/// data was before the place read to), the items, the payloads by entry,
/// and the errors of the entries refused to skip.
#[derive(Default)]
struct FirstReading {
    entries: Vec<Entry<Option<Header>>>,
    items: Vec<Item>,
    payloads: Vec<Option<Payload>>,
    refused: Vec<Error>,
}

/// An entry's error, by its index and its path.
fn entry_error(index: u64, h: &Header, kind: ErrorKind) -> Error {
    Error {
        index: Some(index),
        name: h.path.clone(),
        kind,
    }
}

/// An error in the payload `prefix` names: its entry's index, and its
/// path under the payload's.
fn in_payload(index: u64, prefix: &[u8], e: Error) -> Error {
    let name = match e.name {
        Some(name) => [prefix, b"/", &name].concat(),
        None => prefix.to_vec(),
    };
    Error {
        index: Some(index),
        name: Some(name),
        kind: e.kind,
    }
}

/// `r`, the XAR reader at a payload's entry, opened through its layers.
fn open_payload<R: Read + Send>(
    r: &mut Reader<R>,
) -> Result<(Vec<Layer>, Container, crate::open::Opened<'_>), ErrorKind> {
    let mut once = Some(r);
    let mut opener = Opener::new(move || {
        once.take()
            .ok_or_else(|| io::Error::other("a payload opened twice"))
    });
    let opened = opener.open().map_err(|e| ErrorKind::Payload(e.into()))?;
    Ok((opened.layers().to_vec(), opened.container(), opened))
}

/// The first reading: every header, every file's data read to its end and
/// dropped (its checksums are checked there), and each payload planned.
fn read_headers<R: Read + Send>(
    r: R,
    run: &Run<'_>,
    options: &Options,
) -> Result<FirstReading, Error> {
    let mut xar = Reader::new(r);
    let mut first = FirstReading::default();
    loop {
        let index = first.entries.len() as u64;
        run.check().map_err(Error::global)?;
        let h = match xar.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            // An entry lost: its data is before the place read to, which a
            // stream cannot go back to. The next one comes after it.
            Err(e @ crate::xar::Error::CannotSeek) => {
                let error = Error {
                    index: Some(index),
                    name: None,
                    kind: ErrorKind::Xar(e),
                };
                match options.on_refused {
                    OnRefused::Stop => return Err(error),
                    OnRefused::Skip => first.refused.push(error),
                }
                first.entries.push(Entry {
                    seen: None,
                    item: None,
                    target: Vec::new(),
                });
                first.payloads.push(None);
                continue;
            }
            Err(e) => {
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind: ErrorKind::Xar(e),
                });
            }
        };
        if first.entries.len() as u64 >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let mut entry = Entry {
            seen: Some(h.clone()),
            item: None,
            target: Vec::new(),
        };
        if let Some(warning) = &h.warning {
            let error = entry_error(index, &h, ErrorKind::XarEntry(warning.clone()));
            match options.on_refused {
                OnRefused::Stop => return Err(error),
                OnRefused::Skip => first.refused.push(error),
            }
            first.entries.push(entry);
            first.payloads.push(None);
            continue;
        }
        let raw = h.path.clone().unwrap_or_default();
        let (text, name) = match named_of(&raw, options) {
            Some(named) => named,
            None => (
                String::from_utf8_lossy(&raw).into_owned(),
                Err(NameError::Empty),
            ),
        };
        let mut kind = if h.hardlink.is_some() {
            Kind::HardLink
        } else {
            match h.mode & AE_IFMT {
                AE_IFDIR => Kind::Dir,
                AE_IFLNK => Kind::Link,
                AE_IFCHR | AE_IFBLK | AE_IFIFO | AE_IFSOCK => Kind::Special,
                _ => Kind::File,
            }
        };
        let mut payload = None;
        let is_payload = name.as_ref().is_ok_and(|name| {
            name.components
                .last()
                .is_some_and(|last| PAYLOADS.contains(&last.as_str()))
        });
        if kind == Kind::File && options.packages == Packages::Expand && is_payload {
            let (layers, container, opened) =
                open_payload(&mut xar).map_err(|kind| entry_error(index, &h, kind))?;
            if container == Container::Cpio {
                let plan =
                    cpio::plan(opened, run, options).map_err(|e| in_payload(index, &raw, e))?;
                payload = Some(Payload { layers, plan });
                kind = Kind::Dir;
            }
        }
        // The data, to its end, where its checksums are.
        if kind == Kind::File {
            read_rest(&mut xar, run, options)
                .map_err(|e| entry_error(index, &h, xar_error(e.kind)))?;
        }
        entry.target = match kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        let size = match kind {
            Kind::File => h.size,
            _ => 0,
        };
        first.items.push(Item {
            index,
            raw_name: raw,
            text,
            name,
            kind,
            size,
            compressed: size,
            data: None,
            mode: Some(h.mode & 0o7777),
            mtime: system_time(h.mtime),
        });
        entry.item = Some(first.items.len() - 1);
        first.entries.push(entry);
        first.payloads.push(payload);
    }
    read_rest(xar.into_inner(), run, options)?;
    Ok(first)
}

/// A failed read of an entry's data, as `read_rest` gives it: the XAR
/// reader's error, out of the `io::Error` that holds it.
fn xar_error(kind: ErrorKind) -> ErrorKind {
    match kind {
        ErrorKind::Io(e) => ErrorKind::Xar(crate::xar::Error::from(e)),
        kind => kind,
    }
}

/// Extracts the XAR archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`: a macOS package (`.pkg`), a
/// `.xip` file, or what `xar` makes.
///
/// `open` is called twice, and must give the same archive each time, as
/// for [`extract_tar`](crate::extract::extract_tar): the first reading checks every
/// entry before anything is written, and reads every file's data to its
/// end, where its checksums are; the second writes them, each header
/// compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs).
///
/// With [`Packages::Expand`] (the default), an entry named `Payload`,
/// `Scripts` or `Content` whose data is a cpio archive under its layers
/// becomes a directory of that name with the archive's files, extracted as
/// [`extract_cpio`](crate::extract::extract_cpio) extracts one, with the same checks
/// before anything is written: a package's files under each component's
/// `Payload`, its scripts under `Scripts`, a `.xip` file's under `Content`.
/// The limits count all of them. An error in a payload names its entry, and
/// the path in the payload after the payload's.
///
/// Besides tar's rules: an entry libarchive gives with a warning (a name
/// that is not UTF-8) is refused ([`ErrorKind::XarEntry`]), or left out
/// with [`OnRefused::Skip`]; so is an entry whose data is before the place
/// read to ([`crate::xar::Error::CannotSeek`]), which a stream cannot go
/// back to. Owners, file flags and extended attributes are not restored.
pub fn extract_xar<R: Read + Send, F: FnMut() -> io::Result<R>>(
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

/// Extracts the XAR archive that `open` gives into `sink`, with the checks and in
/// the order of [`extract_xar`], reading it twice as it does, and a package's
/// payload under its directory: see [`Sink`].
pub fn extract_xar_to<R: Read + Send, F: FnMut() -> io::Result<R>>(
    open: F,
    sink: &mut dyn Sink,
    options: &Options,
) -> Result<Summary, Error> {
    let state = SinkState::new(sink);
    extract_into(open, || Ok(state.target(options)), options)
}

/// [`extract_xar`] into the target `make` makes, once the archive is checked.
fn extract_into<R: Read + Send, F: FnMut() -> io::Result<R>, T: Target>(
    mut open: F,
    make: impl FnOnce() -> Result<T, Error>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let run = Run::new(options);

    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let FirstReading {
        entries,
        mut items,
        mut payloads,
        refused,
    } = read_headers(first, &run, options)?;
    let settled = settle(&mut items, options)?;
    let (kept, mut skipped) = check(&items, &settled, options)?;
    let mut renamed = settled.renamed;
    skipped.splice(0..0, refused);
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    // What the payloads write counts with the rest.
    let (mut count, mut bytes) = (
        kept_indexes.len() as u64,
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options),
    );
    for (index, payload) in payloads.iter_mut().enumerate() {
        let Some(payload) = payload else {
            continue;
        };
        if !kept_indexes.contains(&(index as u64)) {
            continue;
        }
        count += payload.plan.entries_to_write();
        bytes = bytes.saturating_add(payload.plan.bytes_to_write(options));
        let prefix = items
            .iter()
            .find(|item| item.index == index as u64)
            .map(|item| item.raw_name.clone())
            .unwrap_or_default();
        skipped.extend(
            std::mem::take(&mut payload.plan.skipped)
                .into_iter()
                .map(|e| in_payload(index as u64, &prefix, e)),
        );
        renamed.extend(
            std::mem::take(&mut payload.plan.renamed)
                .into_iter()
                .map(|r| Renamed {
                    error: in_payload(index as u64, &prefix, r.error),
                    to: r.to,
                }),
        );
    }
    if count > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    if bytes > limits.max_total_size {
        return Err(Error::global(ErrorKind::TotalTooLarge));
    }
    skipped.sort_by_key(|e| e.index);
    let created_later = |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
    run.start(count, bytes);

    let destination = make()?;
    let mut summary = Summary {
        skipped,
        renamed,
        ..Summary::default()
    };
    let writer = Writer {
        destination: &destination,
        plans: &plans,
        run: &run,
        options,
        data_error: |e| ErrorKind::Xar(crate::xar::Error::from(e)),
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut xar = Reader::new(second);
    for (index, entry) in entries.iter().enumerate() {
        let index = index as u64;
        run.check().map_err(Error::global)?;
        let h = match xar.next() {
            Ok(Some(h)) => Some(h),
            Ok(None) => return Err(Error::global(ErrorKind::Changed)),
            Err(crate::xar::Error::CannotSeek) => None,
            Err(e) => return Err(Error::global(ErrorKind::Xar(e))),
        };
        if h != entry.seen {
            return Err(Error {
                index: Some(index),
                name: h.and_then(|h| h.path),
                kind: ErrorKind::Changed,
            });
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
        if item.kind == Kind::Dir {
            let within = destination.within(item, &name.components).map_err(error)?;
            summary.directories += 1;
            run.entry_done();
            let Some(payload) = &mut payloads[index as usize] else {
                continue;
            };
            let (layers, container, opened) = open_payload(&mut xar).map_err(error)?;
            if layers != payload.layers || container != Container::Cpio {
                return Err(error(ErrorKind::Changed));
            }
            cpio::write(
                opened,
                &mut payload.plan,
                &within,
                &run,
                options,
                &mut summary,
            )
            .map_err(|e| in_payload(index, &item.raw_name, e))?;
            continue;
        }
        match plans.get(&item.index) {
            Some(LinkPlan::Hard(_)) => writer.hard_link(item, &mut summary)?,
            Some(LinkPlan::SymlinkAsFile) => writer.file(
                &mut &entry.target[..],
                item,
                entry.target.len() as u64,
                &mut summary,
            )?,
            _ => writer.file(&mut xar, item, item.size, &mut summary)?,
        }
    }
    // The second reading must end where the first did.
    match xar.next() {
        Ok(None) => {}
        Ok(Some(h)) => {
            return Err(entry_error(entries.len() as u64, &h, ErrorKind::Changed));
        }
        Err(e) => return Err(Error::global(ErrorKind::Xar(e))),
    }
    read_rest(xar.into_inner(), &run, options)?;

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
