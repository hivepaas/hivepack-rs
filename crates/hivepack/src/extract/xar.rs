//! Extracting a XAR archive that `hivepack::xar` reads: macOS packages
//! (`.pkg`) and `.xip` files among them.
//!
//! libarchive reads a XAR archive's table of contents, then each file's
//! data where it is in the heap, in order, as from a stream: as for tar,
//! into a folder the archive is read once, each file's data written into a
//! private folder in the destination as it comes and read to its end, where
//! its checksums are, and the entries moved into place once every check has
//! passed (see the repository's `docs/extract-once.md`); into a sink it is
//! read twice, once to check every entry and once to write, each header
//! compared with the first reading's.
//!
//! A package's files are not its entries, but in its payloads: cpio
//! archives, compressed with gzip or pbzx, named `Payload` (and `Scripts`
//! for its scripts) in each component package, or `Content` in a `.xip`
//! file. With [`Packages::Expand`], each is opened through its layers
//! (`hivepack::open::Opener`) and extracted into a directory of its name,
//! as `pkgutil --expand-full` does: read once into the same private folder,
//! as `extract_cpio` reads an archive, and checked with the rest before
//! anything moves; into a sink, planned in the first reading and written in
//! the second.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::open::{Container, Layer, Opener};
use crate::xar::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFSOCK, Header, Reader,
};

use crate::extract::cpio::{self, Writer};
use crate::extract::destination::{Counted, Destination, Target, Walk};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::once::{self, ReadOnce, read_ahead};
use crate::extract::plan::{Item, Kind, OnRefused, Options, Packages, check};
use crate::extract::plan::{Renamed, settle};
use crate::extract::progress::Run;
use crate::extract::sink::{Sink, SinkState};
use crate::extract::tar::named_of;
use crate::extract::tar::{Entry, LinkPlan, bytes_to_write, plan_links, read_rest};
use crate::extract::writers::{with_writers, writer_threads};
use crate::extract::zip::{Summary, set_dir_times};

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

/// What each thread decoding a payload's layers, besides the caller's, may
/// hold: a pbzx chunk of 16 MiB as Apple writes them, what stores it, and
/// its decoder's dictionary.
#[cfg(feature = "memory")]
const PAYLOAD_THREAD: u64 = 48 << 20;

/// The threads a payload's layers are decoded in, and what they may hold.
struct Decoding {
    threads: u32,
    memory: u64,
    /// What they hold of [`Options::memory_budget`], until the reading is
    /// done.
    #[cfg(feature = "memory")]
    _held: Option<crate::memory::Held>,
}

/// The threads of [`Options::threads`], what they hold counted as
/// [`PAYLOAD_THREAD`] each besides the caller's: lowered to fit
/// [`Options::memory_budget`], and what they hold no more than it lets nor
/// than [`Options::memory_limit`].
fn decoding(options: &Options) -> Decoding {
    let wanted = options.threads.count();
    let limit = options.memory_limit.unwrap_or(u64::MAX);
    #[cfg(feature = "memory")]
    if let Some(budget) = &options.memory_budget {
        let (threads, held) = budget.hold_threads(wanted, payload_memory);
        return Decoding {
            threads,
            memory: payload_memory(threads).min(limit),
            _held: Some(held),
        };
    }
    Decoding {
        threads: wanted,
        memory: limit,
        #[cfg(feature = "memory")]
        _held: None,
    }
}

/// What `threads` decoding a payload hold, counted as [`PAYLOAD_THREAD`]
/// each besides the caller's.
#[cfg(feature = "memory")]
fn payload_memory(threads: u32) -> u64 {
    match threads {
        0 | 1 => 0,
        n => u64::from(n).saturating_mul(PAYLOAD_THREAD),
    }
}

/// `r`, the XAR reader at a payload's entry, opened through its layers,
/// decoded as `decoding` says.
fn open_payload<'a, R: Read + Send + 'a>(
    r: R,
    decoding: &Decoding,
) -> Result<(Vec<Layer>, Container, crate::open::Opened<'a>), ErrorKind> {
    let mut once = Some(r);
    let mut opener = Opener::new(move || {
        once.take()
            .ok_or_else(|| io::Error::other("a payload opened twice"))
    })
    .threads(crate::Threads::of(decoding.threads))
    .threads_memory(decoding.memory);
    let opened = opener.open().map_err(|e| ErrorKind::Payload(e.into()))?;
    Ok((opened.layers().to_vec(), opened.container(), opened))
}

/// The item of header `h`, the `index`th entry: a file, until it is found to
/// be a payload.
fn item_of(h: &Header, index: u64, options: &Options) -> Item {
    let raw = h.path.clone().unwrap_or_default();
    let (text, name) = match named_of(&raw, options) {
        Some(named) => named,
        None => (
            String::from_utf8_lossy(&raw).into_owned(),
            Err(NameError::Empty),
        ),
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
        Kind::File => h.size,
        _ => 0,
    };
    Item {
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
        owner: None,
        xattrs: Vec::new(),
    }
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
    let decoding = decoding(options);
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
        let mut item = item_of(&h, index, options);
        let raw = item.raw_name.clone();
        let mut payload = None;
        let is_payload = item.name.as_ref().is_ok_and(|name| {
            name.components
                .last()
                .is_some_and(|last| PAYLOADS.contains(&last.as_str()))
        });
        if item.kind == Kind::File && options.packages == Packages::Expand && is_payload {
            let (layers, container, opened) =
                open_payload(&mut xar, &decoding).map_err(|kind| entry_error(index, &h, kind))?;
            if container == Container::Cpio {
                let plan =
                    cpio::plan(opened, run, options).map_err(|e| in_payload(index, &raw, e))?;
                payload = Some(Payload { layers, plan });
                item.kind = Kind::Dir;
                item.size = 0;
                item.compressed = 0;
            }
        }
        // The data, to its end, where its checksums are.
        if item.kind == Kind::File {
            read_rest(&mut xar, run, options)
                .map_err(|e| entry_error(index, &h, xar_error(e.kind)))?;
        }
        entry.target = match item.kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        first.items.push(item);
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
/// `open` is called once, and the archive read once, as
/// [`extract_tar`](crate::extract::extract_tar) reads one: into a private
/// folder made in the destination, each file's data written there as it
/// comes and read to its end, where its checksums are; once the stream has
/// ended, every entry is checked, what is in the destination already is
/// looked at, and only then do the entries move into place. If anything
/// fails before, a checksum that does not match among them, nothing of the
/// archive appears.
///
/// With [`Packages::Expand`] (the default), an entry named `Payload`,
/// `Scripts` or `Content` whose data is a cpio archive under its layers
/// becomes a directory of that name with the archive's files, extracted as
/// [`extract_cpio`](crate::extract::extract_cpio) extracts one, into the same
/// private folder as it is decoded, with the same checks before anything
/// moves: a package's files under each component's `Payload`, its scripts
/// under `Scripts`, a `.xip` file's under `Content`. The limits count all of
/// them. An error in a payload names its entry, and the path in the payload
/// after the payload's. With [`Options::threads`], a payload's layers are
/// decoded in as many threads as
/// [`Opener::threads`](crate::open::Opener::threads) decodes them (pbzx's
/// chunks, xz's Blocks, bzip2's blocks), what they hold no more than
/// [`Options::memory_limit`] and 48 MiB a thread held from
/// `Options::memory_budget`; what they decode is read ahead by a thread of
/// its own, and its files are written by threads while it is read, as
/// `extract_cpio` writes them; the XAR archive's own files on the caller's
/// thread.
///
/// Besides tar's rules: an entry libarchive gives with a warning (a name
/// that is not UTF-8) is refused ([`ErrorKind::XarEntry`]), or left out
/// with [`OnRefused::Skip`]; so is an entry whose data is before the place
/// read to ([`crate::xar::Error::CannotSeek`]), which a stream cannot go
/// back to. Owners, file flags and extended attributes are not restored.
pub fn extract_xar<R: Read + Send, F: FnMut() -> io::Result<R>>(
    mut open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let options = &options.for_folder(destination);
    once::into_folder(destination, options, |destination, spool, run| {
        let r = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
        // Counted as each entry moves into place, the totals known.
        run.quiet(true);
        let read = read_once(r, spool, run, options);
        run.quiet(false);
        move_into_place(read?, destination, spool, run, options)
    })
}

/// A XAR entry's data that failed to read: the XAR reader's error, out of the
/// `io::Error` that holds it.
fn data_error(e: io::Error) -> ErrorKind {
    ErrorKind::Xar(crate::xar::Error::from(e))
}

/// What the one reading found: the XAR archive's entries, as
/// [`once::ReadOnce`] has them, and the errors of those it refused; and each
/// payload's, by entry.
#[derive(Default)]
struct XarRead {
    read: ReadOnce,
    refused: Vec<Error>,
    payloads: Vec<Option<PayloadRead>>,
}

/// A payload read once: its entry's name, and its cpio archive's entries,
/// with the errors of those refused.
struct PayloadRead {
    raw: Vec<u8>,
    read: ReadOnce,
    refused: Vec<Error>,
}

/// What a payload's layers read of its entry's data, the XAR reader `inner`,
/// copied into `copy` as it goes, until `copy` is let go of: the file it is,
/// if it is not a cpio archive. A write that fails is kept in `failed`, and
/// the copy let go of.
struct Tee<'t, R> {
    inner: R,
    copy: &'t Mutex<Option<Counted<std::fs::File>>>,
    failed: &'t Mutex<Option<io::Error>>,
}

/// What `mutex` holds, even if a thread panicked holding it: the panic goes on
/// to the caller anyway.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut copy = lock(self.copy);
        if let Some(file) = copy.as_mut()
            && let Err(e) = file.write_all(&buf[..n])
        {
            *copy = None;
            *lock(self.failed) = Some(e);
        }
        Ok(n)
    }
}

/// The one reading of the XAR archive `r`: every header kept, the data of each
/// file the checks may keep written into `spool` as it comes, and every
/// file's data read to its end, where its checksums are checked. Each payload,
/// with [`Packages::Expand`], is read once through its layers into `spool`,
/// as `extract_cpio` reads an archive, its files named by its entry's index
/// and theirs. The stream is read to its end.
fn read_once<R: Read + Send>(
    r: R,
    spool: &Destination<'_>,
    run: &Run<'_>,
    options: &Options,
) -> Result<XarRead, Error> {
    let limits = &options.limits;
    let mut xar = Reader::new(r);
    let mut out = XarRead::default();
    let decoding = decoding(options);
    // What the files written so far came to, the payloads' among them.
    let mut total: u64 = 0;
    loop {
        let index = out.read.entries.len() as u64;
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
                    OnRefused::Skip => out.refused.push(error),
                }
                out.read.entries.push(Entry {
                    seen: (),
                    item: None,
                    target: Vec::new(),
                });
                out.payloads.push(None);
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
        if index >= limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let mut entry = Entry {
            seen: (),
            item: None,
            target: Vec::new(),
        };
        if let Some(warning) = &h.warning {
            let error = entry_error(index, &h, ErrorKind::XarEntry(warning.clone()));
            match options.on_refused {
                OnRefused::Stop => return Err(error),
                OnRefused::Skip => out.refused.push(error),
            }
            out.read.entries.push(entry);
            out.payloads.push(None);
            continue;
        }
        let mut item = item_of(&h, index, options);
        let raw = item.raw_name.clone();
        let error = |kind| entry_error(index, &h, kind);
        let name = index.to_string();
        let may_keep = once::may_keep(&item, item.size, options);
        let remaining = limits.max_total_size.saturating_sub(total);
        let mut payload = None;
        let mut spooled = None;
        let is_payload = item.name.as_ref().is_ok_and(|name| {
            name.components
                .last()
                .is_some_and(|last| PAYLOADS.contains(&last.as_str()))
        });
        if item.kind == Kind::File && options.packages == Packages::Expand && is_payload {
            // What its layers read of it, copied as it goes into the file it
            // is if it is not a cpio archive, until that is known.
            let copy = Mutex::new(None);
            let failed = Mutex::new(None);
            if may_keep {
                let file = spool
                    .create_file(
                        &once::spool_item(&item, &name, item.size),
                        std::slice::from_ref(&name),
                        Some(item.size),
                        options,
                    )
                    .map_err(error)?;
                *lock(&copy) = Some(Counted { file, len: 0 });
            }
            let tee = Tee {
                inner: &mut xar,
                copy: &copy,
                failed: &failed,
            };
            let (_, container, opened) = open_payload(tee, &decoding).map_err(error)?;
            if container == Container::Cpio {
                // A directory of its files, not a file: copied no more.
                let copied = lock(&copy).take();
                if copied.is_some() || lock(&failed).is_some() {
                    spool.remove_file(std::slice::from_ref(&name));
                }
                let prefix = format!("{index}-");
                let read = match writer_threads(options, u64::MAX) {
                    Some(writing) => read_ahead(opened, |r| {
                        with_writers(spool, run, options, &writing, |writers| {
                            cpio::read_once(
                                r,
                                spool,
                                &prefix,
                                &mut total,
                                run,
                                options,
                                Some(writers),
                            )
                        })
                    }),
                    None => cpio::read_once(opened, spool, &prefix, &mut total, run, options, None),
                };
                let (read, refused) = read.map_err(|e| in_payload(index, &raw, e))?;
                payload = Some(PayloadRead {
                    raw: raw.clone(),
                    read,
                    refused,
                });
                item.kind = Kind::Dir;
                item.size = 0;
                item.compressed = 0;
            } else {
                // Its layers' threads done first: what they read is copied.
                drop(opened);
                let copied = lock(&copy).take();
                if let Some(e) = lock(&failed).take() {
                    spool.remove_file(std::slice::from_ref(&name));
                    return Err(error(ErrorKind::Io(e)));
                }
                // A file as it is: what its layers read of it, then the rest.
                if let Some(file) = copied {
                    spooled = Some(
                        once::spool_into(
                            file, &mut xar, &item, item.size, &name, spool, remaining, false,
                            data_error, run, options,
                        )
                        .map_err(|e| error(e.kind))?,
                    );
                }
            }
        } else if may_keep {
            spooled = Some(
                once::spool_from(
                    &mut xar, &item, item.size, &name, spool, remaining, false, data_error, run,
                    options,
                )
                .map_err(|e| error(e.kind))?,
            );
        }
        // The data, to its end, where its checksums are.
        if item.kind == Kind::File {
            read_rest(&mut xar, run, options).map_err(|e| error(xar_error(e.kind)))?;
        }
        if let Some(spooled) = spooled {
            total = total.saturating_add(spooled.bytes());
            out.read.spooled.insert(index, (name, spooled));
        }
        entry.target = match item.kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        out.read.items.push(item);
        entry.item = Some(out.read.items.len() - 1);
        out.read.entries.push(entry);
        out.payloads.push(payload);
    }
    read_rest(xar.into_inner(), run, options)?;
    Ok(out)
}

/// The XAR archive read once into `spool`, `read`, checked and moved into
/// `destination`: each payload checked first, as a first reading checked it
/// as it came to it, then the archive's own entries; the limits on them all
/// together; what is in the destination looked at, the payloads' entries in
/// their folders too, before anything moves; then the entries moved into
/// place, each payload's into its folder once it is made.
fn move_into_place(
    read: XarRead,
    destination: &Destination<'_>,
    spool: &Destination<'_>,
    run: &Run<'_>,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let XarRead {
        read,
        refused,
        payloads,
    } = read;
    let mut checked_payloads = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.into_iter().enumerate() {
        checked_payloads.push(match payload {
            None => None,
            Some(PayloadRead { raw, read, refused }) => Some((
                once::check_read(read, Some(refused), options)
                    .map_err(|e| in_payload(index as u64, &raw, e))?,
                raw,
            )),
        });
    }
    let mut checked = once::check_read(read, Some(refused), options)?;
    let mut skipped = std::mem::take(&mut checked.skipped);
    let mut renamed = std::mem::take(&mut checked.renamed);
    // What the payloads write counts with the rest.
    let (mut count, mut bytes) = (checked.entries_to_write(), checked.bytes_to_write(options));
    for (index, payload) in checked_payloads.iter_mut().enumerate() {
        let index = index as u64;
        let Some((payload, raw)) = payload else {
            continue;
        };
        if !checked.keeps(index) {
            continue;
        }
        count += payload.entries_to_write();
        bytes = bytes.saturating_add(payload.bytes_to_write(options));
        skipped.extend(
            std::mem::take(&mut payload.skipped)
                .into_iter()
                .map(|e| in_payload(index, raw, e)),
        );
        renamed.extend(
            std::mem::take(&mut payload.renamed)
                .into_iter()
                .map(|r| Renamed {
                    error: in_payload(index, raw, r.error),
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
    run.start(count, bytes);

    // What is in the destination already, before anything moves.
    let mut walk = Walk::default();
    checked.in_the_way(destination, &[], options, &mut walk)?;
    for (index, payload) in checked_payloads.iter().enumerate() {
        let index = index as u64;
        let (Some((payload, raw)), Some(item)) = (payload, checked.item(index)) else {
            continue;
        };
        let Ok(name) = &item.name else {
            continue;
        };
        if checked.keeps(index) {
            payload
                .in_the_way(destination, &name.components, options, &mut walk)
                .map_err(|e| in_payload(index, raw, e))?;
        }
    }
    // Its handles closed before anything moves, as Windows wants.
    drop(walk);

    let data = spool.open_dir(&[]).map_err(Error::global)?;
    let mut summary = Summary {
        skipped,
        renamed,
        ..Summary::default()
    };
    checked.place(
        destination,
        &data,
        run,
        options,
        &mut summary,
        |item, components, summary| {
            let Some(Some((payload, raw))) = checked_payloads.get_mut(item.index as usize) else {
                return Ok(());
            };
            let within = destination
                .within(components)
                .map_err(|kind| item.error(kind))?;
            payload
                .place(&within, &data, run, options, summary, |_, _, _| Ok(()))
                .map_err(|e| in_payload(item.index, raw, e))
        },
    )?;
    summary.damaged = run.take_damaged();
    Ok(summary)
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
    let options = &options.for_sink();
    extract_into(open, || Ok(state.target(options)), options)
}

/// [`extract_xar_to`] into the target `make` makes, once the archive is checked.
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
        writers: None,
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut xar = Reader::new(second);
    let decoding = decoding(options);
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
            let (layers, container, opened) = open_payload(&mut xar, &decoding).map_err(error)?;
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
