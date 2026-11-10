//! Archives read once into a folder: tar, cpio and XAR, whose entries come one
//! after the other in a stream (see the repository's `docs/extract-once.md`).
//!
//! Each file's data is written as it comes into a private folder in the
//! destination, named by its place in the archive. Once the stream has ended,
//! the entries are checked as after a first reading, what is in the destination
//! already is looked at, and only then do they move into place, by hard link or
//! rename. If anything fails before, the private folder goes, and nothing of the
//! archive appears. What each format reads is its own; this is what they share:
//! the private folder, a file's data written into it, the checks, the moving
//! into place, and a thread reading the stream ahead.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc;

use cap_std::fs::Dir;

use crate::extract::destination::{Counted, Destination, Target, Walk};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::Name;
use crate::extract::plan::{Item, Kind, OnDamaged, Options, Renamed, check, picked, settle};
use crate::extract::progress::Run;
use crate::extract::tar::{
    Entry, LinkPlan, bytes_to_write, copy_of, cut_short, plan_links, write_from, write_into,
};
use crate::extract::writers::Writers;
use crate::extract::zip::{Summary, open_destination, set_dir_times};

/// The directory of a private folder that files' data is written to.
const SPOOL: &str = "data";

/// The archive at `path` extracted by `body`, given the destination, the
/// private folder's files' destination in it, and the run: the destination
/// opened, or made, what a process that died left there removed, and the
/// private folder made; once `body` is done, however it ends, the private
/// folder is removed, and the destination too if this made it and `body`
/// failed. Nothing of the archive is left then.
pub(crate) fn into_folder(
    path: &Path,
    options: &Options,
    body: impl FnOnce(&Destination<'_>, &Destination<'_>, &Run<'_>) -> Result<Summary, Error>,
) -> Result<Summary, Error> {
    let run = Run::new(options);
    let made = std::fs::symlink_metadata(path).is_err();
    let destination = open_destination(path, options)?;
    // What a process that died left here.
    destination.remove_stale();
    let staging = destination.staging(path).map_err(Error::global)?;
    // The files' data, each named by its place, at the root of a destination
    // of its own, the private folder's `data`: each is made without opening a
    // directory for it. Its handle closed before the folder is removed.
    let result = staging
        .data
        .within(&[SPOOL.to_owned()])
        .map_err(Error::global)
        .and_then(|spool| body(&destination, &spool, &run));
    destination.remove_staging(staging);
    // Its handle closed first: Windows removes no folder that is open.
    drop(destination);
    if result.is_err() && made {
        let _ = std::fs::remove_dir(path);
    }
    result
}

/// What the one reading wrote of a file into the private folder: its data
/// whole, or damaged, with how much of it was kept, to be asked about with
/// [`Options::on_damaged`](crate::extract::Options::on_damaged) when its turn
/// comes to be moved into place.
pub(crate) enum Spooled {
    Whole(u64),
    Damaged(ErrorKind, u64),
}

impl Spooled {
    /// The bytes written.
    pub(crate) fn bytes(&self) -> u64 {
        match self {
            Spooled::Whole(bytes) | Spooled::Damaged(_, bytes) => *bytes,
        }
    }
}

/// What the one reading found: the entries and items, as a first reading finds
/// them; how the stream was cut short, if it was and that is gone on from; and
/// what was written of each file, by its item's index, under which name in the
/// private folder.
#[derive(Default)]
pub(crate) struct ReadOnce {
    pub(crate) entries: Vec<Entry<()>>,
    pub(crate) items: Vec<Item>,
    pub(crate) cut: Option<ErrorKind>,
    pub(crate) spooled: HashMap<u64, (String, Spooled)>,
}

/// Whether the data of `item`, `size` bytes, is written into the private folder:
/// a file the checks may keep, picked, whose name is one or may be renamed to
/// one, within the limit on one entry.
pub(crate) fn may_keep(item: &Item, size: u64, options: &Options) -> bool {
    item.kind == Kind::File
        && picked(item, options)
        && item
            .name
            .as_ref()
            .map_or_else(|e| e.is_unnamable(), |_| true)
        && size <= options.limits.max_entry_size
}

/// `item`, as `size` bytes of its data are written into the private folder:
/// named `name`, at its root; its name kept as text, for what an error says.
pub(crate) fn spool_item(item: &Item, name: &str, size: u64) -> Item {
    Item {
        index: item.index,
        raw_name: item.raw_name.clone(),
        text: item.text.clone(),
        name: Ok(Name {
            components: vec![name.to_owned()],
            is_dir: false,
        }),
        kind: Kind::File,
        size,
        compressed: size,
        data: None,
        mode: item.mode,
        mtime: item.mtime,
        owner: item.owner.clone(),
        xattrs: item.xattrs.clone(),
    }
}

/// What reading an entry's data failed with: the archive's error, out of the
/// `io::Error` that holds it.
pub(crate) type DataError = fn(io::Error) -> ErrorKind;

/// The `size` bytes of `item`'s data, read from `r`, written into `spool` as
/// `name`: by the thread `writers` hand it to, where there are, it fits and has
/// no holes, or here. With `ends`, `r` must end after them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spool_data<'a, R: Read>(
    r: &mut R,
    item: &Item,
    size: u64,
    name: &str,
    spool: &Destination<'_>,
    remaining: u64,
    (holes, ends): (bool, bool),
    data_error: DataError,
    run: &Run<'_>,
    options: &Options,
    writers: Option<&Writers<'a>>,
) -> Result<Spooled, Error> {
    match writers.filter(|_| !holes) {
        Some(writers) => {
            match writers.file(r, spool_item(item, name, size), size, remaining, ends)? {
                None => Ok(Spooled::Whole(size)),
                Some(mut replay) => spool_from(
                    &mut replay,
                    item,
                    size,
                    name,
                    spool,
                    remaining,
                    false,
                    data_error,
                    run,
                    options,
                ),
            }
        }
        None => spool_from(
            r, item, size, name, spool, remaining, holes, data_error, run, options,
        ),
    }
}

/// Writes the `size` bytes of `item`'s data, read from `r`, into `spool` as
/// `name`, with its time, permissions and what else a file is given: whole, or
/// damaged where [`Options::on_damaged`](crate::extract::Options::on_damaged)
/// may go on from it, what was read of it kept, to be asked about later.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spool_from(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    name: &str,
    spool: &Destination<'_>,
    remaining: u64,
    holes: bool,
    data_error: DataError,
    run: &Run<'_>,
    options: &Options,
) -> Result<Spooled, Error> {
    let file = spool
        .create_file(
            &spool_item(item, name, size),
            &[name.to_owned()],
            Some(size),
            options,
        )
        .map_err(|kind| item.error(kind))?;
    spool_into(
        Counted { file, len: 0 },
        r,
        item,
        size,
        name,
        spool,
        remaining,
        holes,
        data_error,
        run,
        options,
    )
}

/// [`spool_from`] into `file`, made in `spool` as `name`, which may hold the
/// start of the data already: the rest read from `r`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spool_into(
    mut file: Counted<std::fs::File>,
    r: &mut impl Read,
    item: &Item,
    size: u64,
    name: &str,
    spool: &Destination<'_>,
    remaining: u64,
    holes: bool,
    data_error: DataError,
    run: &Run<'_>,
    options: &Options,
) -> Result<Spooled, Error> {
    let components = &[name.to_owned()];
    let error = |kind| item.error(kind);
    let there = file.len;
    let written = if there > size {
        Err(ErrorKind::SizeMismatch)
    } else if there > remaining {
        Err(ErrorKind::TotalTooLarge)
    } else {
        write_into(
            r,
            size - there,
            &mut file,
            remaining - there,
            holes,
            data_error,
            run,
            options,
        )
        .map(|written| written + there)
    };
    let done = match written {
        Ok(written) => Spooled::Whole(written),
        Err(kind) if kind.is_damage() && options.on_damaged.is_some() => {
            Spooled::Damaged(kind, file.len)
        }
        Err(kind) => {
            drop(file);
            spool.remove_file(components);
            return Err(error(kind));
        }
    };
    if let Err(kind) = spool.finish_file(file.file, &spool_item(item, name, size), options) {
        spool.remove_file(components);
        return Err(error(kind));
    }
    run.entry_done();
    Ok(done)
}

/// The entries of an archive read once, checked as after a first reading:
/// those kept, their links' plans, and those left out or renamed.
pub(crate) struct Checked {
    read: ReadOnce,
    /// The places of the entries to extract in `read.items`.
    kept: Vec<usize>,
    /// Their indexes, but the links whose plans were refused.
    kept_indexes: HashSet<u64>,
    plans: HashMap<u64, LinkPlan>,
    /// The errors of the entries left out, with
    /// [`OnRefused::Skip`](crate::extract::OnRefused::Skip).
    pub(crate) skipped: Vec<Error>,
    /// The entries renamed, as
    /// [`Options::on_unnamable`](crate::extract::Options::on_unnamable) said.
    pub(crate) renamed: Vec<Renamed>,
}

/// What one reading found, checked as a first reading's entries are: `settle`
/// (the names this system cannot take, asked about once), `check`, and the
/// links' plans. With `refused`, the errors of the entries the reading refused
/// itself, put in the archive's order with those the checks leave out before
/// the links are planned, as cpio and XAR do.
pub(crate) fn check_read(
    mut read: ReadOnce,
    refused: Option<Vec<Error>>,
    options: &Options,
) -> Result<Checked, Error> {
    let settled = settle(&mut read.items, options)?;
    let (kept, mut skipped) = check(&read.items, &settled, options)?;
    if let Some(refused) = refused {
        skipped.splice(0..0, refused);
        skipped.sort_by_key(|e| e.index);
    }
    let plans = plan_links(&read.entries, &read.items, &kept, options, &mut skipped)?;
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    // An item's index is its entry's, and items come in their order.
    let place: HashMap<u64, usize> = read
        .items
        .iter()
        .enumerate()
        .map(|(at, item)| (item.index, at))
        .collect();
    let kept = kept
        .iter()
        .filter_map(|item| place.get(&item.index).copied())
        .collect();
    Ok(Checked {
        read,
        kept,
        kept_indexes,
        plans,
        skipped,
        renamed: settled.renamed,
    })
}

impl Checked {
    /// How many entries are moved into place, or made.
    pub(crate) fn entries_to_write(&self) -> u64 {
        self.kept_indexes.len() as u64
    }

    /// The bytes they hold: the files' data, and with
    /// [`Links::AsFile`](crate::extract::Links::AsFile) the targets of symbolic
    /// links and the copies of hard links.
    pub(crate) fn bytes_to_write(&self, options: &Options) -> u64 {
        bytes_to_write(
            &self.read.entries,
            &self.read.items,
            &self.kept_indexes,
            &self.plans,
            options,
        )
    }

    /// Whether the entry at `index` is kept.
    pub(crate) fn keeps(&self, index: u64) -> bool {
        self.kept_indexes.contains(&index)
    }

    /// The item of the entry at `index`, if it has one.
    pub(crate) fn item(&self, index: u64) -> Option<&Item> {
        let entry = self.read.entries.get(usize::try_from(index).ok()?)?;
        entry.item.map(|at| &self.read.items[at])
    }

    /// The item of `entry`, if it is kept.
    fn placed<'s>(&'s self, entry: &Entry<()>) -> Option<&'s Item> {
        entry
            .item
            .map(|at| &self.read.items[at])
            .filter(|item| self.kept_indexes.contains(&item.index))
    }

    /// Whether what is in `destination` already, under `prefix` (a package's
    /// payload's folder), is in the way of an entry to move there, before any
    /// does ([`Destination::in_the_way`]): the parents opened through `walk`.
    pub(crate) fn in_the_way(
        &self,
        destination: &Destination<'_>,
        prefix: &[String],
        options: &Options,
        walk: &mut Walk,
    ) -> Result<(), Error> {
        for item in self.read.entries.iter().filter_map(|e| self.placed(e)) {
            let Ok(name) = &item.name else {
                continue;
            };
            let file = match (item.kind, self.plans.get(&item.index)) {
                (Kind::File, _) | (_, Some(LinkPlan::SymlinkAsFile)) => true,
                (Kind::HardLink, _) => destination.copies_hard_links(options),
                _ => false,
            };
            let components: Cow<'_, [String]> = if prefix.is_empty() {
                Cow::Borrowed(&name.components)
            } else {
                Cow::Owned(prefix.iter().chain(&name.components).cloned().collect())
            };
            destination
                .in_the_way(
                    &components,
                    item.kind == Kind::Dir,
                    file && options.overwrite,
                    walk,
                )
                .map_err(|kind| item.error(kind))?;
        }
        Ok(())
    }

    /// Moves the entries into `destination`, in the archive's order, their files
    /// from `data`, the private folder's: directories made, files moved, hard
    /// links made or copied, links as files written; then a stream cut short is
    /// asked about, the symbolic links are created, and the directories get
    /// their times. `within` is called with each directory made, its path's
    /// components and the summary, to go on into it: a package's payload.
    pub(crate) fn place(
        &mut self,
        destination: &Destination<'_>,
        data: &Dir,
        run: &Run<'_>,
        options: &Options,
        summary: &mut Summary,
        mut within: impl FnMut(&Item, &[String], &mut Summary) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Checked {
            read:
                ReadOnce {
                    entries,
                    items,
                    cut,
                    spooled,
                },
            kept,
            kept_indexes,
            plans,
            ..
        } = self;
        let created_later =
            |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
        let mut walk = Walk::default();
        for entry in entries.iter() {
            let Some(item) = entry
                .item
                .map(|at| &items[at])
                .filter(|item| kept_indexes.contains(&item.index))
            else {
                continue;
            };
            if created_later(item) {
                continue;
            }
            let Ok(name) = &item.name else {
                continue;
            };
            let error = |kind| item.error(kind);
            let components = &name.components;
            run.check().map_err(error)?;
            if item.kind == Kind::Dir {
                Target::directory(destination, item, components).map_err(error)?;
                summary.directories += 1;
                run.entry_done();
                within(item, components, summary)?;
                continue;
            }
            let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
            let written = match plans.get(&item.index) {
                Some(LinkPlan::Hard(target)) if !destination.copies_hard_links(options) => {
                    destination
                        .hard_link(item, components, target)
                        .map_err(error)?;
                    summary.files += 1;
                    run.entry_done();
                    continue;
                }
                Some(LinkPlan::Hard(target)) => {
                    copy_of(destination, target, item, remaining, run, options)?
                }
                Some(LinkPlan::SymlinkAsFile) => write_from(
                    &mut &entry.target[..],
                    item,
                    entry.target.len() as u64,
                    destination,
                    remaining,
                    false,
                    run,
                    options,
                )?,
                _ => {
                    let mut move_it = |spooled_name: &str| {
                        destination.place(
                            data,
                            spooled_name,
                            components,
                            options.overwrite,
                            &mut walk,
                        )
                    };
                    match spooled.remove(&item.index) {
                        Some((spooled_name, Spooled::Whole(bytes))) => {
                            move_it(&spooled_name).map_err(error)?;
                            summary.files += 1;
                            summary.bytes += bytes;
                            run.wrote(bytes);
                        }
                        Some((spooled_name, Spooled::Damaged(kind, kept))) => {
                            match run.decide(item, kind)? {
                                (OnDamaged::Keep, damage) => {
                                    destination.damaged(&damage);
                                    move_it(&spooled_name).map_err(error)?;
                                    run.damaged(damage, Some(kept));
                                    summary.files += 1;
                                    summary.bytes += kept;
                                    run.wrote(kept);
                                }
                                (_, damage) => {
                                    destination.damaged(&damage);
                                    run.damaged(damage, None);
                                }
                            }
                        }
                        // Not read: the checks keep no file they did not let be read.
                        None => {
                            return Err(error(ErrorKind::Io(io::Error::other(
                                "a file kept that was not read",
                            ))));
                        }
                    }
                    run.entry_done();
                    continue;
                }
            };
            if let Some(written) = written {
                summary.files += 1;
                summary.bytes += written;
            }
            run.entry_done();
        }
        drop(walk);
        if let Some(kind) = cut.take() {
            cut_short(entries, kind, run)?;
        }

        let kept: Vec<&Item> = kept.iter().map(|&at| &items[at]).collect();
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

        set_dir_times(destination, &kept, run)
    }
}

/// `checked`, an archive read once into `spool`, moved into `destination`: the
/// totals told, what is in the destination looked at before anything moves,
/// then each entry moved into place.
pub(crate) fn move_into_place(
    mut checked: Checked,
    destination: &Destination<'_>,
    spool: &Destination<'_>,
    run: &Run<'_>,
    options: &Options,
) -> Result<Summary, Error> {
    run.start(checked.entries_to_write(), checked.bytes_to_write(options));
    // Its handles closed before anything moves, as Windows wants.
    checked.in_the_way(destination, &[], options, &mut Walk::default())?;
    let data = spool.open_dir(&[]).map_err(Error::global)?;
    let mut summary = Summary {
        skipped: std::mem::take(&mut checked.skipped),
        renamed: std::mem::take(&mut checked.renamed),
        ..Summary::default()
    };
    checked.place(destination, &data, run, options, &mut summary, |_, _, _| {
        Ok(())
    })?;
    summary.damaged = run.take_damaged();
    summary.owners_left = destination.owners_left();
    Ok(summary)
}

/// What a thread reading ahead reads at a time, and how many of those may
/// wait to be read.
pub(crate) const AHEAD: usize = 1 << 20;
const AHEAD_PIECES: usize = 4;

/// `r` read ahead by a thread of its own while `use_it` reads what it read,
/// [`AHEAD`] bytes at a time, at most [`AHEAD_PIECES`] of them waiting: a
/// compressed archive's decompression, on that thread, goes on while the
/// caller's reads the archive and hands its files to the threads that write
/// them, as `zstd -dc | tar x` runs in two processes. What is read, and the
/// errors, are `r`'s, in order. Once `use_it` is done, the thread stops at its
/// next piece. Where no thread can be made, the reader's first read says why.
pub(crate) fn read_ahead<R: Read + Send, T>(r: R, use_it: impl FnOnce(Ahead) -> T) -> T {
    std::thread::scope(|scope| {
        let (full, read) = mpsc::sync_channel::<io::Result<Vec<u8>>>(AHEAD_PIECES);
        let (back, empty) = mpsc::sync_channel::<Vec<u8>>(AHEAD_PIECES + 2);
        let started = std::thread::Builder::new()
            .name("read-ahead".into())
            .spawn_scoped(scope, move || {
                let mut r = r;
                loop {
                    let mut piece = empty.try_recv().unwrap_or_default();
                    piece.resize(AHEAD, 0);
                    let mut got = 0;
                    let read = loop {
                        match r.read(&mut piece[got..]) {
                            Ok(0) => break Ok(()),
                            Ok(n) => {
                                got += n;
                                if got == piece.len() {
                                    break Ok(());
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => break Err(e),
                        }
                    };
                    piece.truncate(got);
                    let end = got == 0;
                    let sent = match read {
                        Ok(()) if end => full.send(Ok(piece)).map(|()| true),
                        Ok(()) => full.send(Ok(piece)).map(|()| false),
                        Err(e) => {
                            if got > 0 {
                                let _ = full.send(Ok(piece));
                            }
                            full.send(Err(e)).map(|()| true)
                        }
                    };
                    // Ended, or no one is reading any more.
                    if sent.unwrap_or(true) {
                        break;
                    }
                }
            });
        use_it(Ahead {
            read,
            back,
            piece: Vec::new(),
            at: 0,
            ended: false,
            unstarted: started.err(),
        })
    })
}

/// What [`read_ahead`]'s thread read, as a reader.
pub(crate) struct Ahead {
    read: mpsc::Receiver<io::Result<Vec<u8>>>,
    back: mpsc::SyncSender<Vec<u8>>,
    piece: Vec<u8>,
    at: usize,
    ended: bool,
    /// Why the thread could not be made, if it could not.
    unstarted: Option<io::Error>,
}

impl Read for Ahead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.unstarted.take() {
            self.ended = true;
            return Err(e);
        }
        while self.at == self.piece.len() {
            if self.ended || buf.is_empty() {
                return Ok(0);
            }
            match self.read.recv() {
                Ok(Ok(piece)) => {
                    if piece.is_empty() {
                        self.ended = true;
                    }
                    let done = std::mem::replace(&mut self.piece, piece);
                    let _ = self.back.try_send(done);
                    self.at = 0;
                }
                Ok(Err(e)) => {
                    self.ended = true;
                    return Err(e);
                }
                // The thread is gone without a word: not one that ended.
                Err(_) => {
                    self.ended = true;
                    return Err(io::Error::other("the thread reading ahead is gone"));
                }
            }
        }
        let n = buf.len().min(self.piece.len() - self.at);
        buf[..n].copy_from_slice(&self.piece[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is read ahead is what the reader gives, at lengths around a
    /// piece's; an error comes after the bytes before it, in order.
    #[test]
    fn read_ahead_is_the_reader() {
        for len in [
            0,
            1,
            4095,
            AHEAD - 1,
            AHEAD,
            AHEAD + 1,
            3 * AHEAD + 7,
            9 * AHEAD,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 977) as u8).collect();
            let got = read_ahead(&data[..], |mut r| {
                let mut out = Vec::new();
                r.read_to_end(&mut out).map(|_| out)
            });
            assert!(got.is_ok_and(|got| got == data), "{len}");
        }
        /// Some bytes, then an error.
        struct Failing(usize);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::other("damaged"));
                }
                let n = buf.len().min(self.0).min(1000);
                buf[..n].fill(7);
                self.0 -= n;
                Ok(n)
            }
        }
        let (read, error) = read_ahead(Failing(AHEAD + 5000), |mut r| {
            let mut out = Vec::new();
            let error = r.read_to_end(&mut out).err().map(|e| e.to_string());
            (out.len(), error)
        });
        assert_eq!((read, error.as_deref()), (AHEAD + 5000, Some("damaged")));
    }

    /// A reader that stops early lets the thread go: the call returns.
    #[test]
    fn read_ahead_stops_with_its_reader() {
        let data = vec![1u8; 20 * AHEAD];
        let first = read_ahead(&data[..], |mut r| {
            let mut b = [0u8; 10];
            r.read_exact(&mut b).map(|()| b[0])
        });
        assert!(first.is_ok_and(|b| b == 1));
    }
}
