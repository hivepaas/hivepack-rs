//! RAR archives: `hivepack-rar` reads them as UnRAR does, and this writes what
//! it reads by this crate's rules. Only with the feature `rar`, as it takes
//! UnRAR's license, which the rest of this crate does not.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::Path;

use hivepack_rar::{
    Archive, ExitCode, Extract, FileHeader, Format, HEAD_FILE, HostSystem, ReadAt, Redirection,
    WideString, name,
};

use crate::destination::Destination;
use crate::error::{Error, ErrorKind, RarProblem};
use crate::name::{NameError, check_name, prepare};
use crate::plan::{Item, Kind, Links, Names, Options, check, fold};
use crate::progress::Run;
use crate::tar::{Entry, LinkPlan, bytes_to_write, copy_of, finish_file, plan_links, write_from};
use crate::zip::{Summary, set_dir_times};

/// What the second reading must see again of an entry.
#[derive(PartialEq, Eq)]
struct Seen {
    name: WideString,
    unp_size: i64,
    pack_size: i64,
    unknown_size: bool,
    dir: bool,
    redir_type: Redirection,
    redir_name: WideString,
}

impl Seen {
    fn of(head: &FileHeader) -> Seen {
        Seen {
            name: head.file_name.clone(),
            unp_size: head.unp_size,
            pack_size: head.pack_size,
            unknown_size: head.unknown_unp_size,
            dir: head.dir,
            redir_type: head.redir_type,
            redir_name: head.redir_name.clone(),
        }
    }
}

fn rar_error(e: hivepack_rar::Error) -> ErrorKind {
    ErrorKind::Rar(e)
}

/// What [`Extract`] said of the entry last gone through, but for its data's
/// hash: what stops an extraction whatever becomes of the entry.
fn problem(extract: &Extract) -> Option<RarProblem> {
    if extract.missing_password {
        Some(RarProblem::MissingPassword)
    } else if extract.bad_password {
        Some(RarProblem::BadPassword)
    } else if extract.missing_volume {
        Some(RarProblem::MissingVolume)
    } else if extract.needs_previous_volume {
        Some(RarProblem::NeedsPreviousVolume)
    } else if extract.dictionary_too_large {
        Some(RarProblem::DictionaryTooLarge)
    } else if extract.unknown_format {
        Some(RarProblem::UnknownFormat)
    } else if extract.bad_link_target {
        Some(RarProblem::BrokenLink)
    } else {
        None
    }
}

/// A link's target as bytes: one that is not text is not UTF-8 either, which
/// the checks refuse.
fn wide_target(target: &[u32]) -> Vec<u8> {
    name::to_string(target).map_or_else(|| vec![0xff], String::into_bytes)
}

/// What the archive says of the current entry, its place `index`.
fn item_of<R: ReadAt>(arc: &Archive<R>, index: u64, options: &Options) -> Item {
    let head = &arc.file_head;
    let text = name::to_string(&head.file_name);
    let raw_name = name::to_string_lossy(&head.file_name).into_bytes();
    let name = match &text {
        None => Err(NameError::NotUtf8),
        Some(text) => {
            let prepared = prepare(
                text,
                options.backslash_separator,
                options.names == Names::Sanitize,
            );
            check_name(prepared.as_bytes())
        }
    };
    let kind = if head.dir {
        Kind::Dir
    } else {
        match head.redir_type {
            Redirection::None => Kind::File,
            Redirection::UnixSymlink | Redirection::WindowsSymlink | Redirection::Junction => {
                Kind::Link
            }
            Redirection::HardLink | Redirection::FileCopy => Kind::HardLink,
            _ => Kind::Special,
        }
    };
    // A size not known says nothing to check before writing: what is written
    // is what counts.
    let size = if kind == Kind::File && !head.unknown_unp_size {
        head.unp_size.max(0) as u64
    } else {
        0
    };
    Item {
        index,
        raw_name,
        name,
        kind,
        size,
        compressed: head.pack_size.max(0) as u64,
        // Headers follow one another, and data its header: none overlaps.
        data: None,
        mode: (head.hs_type == HostSystem::Unix).then_some(head.file_attr & 0o7777),
        mtime: head
            .mtime
            .is_set()
            .then(|| head.mtime.system_time())
            .flatten(),
    }
}

/// Whether the current entry goes on from the one before in a solid stream.
fn is_solid<R: ReadAt>(arc: &Archive<R>) -> bool {
    let head = &arc.file_head;
    // RAR 1.3 to 1.5 archives do not set a solid flag per file.
    head.solid || arc.solid && arc.format != Format::Rar50 && head.unp_ver <= 15
}

/// Makes each entry of a solid stream's compressed size its share of the
/// stream's, so that the ratio it is held to is the stream's, as with 7z's
/// folders: an entry that repeats one before it takes next to nothing.
fn share_solid(items: &mut [Item], solid: &[bool]) {
    let mut start = 0;
    while start < items.len() {
        let mut end = start + 1;
        while end < items.len() && solid[end] {
            end += 1;
        }
        let group = &mut items[start..end];
        let packed: u128 = group.iter().map(|item| u128::from(item.compressed)).sum();
        let unpacked: u128 = group.iter().map(|item| u128::from(item.size)).sum();
        if group.len() > 1 && unpacked > 0 {
            for item in group {
                let share = u128::from(item.size) * packed / unpacked;
                item.compressed = u64::try_from(share).unwrap_or(u64::MAX).max(1);
            }
        }
        start = end;
    }
}

type Entries = Vec<Entry<Seen>>;

/// What file copies write, which a hard link does not unless it is written as
/// a copy: those [`bytes_to_write`] counts already.
fn bytes_of_copies(
    entries: &[Entry<Seen>],
    items: &[Item],
    kept: &HashSet<u64>,
    plans: &HashMap<u64, LinkPlan>,
    options: &Options,
) -> u64 {
    if options.links == Links::AsFile {
        return 0;
    }
    // What each file written so far holds, for the copies after it.
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;
    for entry in entries {
        let Some(item) = entry.item.map(|at| &items[at]) else {
            continue;
        };
        let (true, Ok(name)) = (kept.contains(&item.index), &item.name) else {
            continue;
        };
        let bytes = match plans.get(&item.index) {
            Some(LinkPlan::Hard(target)) => {
                let bytes = sizes.get(&fold(target)).copied().unwrap_or(0);
                if entry.seen.redir_type == Redirection::FileCopy {
                    total = total.saturating_add(bytes);
                }
                bytes
            }
            _ => item.size,
        };
        sizes.insert(fold(&name.components), bytes);
    }
    total
}

/// The first reading: every entry, with what is read and passed over just as
/// the second reading's, no data decompressed.
fn read_headers<R: ReadAt>(
    arc: &mut Archive<R>,
    run: &Run<'_>,
    options: &Options,
) -> Result<(Entries, Vec<Item>), Error> {
    let mut extract = Extract::new();
    extract.headers_only = true;
    extract.link_targets = true;
    let (mut entries, mut items, mut solid) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        run.check().map_err(Error::global)?;
        let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
        let mut added = false;
        if size != 0 && arc.cur_header_type == HEAD_FILE {
            if arc.file_head.split_before {
                // The part in this volume of the entry before.
                if let Some(item) = items.last_mut() {
                    let item: &mut Item = item;
                    let part = arc.file_head.pack_size.max(0) as u64;
                    item.compressed = item.compressed.saturating_add(part);
                }
            } else {
                if items.len() as u64 >= options.limits.max_entries {
                    return Err(Error::global(ErrorKind::TooManyEntries));
                }
                let item = item_of(arc, items.len() as u64, options);
                entries.push(Entry {
                    seen: Seen::of(&arc.file_head),
                    item: Some(items.len()),
                    target: wide_target(&arc.file_head.redir_name),
                });
                solid.push(is_solid(arc));
                items.push(item);
                added = true;
            }
        }
        let go = extract
            .current_file(arc, size, &mut |_| Ok(()))
            .map_err(|e| Error::global(rar_error(e)))?;
        if let Some(found) = problem(&extract) {
            let kind = ErrorKind::RarEntry(found);
            return Err(match (added, items.last()) {
                (true, Some(item)) => item.error(kind),
                _ => Error::global(kind),
            });
        }
        if added
            && arc.format != Format::Rar50
            && extract.link_targets
            && let (Some(entry), Some(item)) = (entries.last_mut(), items.last())
            && item.kind == Kind::Link
        {
            entry.target = std::mem::take(&mut extract.link_target);
        }
        if extract.broken_file
            && let Some(item) = items.last()
        {
            return Err(item.error(ErrorKind::RarEntry(RarProblem::BrokenLink)));
        }
        if !go {
            break;
        }
    }
    // Damage that left the headers short of the end.
    if arc.broken_header || arc.exit_code() != ExitCode::Success {
        return Err(Error::global(ErrorKind::RarEntry(
            RarProblem::BrokenArchive,
        )));
    }
    share_solid(&mut items, &solid);
    Ok((entries, items))
}

/// Where an entry's data goes as [`Extract`] gives it out: a file, or nowhere
/// for what is only read through, as a solid stream's data before what is wanted.
struct Sink<'a> {
    file: Option<std::fs::File>,
    item: &'a Item,
    /// A size that is not known cannot be compared.
    known_size: bool,
    remaining: u64,
    written: u64,
    run: &'a Run<'a>,
    options: &'a Options,
    /// Why writing stopped.
    failed: Option<ErrorKind>,
}

impl Sink<'_> {
    fn check(&self, written: u64) -> Result<(), ErrorKind> {
        let limits = &self.options.limits;
        self.run.check()?;
        if written > self.remaining {
            return Err(ErrorKind::TotalTooLarge);
        }
        if self.file.is_none() {
            return Ok(());
        }
        if written > limits.max_entry_size {
            return Err(ErrorKind::EntryTooLarge);
        }
        if self.known_size && written > self.item.size {
            return Err(ErrorKind::SizeMismatch);
        }
        if written > limits.ratio_threshold
            && written > self.item.compressed.saturating_mul(limits.max_ratio)
        {
            return Err(ErrorKind::Ratio);
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let written = self.written.saturating_add(data.len() as u64);
        self.check(written).map_err(|kind| {
            self.failed = Some(kind);
            io::Error::other("stopped")
        })?;
        self.written = written;
        if self.file.is_some() && !self.known_size {
            self.run.more_to_write(data.len() as u64);
        }
        if let Some(file) = &mut self.file {
            if let Err(e) = file.write_all(data) {
                self.failed = Some(ErrorKind::Io(e));
                return Err(io::Error::other("stopped"));
            }
            self.run.wrote(data.len() as u64);
        }
        Ok(())
    }
}

/// Extracts the RAR archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`. Only with the feature `rar`.
///
/// `open` is given [`Options::password`] as UTF-8, or nothing, and is called
/// twice, and must give the same archive each time, with
/// [`Archive::open_with_password`], or [`Archive::open_volumes`] for a volume
/// of many. An archive with a broken header is best opened refusing it.
///
/// The first reading goes through the entries as the second will, without
/// decompressing, and checks them as [`extract_zip`](crate::extract_zip) does
/// (names, the same path twice, links, the sizes against the limits), and also
/// that no header is broken or cut short, no volume missing, and that RAR 5's
/// check takes the password; a QuickOpen record's copies of headers are what
/// both readings see, as they are what UnRAR's library sees. The second writes
/// them, each header compared with the first reading's ([`ErrorKind::Changed`]
/// if one differs). A file whose hash fails is removed, and the extraction
/// stops there ([`ErrorKind::RarEntry`]). A wrong password that RAR 3 and
/// earlier have nothing to check with shows as that.
///
/// Besides ZIP's rules: symbolic links are RAR 5's redirections, and RAR 4's
/// Unix links, whose target is their data. A Windows link or junction goes by
/// the same rules, which refuse its absolute or `\` targets. A hard link or
/// file copy is created only from a file extracted before it
/// ([`ErrorKind::HardLinkTarget`] otherwise); a file copy, and with
/// [`Links::AsFile`] a hard link, is a copy. A kind of link not known is
/// refused ([`ErrorKind::Special`]). A file in a solid stream is held to its
/// share of the stream's compressed data. Data of entries left out with
/// [`OnRefused::Skip`](crate::OnRefused::Skip) is still decompressed, as what
/// follows may need it, and counts against the total limit. Files get their
/// Unix permissions when the archive was made on Unix, and their modification
/// time. Recovery records are not used, and comments are left in the archive.
pub fn extract_rar<R, F>(
    mut open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error>
where
    R: ReadAt,
    F: FnMut(&str) -> Result<Archive<R>, hivepack_rar::Error>,
{
    let run = Run::new(options);
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }
    let password = options
        .password
        .as_ref()
        .map(|password| String::from_utf8_lossy(password).into_owned())
        .unwrap_or_default();

    let mut first = open(&password).map_err(|e| Error::global(rar_error(e)))?;
    let (entries, items) = read_headers(&mut first, &run, options)?;
    drop(first);
    let (kept, mut skipped) = check(&items, options)?;
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let is_copy = |at: usize| entries[at].seen.redir_type == Redirection::FileCopy;
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
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options).saturating_add(
            bytes_of_copies(&entries, &items, &kept_indexes, &plans, options),
        ),
    );

    let destination = Destination::open(destination, options.origin.as_ref())
        .map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut summary = Summary {
        skipped,
        ..Summary::default()
    };

    let mut arc = open(&password).map_err(|e| Error::global(rar_error(e)))?;
    let mut extract = Extract::new();
    extract.link_targets = true;
    let mut next = 0;
    // What the entries not written read through.
    let mut read_through = 0u64;
    loop {
        run.check().map_err(Error::global)?;
        let size = arc.read_header().map_err(|e| Error::global(rar_error(e)))?;
        let mut current = None;
        if size != 0 && arc.cur_header_type == HEAD_FILE && !arc.file_head.split_before {
            let at = next;
            next += 1;
            let changed = || {
                let raw = name::to_string_lossy(&arc.file_head.file_name);
                Error::new(at as u64, raw.as_bytes(), ErrorKind::Changed)
            };
            let entry = entries.get(at).ok_or_else(changed)?;
            if entry.seen != Seen::of(&arc.file_head) {
                return Err(changed());
            }
            current = Some(at);
        }
        let item = current.map(|at| &items[at]);
        let plan = item.and_then(|item| plans.get(&item.index));
        let wanted = item
            .filter(|item| kept_indexes.contains(&item.index) && !created_later(item))
            .and_then(|item| item.name.as_ref().ok().map(|name| (item, name)));

        // What has no data here comes first: only files are written as read.
        let mut created = None;
        let mut link_place = None;
        if let Some((item, name)) = wanted {
            let error = |kind| item.error(kind);
            if item.kind == Kind::Dir {
                destination.directory(&name.components).map_err(error)?;
                summary.directories += 1;
                run.entry_done();
            } else {
                let (last, parents) = name
                    .components
                    .split_last()
                    .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
                let dir = destination.directory(parents).map_err(error)?;
                let copy = current.is_some_and(is_copy);
                if let Some(LinkPlan::Hard(target)) = plan {
                    if options.links != Links::AsFile && !copy {
                        let (target_last, target_parents) = target
                            .split_last()
                            .ok_or_else(|| error(ErrorKind::HardLinkTarget))?;
                        let target_dir = destination.directory(target_parents).map_err(error)?;
                        Destination::hard_link(&target_dir, target_last, &dir, last)
                            .map_err(error)?;
                        summary.files += 1;
                        run.entry_done();
                    } else {
                        let file = Destination::create_file(&dir, last, options.overwrite)
                            .map_err(error)?;
                        let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
                        let written =
                            copy_of(&destination, target, item, file, remaining, &run, options)
                                .inspect_err(|_| {
                                    let _ = dir.remove_file(last);
                                })
                                .map_err(error)?;
                        summary.files += 1;
                        summary.bytes += written;
                        run.entry_done();
                    }
                } else if matches!(plan, Some(LinkPlan::SymlinkAsFile)) {
                    link_place = Some((dir, last.clone()));
                } else {
                    let file =
                        Destination::create_file(&dir, last, options.overwrite).map_err(error)?;
                    created = Some((file.into_std(), dir, last.clone()));
                }
            }
        }

        let (file, place) = match created {
            Some((file, dir, last)) => (Some(file), Some((dir, last))),
            None => (None, None),
        };
        let as_file = file.is_some();
        let remove = |place: &Option<(cap_std::fs::Dir, String)>| {
            if let Some((dir, last)) = place {
                let _ = dir.remove_file(last);
            }
        };
        let fallback = Item {
            index: u64::MAX,
            raw_name: Vec::new(),
            name: Err(NameError::Empty),
            kind: Kind::Special,
            size: 0,
            compressed: 0,
            data: None,
            mode: None,
            mtime: None,
        };
        let about = item.unwrap_or(&fallback);
        let total_left = options.limits.max_total_size;
        let mut sink = Sink {
            file,
            item: about,
            known_size: !arc.file_head.unknown_unp_size,
            remaining: if as_file {
                total_left.saturating_sub(summary.bytes)
            } else {
                total_left.saturating_sub(read_through)
            },
            written: 0,
            run: &run,
            options,
            failed: None,
        };
        let link_file = link_place.is_some();
        let result = extract.current_file(&mut arc, size, &mut |data| sink.write(data));
        let at_error = |kind| match item {
            Some(item) => item.error(kind),
            None => Error::global(kind),
        };
        let go = match result {
            Ok(go) => go,
            Err(e) => {
                remove(&place);
                return Err(at_error(sink.failed.take().unwrap_or_else(|| rar_error(e))));
            }
        };
        let Sink { file, written, .. } = sink;
        if let Some(found) = problem(&extract) {
            remove(&place);
            return Err(at_error(ErrorKind::RarEntry(found)));
        }
        if (as_file || link_file) && extract.broken_file {
            remove(&place);
            return Err(at_error(ErrorKind::RarEntry(RarProblem::BrokenData)));
        }
        if let (Some(at), true) = (current, arc.format != Format::Rar50)
            && items[at].kind == Kind::Link
            && extract.link_target != entries[at].target
        {
            remove(&place);
            return Err(at_error(ErrorKind::Changed));
        }
        if as_file {
            let Some(file) = file else {
                return Err(at_error(ErrorKind::SizeMismatch));
            };
            if !arc.file_head.unknown_unp_size
                && written != about.size
                && !arc.file_head.split_after
            {
                remove(&place);
                return Err(at_error(ErrorKind::SizeMismatch));
            }
            finish_file(&file, about, options)
                .inspect_err(|_| remove(&place))
                .map_err(at_error)?;
            summary.files += 1;
            summary.bytes += written;
            run.entry_done();
        } else if link_file {
            // A link written as a file holding its target, with Links::AsFile.
            if let (Some(at), Some((dir, last))) = (current, &link_place) {
                let target = &entries[at].target;
                let file =
                    Destination::create_file(dir, last, options.overwrite).map_err(at_error)?;
                let remaining = options.limits.max_total_size.saturating_sub(summary.bytes);
                let written = write_from(
                    &mut &target[..],
                    about,
                    target.len() as u64,
                    file,
                    remaining,
                    false,
                    &run,
                    options,
                )
                .map_err(at_error)?;
                summary.files += 1;
                summary.bytes += written;
                run.entry_done();
            }
        } else {
            read_through = read_through.saturating_add(written);
        }
        if !go {
            break;
        }
    }
    if next != entries.len() {
        return Err(Error::global(ErrorKind::Changed));
    }
    if arc.broken_header {
        return Err(Error::global(ErrorKind::RarEntry(
            RarProblem::BrokenArchive,
        )));
    }

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
