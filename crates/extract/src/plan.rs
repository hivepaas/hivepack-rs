//! What is to be extracted, the options, and the checks made on all of it
//! before anything is written: the limits that can be checked on what the
//! archive says, the same path named twice, links, and data that
//! overlaps.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::error::{Error, ErrorKind};
use crate::name::{Name, NameError};
use crate::origin::Origin;
use crate::progress::{Cancel, ProgressFn};

/// Limits on what an archive may write, against archive bombs. They count
/// the bytes actually written, not what the archive says: the declared
/// sizes are checked first, and the data is cut off where it passes them.
///
/// The defaults are a judgment, to be tuned on real archives: 100,000
/// entries, 4 GiB an entry, 16 GiB in all, and 2,000 bytes for each byte
/// of compressed data, once an entry has passed 1 MiB. Deflate tops out
/// near 1,032 to one, which a file of zeros reaches, so the ratio stops
/// only methods that go further (Deflate64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Entries in the archive.
    pub max_entries: u64,
    /// Bytes an entry writes.
    pub max_entry_size: u64,
    /// Bytes all entries write.
    pub max_total_size: u64,
    /// Bytes written for each byte of compressed data.
    pub max_ratio: u64,
    /// The bytes an entry writes before its ratio is checked.
    pub ratio_threshold: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_entries: 100_000,
            max_entry_size: 4 << 30,
            max_total_size: 16 << 30,
            max_ratio: 2_000,
            ratio_threshold: 1 << 20,
        }
    }
}

/// What to do with symbolic links.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Links {
    /// Refuse them (the default).
    #[default]
    Refuse,
    /// Write a file holding the link's target, as extractors on Windows do.
    AsFile,
    /// Create those whose target is relative and stays inside the
    /// destination, after every other entry, so that nothing is written
    /// through them; refuse the others. On Windows, creating a link takes a
    /// privilege that most accounts lack.
    Inside,
}

/// How names are taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Names {
    /// Refuse what [`check_name`](crate::check_name) refuses (the
    /// default).
    #[default]
    Strict,
    /// First drop what Python's `zipfile` drops: a leading `/`, a drive
    /// (`C:`), and `.`, `..` and empty components; then refuse what is
    /// still refused. Two extractors that clean names differently write
    /// different files, which is why this is not the default.
    Sanitize,
}

/// What to do with an entry that is refused for its name, as a link, or
/// as the same path as another.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnRefused {
    /// Stop, before anything is written (the default).
    #[default]
    Stop,
    /// Leave it out, and extract the rest; the entries left out are in
    /// [`Summary::skipped`](crate::Summary::skipped). The limits and data
    /// that overlaps still stop the extraction.
    Skip,
}

/// What permissions files get on Unix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Permissions {
    /// The entry's, masked as Python's `data` filter masks them: no
    /// setuid, setgid or sticky bit, nothing writable by group or others,
    /// readable and writable by the owner (the default).
    #[default]
    Masked,
    /// The entry's, without the setuid, setgid and sticky bits.
    Preserve,
    /// The system's defaults.
    Ignore,
}

/// What to do with the payloads of macOS packages, in a XAR archive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Packages {
    /// Extract them, as `pkgutil --expand-full` does: an entry named
    /// `Payload` or `Scripts` (a package's), or `Content` (a `.xip`
    /// file's), whose data is a cpio archive under its layers (gzip,
    /// pbzx), becomes a directory of that name, with the archive's files
    /// (the default).
    #[default]
    Expand,
    /// Write them as they are, as files.
    AsFiles,
}

/// Which entries to extract: told an entry's path, a component at a time, and
/// whether it is one of them.
pub type Select = Arc<dyn Fn(&[String]) -> bool + Send + Sync>;

/// How to extract.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Options {
    pub limits: Limits,
    /// The password encrypted entries are read with.
    pub password: Option<Vec<u8>>,
    pub links: Links,
    pub names: Names,
    /// Takes `\` in names for a separator, as PowerShell 5.1's
    /// `Compress-Archive` writes it; refused otherwise.
    pub backslash_separator: bool,
    pub on_refused: OnRefused,
    /// Replaces files that are there, which must be files: not links, not
    /// directories. Nothing is overwritten otherwise.
    pub overwrite: bool,
    pub permissions: Permissions,
    /// How long the extraction may take, from when it starts; none by
    /// default. It stops with [`ErrorKind::TimeLimit`] once past it.
    pub time_limit: Option<Duration>,
    /// A token that stops the extraction with [`ErrorKind::Cancelled`].
    pub cancel: Option<Cancel>,
    /// Told how far the extraction is: once the entries are checked, after
    /// each piece of data written (at most 64 KiB), and after each entry.
    pub progress: Option<ProgressFn>,
    /// The archive's mark of origin ([`Origin::of`]), written on every file
    /// extracted, and on macOS every directory created; a mark not written
    /// stops the extraction. None by default: the archive's path is the
    /// caller's.
    pub origin: Option<Origin>,
    /// What to do with a macOS package's payloads ([`extract_xar`](crate::extract_xar)).
    pub packages: Packages,
    /// Extracts only the entries this picks, the folders they are in made as
    /// they are needed. The others are as if not in the archive: not checked,
    /// not counted against the limits, not written; an entry whose name cannot
    /// be used is not picked. All of them by default. Data the picked ones
    /// depend on, in a solid block or stream, is still read.
    pub select: Option<Select>,
}

/// Shows the options, not the password or the progress function.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("limits", &self.limits)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .field("links", &self.links)
            .field("names", &self.names)
            .field("backslash_separator", &self.backslash_separator)
            .field("on_refused", &self.on_refused)
            .field("overwrite", &self.overwrite)
            .field("permissions", &self.permissions)
            .field("time_limit", &self.time_limit)
            .field("cancel", &self.cancel)
            .field("progress", &self.progress.as_ref().map(|_| ".."))
            .field("origin", &self.origin)
            .field("select", &self.select.as_ref().map(|_| ".."))
            .finish()
    }
}

/// What an entry is, as the archive says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Link,
    /// A hard link (tar, ISO 9660): a second name for a file extracted
    /// before it.
    HardLink,
    /// A device or FIFO (tar, ISO 9660), which is never created.
    Special,
}

/// An entry to extract.
pub(crate) struct Item {
    pub index: u64,
    pub raw_name: Vec<u8>,
    pub name: Result<Name, NameError>,
    pub kind: Kind,
    /// what the archive says it decompresses to
    pub size: u64,
    /// its compressed data
    pub compressed: u64,
    /// where its compressed data is in the archive, if it has any
    pub data: Option<Range<u64>>,
    /// Unix permission bits, if the archive has them
    pub mode: Option<u32>,
    pub mtime: Option<SystemTime>,
}

impl Item {
    pub(crate) fn error(&self, kind: ErrorKind) -> Error {
        Error::new(self.index, &self.raw_name, kind)
    }
}

/// A path as the checks see it: case folded and canonically decomposed, as
/// a case-insensitive file system, and macOS, would (see
/// [`unicode::key`](crate::unicode::key)).
pub(crate) fn fold(components: &[String]) -> String {
    crate::unicode::key(&components.join("/"))
}

/// What a path already is, among the entries checked.
struct Seen {
    spelling: Vec<String>,
    is_dir: bool,
    /// the first entry that names it, or that it is on the way to
    first: u64,
    /// whether an entry names it, not only has it on its way
    named: bool,
}

/// Why an entry is refused for itself, before the others are looked at.
fn refused(item: &Item, options: &Options) -> Option<ErrorKind> {
    match (&item.name, item.kind) {
        (Err(e), _) => Some(ErrorKind::Name(*e)),
        (Ok(_), Kind::Link) if options.links == Links::Refuse => Some(ErrorKind::Link),
        (Ok(_), Kind::Special) => Some(ErrorKind::Special),
        (Ok(_), _) => None,
    }
}

/// Checks the entries before anything is written: their number, what
/// they say of their sizes, their names, that no two name the same path
/// (ignoring case, and a directory one way and a file another), links,
/// and that no two share compressed data. The entries to
/// extract, with those refused but skipped (with [`OnRefused::Skip`])
/// left out, and the errors that left them out.
pub(crate) fn check<'a>(
    items: &'a [Item],
    options: &Options,
) -> Result<(Vec<&'a Item>, Vec<Error>), Error> {
    let limits = &options.limits;
    if items.len() as u64 > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    let mut total: u64 = 0;
    let mut seen: HashMap<String, Seen> = HashMap::new();
    for item in items {
        if let Some(select) = &options.select
            && !item
                .name
                .as_ref()
                .is_ok_and(|name| select(&name.components))
        {
            continue;
        }
        let refusal = match refused(item, options) {
            Some(kind) => Some(kind),
            None => {
                if item.size > limits.max_entry_size {
                    return Err(item.error(ErrorKind::EntryTooLarge));
                }
                total = total.saturating_add(item.size);
                if total > limits.max_total_size {
                    return Err(item.error(ErrorKind::TotalTooLarge));
                }
                match &item.name {
                    Ok(name) => {
                        duplicate(&mut seen, item, name).map(|first| ErrorKind::Duplicate { first })
                    }
                    Err(e) => Some(ErrorKind::Name(*e)),
                }
            }
        };
        match (refusal, options.on_refused) {
            (None, _) => kept.push(item),
            (Some(kind), OnRefused::Stop) => return Err(item.error(kind)),
            (Some(kind), OnRefused::Skip) => skipped.push(item.error(kind)),
        }
    }

    // Data that two entries share: the overlapping entries of Fifield's
    // archive bombs, which reuse one stream for many files.
    let mut ranges: Vec<(&Range<u64>, &Item)> = items
        .iter()
        .filter_map(|item| item.data.as_ref().map(|range| (range, item)))
        .filter(|(range, _)| !range.is_empty())
        .collect();
    ranges.sort_by_key(|(range, _)| (range.start, range.end));
    for pair in ranges.windows(2) {
        let ((before, first), (after, second)) = (pair[0], pair[1]);
        if after.start < before.end {
            return Err(second.error(ErrorKind::Overlap { other: first.index }));
        }
    }
    Ok((kept, skipped))
}

/// Records the path of `item`, and the directories on its way, in `seen`:
/// the entry it is the same path as, if one is. A link is a file here.
fn duplicate(seen: &mut HashMap<String, Seen>, item: &Item, name: &Name) -> Option<u64> {
    let components = &name.components;
    // The directories on the way.
    for end in 1..components.len() {
        let prefix = &components[..end];
        match seen.get(&fold(prefix)) {
            Some(other) if other.spelling != prefix || !other.is_dir => return Some(other.first),
            Some(_) => {}
            None => {
                seen.insert(
                    fold(prefix),
                    Seen {
                        spelling: prefix.to_vec(),
                        is_dir: true,
                        first: item.index,
                        named: false,
                    },
                );
            }
        }
    }
    let is_dir = item.kind == Kind::Dir;
    match seen.get_mut(&fold(components)) {
        // A directory named after files in it.
        Some(other) if is_dir && other.is_dir && !other.named && other.spelling == *components => {
            other.named = true;
            None
        }
        Some(other) => Some(other.first),
        None => {
            seen.insert(
                fold(components),
                Seen {
                    spelling: components.clone(),
                    is_dir,
                    first: item.index,
                    named: true,
                },
            );
            None
        }
    }
}
