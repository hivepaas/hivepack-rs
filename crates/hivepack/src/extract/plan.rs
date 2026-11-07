//! What is to be extracted, the options, and the checks made on all of it
//! before anything is written: the limits that can be checked on what the
//! archive says, the same path named twice, links, and data that
//! overlaps.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::{
    Checks, Name, NameError, NameRules, link_on_the_way, link_target, link_text, renamed,
};
use crate::extract::origin::Origin;
use crate::extract::progress::{Cancel, ProgressFn};
use crate::threads::Threads;

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
    /// through them; refuse the others, or ask about them
    /// ([`Options::on_links_outside`]). On Windows, creating a link takes a
    /// privilege that most accounts lack.
    Inside,
    /// Create every one, its target as the archive has it, absolute or
    /// leading outside the destination too, as tar does: after every other
    /// entry, as with [`Links::Inside`], so that nothing is written through
    /// them, and a name under a link is still the same path as the link
    /// ([`ErrorKind::Duplicate`]). Only a target that is no path is refused
    /// ([`ErrorKind::LinkTarget`]): empty, not UTF-8, or with a control
    /// character; and on Windows, into a folder, one from a root or a drive,
    /// which cap-std does not create. What is extracted can then lead elsewhere on the
    /// system: for archives that are trusted, as a backup of one's own files.
    Any,
}

/// How names are taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Names {
    /// Refuse what [`check_name`](crate::extract::check_name) refuses (the
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
    /// [`Summary::skipped`](crate::extract::Summary::skipped). The limits and data
    /// that overlaps still stop the extraction.
    Skip,
}

/// What to do with an entry whose data is damaged: it fails its check (a CRC, a
/// hash, an authentication code), cannot be decompressed, or ends before its
/// size ([`ErrorKind::is_damage`]). Asked of [`Options::on_damaged`] for each
/// such entry; the other errors, and among them every check against what an
/// archive can do to the destination, stop the extraction whatever it says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnDamaged {
    /// Stop, the entry not left (the default).
    #[default]
    Stop,
    /// Leave the entry out, and go on with the next.
    Skip,
    /// Keep what was read of the entry's data, as it came, and go on with the
    /// next.
    Keep,
}

/// Told an entry's damage, and what to do with it: called on the extracting
/// thread, which waits for its answer. With [`Options::threads`], on the
/// thread writing the entry, about one entry at a time.
pub type OnDamagedFn = Arc<dyn Fn(&Error) -> OnDamaged + Send + Sync>;

/// What to do with the entries whose names this system cannot take, asked once,
/// of all of them, before anything is written ([`Options::on_unnamable`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnUnnamable {
    /// Stop, before anything is written (the default).
    #[default]
    Stop,
    /// Leave them out, and extract the rest; they are in
    /// [`Summary::skipped`](crate::extract::Summary::skipped).
    Skip,
    /// Give each a name this system takes, and extract it under that; they are
    /// in [`Summary::renamed`](crate::extract::Summary::renamed). One that cannot
    /// be renamed is left out.
    Rename,
}

/// Told the entries whose names this system cannot take, each with why, and what
/// to do with them: called once, on the extracting thread, which waits for its
/// answer.
pub type OnUnnamableFn = Arc<dyn Fn(&[Error]) -> OnUnnamable + Send + Sync>;

/// What to do with the symbolic links whose targets lead outside the destination,
/// asked once, of all of them, before anything is written
/// ([`Options::on_links_outside`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnLinksOutside {
    /// Stop, before anything is written (the default).
    #[default]
    Stop,
    /// Leave them out, and extract the rest; they are in
    /// [`Summary::skipped`](crate::extract::Summary::skipped).
    Skip,
    /// Create them, as [`Links::Any`] creates links: after every other entry,
    /// their targets as the archive has them.
    Create,
}

/// A symbolic link whose target leads outside the destination, as
/// [`Options::on_links_outside`] is told it.
#[derive(Debug)]
#[non_exhaustive]
pub struct LinkOutside {
    /// The link, and why its target is refused ([`ErrorKind::LinkTarget`],
    /// [`ErrorKind::LinkChain`]).
    pub error: Error,
    /// Its target, as the archive has it.
    pub target: String,
}

/// Told the symbolic links whose targets lead outside the destination, and what
/// to do with them: called once, on the extracting thread, which waits for its
/// answer.
pub type OnLinksOutsideFn = Arc<dyn Fn(&[LinkOutside]) -> OnLinksOutside + Send + Sync>;

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

/// Makes text of an entry's name whose bytes are not UTF-8 and that the archive
/// says nothing certain of: the names of old ZIP, tar, cpio and other archives,
/// in whatever encoding the system that made them used. Told the bytes, and what
/// the format itself reads them as, if it has a way: CP437 for ZIP, nothing for
/// the others. No text refuses the name ([`NameError::NotUtf8`](crate::extract::NameError)).
///
/// What it gives is checked as any name is, by [`check_name`](crate::extract::check_name)
/// and against the other entries, so it cannot lead outside the destination. A
/// `/` in it separates folders. Links' targets are not given to it: one that is
/// not UTF-8 stays refused.
#[derive(Clone)]
pub struct NameDecoder(Arc<NameDecoderFn>);

type NameDecoderFn = dyn Fn(&[u8], Option<&str>) -> Option<String> + Send + Sync;

impl NameDecoder {
    /// A decoder of the caller's: one that knows the encoding, or finds it.
    pub fn new(
        decode: impl Fn(&[u8], Option<&str>) -> Option<String> + Send + Sync + 'static,
    ) -> NameDecoder {
        NameDecoder(Arc::new(decode))
    }

    /// What the format reads, or else the bytes as UTF-8 with U+FFFD for what is
    /// not. Every name can then be written, but two that differ only in those
    /// bytes come to one, which is refused as the same path twice.
    pub fn lossy() -> NameDecoder {
        NameDecoder::new(|raw, format_reads| {
            Some(
                format_reads
                    .map_or_else(|| String::from_utf8_lossy(raw).into_owned(), str::to_owned),
            )
        })
    }

    pub(crate) fn decode(&self, raw: &[u8], format_reads: Option<&str>) -> Option<String> {
        (self.0)(raw, format_reads)
    }
}

impl std::fmt::Debug for NameDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameDecoder")
    }
}

/// How to extract.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Options {
    pub limits: Limits,
    /// The password encrypted entries are read with.
    pub password: Option<Vec<u8>>,
    pub links: Links,
    /// What to do with a symbolic link whose target leads outside the
    /// destination, or through another link ([`ErrorKind::LinkTarget`],
    /// [`ErrorKind::LinkChain`]), with [`Links::Inside`]: as
    /// [`Options::on_refused`] says (the default), or left out whatever it says.
    /// Nothing is ever written through a link, as links are made last.
    /// [`Options::on_links_outside`], if given, is asked instead.
    pub links_outside: OnRefused,
    /// With [`Links::Inside`], asked once, before anything is written, what to do
    /// with the symbolic links whose targets lead outside the destination or
    /// through another link, each with its target: stop, leave them out, or
    /// create them as [`Links::Any`] does ([`OnLinksOutside`]). Without it, they
    /// are refused as [`Options::links_outside`] says. A target that is no path
    /// (empty, not UTF-8, with a control character) is never asked about: it is
    /// refused. Asked after [`Options::on_unnamable`], of the links it left.
    pub on_links_outside: Option<OnLinksOutsideFn>,
    pub names: Names,
    /// Which systems' names an entry's has to be: this one's (the default), or
    /// every one's ([`NameRules`]).
    pub name_rules: NameRules,
    /// Asked once, before anything is written, what to do with the entries whose
    /// names this system cannot take ([`NameError::is_unnamable`], and two names
    /// it takes for one, as `README` and `readme` on Windows and macOS): stop,
    /// leave them out, or rename them ([`OnUnnamable`]). Without it, they are
    /// refused as [`Options::on_refused`] says. A name that leads outside the
    /// destination (`..`, `/etc`) is never asked about: it is refused.
    pub on_unnamable: Option<OnUnnamableFn>,
    /// Makes text of names that are not UTF-8. By default a ZIP archive's are
    /// read as CP437, and those of other formats refused.
    pub decode_names: Option<NameDecoder>,
    /// Takes `\` in names for a separator, as PowerShell 5.1's
    /// `Compress-Archive` writes it; refused otherwise.
    pub backslash_separator: bool,
    pub on_refused: OnRefused,
    /// What to do with each entry whose data is damaged ([`OnDamaged`]); none by
    /// default, which stops. The entries gone on from are in
    /// [`Summary::damaged`](crate::extract::Summary::damaged).
    ///
    /// What follows a damaged entry may be lost with it: the rest of a solid
    /// block in 7z, whose files are asked about too, as left out. A tar, cpio or
    /// ISO 9660 stream cut short, or that cannot be read on from a place, is
    /// extracted up to there: the entry it ends in is asked about, or, if it ends
    /// between entries, what it ends with, an error at the index the next entry
    /// would have, with no name. So the first reading no longer stops what is
    /// before from being written, as it does without this.
    ///
    /// The time it takes to answer counts against [`Options::time_limit`].
    pub on_damaged: Option<OnDamagedFn>,
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
    /// With [`Options::threads`], by the thread that wrote, one at a time.
    pub progress: Option<ProgressFn>,
    /// The archive's mark of origin ([`Origin::of`]), written on every file
    /// extracted, and on macOS every directory created; a mark not written
    /// stops the extraction. None by default: the archive's path is the
    /// caller's.
    pub origin: Option<Origin>,
    /// What to do with a macOS package's payloads ([`extract_xar`](crate::extract::extract_xar)).
    pub packages: Packages,
    /// Extracts only the entries this picks, the folders they are in made as
    /// they are needed. The others are as if not in the archive: not checked,
    /// not counted against the limits, not written; an entry whose name cannot
    /// be used is not picked. All of them by default. Data the picked ones
    /// depend on, in a solid block or stream, is still read.
    pub select: Option<Select>,
    /// How many threads extraction may use, at most; one by default. Where the
    /// archive's entries are apart (ZIP, and RAR that is not solid), that many
    /// files are written at once, each read and decompressed in a thread of
    /// its own. A tar or cpio archive, a stream, is read on the caller's
    /// thread, and its files written by the others, as many at once. In 7z,
    /// that many folders (solid blocks, or the files of an archive that is not
    /// solid) are decoded at once, each by a thread that writes its files; the
    /// threads left over decompress LZMA2 whose stream resets its dictionary
    /// on the way (7-Zip's in threads,
    /// [`Lzma2Blocks`](crate::sevenz::Lzma2Blocks)) a block in each. What is
    /// written is the same.
    pub threads: Threads,
    /// The memory the threads may take, where each holds what it decompresses
    /// with: RAR's ([`extract_rar`](crate::extract::extract_rar)), whose every
    /// thread has a window as large as the archive's dictionary asks, and
    /// PPMd's model in RAR 4; 7z's ([`extract_7z`](crate::extract::extract_7z)),
    /// whose every thread has its folder's dictionaries and models, LZMA2's
    /// blocks decoded ahead taking what they leave. The threads are lowered
    /// until what they take, counted for the most each may hold, fits; one is
    /// always allowed, as it takes what extracting without threads does. For tar and cpio, the data
    /// read and handed to threads to write, 32 MiB at most, is held to it.
    /// None by default. See
    /// [docs/memory.md](https://github.com/hivepaas/hivepack-rs/blob/main/docs/memory.md#readers).
    pub memory_limit: Option<u64>,
    /// Where the memory of the threads is held from, once what they need is
    /// known, after the first reading: the most threads that fit what is left
    /// of it ([`Budget::hold_threads`](crate::memory::Budget::hold_threads)),
    /// held until the extraction is done, and no more than
    /// [`Options::memory_limit`] lets. None by default.
    #[cfg(feature = "memory")]
    pub memory_budget: Option<crate::memory::Budget>,
    /// Whether the destination takes two names that differ only in case, or in
    /// how their Unicode is composed, for one, as found there; the system's
    /// default if it could not be.
    pub(crate) folds: Option<bool>,
    /// Extracting into a [`Sink`](crate::extract::Sink), whose archive holds any
    /// name: with this system's rules, only what leads outside is refused.
    pub(crate) into_archive: bool,
}

/// Shows the options, not the password or the progress function.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Options");
        f.field("limits", &self.limits)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .field("links", &self.links)
            .field("links_outside", &self.links_outside)
            .field(
                "on_links_outside",
                &self.on_links_outside.as_ref().map(|_| ".."),
            )
            .field("names", &self.names)
            .field("name_rules", &self.name_rules)
            .field("on_unnamable", &self.on_unnamable.as_ref().map(|_| ".."))
            .field("decode_names", &self.decode_names)
            .field("backslash_separator", &self.backslash_separator)
            .field("on_refused", &self.on_refused)
            .field("on_damaged", &self.on_damaged.as_ref().map(|_| ".."))
            .field("overwrite", &self.overwrite)
            .field("permissions", &self.permissions)
            .field("time_limit", &self.time_limit)
            .field("cancel", &self.cancel)
            .field("progress", &self.progress.as_ref().map(|_| ".."))
            .field("origin", &self.origin)
            .field("select", &self.select.as_ref().map(|_| ".."))
            .field("threads", &self.threads)
            .field("memory_limit", &self.memory_limit);
        #[cfg(feature = "memory")]
        f.field("memory_budget", &self.memory_budget);
        f.field("folds", &self.folds)
            .field("into_archive", &self.into_archive)
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
    /// The name as text, before it is checked: decoded and prepared, or read as
    /// UTF-8 with U+FFFD where it cannot be. What it is renamed from.
    pub text: String,
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
/// [`unicode::key`](crate::extract::unicode::key)).
pub(crate) fn fold(components: &[String]) -> String {
    crate::extract::unicode::key(&components.join("/"))
}

/// A path as two names that are one where it is extracted are the same: folded
/// as [`fold`] folds it where they are ([`folds`]), and as it is elsewhere.
pub(crate) fn key(components: &[String], folds: bool) -> String {
    if folds {
        fold(components)
    } else {
        components.join("/")
    }
}

/// Whether two names that differ only in case, or in how their Unicode is
/// composed, are one where `options` extract: always by every system's rules;
/// by this one's, as the destination was found to take them, or else as
/// Windows and macOS do by default.
pub(crate) fn folds(options: &Options) -> bool {
    match options.name_rules {
        NameRules::Portable => true,
        _ => options
            .folds
            .unwrap_or(cfg!(any(windows, target_os = "macos"))),
    }
}

impl Options {
    /// These options, for an extraction into the folder at `destination`: what
    /// its file system takes for one name found, if this system's rules apply.
    pub(crate) fn for_folder(&self, destination: &std::path::Path) -> Options {
        let mut options = self.clone();
        if options.name_rules == NameRules::Native {
            options.folds = folds_at(destination);
        }
        options
    }

    /// These options, for an extraction into a [`Sink`](crate::extract::Sink):
    /// no file system takes two names for one there.
    pub(crate) fn for_sink(&self) -> Options {
        let mut options = self.clone();
        if options.name_rules == NameRules::Native {
            options.folds = Some(false);
            options.into_archive = true;
        }
        options
    }

    /// What names are checked for, as these options extract.
    pub(crate) fn checks(&self) -> Checks {
        if self.into_archive && self.name_rules == NameRules::Native {
            Checks::Archive
        } else {
            Checks::Folder(self.name_rules)
        }
    }
}

/// Whether the file system at `destination`, or at the nearest folder above it
/// that is there, takes two names that differ only in case, or in how their
/// Unicode is composed, for one: a file made there, looked for by those names,
/// and taken away. None if it cannot be told.
pub(crate) fn folds_at(destination: &std::path::Path) -> Option<bool> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut at = destination;
    while !at.as_os_str().is_empty() && !at.is_dir() {
        at = at.parent()?;
    }
    if at.as_os_str().is_empty() {
        at = std::path::Path::new(".");
    }
    let base = format!(
        ".hivepack-probe-{}-{}-",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // É as one character, and é as one, and É as E and an accent.
    let made = at.join(format!("{base}\u{c9}"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&made)
        .ok()?;
    let found = |name: String| at.join(name).symlink_metadata().is_ok();
    let folds = found(format!("{base}\u{e9}")) || found(format!("{base}E\u{301}"));
    let _ = std::fs::remove_file(&made);
    Some(folds)
}

/// `text`, an entry's name, prepared as `options` say ([`Names`], a `\\` for a
/// separator) and checked by their rules: the text prepared, and the name or why
/// it is refused.
pub(crate) fn named(text: &str, options: &Options) -> (String, Result<Name, NameError>) {
    let prepared = crate::extract::name::prepare(
        text,
        options.backslash_separator,
        options.names == Names::Sanitize,
    );
    let checked = crate::extract::name::check(prepared.as_bytes(), options.checks());
    (prepared, checked)
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

/// What [`settle`] made of the entries whose names this system cannot take:
/// those left out, and why, and those renamed.
#[derive(Default)]
pub(crate) struct Settled {
    pub skipped: Vec<Error>,
    pub renamed: Vec<Renamed>,
    /// The indexes of those left out.
    left: HashSet<u64>,
}

/// An entry extracted under another name than its own, as
/// [`OnUnnamable::Rename`] gives it.
#[derive(Debug)]
#[non_exhaustive]
pub struct Renamed {
    /// The entry, and why its own name was not taken.
    pub error: Error,
    /// The name it was given, a component at a time.
    pub to: Vec<String>,
}

/// Checks the entries before anything is written: their number, what
/// they say of their sizes, their names, that no two name the same path
/// (ignoring case where the system does, and a directory one way and a file
/// another), links, and that no two share compressed data. Those whose names
/// this system cannot take are first asked about ([`Options::on_unnamable`]),
/// and left out or renamed. The entries to extract, with those refused but
/// skipped (with [`OnRefused::Skip`]) left out, the errors that left them out,
/// and those renamed.
pub(crate) fn check<'a>(
    items: &'a [Item],
    settled: &Settled,
    options: &Options,
) -> Result<(Vec<&'a Item>, Vec<Error>), Error> {
    let limits = &options.limits;
    if items.len() as u64 > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let mut skipped: Vec<Error> = settled
        .skipped
        .iter()
        .map(|e| Error {
            index: e.index,
            name: e.name.clone(),
            kind: clone_kind(&e.kind),
        })
        .collect();
    let mut kept = Vec::new();
    let mut total: u64 = 0;
    let mut seen: HashMap<String, Seen> = HashMap::new();
    for item in items {
        if settled.left.contains(&item.index) || !picked(item, options) {
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
                    Ok(name) => duplicate(&mut seen, item, name, folds(options))
                        .map(|first| ErrorKind::Duplicate { first }),
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

/// What to do with a link refused for its target ([`Options::links_outside`]).
pub(crate) fn skips_links(options: &Options) -> OnRefused {
    match (options.on_refused, options.links_outside) {
        (OnRefused::Skip, _) | (_, OnRefused::Skip) => OnRefused::Skip,
        _ => OnRefused::Stop,
    }
}

/// A symbolic link to create: its target, and whether it leads to a directory
/// of the archive (which Windows asks).
pub(crate) struct LinkTo {
    pub target: String,
    pub to_dir: bool,
}

/// A symbolic link's target, checked as [`Options::links`] says, by [`link_to`]:
/// the link it makes, if its target is a path at all, and why it is refused, if
/// it is.
pub(crate) struct LinkChecked {
    link: Option<LinkTo>,
    refused: Option<ErrorKind>,
}

impl LinkChecked {
    /// Refused, with no link to create or ask about: its target too long, no
    /// path, one this system cannot link to, or damaged as it was read.
    pub(crate) fn unread(kind: ErrorKind) -> LinkChecked {
        LinkChecked {
            link: None,
            refused: Some(kind),
        }
    }
}

/// The target of the symbolic link at `parent` (its directory), checked: with
/// [`Links::Inside`], it must stay inside the destination and not pass through
/// another link of the archive (`links`, by their folded paths); with
/// [`Links::Any`], only be a path. `dirs` are the archive's directories, by
/// their folded paths.
pub(crate) fn link_to(
    target: &[u8],
    parent: &[String],
    options: &Options,
    links: &HashMap<String, u64>,
    dirs: &HashMap<String, u64>,
) -> LinkChecked {
    let text = match link_text(target) {
        Ok(text) => text,
        Err(e) => return LinkChecked::unread(ErrorKind::LinkTarget(e)),
    };
    let resolved = link_target(target, parent, options.checks());
    let to_dir = resolved
        .as_ref()
        .is_ok_and(|resolved| dirs.contains_key(&fold(resolved)));
    let refused = match resolved {
        _ if options.links == Links::Any => None,
        Err(e) => Some(ErrorKind::LinkTarget(e)),
        // A link on the way, which the system would follow.
        Ok(_) => link_on_the_way(target, parent, |walked: &[String]| {
            links.get(&fold(walked)).copied()
        })
        .map(|other| ErrorKind::LinkChain { other }),
    };
    if rooted(&text) && !options.into_archive {
        // Not to be created here, whatever the options, nor asked about; an
        // archive a Sink makes holds it.
        return LinkChecked::unread(refused.unwrap_or(ErrorKind::LinkTarget(NameError::Absolute)));
    }
    LinkChecked {
        link: Some(LinkTo {
            target: text,
            to_dir,
        }),
        refused,
    }
}

/// Whether a link to `target` cannot be created in a folder on this system,
/// wherever it leads: on Windows, one from a root or a drive (`\\x`, `C:x`), which cap-std
/// refuses to create.
fn rooted(target: &str) -> bool {
    cfg!(windows) && (target.starts_with(['/', '\\']) || target.get(1..2) == Some(":"))
}

/// The symbolic links checked by [`link_to`], settled: those that pass, those
/// whose targets lead outside as [`Options::on_links_outside`] says once asked,
/// and the others as [`skips_links`] says, those left out going to `skipped`
/// in the archive's order. The links to create, in the archive's order.
pub(crate) fn settle_links<'a>(
    checked: Vec<(&'a Item, LinkChecked)>,
    options: &Options,
    skipped: &mut Vec<Error>,
) -> Result<Vec<(&'a Item, LinkTo)>, Error> {
    let asking = options
        .on_links_outside
        .as_ref()
        .filter(|_| options.links == Links::Inside);
    let mut links = Vec::new();
    let mut left = Vec::new();
    let mut outside: Vec<(&'a Item, LinkTo, ErrorKind)> = Vec::new();
    for (item, LinkChecked { link, refused }) in checked {
        match (link, refused) {
            (Some(link), None) => links.push((item, link)),
            (Some(link), Some(kind)) if asking.is_some() && leads_outside(&kind) => {
                outside.push((item, link, kind));
            }
            (_, Some(kind)) => match (leads_outside(&kind), skips_links(options)) {
                (true, OnRefused::Skip) => left.push(item.error(kind)),
                _ => return Err(item.error(kind)),
            },
            (None, None) => {}
        }
    }
    if let (Some(asked), false) = (asking, outside.is_empty()) {
        let told: Vec<LinkOutside> = outside
            .iter()
            .map(|(item, link, kind)| LinkOutside {
                error: item.error(clone_link_kind(kind)),
                target: link.target.clone(),
            })
            .collect();
        match asked(&told) {
            OnLinksOutside::Stop => {
                let first = told.into_iter().next().map(|told| told.error);
                return Err(first.unwrap_or_else(|| Error::global(ErrorKind::Link)));
            }
            OnLinksOutside::Skip => left.extend(told.into_iter().map(|told| told.error)),
            OnLinksOutside::Create => {
                links.extend(outside.into_iter().map(|(item, link, _)| (item, link)));
                links.sort_by_key(|(item, _)| item.index);
            }
        }
    }
    left.sort_by_key(|error| error.index);
    skipped.extend(left);
    Ok(links)
}

/// Whether a link is refused for where its target leads, as
/// [`Options::links_outside`] and [`Options::on_links_outside`] take it.
fn leads_outside(kind: &ErrorKind) -> bool {
    matches!(kind, ErrorKind::LinkTarget(_) | ErrorKind::LinkChain { .. })
}

/// A copy of `kind`, one of those [`link_to`] makes.
fn clone_link_kind(kind: &ErrorKind) -> ErrorKind {
    match kind {
        ErrorKind::LinkTarget(e) => ErrorKind::LinkTarget(*e),
        ErrorKind::LinkChain { other } => ErrorKind::LinkChain { other: *other },
        _ => ErrorKind::Link,
    }
}

/// Whether `item` is one [`Options::select`] picks.
fn picked(item: &Item, options: &Options) -> bool {
    match &options.select {
        Some(select) => item
            .name
            .as_ref()
            .is_ok_and(|name| select(&name.components)),
        None => true,
    }
}

/// The entries whose names this system cannot take, asked about with
/// [`Options::on_unnamable`], before [`check`]: those left out, and those
/// renamed, their names changed in `items`. Nothing without it.
pub(crate) fn settle(items: &mut [Item], options: &Options) -> Result<Settled, Error> {
    let Some(asked) = &options.on_unnamable else {
        return Ok(Settled::default());
    };
    let rules = options.checks();
    let folds = folds(options);
    // Each, and why: a name refused, or one the system takes for another's.
    let mut unnamable: Vec<(usize, ErrorKind)> = Vec::new();
    let mut seen: HashMap<String, Seen> = HashMap::new();
    for (at, item) in items.iter().enumerate() {
        if !picked(item, options) {
            continue;
        }
        match (&item.name, item.kind) {
            (Err(e), _) if e.is_unnamable() => unnamable.push((at, ErrorKind::Name(*e))),
            (Ok(name), kind) if kind != Kind::Special => {
                if let Some(first) = duplicate(&mut seen, item, name, folds)
                    && let Some(other) = items.iter().find(|i| i.index == first)
                    && other
                        .name
                        .as_ref()
                        .is_ok_and(|o| o.components != name.components)
                {
                    unnamable.push((at, ErrorKind::Duplicate { first }));
                }
            }
            _ => {}
        }
    }
    if unnamable.is_empty() {
        return Ok(Settled::default());
    }
    let errors: Vec<Error> = unnamable
        .iter()
        .map(|(at, kind)| items[*at].error(clone_kind(kind)))
        .collect();
    let chosen = asked(&errors);
    let mut skipped = Vec::new();
    let mut left = HashSet::new();
    let mut given = Vec::new();
    match chosen {
        OnUnnamable::Stop => {
            return Err(errors
                .into_iter()
                .next()
                .unwrap_or_else(|| Error::global(ErrorKind::Name(NameError::Empty))));
        }
        OnUnnamable::Skip => {
            for ((at, _), error) in unnamable.iter().zip(errors) {
                left.insert(items[*at].index);
                skipped.push(error);
            }
        }
        OnUnnamable::Rename => {
            let moving: HashSet<usize> = unnamable.iter().map(|(at, _)| *at).collect();
            // What the names that stay take up, each folder on their way too.
            let mut taken: HashMap<String, Vec<String>> = HashMap::new();
            for (at, item) in items.iter().enumerate() {
                if let (false, Ok(name)) = (moving.contains(&at), &item.name) {
                    for end in 1..=name.components.len() {
                        let path = &name.components[..end];
                        taken
                            .entry(key(path, folds))
                            .or_insert_with(|| path.to_vec());
                    }
                }
            }
            for ((at, kind), error) in unnamable.iter().zip(errors) {
                let item = &items[*at];
                let wanted = match kind {
                    ErrorKind::Name(_) => renamed(&item.text, rules),
                    _ => item.name.clone().ok(),
                };
                match wanted.map(|name| free(name, &taken, folds)) {
                    Some(name) => {
                        for end in 1..=name.components.len() {
                            let path = &name.components[..end];
                            taken
                                .entry(key(path, folds))
                                .or_insert_with(|| path.to_vec());
                        }
                        given.push(Renamed {
                            error,
                            to: name.components.clone(),
                        });
                        items[*at].name = Ok(name);
                    }
                    None => {
                        left.insert(items[*at].index);
                        skipped.push(error);
                    }
                }
            }
        }
    }
    Ok(Settled {
        skipped,
        renamed: given,
        left,
    })
}

/// `name`, its folders spelled as those already `taken` that the system takes
/// them for, and its last part numbered (`a (2).txt`) if that is taken too.
fn free(mut name: Name, taken: &HashMap<String, Vec<String>>, folds: bool) -> Name {
    let n = name.components.len();
    for end in 1..n {
        if let Some(spelling) = taken.get(&key(&name.components[..end], folds)) {
            name.components[end - 1] = spelling[end - 1].clone();
        }
    }
    if !taken.contains_key(&key(&name.components, folds)) || n == 0 {
        return name;
    }
    let last = name.components[n - 1].clone();
    let (stem, extension) = match last.rfind('.').filter(|&dot| dot > 0) {
        Some(dot) => last.split_at(dot),
        None => (last.as_str(), ""),
    };
    for number in 2.. {
        name.components[n - 1] = format!("{stem} ({number}){extension}");
        if !taken.contains_key(&key(&name.components, folds)) {
            break;
        }
    }
    name
}

/// A copy of `kind`, one of those [`settle`] makes.
fn clone_kind(kind: &ErrorKind) -> ErrorKind {
    match kind {
        ErrorKind::Name(e) => ErrorKind::Name(*e),
        ErrorKind::Duplicate { first } => ErrorKind::Duplicate { first: *first },
        _ => ErrorKind::Name(NameError::Empty),
    }
}

/// Records the path of `item`, and the directories on its way, in `seen`:
/// the entry it is the same path as, if one is. A link is a file here.
fn duplicate(
    seen: &mut HashMap<String, Seen>,
    item: &Item,
    name: &Name,
    folds: bool,
) -> Option<u64> {
    let components = &name.components;
    // The directories on the way.
    for end in 1..components.len() {
        let prefix = &components[..end];
        match seen.get(&key(prefix, folds)) {
            Some(other) if other.spelling != prefix || !other.is_dir => return Some(other.first),
            Some(_) => {}
            None => {
                seen.insert(
                    key(prefix, folds),
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
    match seen.get_mut(&key(components, folds)) {
        // A directory named after files in it.
        Some(other) if is_dir && other.is_dir && !other.named && other.spelling == *components => {
            other.named = true;
            None
        }
        Some(other) => Some(other.first),
        None => {
            seen.insert(
                key(components, folds),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_is_found_to_take_names_for_one_or_not() {
        let dir = std::env::temp_dir().join(format!("hivepack-folds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The systems' own file systems, as CI's runners have them.
        let default = cfg!(any(windows, target_os = "macos"));
        assert_eq!(folds_at(&dir), Some(default));
        // A folder not there yet is on the file system of the one above it.
        assert_eq!(folds_at(&dir.join("not/there/yet")), Some(default));
        // Nothing is left of the probe.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
