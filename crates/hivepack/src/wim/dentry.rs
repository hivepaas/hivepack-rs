//! The tree in a metadata resource: the security descriptors in front of
//! it, and the entries, each naming its children by where they are.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::error::Error;
use super::lookup::Resources;
use super::{MAX_DEPTH, Resource, le16, le32, le64};

/// How long an entry is before its name: measured against what 7-Zip
/// writes, which is what the format fixes.
const BASE: usize = 102;

/// How long a stream entry is before its name: its own length, eight
/// bytes kept, the SHA-1 of what the stream holds, and how long its name
/// is. Measured against what `wimlib-imagex` writes for a reparse point,
/// whose data is a stream of its own: two entries of 40 bytes, which is
/// this and a name of nothing but its NUL.
const STREAM: usize = 38;

/// How many entries one image may hold. They are kept in memory, and a
/// Windows disc's largest image is a few hundred thousand.
const MOST_ENTRIES: usize = 1 << 22;

/// The attributes that matter here, as Windows names them.
const DIRECTORY: u32 = 0x0000_0010;
const REPARSE_POINT: u32 = 0x0000_0400;
const READ_ONLY: u32 = 0x0000_0001;
const HIDDEN: u32 = 0x0000_0002;
const SYSTEM: u32 = 0x0000_0004;
const ARCHIVE: u32 = 0x0000_0020;
/// What 7-Zip sets when it keeps a Unix mode in the high half of the
/// field, which is its own extension and not Windows'.
const UNIX_EXTENSION: u32 = 0x0000_8000;

/// One file or directory of an image's tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The path to it inside the image, `/` between its parts, with no
    /// leading one.
    pub path: String,
    /// Its own name, the last part of the path.
    pub name: String,
    /// The name MS-DOS would see, where the entry carries one.
    pub short_name: Option<String>,
    /// How many bytes it holds: what the table of resources says of the
    /// resource its hash names, and 0 for a directory or an empty file.
    pub size: u64,
    /// The SHA-1 of what it holds, as the entry carries it. All zeroes for
    /// a directory and for a file of no bytes.
    pub hash: [u8; 20],
    pub created: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    /// What Windows' own attributes say.
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    /// The whole attribute field, for what the four above leave out.
    pub attributes: u32,
    /// The Unix mode 7-Zip keeps in the high half of the attributes when
    /// it writes a WIM on a Unix system, where it says it did. Windows'
    /// own tools write none.
    pub unix_mode: Option<u32>,
    /// Which kind of reparse point it is, where it is one: a symbolic
    /// link, a junction, a placeholder. Its data is not a file's bytes, so
    /// reading it is refused.
    pub reparse_tag: Option<u32>,
    /// Which set of names share one file, where the entry says: every
    /// entry of a set carries the same number, and they are one file on
    /// the disk the image came from.
    pub hard_link_group: Option<u64>,
    /// How many **named** streams the entry has beside the file's own
    /// (`file.txt:stream`), which are not read. The unnamed stream, where
    /// the entry has one, is the file itself and is not counted here: it
    /// is what [`crate::wim::Wim::read`] gives.
    pub extra_streams: u16,
    dir: bool,
    /// Where its bytes are, where the table holds a resource for its hash.
    pub(crate) resource: Option<Resource>,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.dir
    }

    pub fn is_file(&self) -> bool {
        !self.dir
    }

    /// Whether it is a reparse point, whose data is not a file's bytes.
    pub fn is_reparse_point(&self) -> bool {
        self.reparse_tag.is_some()
    }
}

/// The tree in `raw`, a metadata resource, parents before what they hold.
///
/// The security descriptors in front of the tree are stepped over: what
/// they hold is Windows' own access control, which nothing here turns into
/// a Unix owner or mode.
pub(crate) fn tree(raw: &[u8], resources: &Resources) -> Result<Vec<Entry>, Error> {
    let at = security_end(raw)?;
    // The root entry, whose children are the image's own.
    let root = read_one(raw, at)?.ok_or(Error::Tree)?;
    let mut entries = Vec::new();
    // Every child list walked into, so that a directory naming one of
    // them again is told rather than walked for ever. **The root's own
    // list counts**: without it, an entry pointing back at the image's
    // top level walked the whole tree a second time, and a chain of such
    // entries would not end.
    let mut seen = BTreeSet::new();
    seen.insert(at);
    seen.insert(root.children);
    // Directories still to walk: where their children are, and the path
    // to put in front of them.
    let mut todo = vec![(root.children, String::new(), 1usize)];
    while let Some((children, path, depth)) = todo.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut at = children;
        let mut inside = Vec::new();
        while let Some(read) = read_one(raw, at)? {
            if entries.len() >= MOST_ENTRIES {
                return Err(Error::TooMany);
            }
            let name = read.name.clone();
            let here = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            let mut entry = read.entry;
            entry.path = here.clone();
            if entry.dir && read.children != 0 {
                // A directory whose children are a list already walked
                // into is a tree that leads back on itself.
                if !seen.insert(read.children) {
                    return Err(Error::TreeLoops);
                }
                inside.push((read.children, here, depth + 1));
            }
            if !entry.dir && entry.hash != [0u8; 20] {
                entry.resource = resources.by_hash(&entry.hash);
                entry.size = entry.resource.map_or(0, |r| r.size);
            }
            entries.push(entry);
            at = read.next;
        }
        // Depth first, in the order the directory holds its entries.
        todo.extend(inside.into_iter().rev());
    }
    Ok(entries)
}

/// Where the security descriptors end and the tree begins.
fn security_end(raw: &[u8]) -> Result<usize, Error> {
    // The table's own length counts itself, and the tree begins at the
    // next multiple of eight.
    let total = le32(raw, 0) as usize;
    if total < 8 || total > raw.len() {
        return Err(Error::Tree);
    }
    let at = total.next_multiple_of(8);
    if at >= raw.len() {
        return Err(Error::Tree);
    }
    Ok(at)
}

/// What one entry says, and where the entry after it begins.
struct Read {
    entry: Entry,
    /// Where the next entry of the same list is: past this entry, padded
    /// to eight bytes, and past the stream entries that follow it.
    next: usize,
    /// Where its children are, and 0 for none.
    children: usize,
    name: String,
}

/// The entry at `at`, or none where the list ends, which is a length of
/// zero.
fn read_one(raw: &[u8], at: usize) -> Result<Option<Read>, Error> {
    if at >= raw.len() {
        return Err(Error::Tree);
    }
    let length = le64(raw, at);
    if length == 0 {
        return Ok(None);
    }
    // An entry has to hold itself, and to be on the metadata.
    let length = usize::try_from(length).map_err(|_| Error::Tree)?;
    if length < BASE || at.checked_add(length).is_none_or(|end| end > raw.len()) {
        return Err(Error::Tree);
    }
    let entry = &raw[at..at + length];
    let attributes = le32(entry, 8);
    let children = usize::try_from(le64(entry, 16)).map_err(|_| Error::Tree)?;
    if children != 0 && children >= raw.len() {
        return Err(Error::Tree);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&entry[64..84]);

    let dir = attributes & DIRECTORY != 0;
    let reparse = attributes & REPARSE_POINT != 0;
    // The twelve bytes after the hash are one thing or the other: for a
    // reparse point, what kind it is; for anything else, which set of
    // names share the file.
    let reparse_tag = reparse.then(|| le32(entry, 88));
    let hard_link_group = (!reparse)
        .then(|| le64(entry, 84))
        .filter(|group| *group != 0);

    let extra_streams = le16(entry, 96);
    let short_len = le16(entry, 98) as usize;
    let name_len = le16(entry, 100) as usize;
    // The names follow the entry, each with a NUL after it, and the whole
    // entry is padded to eight bytes.
    let names = length - BASE;
    if name_len + short_len > names {
        return Err(Error::Tree);
    }
    let name = utf16(&entry[BASE..BASE + name_len])?;
    let short_at = BASE + name_len + 2.min(names - name_len);
    let short_name = if short_len > 0 && short_at + short_len <= length {
        Some(utf16(&entry[short_at..short_at + short_len])?)
    } else {
        None
    };

    // **The streams beside an entry follow it**, as many as it says,
    // each as long as it says and padded to eight bytes, and the entry
    // after it begins where they end. A reader that stepped over the
    // entry alone would read the first stream entry as an entry and
    // refuse the tree: `wimlib-imagex` writes two of them for every
    // symbolic link it captures, and a Windows image carries them for
    // every file that has a stream beside its own.
    //
    // **The file's own hash is in the unnamed stream where there are
    // streams at all.** The field in the entry is zeroes then, and a
    // reader that took it would read the file as empty. Measured on an
    // archive wimlib wrote: a symbolic link's entry carries zeroes where
    // the hash goes, and the unnamed stream entry after it carries the
    // SHA-1 of the reparse data, which is the resource the table holds.
    // Where the entry carries a hash of its own, that one stands: what is
    // there is not thrown away for what is beside it.
    let mut next = at
        .checked_add(length.next_multiple_of(8))
        .ok_or(Error::Tree)?;
    let mut named = 0u16;
    for _ in 0..extra_streams {
        if next >= raw.len() {
            return Err(Error::Tree);
        }
        let stream = usize::try_from(le64(raw, next)).map_err(|_| Error::Tree)?;
        if stream < STREAM || next.checked_add(stream).is_none_or(|end| end > raw.len()) {
            return Err(Error::Tree);
        }
        let name_len = le16(raw, next + 36) as usize;
        if name_len == 0 {
            if hash == [0u8; 20] {
                hash.copy_from_slice(&raw[next + 16..next + 36]);
            }
        } else {
            named += 1;
        }
        next = next
            .checked_add(stream.next_multiple_of(8))
            .ok_or(Error::Tree)?;
    }

    Ok(Some(Read {
        entry: Entry {
            path: String::new(),
            name: name.clone(),
            short_name,
            size: 0,
            hash,
            created: filetime(le64(entry, 40)),
            accessed: filetime(le64(entry, 48)),
            modified: filetime(le64(entry, 56)),
            read_only: attributes & READ_ONLY != 0,
            hidden: attributes & HIDDEN != 0,
            system: attributes & SYSTEM != 0,
            archive: attributes & ARCHIVE != 0,
            attributes,
            unix_mode: (attributes & UNIX_EXTENSION != 0).then_some(attributes >> 16),
            reparse_tag,
            hard_link_group,
            extra_streams: named,
            dir,
            resource: None,
        },
        next,
        children,
        name,
    }))
}

/// A name as the entry holds it: UTF-16, little-endian, with no NUL in it.
///
/// A name that is not UTF-16 is an error rather than something replaced:
/// what would come out is a name no file ever had, and extraction would
/// write it.
fn utf16(raw: &[u8]) -> Result<String, Error> {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).map_err(|_| Error::Tree)
}

/// A Windows FILETIME as a `SystemTime`: hundreds of nanoseconds from
/// 1601-01-01, which is 11,644,473,600 seconds before 1970.
fn filetime(stamp: u64) -> Option<SystemTime> {
    if stamp == 0 {
        return None;
    }
    let hundreds = Duration::new(stamp / 10_000_000, (stamp % 10_000_000) as u32 * 100);
    let since_1601 = Duration::from_secs(11_644_473_600);
    match hundreds.checked_sub(since_1601) {
        Some(after) => UNIX_EPOCH.checked_add(after),
        None => UNIX_EPOCH.checked_sub(since_1601 - hundreds),
    }
}
