//! Directory entries: the sets of them one file takes, the name spread
//! over as many as it needs, and the checksum each set carries.

use super::error::Error;
use super::time::Time;

/// How long an entry is. Every one of them is this long, whatever it says.
pub(crate) const ENTRY: usize = 32;

/// The entry types read here, as the type byte holds them with its in-use
/// bit set.
const END: u8 = 0x00;
const FILE: u8 = 0x85;
const VOLUME_LABEL: u8 = 0x83;
const STREAM: u8 = 0xC0;
const NAME: u8 = 0xC1;
/// The bit that says an entry is in use. An entry whose file was deleted
/// keeps its type with this bit cleared.
const IN_USE: u8 = 0x80;

/// How many characters of a name each entry carries, and how many
/// characters a name may be: 255, which is 17 entries of 15.
const PER_NAME: usize = 15;
const MOST_NAME: usize = 255;
/// How many entries one set may hold: a name of 255 characters, the file
/// entry and the stream entry, and room for the few other secondary
/// entries a writer may put in a set.
const MOST_IN_SET: usize = 19;
/// How many entries a directory may hold at all. They are kept in memory,
/// and no directory any tool writes comes near this many.
const MOST_ENTRIES: usize = 1 << 17;

/// How many characters the volume's label holds at most.
const LABEL_CHARS: usize = 11;

const READ_ONLY: u16 = 0x01;
const HIDDEN: u16 = 0x02;
const SYSTEM: u16 = 0x04;
const DIRECTORY: u16 = 0x10;
const ARCHIVE: u16 = 0x20;

/// One file or directory, as its set of entries says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name, as the name entries of the set hold it: UTF-16, with
    /// anything that is not a character of its own replaced.
    pub name: String,
    /// How many bytes the file holds. A directory's is how long its chain
    /// of clusters is, which exFAT writes where a file's length goes.
    pub size: u64,
    /// How many bytes of it have ever been written. The rest of the file
    /// is room that was given to it and never filled, and reads as zeroes:
    /// see [`crate::exfat::Exfat::file`].
    pub valid: u64,
    pub created: Option<Time>,
    pub modified: Option<Time>,
    pub accessed: Option<Time>,
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    dir: bool,
    first: u32,
    /// Whether the data is in one run of clusters, with nothing in the
    /// table to follow: what exFAT writes for a file that was never cut up.
    contiguous: bool,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.dir
    }

    pub fn is_file(&self) -> bool {
        !self.dir
    }

    /// Which cluster its data begins at, and 0 for a file of no bytes,
    /// which is given no cluster at all.
    pub fn first_cluster(&self) -> u32 {
        self.first
    }

    /// Whether its clusters are one run, which the set says and the table
    /// is not asked about.
    pub fn is_contiguous(&self) -> bool {
        self.contiguous
    }
}

/// What a directory holds: its entries, and the volume's label where the
/// directory is the root one, which is where it belongs.
pub(crate) struct Listing {
    pub(crate) entries: Vec<Entry>,
    pub(crate) label: Option<String>,
}

/// The entries in `raw`, a directory's own bytes.
///
/// A file is a **set** of entries: one file entry saying how many follow
/// it, a stream entry saying where the data is and how long, and one name
/// entry for every fifteen characters of the name. The set carries a
/// checksum of itself in the file entry, and a set that fails it is not
/// read: a name and a length taken from it would be anybody's guess.
///
/// There are no `.` and `..` entries to leave out. exFAT keeps none, so a
/// directory holds what is in it and nothing that leads back out.
pub(crate) fn listing(raw: &[u8]) -> Result<Listing, Error> {
    let mut entries = Vec::new();
    let mut label = None;
    let all = raw.as_chunks::<ENTRY>().0;
    let mut i = 0;
    while i < all.len() {
        let entry = &all[i];
        let kind = entry[0];
        // Nothing follows the first entry that was never used, which is
        // what lets a reader stop before the end of a directory's last
        // cluster.
        if kind == END {
            break;
        }
        // A deleted file keeps its entries with the in-use bit cleared:
        // the set is still as long as it was, and is stepped over whole.
        if kind & IN_USE == 0 {
            i += 1 + usize::from(if kind & 0x7F == FILE & 0x7F {
                entry[1]
            } else {
                0
            });
            continue;
        }
        match kind {
            FILE => {
                let (entry, took) = file(all, i)?;
                if entries.len() >= MOST_ENTRIES {
                    return Err(Error::TooMany);
                }
                entries.push(entry);
                i += took;
            }
            VOLUME_LABEL => {
                label = volume_label(entry);
                i += 1;
            }
            // A secondary entry outside a set, and the entries this does
            // not read (the allocation bitmap, the upcase table, the
            // volume's GUID, and whatever a later version adds): stepped
            // over, since each is one entry and says nothing about a file.
            _ => i += 1,
        }
    }
    Ok(Listing { entries, label })
}

/// The set beginning at `at`, and how many entries it took.
fn file(all: &[[u8; ENTRY]], at: usize) -> Result<(Entry, usize), Error> {
    let first = &all[at];
    let secondaries = usize::from(first[1]);
    // A file takes at least a stream entry and one name entry beside its
    // own, and no more entries than a name of 255 characters needs.
    if !(2..=MOST_IN_SET).contains(&secondaries) {
        return Err(Error::Set);
    }
    let set = all.get(at..=at + secondaries).ok_or(Error::Set)?;
    if checksum(set) != u16::from_le_bytes([first[2], first[3]]) {
        return Err(Error::SetChecksum);
    }

    let attributes = u16::from_le_bytes([first[4], first[5]]);
    let created = Time::of(le32(first, 8), first[20], first[22]);
    let modified = Time::of(le32(first, 12), first[21], first[23]);
    // The accessed time keeps no tenths of a second, only its offset.
    let accessed = Time::of(le32(first, 16), 0, first[24]);

    // The stream entry comes first among the secondary ones, and the name
    // entries follow it in the order the name reads.
    let stream = &set[1];
    if stream[0] != STREAM {
        return Err(Error::Set);
    }
    let flags = stream[1];
    let length = usize::from(stream[3]);
    if length == 0 || length > MOST_NAME {
        return Err(Error::Set);
    }
    // The name takes as many entries as 15 characters each needs, and they
    // come first among the secondary entries. A set that says a longer
    // name than it has entries for is not one; entries of other kinds
    // after the name — what a writer may add for its own use — are left
    // where they are.
    let needed = length.div_ceil(PER_NAME);
    let names = set.get(2..2 + needed).ok_or(Error::Set)?;
    let mut units = Vec::with_capacity(length);
    for entry in names {
        if entry[0] != NAME {
            return Err(Error::Set);
        }
        for pair in entry[2..].as_chunks::<2>().0 {
            if units.len() == length {
                break;
            }
            units.push(u16::from_le_bytes(*pair));
        }
    }
    if units.len() != length {
        return Err(Error::Set);
    }
    let name = String::from_utf16_lossy(&units);

    let dir = attributes & DIRECTORY != 0;
    let size = le64(stream, 24);
    let valid = le64(stream, 8);
    Ok((
        Entry {
            name,
            size,
            // A directory is written whole, so what has been written of it
            // is all of it; some writers leave its valid length at zero.
            valid: if dir { size } else { valid.min(size) },
            created,
            modified,
            accessed,
            read_only: attributes & READ_ONLY != 0,
            hidden: attributes & HIDDEN != 0,
            system: attributes & SYSTEM != 0,
            archive: attributes & ARCHIVE != 0,
            dir,
            first: le32(stream, 20),
            // The second flag of a stream entry says the data is one run
            // and the table holds nothing for it.
            contiguous: flags & 2 != 0,
        },
        1 + secondaries,
    ))
}

/// The volume's label, where the entry holds one.
fn volume_label(entry: &[u8; ENTRY]) -> Option<String> {
    let count = usize::from(entry[1]).min(LABEL_CHARS);
    if count == 0 {
        return None;
    }
    let units: Vec<u16> = entry[2..2 + count * 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// The checksum a set carries of itself: every byte of every entry in it,
/// each added to the sum after it is turned about by one bit, with the two
/// bytes holding the checksum itself skipped.
fn checksum(set: &[[u8; ENTRY]]) -> u16 {
    let mut sum = 0u16;
    for (i, byte) in set.iter().flatten().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(u16::from(*byte));
    }
    sum
}

fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A set of entries for one file, built as a writer builds one, with
    /// its checksum put in afterwards.
    pub(crate) fn a_set(name: &str, size: u64, dir: bool, contiguous: bool) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(PER_NAME);
        let mut set = vec![0u8; ENTRY * (2 + names)];
        set[0] = FILE;
        set[1] = (1 + names) as u8;
        let attributes: u16 = if dir { DIRECTORY } else { ARCHIVE };
        set[4..6].copy_from_slice(&attributes.to_le_bytes());
        set[ENTRY] = STREAM;
        set[ENTRY + 1] = if contiguous { 3 } else { 1 };
        set[ENTRY + 3] = units.len() as u8;
        set[ENTRY + 8..ENTRY + 16].copy_from_slice(&size.to_le_bytes());
        set[ENTRY + 20..ENTRY + 24].copy_from_slice(&2u32.to_le_bytes());
        set[ENTRY + 24..ENTRY + 32].copy_from_slice(&size.to_le_bytes());
        for (i, chunk) in units.chunks(PER_NAME).enumerate() {
            let at = ENTRY * (2 + i);
            set[at] = NAME;
            for (j, unit) in chunk.iter().enumerate() {
                set[at + 2 + j * 2..at + 4 + j * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        let sum = checksum(set.as_chunks::<ENTRY>().0);
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        set
    }

    #[test]
    fn a_set_reads_as_the_file_it_describes() {
        let raw = a_set("Hồ sơ.txt", 1234, false, true);
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.entries.len(), 1);
        let entry = &listing.entries[0];
        assert_eq!(entry.name, "Hồ sơ.txt");
        assert_eq!(entry.size, 1234);
        assert!(entry.is_file() && entry.is_contiguous() && entry.archive);
        assert_eq!(entry.first_cluster(), 2);
    }

    /// A name longer than one entry holds is spread over as many as it
    /// needs, and comes back in one piece.
    #[test]
    fn a_name_over_many_entries_comes_back_whole() {
        let long = "ê".repeat(200);
        let raw = a_set(&long, 0, false, true);
        assert_eq!(raw.len(), ENTRY * (2 + 200usize.div_ceil(15)));
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.entries[0].name, long);
    }

    #[test]
    fn a_set_whose_checksum_is_wrong_is_not_read() {
        let mut raw = a_set("notes.txt", 10, false, true);
        raw[2] ^= 1;
        assert!(matches!(listing(&raw), Err(Error::SetChecksum)));
    }

    #[test]
    fn what_is_not_a_set_is_refused() {
        // A file entry saying it has no secondary entries at all.
        let mut raw = a_set("a.txt", 1, false, true);
        raw[1] = 0;
        let sum = checksum(raw.as_chunks::<ENTRY>().0);
        raw[2..4].copy_from_slice(&sum.to_le_bytes());
        assert!(matches!(listing(&raw), Err(Error::Set)));

        // A set that says it has more entries than are there.
        let mut raw = a_set("a.txt", 1, false, true);
        raw[1] = 8;
        assert!(matches!(listing(&raw), Err(Error::Set)));

        // A name of no characters at all.
        let mut raw = a_set("a.txt", 1, false, true);
        raw[ENTRY + 3] = 0;
        let sum = checksum(raw.as_chunks::<ENTRY>().0);
        raw[2..4].copy_from_slice(&sum.to_le_bytes());
        assert!(matches!(listing(&raw), Err(Error::Set)));

        // A name shorter than it says it is.
        let mut raw = a_set("a.txt", 1, false, true);
        raw[ENTRY + 3] = 40;
        let sum = checksum(raw.as_chunks::<ENTRY>().0);
        raw[2..4].copy_from_slice(&sum.to_le_bytes());
        assert!(matches!(listing(&raw), Err(Error::Set)));
    }

    /// A deleted file keeps its entries with the in-use bit cleared: they
    /// are stepped over whole, so what follows is read and the name
    /// entries of the deleted set are not read as entries of their own.
    #[test]
    fn a_deleted_set_is_stepped_over_whole() {
        let mut gone = a_set("gone.txt", 7, false, true);
        gone[0] &= !IN_USE;
        let mut raw = gone;
        raw.extend_from_slice(&a_set("here.txt", 9, false, true));
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "here.txt");
    }

    #[test]
    fn the_volume_label_is_an_entry_of_its_own() {
        let mut raw = vec![0u8; ENTRY];
        raw[0] = VOLUME_LABEL;
        let units: Vec<u16> = "Thẻ nhớ".encode_utf16().collect();
        raw[1] = units.len() as u8;
        for (i, unit) in units.iter().enumerate() {
            raw[2 + i * 2..4 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
        raw.extend_from_slice(&a_set("a.txt", 1, false, true));
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.label.as_deref(), Some("Thẻ nhớ"));
        assert_eq!(listing.entries.len(), 1);
    }

    /// The entries this does not read — the allocation bitmap, the upcase
    /// table, the volume's GUID — are one entry each and are stepped over.
    #[test]
    fn the_entries_that_are_not_files_are_passed_by() {
        let mut raw = Vec::new();
        for kind in [0x81u8, 0x82, 0xA0] {
            let mut entry = vec![0u8; ENTRY];
            entry[0] = kind;
            raw.extend_from_slice(&entry);
        }
        raw.extend_from_slice(&a_set("a.txt", 1, false, true));
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "a.txt");
    }

    /// Nothing follows the first entry that was never used.
    #[test]
    fn reading_stops_at_the_first_unused_entry() {
        let mut raw = a_set("a.txt", 1, false, true);
        raw.extend_from_slice(&[0u8; ENTRY]);
        raw.extend_from_slice(&a_set("past-the-end.txt", 1, false, true));
        let listing = listing(&raw).unwrap();
        assert_eq!(listing.entries.len(), 1);
    }
}
