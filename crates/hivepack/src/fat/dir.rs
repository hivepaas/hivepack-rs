//! Directory records: the 8.3 names MS-DOS had, the long names VFAT added
//! in front of them, and what each record says about a file.

use super::error::Error;
use super::time::Time;

/// How long a record is, and how many characters of a long name each
/// record of one carries.
pub(crate) const RECORD: usize = 32;
const PER_LONG: usize = 13;

/// The first byte of a record that is free, and of one whose file was
/// deleted. Nothing follows the first free record, which is what lets a
/// tool stop reading a directory early.
const FREE: u8 = 0x00;
const DELETED: u8 = 0xE5;
/// What the first byte of a name is where the name's own first byte is
/// 0xE5, which a record cannot hold because that is what a deleted record
/// says.
const REALLY_E5: u8 = 0x05;

const READ_ONLY: u8 = 0x01;
const HIDDEN: u8 = 0x02;
const SYSTEM: u8 = 0x04;
const VOLUME: u8 = 0x08;
const DIRECTORY: u8 = 0x10;
const ARCHIVE: u8 = 0x20;
/// A record of a long name, which is read-only, hidden, system and the
/// volume's label all at once: no file system before VFAT would show it.
const LONG: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME;

/// How many records a long name may be spread over, and how many entries a
/// directory may hold at all. A long name is 255 characters, which is 20
/// records of 13; the entries are kept in memory, and no directory any tool
/// writes comes near this many.
const MOST_LONG: u8 = 20;
const MOST_ENTRIES: usize = 1 << 17;

/// One file or directory, as its record says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name to show: the long name where the records carry one, and
    /// the 8.3 name where they do not.
    pub name: String,
    /// The 8.3 name as MS-DOS would read it, lowercased where the record
    /// says the name was written in one case.
    pub short: String,
    /// How many bytes the file holds, and 0 for a directory, whose length
    /// is however long its chain of clusters is.
    pub size: u64,
    pub created: Option<Time>,
    pub modified: Option<Time>,
    /// The day it was last read, which is all a FAT file system keeps of
    /// that: the time is always zero.
    pub accessed: Option<Time>,
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    dir: bool,
    first: u32,
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
}

/// What a directory holds: its entries, and the volume's label where the
/// directory is the root one, which is where a tool writes it.
pub(crate) struct Listing {
    pub(crate) entries: Vec<Entry>,
    pub(crate) label: Option<String>,
}

/// The entries in `raw`, a directory's records one after another, with the
/// long names put back together.
///
/// `.` and `..` are left out: they are what the file system needs to find
/// its way about, not files, and following them would walk a directory
/// into its own parent.
pub(crate) fn listing(raw: &[u8]) -> Result<Listing, Error> {
    let mut entries = Vec::new();
    let mut label = None;
    // The records of a long name come before the record of the file, in
    // reverse order, so what has been read of one is kept until the file's
    // own record arrives.
    let mut long: Vec<u16> = Vec::new();
    let mut next = 0u8;
    let mut sum = 0u8;
    for record in raw.as_chunks::<RECORD>().0 {
        match record[0] {
            FREE => break,
            DELETED => {
                long.clear();
                next = 0;
                continue;
            }
            _ => {}
        }
        let attributes = record[11];
        if attributes & LONG == LONG && attributes & DIRECTORY == 0 {
            let sequence = record[0] & 0x3F;
            if record[0] & 0x40 != 0 {
                // The last record of the name, which is the first to be
                // read: it says how many there are.
                if sequence == 0 || sequence > MOST_LONG {
                    long.clear();
                    next = 0;
                    continue;
                }
                long = vec![0u16; usize::from(sequence) * PER_LONG];
                next = sequence;
                sum = record[13];
            }
            // A record out of order, or of another name, leaves nothing to
            // put together: the file's own record is read on its own.
            if sequence != next || sequence == 0 || record[13] != sum {
                long.clear();
                next = 0;
                continue;
            }
            let from = usize::from(sequence - 1) * PER_LONG;
            for (i, at) in characters().enumerate() {
                long[from + i] = u16::from_le_bytes([record[at], record[at + 1]]);
            }
            next -= 1;
            continue;
        }
        // The file's own record. A long name counts only where every one of
        // its records was there and the name was written for this record:
        // the checksum of the 8.3 name is what says so, and is what a
        // reader checks rather than trusting what lies in front of it.
        let short: [u8; 11] = record[..11].try_into().map_err(|_| Error::Says)?;
        let name = if next == 0 && !long.is_empty() && checksum(&short) == sum {
            Some(of_long(&long))
        } else {
            None
        };
        long.clear();
        next = 0;
        if attributes & VOLUME != 0 {
            // The label of the volume, which is a record of the root
            // directory and not a file.
            if label.is_none() {
                let text = oem_text(&short);
                if !text.is_empty() {
                    label = Some(text);
                }
            }
            continue;
        }
        let short = of_short(&short, record[12]);
        if short == "." || short == ".." {
            continue;
        }
        if entries.len() >= MOST_ENTRIES {
            return Err(Error::TooMany);
        }
        entries.push(Entry {
            name: name.unwrap_or_else(|| short.clone()),
            short,
            size: u64::from(le32(record, 28)),
            created: Time::of(le16(record, 16), le16(record, 14), record[13]),
            modified: Time::of(le16(record, 24), le16(record, 22), 0),
            accessed: Time::of(le16(record, 18), 0, 0),
            read_only: attributes & READ_ONLY != 0,
            hidden: attributes & HIDDEN != 0,
            system: attributes & SYSTEM != 0,
            archive: attributes & ARCHIVE != 0,
            dir: attributes & DIRECTORY != 0,
            first: (u32::from(le16(record, 20)) << 16) | u32::from(le16(record, 26)),
        });
    }
    Ok(Listing { entries, label })
}

/// Where the characters of a long name are in its record: five, then six,
/// then two, with the fields a record of a file needs between them.
fn characters() -> impl Iterator<Item = usize> {
    (1..11)
        .step_by(2)
        .chain((14..26).step_by(2))
        .chain([28, 30])
}

/// The checksum of an 8.3 name, which every record of a long name carries
/// so that a reader can tell the name is this file's.
fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, byte| {
        ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte)
    })
}

/// A long name's characters as text: UTF-16, to the first character that is
/// nothing, with what pads the last record left out.
fn of_long(characters: &[u16]) -> String {
    let end = characters
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(characters.len());
    char::decode_utf16(characters[..end].iter().copied())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// An 8.3 name as text: eight bytes of a name and three of a kind, each
/// padded with spaces, and a dot between them where there is a kind.
///
/// `nt` is the byte Windows NT took for itself, which says the name was
/// written in one case and may be shown in it: this is what makes
/// `readme.txt` read as it was written rather than as `README.TXT`.
fn of_short(short: &[u8; 11], nt: u8) -> String {
    let mut first = short[0];
    if first == REALLY_E5 {
        first = DELETED;
    }
    let mut base = oem_text(&[&[first], &short[1..8]].concat());
    let mut kind = oem_text(&short[8..11]);
    if nt & 0x08 != 0 {
        base = base.to_lowercase();
    }
    if nt & 0x10 != 0 {
        kind = kind.to_lowercase();
    }
    if kind.is_empty() {
        base
    } else {
        format!("{base}.{kind}")
    }
}

/// Bytes of a name as text, with the spaces that pad it on the right taken
/// off.
fn oem_text(raw: &[u8]) -> String {
    raw.iter()
        .map(|b| oem(*b))
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// What a byte of an 8.3 name is as a character. The bytes above ASCII are
/// code page 437, the one every IBM PC had and the one Linux reads a FAT
/// file system in unless it is told another: nothing in the file system
/// says which was meant, and a name of anything but ASCII carries a long
/// name beside it in every file system written since VFAT.
pub(crate) fn oem(byte: u8) -> char {
    const ABOVE: [char; 128] = [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ',
        'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú',
        'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡',
        '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟',
        '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘',
        '┌', '█', '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ',
        '∞', 'φ', 'ε', '∩', '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²',
        '■', '\u{a0}',
    ];

    if byte < 0x80 {
        byte as char
    } else {
        ABOVE[usize::from(byte - 0x80)]
    }
}

fn le16(of: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([of[at], of[at + 1]])
}

fn le32(of: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([of[at], of[at + 1], of[at + 2], of[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checksum every record of a long name carries, which is what
    /// says the name belongs to the file it lies in front of.
    #[test]
    fn the_checksum_is_of_the_short_name() {
        assert_eq!(checksum(b"THEFIL~1TXT"), 0x21);
        assert_eq!(checksum(b"README  TXT"), 0x73);
        assert_eq!(checksum(b"           "), 0xF7);
    }

    #[test]
    fn a_short_name_reads_as_it_was_written() {
        assert_eq!(of_short(b"README  TXT", 0), "README.TXT");
        assert_eq!(of_short(b"README  TXT", 0x18), "readme.txt");
        assert_eq!(of_short(b"README  TXT", 0x08), "readme.TXT");
        assert_eq!(of_short(b"MAKEFILE   ", 0), "MAKEFILE");
        assert_eq!(of_short(b".          ", 0), ".");
        // The byte a name cannot begin with, because a deleted record does:
        // 0x05 stands for it, and 0xE5 is a sigma in code page 437.
        assert_eq!(of_short(b"\x05ABC    TXT", 0), "σABC.TXT");
        assert_eq!(of_short(b"\x82\x84\x94     TXT", 0), "éäö.TXT");
    }

    #[test]
    fn a_long_name_ends_where_it_ends() {
        let mut characters = vec![0xFFFFu16; 26];
        for (i, c) in "a name".encode_utf16().enumerate() {
            characters[i] = c;
        }
        characters[6] = 0;
        assert_eq!(of_long(&characters), "a name");
    }
}
