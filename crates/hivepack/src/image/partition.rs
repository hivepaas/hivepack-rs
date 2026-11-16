//! What a partition table names: where each partition is on the disk, how
//! long it is, and what the table says it holds.

use core::fmt;

/// Which table the partitions were read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// A master boot record: four partitions in the first sector, and the
    /// logical ones in the chain an extended partition starts.
    Mbr,
    /// A GUID partition table, as UEFI specifies it. Its protective master
    /// boot record is not read as a table of its own.
    Gpt,
}

/// What the table says a partition holds. Neither table says it for
/// certain: what is in a partition is told by reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A master boot record entry's type byte.
    Type(u8),
    /// A GUID partition table entry's partition type GUID, in the order
    /// the bytes are on the disk.
    Guid([u8; 16]),
}

/// One partition of a disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// Its number, as the systems that name partitions number them: 1 to 4
    /// for a master boot record's own entries, from 5 for the logical ones
    /// in an extended partition's chain, and 1 upwards for a GUID
    /// partition table's, counting the empty entries it leaves between.
    pub number: u32,
    /// Where it starts on the disk, in bytes.
    pub at: u64,
    /// How long it is, in bytes.
    pub size: u64,
    /// What the table says it holds.
    pub kind: Kind,
    /// Its name, which a GUID partition table keeps for each partition and
    /// a master boot record keeps for none. Empty names are none.
    pub name: Option<String>,
    /// What tells this partition from every other, which a GUID partition
    /// table gives and a master boot record does not.
    pub id: Option<String>,
    /// Whether the table marks it as the one to start the computer from: an
    /// entry's active flag, or the legacy BIOS bootable attribute.
    pub bootable: bool,
}

impl Partition {
    /// Where it ends, one past its last byte.
    pub fn end(&self) -> u64 {
        self.at.saturating_add(self.size)
    }
}

impl Kind {
    /// What the table's own number for it is known to mean, for the kinds
    /// met on a disk anyone opens. None for one not in the list, which says
    /// nothing about whether the partition can be read: what is in it is
    /// told by reading it.
    pub fn says(&self) -> Option<&'static str> {
        match self {
            Kind::Type(t) => Some(match t {
                0x01 => "FAT12",
                0x04 | 0x06 | 0x0E => "FAT16",
                0x05 | 0x0F | 0x85 => "Extended",
                0x07 => "NTFS or exFAT",
                0x0B | 0x0C => "FAT32",
                0x82 => "Linux swap",
                0x83 => "Linux file system",
                0x8E => "Linux LVM",
                0xA5 => "FreeBSD",
                0xAF => "Apple HFS or HFS+",
                0xEE => "GPT's protective record",
                0xEF => "EFI system",
                0xFD => "Linux RAID",
                _ => return None,
            }),
            Kind::Guid(g) => Some(match &guid(g)[..] {
                "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI system",
                "21686148-6449-6E6F-744E-656564454649" => "BIOS boot",
                "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft basic data",
                "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows recovery",
                "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft reserved",
                "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux file system",
                "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
                "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
                "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => "Linux root (x86-64)",
                "933AC7E1-2EB4-4F13-B844-0E14E2AEF915" => "Linux home",
                "BC13C2FF-59E6-4262-A352-B275FD6F7172" => "Linux extended boot",
                "7C3457EF-0000-11AA-AA11-00306543ECAC" => "Apple APFS",
                "48465300-0000-11AA-AA11-00306543ECAC" => "Apple HFS+",
                "516E7CBA-6ECF-11D6-8FF8-00022D09712B" => "FreeBSD ZFS",
                _ => return None,
            }),
        }
    }

    /// Whether it is an entry no partition is in: a type of 0, or the GUID
    /// of all zeroes that an unused GUID partition table entry has.
    pub fn is_empty(&self) -> bool {
        match self {
            Kind::Type(t) => *t == 0,
            Kind::Guid(g) => g.iter().all(|b| *b == 0),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Type(t) => write!(f, "{t:#04x}"),
            Kind::Guid(g) => f.write_str(&guid(g)),
        }
    }
}

/// A GUID as every system writes one: the first three fields as the numbers
/// they are, which are kept on the disk with their bytes the other way
/// about, and the rest as they lie.
pub(crate) fn guid(g: &[u8; 16]) -> String {
    use core::fmt::Write;

    let mut text = String::with_capacity(36);
    // The first three fields are numbers, whose bytes lie the other way
    // about on the disk; the last two are bytes as they lie.
    let backwards: [&[usize]; 3] = [&[3, 2, 1, 0], &[5, 4], &[7, 6]];
    let forwards: [&[usize]; 2] = [&[8, 9], &[10, 11, 12, 13, 14, 15]];
    for (i, field) in backwards.iter().chain(forwards.iter()).enumerate() {
        if i > 0 {
            text.push('-');
        }
        for at in *field {
            // A write to a String cannot fail.
            let _ = write!(text, "{:02X}", g[*at]);
        }
    }
    text
}

/// A name a GUID partition table entry holds: UTF-16, little-endian, as
/// many characters as there are before the first NUL. None for a name of
/// nothing.
pub(crate) fn name_of(raw: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(*pair);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    let name = String::from_utf16_lossy(&units);
    (!name.is_empty()).then_some(name)
}
