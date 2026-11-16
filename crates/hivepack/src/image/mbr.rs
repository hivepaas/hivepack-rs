//! A master boot record: four entries in the disk's first sector, and the
//! chain of extended boot records that holds the logical partitions.
//!
//! Nothing is ported here. The layout is the one every system has agreed on
//! since MS-DOS: the signature `0x55AA` in the last two bytes of the first
//! sector, and four 16-byte entries from byte 446.

use super::disk::Disk;
use super::error::Error;
use super::partition::{Kind, Partition};

/// Where the entries are in the first sector, and how many there are.
const ENTRIES: usize = 446;
const COUNT: usize = 4;
const ENTRY: usize = 16;

/// The signature, in the last two bytes of the first sector.
pub(crate) const SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// The types that say a partition holds other partitions, each the start of
/// a chain of extended boot records.
const EXTENDED: [u8; 3] = [0x05, 0x0F, 0x85];

/// GPT's protective record: one entry of this type, over the whole disk, is
/// what a GUID partition table leaves for a system that cannot read it.
pub(crate) const PROTECTIVE: u8 = 0xEE;

/// How many extended boot records are followed before the chain is taken to
/// lead nowhere. A disk with more logical partitions than this is not one
/// anything makes.
const MOST_LOGICAL: u32 = 128;

/// One entry, as the 16 bytes hold it.
struct Entry {
    bootable: bool,
    kind: u8,
    /// Where it starts, in sectors, counted from wherever the entry's own
    /// sector says it is counted from.
    start: u32,
    /// How long it is, in sectors.
    sectors: u32,
}

fn entry(of: &[u8]) -> Option<Entry> {
    let of = of.get(..ENTRY)?;
    Some(Entry {
        bootable: of[0] == 0x80,
        kind: of[4],
        start: u32::from_le_bytes(of[8..12].try_into().ok()?),
        sectors: u32::from_le_bytes(of[12..16].try_into().ok()?),
    })
}

/// Whether `first` is a sector with a master boot record's signature.
pub(crate) fn signed(first: &[u8]) -> bool {
    first.len() >= 512 && first[510..512] == SIGNATURE
}

/// Whether the record in `first` is GPT's protective one: one entry, of
/// GPT's own type, and nothing else.
pub(crate) fn protective(first: &[u8]) -> bool {
    let mut found = false;
    for i in 0..COUNT {
        let Some(e) = first.get(ENTRIES + i * ENTRY..).and_then(entry) else {
            return false;
        };
        if e.kind == PROTECTIVE {
            found = true;
        } else if e.kind != 0 {
            return false;
        }
    }
    found
}

/// The partitions a master boot record names, the primary ones first and
/// then the logical ones in the chains the extended entries start. `sector`
/// is how many bytes a sector is, which the entries count in.
pub(crate) fn partitions<D: Disk>(
    disk: &D,
    first: &[u8],
    sector: u64,
    whole: u64,
) -> Result<Vec<Partition>, Error> {
    let mut found = Vec::new();
    let mut chains = Vec::new();
    for i in 0..COUNT {
        let Some(e) = first.get(ENTRIES + i * ENTRY..).and_then(entry) else {
            continue;
        };
        // A type but no sectors is no partition: what some tools leave
        // behind when one is deleted.
        if e.kind == 0 || e.sectors == 0 {
            continue;
        }
        let number = i as u32 + 1;
        if EXTENDED.contains(&e.kind) {
            // The chain's own entry is not a partition anything is in: it
            // holds the logical ones, which are read below.
            chains.push(u64::from(e.start) * sector);
            continue;
        }
        found.push(made(
            number,
            u64::from(e.start) * sector,
            u64::from(e.sectors) * sector,
            Kind::Type(e.kind),
            e.bootable,
            whole,
        )?);
    }
    // Each logical partition's own record says where its data starts,
    // counted from that record, and where the next record is, counted from
    // the extended partition the chain belongs to.
    let mut number = 5;
    for chain in chains {
        let mut at = chain;
        let mut seen = Vec::new();
        let mut steps = 0;
        loop {
            if seen.contains(&at) || steps > MOST_LOGICAL {
                return Err(Error::ExtendedLoops);
            }
            seen.push(at);
            steps += 1;
            let mut record = [0u8; 512];
            if at >= whole || disk.read_at(at, &mut record)? < record.len() {
                break;
            }
            if !signed(&record) {
                break;
            }
            let (Some(here), Some(next)) = (
                record.get(ENTRIES..).and_then(entry),
                record.get(ENTRIES + ENTRY..).and_then(entry),
            ) else {
                break;
            };
            if here.kind != 0 && here.sectors > 0 {
                found.push(made(
                    number,
                    at + u64::from(here.start) * sector,
                    u64::from(here.sectors) * sector,
                    Kind::Type(here.kind),
                    here.bootable,
                    whole,
                )?);
                number += 1;
            }
            if next.kind == 0 || next.sectors == 0 {
                break;
            }
            at = chain + u64::from(next.start) * sector;
        }
    }
    Ok(found)
}

/// One partition, if it is on the disk at all.
fn made(
    number: u32,
    at: u64,
    size: u64,
    kind: Kind,
    bootable: bool,
    whole: u64,
) -> Result<Partition, Error> {
    if at.checked_add(size).is_none_or(|end| end > whole) {
        return Err(Error::PastTheEnd { number });
    }
    Ok(Partition {
        number,
        at,
        size,
        kind,
        name: None,
        id: None,
        bootable,
    })
}
