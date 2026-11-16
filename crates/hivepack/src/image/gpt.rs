//! A GUID partition table, as the UEFI specification gives it (2.10, §5.3):
//! a header in the disk's second sector, an array of entries after it, and
//! a copy of both at the disk's end.
//!
//! Nothing is ported here; the specification is the whole of it. Both the
//! header and the entries carry a CRC-32, which is what tells a table from
//! bytes that look like one, and what makes the copy at the end worth
//! falling back to.

use super::disk::Disk;
use super::error::Error;
use super::partition::{Kind, Partition, guid, name_of};

/// The signature a header starts with.
pub(crate) const SIGNATURE: &[u8; 8] = b"EFI PART";

/// The least a header is, and the least an entry is: the specification
/// fixes both, and allows either to grow.
const HEADER: usize = 92;
const ENTRY: usize = 128;

/// How many entries are read at most, so that a header saying a number no
/// disk holds costs nothing. The specification reserves at least 16 KiB for
/// the array, which is the 128 entries of 128 bytes that every tool writes;
/// this allows eight times that before refusing the header.
const MOST_ENTRIES: u32 = 1024;

/// What a header holds, of what is read here.
struct Header {
    entries_at: u64,
    count: u32,
    entry_size: u32,
    entries_crc: u32,
}

/// The partitions the table names, with the header read from the disk's
/// second sector and, where that one cannot be trusted, from the copy at the
/// disk's end. `sector` is how many bytes a sector is.
pub(crate) fn partitions<D: Disk>(
    disk: &D,
    sector: u64,
    whole: u64,
) -> Result<Vec<Partition>, Error> {
    let last = (whole / sector).saturating_sub(1);
    let mut why = None;
    for at in [sector, last * sector] {
        if at == 0 || at >= whole {
            continue;
        }
        match read(disk, at, sector, whole) {
            Ok(found) => return Ok(found),
            // A partition the table names that is not on the disk is the
            // table's own answer, not a reason to read the copy: both
            // copies name the same partitions.
            Err(e @ (Error::Io(_) | Error::PastTheEnd { .. })) => return Err(e),
            Err(e) => why = Some(e),
        }
    }
    Err(why.unwrap_or(Error::HeaderCheck))
}

/// The partitions the header at `at` names.
fn read<D: Disk>(disk: &D, at: u64, sector: u64, whole: u64) -> Result<Vec<Partition>, Error> {
    let mut head = vec![0u8; HEADER];
    disk.read_exact_at(at, &mut head)?;
    if head.get(..8) != Some(&SIGNATURE[..]) {
        return Err(Error::HeaderCheck);
    }
    let size = u32::from_le_bytes(head[12..16].try_into().unwrap_or_default()) as usize;
    if size < HEADER || size as u64 > sector {
        return Err(Error::HeaderSays);
    }
    // The CRC-32 covers the header the size says it is, with its own field
    // read as zeroes.
    let mut whole_head = vec![0u8; size];
    disk.read_exact_at(at, &mut whole_head)?;
    let told = u32::from_le_bytes(whole_head[16..20].try_into().unwrap_or_default());
    whole_head[16..20].fill(0);
    if crate::deflate::crc32(0, &whole_head) != told {
        return Err(Error::HeaderCheck);
    }
    let header = Header {
        entries_at: u64::from_le_bytes(head[72..80].try_into().unwrap_or_default())
            .saturating_mul(sector),
        count: u32::from_le_bytes(head[80..84].try_into().unwrap_or_default()),
        entry_size: u32::from_le_bytes(head[84..88].try_into().unwrap_or_default()),
        entries_crc: u32::from_le_bytes(head[88..92].try_into().unwrap_or_default()),
    };
    if header.entry_size < ENTRY as u32
        || !header.entry_size.is_multiple_of(8)
        || header.count == 0
        || header.count > MOST_ENTRIES
    {
        return Err(Error::HeaderSays);
    }
    let room = u64::from(header.count) * u64::from(header.entry_size);
    if header.entries_at == 0 || header.entries_at.saturating_add(room) > whole {
        return Err(Error::HeaderSays);
    }
    let mut entries = vec![0u8; room as usize];
    disk.read_exact_at(header.entries_at, &mut entries)?;
    if crate::deflate::crc32(0, &entries) != header.entries_crc {
        return Err(Error::EntriesCheck);
    }
    let mut found = Vec::new();
    for (i, entry) in entries.chunks_exact(header.entry_size as usize).enumerate() {
        let kind = Kind::Guid(entry[..16].try_into().unwrap_or_default());
        if kind.is_empty() {
            continue;
        }
        let number = i as u32 + 1;
        let first = u64::from_le_bytes(entry[32..40].try_into().unwrap_or_default());
        let last = u64::from_le_bytes(entry[40..48].try_into().unwrap_or_default());
        let attributes = u64::from_le_bytes(entry[48..56].try_into().unwrap_or_default());
        // Both are sector numbers, and the last one is the partition's own
        // last sector, not the one after it.
        let (Some(at), Some(sectors)) = (
            first.checked_mul(sector),
            last.checked_sub(first).and_then(|n| n.checked_add(1)),
        ) else {
            return Err(Error::PastTheEnd { number });
        };
        let Some(size) = sectors.checked_mul(sector) else {
            return Err(Error::PastTheEnd { number });
        };
        if at.checked_add(size).is_none_or(|end| end > whole) {
            return Err(Error::PastTheEnd { number });
        }
        found.push(Partition {
            number,
            at,
            size,
            kind,
            name: entry.get(56..128).and_then(name_of),
            id: entry
                .get(16..32)
                .and_then(|g| g.try_into().ok())
                .map(|g: [u8; 16]| guid(&g)),
            // Bit 2: legacy BIOS bootable.
            bootable: attributes & (1 << 2) != 0,
        });
    }
    Ok(found)
}
