//! A disk image's partition tables: a master boot record and a GUID
//! partition table, read from tables built here byte by byte, and from
//! tables that util-linux's own tools wrote where they are installed.
//!
//! See crates/hivepack/src/image and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use hivepack::deflate::crc32;
use hivepack::image::{Disk, Error, Part, Table, partitions, partitions_in};

const SECTOR: usize = 512;

/// The type GUIDs used here, as they lie on the disk.
const EFI: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
const LINUX: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// A disk of `sectors` sectors of `sector` bytes, all zeroes.
fn disk(sectors: usize, sector: usize) -> Vec<u8> {
    vec![0u8; sectors * sector]
}

fn put(into: &mut [u8], at: usize, bytes: &[u8]) {
    into[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A master boot record's signature, and one entry of it.
fn mbr_signed(into: &mut [u8]) {
    put(into, 510, &[0x55, 0xAA]);
}

fn mbr_entry(into: &mut [u8], at: usize, kind: u8, start: u32, sectors: u32, bootable: bool) {
    let entry = 446 + at * 16;
    into[entry] = if bootable { 0x80 } else { 0 };
    into[entry + 4] = kind;
    put(into, entry + 8, &start.to_le_bytes());
    put(into, entry + 12, &sectors.to_le_bytes());
}

/// A GUID partition table over `image`, with the entries given as (type,
/// first sector, last sector, name, bootable). Both copies are written, as
/// every tool writes them.
fn gpt(image: &mut [u8], sector: usize, entries: &[([u8; 16], u64, u64, &str, bool)]) {
    const COUNT: u64 = 128;
    const ENTRY: u64 = 128;
    let sectors = (image.len() / sector) as u64;
    let room = (COUNT * ENTRY).div_ceil(sector as u64);
    let mut array = vec![0u8; (COUNT * ENTRY) as usize];
    for (i, (kind, first, last, name, bootable)) in entries.iter().enumerate() {
        let at = i * ENTRY as usize;
        put(&mut array, at, kind);
        // Something to tell it from every other partition.
        put(&mut array, at + 16, &[i as u8 + 1; 16]);
        put(&mut array, at + 32, &first.to_le_bytes());
        put(&mut array, at + 40, &last.to_le_bytes());
        put(
            &mut array,
            at + 48,
            &(if *bootable { 1u64 << 2 } else { 0 }).to_le_bytes(),
        );
        let utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain(std::iter::repeat_n(0, 72))
            .take(72)
            .collect();
        put(&mut array, at + 56, &utf16);
    }
    let entries_crc = crc32(0, &array);
    // The primary array after the header, the backup one before the backup
    // header, which is the disk's last sector.
    let primary_at = 2u64;
    let backup_at = sectors - 1 - room;
    put(image, primary_at as usize * sector, &array);
    put(image, backup_at as usize * sector, &array);
    for (me, other, array_at) in [
        (1u64, sectors - 1, primary_at),
        (sectors - 1, 1u64, backup_at),
    ] {
        let mut head = vec![0u8; 92];
        put(&mut head, 0, b"EFI PART");
        put(&mut head, 8, &0x0001_0000u32.to_le_bytes());
        put(&mut head, 12, &92u32.to_le_bytes());
        put(&mut head, 24, &me.to_le_bytes());
        put(&mut head, 32, &other.to_le_bytes());
        put(&mut head, 40, &(primary_at + room).to_le_bytes());
        put(&mut head, 48, &(backup_at - 1).to_le_bytes());
        put(&mut head, 56, &[0x11; 16]);
        put(&mut head, 72, &array_at.to_le_bytes());
        put(&mut head, 80, &(COUNT as u32).to_le_bytes());
        put(&mut head, 84, &(ENTRY as u32).to_le_bytes());
        put(&mut head, 88, &entries_crc.to_le_bytes());
        let crc = crc32(0, &head);
        put(&mut head, 16, &crc.to_le_bytes());
        put(image, me as usize * sector, &head);
    }
    // What a system that cannot read the table sees: one partition of
    // GPT's own type over the whole disk.
    mbr_signed(image);
    mbr_entry(image, 0, 0xEE, 1, (sectors - 1) as u32, false);
}

#[test]
fn a_master_boot_record_names_its_four_partitions() {
    let mut image = disk(2048, SECTOR);
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0x0C, 2048 / 2, 256, true);
    mbr_entry(&mut image, 1, 0x83, 2048 / 2 + 256, 256, false);
    let found = partitions(&image).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.sector, 512);
    assert_eq!(found.partitions.len(), 2);
    let first = &found.partitions[0];
    assert_eq!(first.number, 1);
    assert_eq!(first.at, 1024 * SECTOR as u64);
    assert_eq!(first.size, 256 * SECTOR as u64);
    assert_eq!(first.kind.says(), Some("FAT32"));
    assert!(first.bootable);
    assert_eq!(first.name, None, "a master boot record keeps no names");
    assert_eq!(found.partitions[1].kind.says(), Some("Linux file system"));
    assert!(!found.partitions[1].bootable);
}

#[test]
fn the_logical_partitions_of_an_extended_one_come_after_the_four() {
    let mut image = disk(4096, SECTOR);
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0x83, 64, 64, false);
    // An extended partition from sector 1024, holding two logical ones:
    // each record says where its own data is, counted from itself, and
    // where the next record is, counted from the extended partition.
    mbr_entry(&mut image, 1, 0x05, 1024, 3072, false);
    let first = 1024 * SECTOR;
    mbr_signed(&mut image[first..first + SECTOR]);
    mbr_entry(&mut image[first..first + SECTOR], 0, 0x0C, 1, 511, false);
    mbr_entry(&mut image[first..first + SECTOR], 1, 0x05, 512, 512, false);
    let second = (1024 + 512) * SECTOR;
    mbr_signed(&mut image[second..second + SECTOR]);
    mbr_entry(&mut image[second..second + SECTOR], 0, 0x83, 1, 511, false);
    let found = partitions(&image).unwrap().unwrap();
    let numbers: Vec<u32> = found.partitions.iter().map(|p| p.number).collect();
    assert_eq!(
        numbers,
        [1, 5, 6],
        "the chain's own entry is not a partition"
    );
    assert_eq!(found.partitions[1].at, 1025 * SECTOR as u64);
    assert_eq!(found.partitions[2].at, (1024 + 513) * SECTOR as u64);
    assert_eq!(found.partitions[2].kind.says(), Some("Linux file system"));
}

#[test]
fn a_chain_that_leads_back_into_itself_is_refused() {
    let mut image = disk(4096, SECTOR);
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0x05, 1024, 3072, false);
    let at = 1024 * SECTOR;
    mbr_signed(&mut image[at..at + SECTOR]);
    mbr_entry(&mut image[at..at + SECTOR], 0, 0x83, 1, 511, false);
    // The next record is this one.
    mbr_entry(&mut image[at..at + SECTOR], 1, 0x05, 0, 512, false);
    assert!(
        matches!(partitions(&image), Err(Error::ExtendedLoops)),
        "a chain that leads back into itself is read for ever otherwise"
    );
}

#[test]
fn a_guid_partition_table_names_its_partitions_with_their_names() {
    let mut image = disk(2048, SECTOR);
    gpt(
        &mut image,
        SECTOR,
        &[
            (EFI, 2048 - 1024, 2048 - 513, "EFI System", true),
            (LINUX, 2048 - 512, 2048 - 300, "Hệ thống", false),
        ],
    );
    let found = partitions(&image).unwrap().unwrap();
    assert_eq!(found.table, Table::Gpt);
    assert_eq!(found.sector, 512);
    assert_eq!(found.partitions.len(), 2);
    let efi = &found.partitions[0];
    assert_eq!(efi.number, 1);
    assert_eq!(efi.at, 1024 * SECTOR as u64);
    // The last sector is the partition's own, not the one after it.
    assert_eq!(efi.size, 512 * SECTOR as u64);
    assert_eq!(efi.kind.says(), Some("EFI system"));
    assert_eq!(efi.name.as_deref(), Some("EFI System"));
    assert_eq!(
        efi.id.as_deref(),
        Some("01010101-0101-0101-0101-010101010101")
    );
    assert!(efi.bootable);
    assert_eq!(
        found.partitions[1].name.as_deref(),
        Some("Hệ thống"),
        "a name is UTF-16, and not every name is ASCII"
    );
    assert_eq!(found.partitions[1].kind.says(), Some("Linux file system"));
}

#[test]
fn the_copy_at_the_end_is_read_where_the_first_header_is_damaged() {
    let mut image = disk(2048, SECTOR);
    gpt(&mut image, SECTOR, &[(LINUX, 1024, 1500, "root", false)]);
    let whole = partitions(&image).unwrap().unwrap();
    // One byte of the primary header, which its CRC-32 covers.
    image[SECTOR + 56] ^= 0xFF;
    let fallen_back = partitions(&image).unwrap().unwrap();
    assert_eq!(fallen_back, whole, "the copy at the end says the same");
    // Both damaged: it says why, and does not make partitions up.
    let backup = image.len() - SECTOR + 56;
    image[backup] ^= 0xFF;
    assert!(matches!(partitions(&image), Err(Error::HeaderCheck)));
}

#[test]
fn entries_that_fail_their_own_check_are_refused() {
    let mut image = disk(2048, SECTOR);
    gpt(&mut image, SECTOR, &[(LINUX, 1024, 1500, "root", false)]);
    // A byte of both copies of the array, which the header's CRC-32 covers.
    image[2 * SECTOR + 40] ^= 0xFF;
    let backup = image.len() - SECTOR - 32 * SECTOR + 40;
    image[backup] ^= 0xFF;
    assert!(matches!(partitions(&image), Err(Error::EntriesCheck)));
}

#[test]
fn a_partition_that_is_not_on_the_disk_is_refused() {
    let mut image = disk(2048, SECTOR);
    gpt(
        &mut image,
        SECTOR,
        &[(LINUX, 1024, 1_000_000, "root", false)],
    );
    assert!(matches!(
        partitions(&image),
        Err(Error::PastTheEnd { number: 1 })
    ));
}

#[test]
fn a_disk_that_says_it_has_a_table_but_has_none_says_why() {
    let mut image = disk(2048, SECTOR);
    // GPT's protective record, and no table behind it.
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0xEE, 1, 2047, false);
    assert!(
        partitions(&image).is_err(),
        "a protective record is not a disk of empty partitions"
    );
}

#[test]
fn a_table_counted_in_four_kibibyte_sectors_is_read_in_them() {
    let mut image = disk(512, 4096);
    gpt(&mut image, 4096, &[(LINUX, 64, 200, "root", false)]);
    let found = partitions(&image).unwrap().unwrap();
    assert_eq!(found.sector, 4096);
    assert_eq!(found.partitions[0].at, 64 * 4096);
    assert_eq!(found.partitions[0].size, 137 * 4096);
}

/// A master boot record says nothing about what a sector is, and its own
/// numbers cannot tell: in 512-byte sectors they come out smaller, so they
/// fit the disk either way. A disk of its own sectors is read by being told.
#[test]
fn a_master_boot_record_is_read_in_the_sectors_it_is_told() {
    let mut image = disk(512, 4096);
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0x83, 64, 128, false);
    // Read as every tool reads an image: 512-byte sectors.
    let as_usual = partitions(&image).unwrap().unwrap();
    assert_eq!(as_usual.sector, 512);
    assert_eq!(as_usual.partitions[0].at, 64 * 512);
    // Read as the disk's own container would say: its own sectors, which
    // is the only place that can be known from.
    let told = partitions_in(&image, 4096).unwrap().unwrap();
    assert_eq!(told.sector, 4096);
    assert_eq!(told.partitions[0].at, 64 * 4096);
    assert_eq!(told.partitions[0].size, 128 * 4096);
    // A sector size no disk has.
    assert!(matches!(
        partitions_in(&image, 500),
        Err(Error::SectorSize { sector: 500 })
    ));
    assert!(matches!(
        partitions_in(&image, 3000),
        Err(Error::SectorSize { sector: 3000 })
    ));
}

#[test]
fn a_file_with_no_table_has_none() {
    assert!(partitions(&disk(64, SECTOR)).unwrap().is_none());
    assert!(partitions(&Vec::new()).unwrap().is_none());
    // A file system with no table around it: SquashFS's own first bytes.
    let mut alone = disk(64, SECTOR);
    put(&mut alone, 0, b"hsqs");
    assert!(partitions(&alone).unwrap().is_none());
}

#[test]
fn a_partition_is_read_as_a_disk_of_its_own() {
    let mut image = disk(2048, SECTOR);
    mbr_signed(&mut image);
    mbr_entry(&mut image, 0, 0x83, 1024, 512, false);
    put(
        &mut image,
        1024 * SECTOR,
        b"the partition's own first bytes",
    );
    let found = partitions(&image).unwrap().unwrap();
    let part = &found.partitions[0];
    let inside = Part::new(&image, part.at, part.size);
    assert_eq!(inside.size().unwrap(), 512 * SECTOR as u64);
    let mut head = [0u8; 31];
    inside.read_exact_at(0, &mut head).unwrap();
    assert_eq!(&head, b"the partition's own first bytes");
    // Nothing of the disk past the partition is in it.
    let mut over = [0xAAu8; 16];
    assert_eq!(
        inside.read_at(512 * SECTOR as u64 - 8, &mut over).unwrap(),
        8
    );
}

/// What util-linux's `sfdisk` writes, where it is installed: the tables
/// hivepack reads are the tables the system's own tool makes, not only the
/// ones these tests build.
#[test]
fn the_tables_util_linux_writes_are_read_as_it_names_them() {
    let Some(sfdisk) = ["/usr/sbin/sfdisk", "/sbin/sfdisk", "/usr/bin/sfdisk"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
    else {
        eprintln!("sfdisk is not installed: the tables it writes are not checked");
        return;
    };
    let folder = std::env::temp_dir().join(format!("hivepack-image-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    for (label, script) in [
        (
            Table::Mbr,
            "label: dos\nstart=2048, size=4096, type=83, bootable\nstart=6144, size=4096, type=c\n",
        ),
        (
            Table::Gpt,
            "label: gpt\nstart=2048, size=4096, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"EFI System\"\nstart=6144, size=4096, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=root\n",
        ),
    ] {
        let image = folder.join(format!("{label:?}.img"));
        std::fs::write(&image, vec![0u8; 16 << 20]).unwrap();
        let mut child = Command::new(&sfdisk)
            .arg(&image)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        {
            // In its own scope, so that the pipe is closed before it is
            // waited for: sfdisk reads its script to the end of the input,
            // and waits for ever for an input nothing closed.
            use std::io::Write;
            let mut writing = child.stdin.take().unwrap();
            writing.write_all(script.as_bytes()).unwrap();
        }
        assert!(
            child.wait().unwrap().success(),
            "sfdisk wrote no {label:?} table"
        );
        let read = partitions(&std::fs::File::open(&image).unwrap()).unwrap();
        assert!(
            read.is_some(),
            "no table where sfdisk wrote a {label:?} one"
        );
        let found = read.unwrap();
        assert_eq!(found.table, label);
        assert_eq!(found.sector, 512);
        assert_eq!(found.partitions.len(), 2, "{label:?}");
        assert_eq!(found.partitions[0].at, 2048 * 512, "{label:?}");
        assert_eq!(found.partitions[0].size, 4096 * 512, "{label:?}");
        assert_eq!(found.partitions[1].at, 6144 * 512, "{label:?}");
        if label == Table::Gpt {
            assert_eq!(found.partitions[0].kind.says(), Some("EFI system"));
            assert_eq!(found.partitions[0].name.as_deref(), Some("EFI System"));
            assert_eq!(found.partitions[1].name.as_deref(), Some("root"));
        } else {
            assert_eq!(found.partitions[0].kind.says(), Some("Linux file system"));
            assert!(found.partitions[0].bootable);
        }
    }
    let _ = std::fs::remove_dir_all(&folder);
}
