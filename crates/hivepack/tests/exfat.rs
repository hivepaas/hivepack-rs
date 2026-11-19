//! exFAT file systems: volumes `mkfs.exfat` wrote with files put in them
//! here and `fsck.exfat` run over the result, and volumes built byte by
//! byte so that the reader is checked where no tool is installed.
//!
//! See crates/hivepack/src/exfat/mod.rs, tests/exfat_support/mod.rs and
//! docs/exfat.md.

#![cfg(feature = "exfat")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "exfat_support/mod.rs"]
mod support;

use std::io::Read;
use std::process::Command;

use hivepack::exfat::{Error, Exfat};
use support::{ENTRY, FILE, Scratch, Volume, pattern, say_or_fail, tool, whole};

/// A volume as `mkfs.exfat` writes one: it opens, and its root holds the
/// files the format keeps there and nothing else.
#[test]
fn a_volume_a_tool_wrote_opens_and_its_root_is_empty() {
    let s = Scratch::new("empty");
    let Some(mut volume) = Volume::new(&s, 64 << 20, &["-q"]) else {
        say_or_fail("mkfs.exfat cannot be run here: a volume it wrote is not checked");
        return;
    };
    let path = volume.write(&s, "empty.img");
    Volume::fsck(&path).unwrap();
    let exfat = Exfat::open(std::fs::File::open(&path).unwrap()).unwrap();
    assert_eq!(exfat.cluster_size(), volume.cluster as u32);
    assert_eq!(exfat.sector_size(), volume.sector as u32);
    assert_eq!(exfat.clusters(), volume.clusters);
    assert!(!exfat.dirty() && !exfat.media_failure() && !exfat.from_backup());
    // The bitmap, the upcase table and the label are entries of the root,
    // and none of them is a file: what is read is what is in it.
    assert_eq!(exfat.read_root().unwrap(), Vec::new());
}

/// The label a tool set is the label that is read. exFAT keeps it in the
/// root directory and nowhere else, unlike FAT, which keeps a copy in the
/// boot sector.
#[test]
fn the_label_a_tool_set_is_the_one_that_is_read() {
    let s = Scratch::new("label");
    let Some(mut volume) = Volume::new(&s, 64 << 20, &["-q", "-L", "Thẻ nhớ"]) else {
        say_or_fail("mkfs.exfat cannot be run here: the label is not checked");
        return;
    };
    let path = volume.write(&s, "label.img");
    Volume::fsck(&path).unwrap();
    let exfat = Exfat::open(std::fs::File::open(&path).unwrap()).unwrap();
    assert_eq!(exfat.label(), Some("Thẻ nhớ"));
    // And what `exfatlabel` reads from it is the same thing. It prints its
    // own version first, and the label on a line of its own.
    if let Some(exfatlabel) = tool("exfatlabel") {
        let out = Command::new(&exfatlabel).arg(&path).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        let label = said
            .lines()
            .find_map(|line| line.strip_prefix("label:"))
            .unwrap_or_else(|| panic!("exfatlabel said no label: {said}"));
        assert_eq!(label.trim(), "Thẻ nhớ");
    }
}

/// Files written into a volume `mkfs.exfat` made, with `fsck.exfat` run
/// over the result: every name, length and byte comes back as it went in.
///
/// The files are written here because nothing can mount exFAT without root
/// — and because a volume this test built is one `fsck.exfat` will say is
/// clean or not, which is a better check than anything this test could
/// assert on its own.
#[test]
fn files_written_into_a_real_volume_read_back_as_they_went_in() {
    let s = Scratch::new("files");
    let Some(mut volume) = Volume::new(&s, 64 << 20, &["-q", "-c", "32K"]) else {
        say_or_fail("mkfs.exfat cannot be run here: files in a real volume are not checked");
        return;
    };
    let small = b"hello from exFAT\n".to_vec();
    let over_a_cluster = pattern(100_000, 7);
    let cut_up = pattern(90_000, 11);
    volume.add_file("NOTES.TXT", &small, true);
    volume.add_file("big.bin", &over_a_cluster, true);
    // One whose clusters are not a run, so the table is what finds them.
    volume.add_file("Hồ sơ.bin", &cut_up, false);
    volume.add_dir_with_file("thư mục", "inside.txt", b"a file in a directory\n");
    let path = volume.write(&s, "files.img");
    Volume::fsck(&path).unwrap();

    let exfat = Exfat::open(std::fs::File::open(&path).unwrap()).unwrap();
    let mut names: Vec<String> = exfat
        .read_root()
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    names.sort();
    assert_eq!(names, ["Hồ sơ.bin", "NOTES.TXT", "big.bin", "thư mục"]);

    assert_eq!(whole(&exfat, "NOTES.TXT"), small);
    assert_eq!(whole(&exfat, "big.bin"), over_a_cluster);
    assert_eq!(whole(&exfat, "Hồ sơ.bin"), cut_up);
    assert_eq!(
        whole(&exfat, "thư mục/inside.txt"),
        b"a file in a directory\n"
    );
    // A name is looked for without regard to case, as every system that
    // reads exFAT does.
    assert_eq!(whole(&exfat, "notes.txt"), small);
    assert_eq!(
        whole(&exfat, "THƯ MỤC/INSIDE.TXT"),
        b"a file in a directory\n"
    );

    // The whole tree, walked: the directory comes with what is in it.
    let mut walk = exfat.walk().unwrap();
    let mut paths = Vec::new();
    while let Some((path, _)) = walk.next(&exfat).unwrap() {
        paths.push(path);
    }
    paths.sort();
    assert_eq!(
        paths,
        [
            "Hồ sơ.bin",
            "NOTES.TXT",
            "big.bin",
            "thư mục",
            "thư mục/inside.txt"
        ]
    );

    // The times, which exFAT keeps with the offset from UTC beside them.
    let entry = exfat.lookup_path("NOTES.TXT").unwrap().unwrap();
    let modified = entry.modified.unwrap();
    assert_eq!(
        (modified.year, modified.month, modified.day, modified.hour),
        (2026, 11, 19, 12)
    );
    assert_eq!(modified.offset, Some(0));
}

/// `fsck.exfat` is the oracle the tests above lean on, so it has to be one
/// that would notice: the same volume with one byte of a set's checksum
/// turned over is one it refuses.
#[test]
fn the_tool_that_checks_the_volumes_would_notice_a_wrong_one() {
    let s = Scratch::new("teeth");
    let Some(mut volume) = Volume::new(&s, 64 << 20, &["-q", "-c", "32K"]) else {
        say_or_fail("mkfs.exfat cannot be run here: the oracle is not checked");
        return;
    };
    if tool("fsck.exfat").is_none() {
        say_or_fail("fsck.exfat cannot be run here: the oracle is not checked");
        return;
    }
    volume.add_file("NOTES.TXT", b"hello\n", true);
    let good = volume.write(&s, "good.img");
    Volume::fsck(&good).expect("the volume as it was built is not clean");

    // The set's own checksum, two bytes into the file entry, turned over:
    // the volume is the same in every other way.
    let at = volume.cluster_at(volume.root) as usize;
    let set = volume.bytes[at..at + 32 * 8]
        .as_chunks::<ENTRY>()
        .0
        .iter()
        .position(|entry| entry[0] == FILE)
        .expect("no file entry in the root");
    volume.bytes[at + set * 32 + 2] ^= 1;
    let bad = volume.write(&s, "bad.img");
    assert!(
        Volume::fsck(&bad).is_err(),
        "fsck.exfat called a volume clean whose set checksum is wrong, \
         so it is not an oracle for the tests above"
    );
    // And hivepack refuses it for the same reason.
    let exfat = Exfat::open(std::fs::File::open(&bad).unwrap()).unwrap();
    assert!(matches!(exfat.read_root(), Err(Error::SetChecksum)));
}

/// Room a file was given and never filled reads as zeroes, and not as
/// whatever was in those clusters before. exFAT is the only file system
/// here that says how much of a file has been written.
#[test]
fn room_a_file_was_given_and_never_filled_reads_as_zeroes() {
    let s = Scratch::new("valid");
    let Some(mut volume) = Volume::new(&s, 64 << 20, &["-q", "-c", "32K"]) else {
        say_or_fail("mkfs.exfat cannot be run here: valid data length is not checked");
        return;
    };
    // Two clusters of somebody else's data, given to a file that says only
    // the first hundred bytes of it have ever been written.
    let before = pattern(64 << 10, 13);
    let clusters = volume.give(2, true);
    volume.put_data(&before, &clusters);
    let set = volume.a_set("HALF.BIN", 64 << 10, 100, clusters[0], false, true);
    let root = volume.root;
    volume.add_entries(root, &[set]);
    let path = volume.write(&s, "valid.img");
    Volume::fsck(&path).unwrap();

    let exfat = Exfat::open(std::fs::File::open(&path).unwrap()).unwrap();
    let entry = exfat.lookup_path("HALF.BIN").unwrap().unwrap();
    assert_eq!((entry.size, entry.valid), (64 << 10, 100));
    let read = whole(&exfat, "HALF.BIN");
    assert_eq!(read.len(), 64 << 10);
    assert_eq!(&read[..100], &before[..100]);
    assert!(
        read[100..].iter().all(|b| *b == 0),
        "room that was never written read something"
    );
}

/// Volumes built byte by byte: the reader is checked where no tool is
/// installed, and the volumes that say something impossible are built here
/// because no tool writes one.
mod by_hand {
    use super::*;

    use support::by_hand::*;

    #[test]
    fn a_volume_built_here_reads_as_it_was_built() {
        let data = pattern(CLUSTER + 200, 3);
        let bytes = with_a_cut_up_file(&data);
        let exfat = Exfat::open(bytes.as_slice()).unwrap();
        assert_eq!(exfat.cluster_size(), CLUSTER as u32);
        assert_eq!(exfat.sector_size(), SECTOR as u32);
        assert_eq!(exfat.serial(), 0x1234_5678);
        let entry = exfat.lookup_path("cut.bin").unwrap().unwrap();
        assert_eq!(entry.size, data.len() as u64);
        assert!(!entry.is_contiguous());
        let mut read = Vec::new();
        exfat.file(&entry).unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, data);
    }

    /// The backup boot region is read where the one at the volume's start
    /// fails the checksum the format keeps over it — a volume whose first
    /// sectors were written over, which is what a tool repairs from the
    /// backup.
    #[test]
    fn the_backup_region_is_read_where_the_first_one_is_ruined() {
        let data = pattern(100, 5);
        let mut bytes = with_a_cut_up_file(&data);
        // The backup region, as every volume carries one: the first twelve
        // sectors copied to sector 12.
        let region = bytes[..12 * SECTOR].to_vec();
        bytes[12 * SECTOR..24 * SECTOR].copy_from_slice(&region);
        // Now the first region is overwritten, as a partition table
        // written over the volume would: it still says exFAT, and its
        // checksum no longer holds.
        bytes[200..300].fill(0xAA);
        let exfat = Exfat::open(bytes.as_slice()).unwrap();
        assert!(
            exfat.from_backup(),
            "the backup region was not the one read"
        );
        assert_eq!(exfat.lookup_path("cut.bin").unwrap().unwrap().size, 100);

        // With no backup to fall back on, the volume says what is wrong.
        let mut alone = with_a_cut_up_file(&data);
        alone[200..300].fill(0xAA);
        assert!(matches!(
            Exfat::open(alone.as_slice()),
            Err(Error::Checksum)
        ));
    }

    #[test]
    fn what_is_not_exfat_is_not_opened_as_it() {
        // Nothing, and a file too short to hold a boot sector.
        assert!(matches!(
            Exfat::open([].as_slice()),
            Err(Error::Unrecognized)
        ));
        assert!(matches!(
            Exfat::open(vec![0u8; 100].as_slice()),
            Err(Error::Unrecognized)
        ));
        // A boot sector with no signature at its end.
        let bytes = a_volume(|boot| boot[510..512].fill(0));
        assert!(matches!(
            Exfat::open(bytes.as_slice()),
            Err(Error::Unrecognized)
        ));
        // FAT, which ends with the same two bytes and says its own name
        // further on: what tells it is that the bytes exFAT keeps at zero
        // hold FAT's numbers.
        let bytes = a_volume(|boot| {
            boot[11..13].copy_from_slice(&512u16.to_le_bytes());
            boot[13] = 8;
        });
        assert!(matches!(Exfat::open(bytes.as_slice()), Err(Error::Fat)));
    }

    /// Each of these is a volume that says it is exFAT and then says
    /// something that cannot be read.
    #[test]
    fn a_volume_that_says_what_it_cannot_is_refused() {
        let says =
            |change: fn(&mut [u8])| Exfat::open(a_volume(change).as_slice()).map(|_| ()).err();
        let cannot = |change: fn(&mut [u8])| {
            assert!(
                matches!(says(change), Some(Error::Says)),
                "a volume that cannot be read was read"
            );
        };
        // Sector sizes no disk has, and a cluster past the 32 MiB the
        // shifts allow.
        cannot(|boot| boot[108] = 8);
        cannot(|boot| boot[108] = 13);
        cannot(|boot| boot[109] = 20);
        // Two tables where the volume has room for one, no table at all,
        // and a table too short for the clusters it must reach.
        cannot(|boot| boot[110] = 3);
        cannot(|boot| boot[84..88].fill(0));
        cannot(|boot| boot[92..96].copy_from_slice(&1_000_000u32.to_le_bytes()));
        // A table over the boot regions, which are not free for one.
        cannot(|boot| boot[80..84].copy_from_slice(&4u32.to_le_bytes()));
        // No clusters at all, and more than a volume can hold.
        cannot(|boot| boot[92..96].fill(0));
        cannot(|boot| boot[92..96].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()));
        // A root directory that is not a cluster of this volume.
        cannot(|boot| boot[96..100].fill(0));
        cannot(|boot| boot[96..100].copy_from_slice(&1u32.to_le_bytes()));
        cannot(|boot| boot[96..100].copy_from_slice(&999u32.to_le_bytes()));
    }

    /// A chain that leads back into itself, and one that leads out of the
    /// volume: told, rather than read for ever.
    #[test]
    fn a_chain_that_goes_wrong_is_told() {
        let mut bytes = with_a_cut_up_file(&pattern(CLUSTER + 10, 9));
        put_fat(&mut bytes, 6, 4);
        let exfat = Exfat::open(bytes.as_slice()).unwrap();
        let entry = exfat.lookup_path("cut.bin").unwrap().unwrap();
        // The file is only two clusters long, so the loop is not read for
        // it; what it says is read is read.
        let mut read = Vec::new();
        exfat.file(&entry).unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read.len(), CLUSTER + 10);

        // A directory whose chain leads back into itself is walked once
        // and then told, since a directory is read whole.
        let mut bytes = a_volume(|_| {});
        let set = a_set("dir", CLUSTER as u64, 4, true, false);
        let root = cluster_at(2);
        bytes[root..root + set.len()].copy_from_slice(&set);
        put_fat(&mut bytes, 4, 4);
        let exfat = Exfat::open(bytes.as_slice()).unwrap();
        let entry = exfat.lookup_path("dir").unwrap().unwrap();
        assert!(matches!(
            exfat.read_dir(&entry),
            Err(Error::Chain { .. }) | Err(Error::TooMany)
        ));
    }

    #[test]
    fn a_file_is_not_a_directory_and_a_directory_is_not_a_file() {
        let bytes = with_a_cut_up_file(&pattern(10, 1));
        let exfat = Exfat::open(bytes.as_slice()).unwrap();
        let file = exfat.lookup_path("cut.bin").unwrap().unwrap();
        assert!(matches!(exfat.read_dir(&file), Err(Error::NotADirectory)));
        // A path that leads into a file leads nowhere.
        assert!(exfat.lookup_path("cut.bin/inside").unwrap().is_none());
        assert!(exfat.lookup_path("nothing-here").unwrap().is_none());
    }
}
