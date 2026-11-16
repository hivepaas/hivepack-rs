//! VHD images: the disk one holds, read against what `qemu-img` converts the
//! same image to, byte for byte, and against an image built here by hand so
//! that the reader is checked where `qemu-img` is not installed.
//!
//! See crates/hivepack/src/image/vhd.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{Disk, Error, Table, Unsupported, Vhd, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("hivepack-vhd-{}-{what}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `qemu-img`, if it is installed **and** can be run: a process cannot be
/// started everywhere these tests run — CI's 32-bit container answers
/// `ENOSYS` to `spawn` — so a test that needs a tool says so and passes
/// rather than failing for the want of one. The images built by hand are
/// what checks the reader there.
fn qemu_img() -> Option<PathBuf> {
    let path = [
        "/usr/bin/qemu-img",
        "/usr/local/bin/qemu-img",
        "/bin/qemu-img",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())?;
    Command::new(&path).arg("--version").output().ok()?;
    Some(path)
}

fn run(tool: &Path, args: &[&str]) {
    let out = Command::new(tool).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{tool:?} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Bytes that are the same every run, and not all alike: a block of them
/// compresses to nothing like a disk's own, and a sparse image keeps the
/// zeroes between.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        bytes.push((x >> 24) as u8);
    }
    bytes
}

/// A raw disk of `size` bytes, with `at` holding what `pattern` gives and
/// zeroes elsewhere: the holes are what tells a reader that answers with
/// zeroes from one that answers with whatever was in the file.
fn a_raw_disk(size: usize, at: &[(usize, usize)]) -> Vec<u8> {
    let mut disk = vec![0u8; size];
    for (i, (from, len)) in at.iter().enumerate() {
        disk[*from..*from + *len].copy_from_slice(&pattern(*len, i as u64 + 1));
    }
    disk
}

/// Every byte of `disk`, read in pieces that do not line up with its
/// blocks, so that a read crossing one is read too.
fn read_whole<D: Disk>(disk: &D) -> Vec<u8> {
    let size = disk.size().unwrap() as usize;
    let mut whole = vec![0u8; size];
    let mut at = 0;
    while at < size {
        // A size that is not a power of two, and not a divisor of a block.
        let want = 100_003.min(size - at);
        let read = disk.read_at(at as u64, &mut whole[at..at + want]).unwrap();
        assert!(read > 0, "the disk stopped answering at {at}");
        at += read;
    }
    whole
}

/// What `qemu-img` makes of `raw` in `format`, read back by both: hivepack's
/// bytes are compared with the ones `qemu-img convert -O raw` gives for the
/// same image, which is what says the two agree and not only that each is
/// consistent with itself.
///
/// The image is not as long as `raw`. A VHD's size is a whole number of
/// cylinders of its CHS geometry, so `qemu-img` rounds a disk up to one and
/// writes that as the size in the footer: an 8 MiB disk becomes 241 × 4 × 17
/// sectors, 2 KiB more. What `raw` held is at the front of it, and the rest
/// is zeroes, which is checked too.
fn through_qemu(what: &str, raw: &[u8], format: &str, options: &[&str]) {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(what);
    let source = s.0.join("disk.raw");
    let image = s.0.join(format!("disk.{format}"));
    std::fs::write(&source, raw).unwrap();
    let mut args = vec!["convert", "-f", "raw", "-O", format];
    args.extend_from_slice(options);
    args.push(source.to_str().unwrap());
    args.push(image.to_str().unwrap());
    run(&tool, &args);

    // What qemu-img itself says the image holds: the disk, as it reads it.
    let back = s.0.join("back.raw");
    run(
        &tool,
        [
            "convert",
            "-f",
            format,
            "-O",
            "raw",
            image.to_str().unwrap(),
            back.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let theirs = std::fs::read(&back).unwrap();

    // What hivepack reads from the same image.
    let file = std::fs::File::open(&image).unwrap();
    let vhd = Vhd::open(&file)
        .map_err(|e| format!("{what}: {e}"))
        .unwrap();
    assert_eq!(
        vhd.size().unwrap(),
        theirs.len() as u64,
        "{what}: the disk is as long as qemu-img reads it"
    );
    let mine = read_whole(&vhd);
    let differs = mine.iter().zip(&theirs).position(|(a, b)| a != b);
    assert!(
        differs.is_none() && mine.len() == theirs.len(),
        "{what}: differs from what qemu-img reads, at byte {differs:?}"
    );

    // And what was put in is at the front of it, the rounding's own bytes
    // after it being zeroes: the image holds the disk, not something near
    // it.
    assert!(theirs.len() >= raw.len(), "{what}: the disk shrank");
    assert!(
        &theirs[..raw.len()] == raw,
        "{what}: the disk itself changed"
    );
    assert!(
        theirs[raw.len()..].iter().all(|b| *b == 0),
        "{what}: what the rounding added is not zeroes"
    );
}

/// Four blocks of 2 MiB, with data in the first and third and holes in the
/// others: what a disk that grows is for.
fn sparse() -> Vec<u8> {
    a_raw_disk(
        8 << 20,
        &[(0, 1 << 20), (4 << 20, 3 << 20), ((8 << 20) - 512, 512)],
    )
}

#[test]
fn a_vhd_that_grows_reads_as_the_disk_it_holds() {
    through_qemu("dynamic", &sparse(), "vpc", &[]);
}

#[test]
fn a_vhd_that_does_not_grow_reads_as_the_disk_it_holds() {
    through_qemu("fixed", &sparse(), "vpc", &["-o", "subformat=fixed"]);
}

#[test]
fn a_disk_of_nothing_but_holes_reads_as_zeroes() {
    let empty = vec![0u8; 8 << 20];
    through_qemu("all holes", &empty, "vpc", &[]);
}

#[test]
fn a_disk_whose_data_is_everywhere_reads_whole() {
    through_qemu("full", &pattern(6 << 20, 7), "vpc", &[]);
}

#[test]
fn the_partitions_of_a_disk_in_a_vhd_are_its_own() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: partitions in a VHD are not checked");
        return;
    };
    let s = Scratch::new("partitions");
    // A disk with a table, as a card has.
    let mut raw = vec![0u8; 16 << 20];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    raw[entry + 4] = 0x83;
    raw[entry + 8..entry + 12].copy_from_slice(&2048u32.to_le_bytes());
    raw[entry + 12..entry + 16].copy_from_slice(&4096u32.to_le_bytes());
    let source = s.0.join("card.raw");
    let image = s.0.join("card.vhd");
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "vpc",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&image).unwrap();
    let vhd = Vhd::open(&file).unwrap();
    let found = partitions(&vhd).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions.len(), 1);
    assert_eq!(found.partitions[0].at, 2048 * 512);
    assert_eq!(found.partitions[0].size, 4096 * 512);
    assert_eq!(found.partitions[0].kind.says(), Some("Linux file system"));
}

/// A VHD that grows, built here: the reader is checked where `qemu-img` is
/// not installed, which is what CI has.
mod by_hand {
    use super::*;

    const SECTOR: usize = 512;
    const BLOCK: usize = 2 << 20;

    /// The footer and the dynamic header carry the ones' complement of the
    /// sum of their bytes, the checksum's own four read as zeroes.
    fn checksum(of: &mut [u8], at: usize) {
        of[at..at + 4].fill(0);
        let sum = of
            .iter()
            .fold(0u32, |sum, b| sum.wrapping_add(u32::from(*b)));
        of[at..at + 4].copy_from_slice(&(!sum).to_be_bytes());
    }

    /// An image of `blocks` blocks of 2 MiB, those in `written` holding
    /// `pattern` and the rest never written, with every sector of each
    /// written block marked in its bitmap, as a tool writes it.
    fn an_image(blocks: usize, written: &[usize]) -> (Vec<u8>, Vec<u8>) {
        an_image_with_bitmap(blocks, written, 0xFF)
    }

    /// The same, with `bits` in every byte of each block's bitmap.
    fn an_image_with_bitmap(blocks: usize, written: &[usize], bits: u8) -> (Vec<u8>, Vec<u8>) {
        let size = blocks * BLOCK;
        let bitmap = (BLOCK / SECTOR).div_ceil(8).next_multiple_of(SECTOR);
        let mut image = Vec::new();
        let mut disk = vec![0u8; size];

        let mut footer = vec![0u8; 512];
        footer[..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes()); // features
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&512u64.to_be_bytes()); // the header
        footer[40..48].copy_from_slice(&(size as u64).to_be_bytes()); // original
        footer[48..56].copy_from_slice(&(size as u64).to_be_bytes()); // current
        footer[60..64].copy_from_slice(&3u32.to_be_bytes()); // it grows
        checksum(&mut footer, 64);
        // The copy at the start, the header, then the table.
        image.extend_from_slice(&footer);

        let table_at = 512 + 1024;
        let mut header = vec![0u8; 1024];
        header[..8].copy_from_slice(b"cxsparse");
        header[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        header[16..24].copy_from_slice(&(table_at as u64).to_be_bytes());
        header[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        header[28..32].copy_from_slice(&(blocks as u32).to_be_bytes());
        header[32..36].copy_from_slice(&(BLOCK as u32).to_be_bytes());
        checksum(&mut header, 36);
        image.extend_from_slice(&header);

        // The table, padded to a whole sector, as every tool writes it.
        let room = (blocks * 4).next_multiple_of(SECTOR);
        let mut table = vec![0xFFu8; room];
        let mut next = (table_at + room) / SECTOR;
        for block in written {
            let sector = next;
            table[block * 4..block * 4 + 4].copy_from_slice(&(sector as u32).to_be_bytes());
            next += (bitmap + BLOCK) / SECTOR;
        }
        image.extend_from_slice(&table);

        for (i, block) in written.iter().enumerate() {
            image.extend(std::iter::repeat_n(bits, bitmap));
            let data = pattern(BLOCK, i as u64 + 1);
            disk[block * BLOCK..(block + 1) * BLOCK].copy_from_slice(&data);
            image.extend_from_slice(&data);
        }
        image.extend_from_slice(&footer);
        (image, disk)
    }

    #[test]
    fn an_image_built_by_hand_reads_as_its_disk() {
        let (image, disk) = an_image(4, &[0, 2]);
        let vhd = Vhd::open(&image).unwrap();
        assert_eq!(vhd.size().unwrap(), disk.len() as u64);
        assert_eq!(read_whole(&vhd), disk);
    }

    #[test]
    fn the_footer_at_the_start_is_read_where_the_end_is_lost() {
        let (mut image, disk) = an_image(2, &[1]);
        let last = image.len() - 512;
        image[last..last + 8].copy_from_slice(b"ruinedit");
        let vhd = Vhd::open(&image).unwrap();
        assert_eq!(read_whole(&vhd), disk);
    }

    /// The bitmap before each block says which of its sectors have been
    /// written, and the specification leaves the rest undefined. Neither
    /// QEMU nor hivepack reads it: a block is zeroes in the file where
    /// nothing was put in it, so the bitmap says nothing the data does not.
    /// Checked against `qemu-img`, which answers with the data for a block
    /// whose bitmap is all zeroes.
    #[test]
    fn the_bitmap_before_a_block_is_not_what_is_read() {
        let (image, disk) = an_image_with_bitmap(2, &[0], 0x00);
        let vhd = Vhd::open(&image).unwrap();
        assert_eq!(
            read_whole(&vhd),
            disk,
            "a block's data is its data, whatever its bitmap says"
        );
        let Some(tool) = qemu_img() else {
            return;
        };
        // And that is what qemu-img reads from the same image.
        let s = Scratch::new("bitmap");
        let path = s.0.join("cleared.vhd");
        let back = s.0.join("cleared.raw");
        std::fs::write(&path, &image).unwrap();
        run(
            &tool,
            [
                "convert",
                "-f",
                "vpc",
                "-O",
                "raw",
                path.to_str().unwrap(),
                back.to_str().unwrap(),
            ]
            .as_slice(),
        );
        assert_eq!(std::fs::read(&back).unwrap(), disk);
    }

    /// A footer holds both the disk's size and a CHS geometry, and an image
    /// can say two things. hivepack reads the size, which is what Microsoft's
    /// own tools write and the only field that can hold a disk larger than
    /// CHS can count (65535 × 16 × 255 sectors, about 127 GiB).
    ///
    /// QEMU reads the size too, for an image whose creator is `win ` (what
    /// Hyper-V and disk2vhd write) or its own `qem2`; for its own older
    /// `qemu` images it takes the geometry instead, and those it wrote with
    /// the geometry's own size, so the two agree in every file that is not
    /// made to disagree.
    #[test]
    fn the_size_in_the_footer_is_what_the_disk_is() {
        let (mut image, _) = an_image(2, &[0]);
        // The geometry of a disk half as long: 2 MiB in 512-byte sectors.
        for at in [0usize, image.len() - 512] {
            image[at + 56..at + 60].copy_from_slice(&[0, 64, 4, 16]);
            let footer = &mut image[at..at + 512];
            checksum(footer, 64);
        }
        let vhd = Vhd::open(&image).unwrap();
        assert_eq!(
            vhd.size().unwrap(),
            4 << 20,
            "the size in the footer, not what the geometry multiplies out to"
        );
    }

    #[test]
    fn what_is_not_a_vhd_and_what_cannot_be_read_are_told_apart() {
        assert!(matches!(
            Vhd::open(&vec![0u8; 4096]),
            Err(Error::Unrecognized)
        ));
        assert!(matches!(Vhd::open(&Vec::new()), Err(Error::Unrecognized)));
        // A header whose own checksum is wrong.
        let (mut image, _) = an_image(2, &[0]);
        image[512 + 36] ^= 0xFF;
        assert!(matches!(Vhd::open(&image), Err(Error::VhdCheck)));
        // A disk that holds only what changed from another.
        let (mut image, _) = an_image(2, &[0]);
        let last = image.len() - 512;
        for at in [60, last + 60] {
            image[at..at + 4].copy_from_slice(&4u32.to_be_bytes());
            let footer = &mut image[at - 60..at - 60 + 512];
            checksum(footer, 64);
        }
        assert!(matches!(
            Vhd::open(&image),
            Err(Error::Needs(Unsupported::Backing))
        ));
        // A block size that is not a power of two.
        let (mut image, _) = an_image(2, &[0]);
        image[512 + 32..512 + 36].copy_from_slice(&3_000_000u32.to_be_bytes());
        let header = &mut image[512..512 + 1024];
        checksum(header, 36);
        assert!(matches!(Vhd::open(&image), Err(Error::VhdSays)));
    }
}
