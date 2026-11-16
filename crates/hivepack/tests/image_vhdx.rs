//! VHDX images: the disk one holds, read against what `qemu-img` converts
//! the same image to, byte for byte, with blocks and sectors of several
//! sizes — and the sector size the image itself says, which is what a
//! master boot record cannot say and what `partitions_in` is for.
//!
//! See crates/hivepack/src/image/vhdx.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{Disk, Error, Table, Vhdx, partitions, partitions_in};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "hivepack-vhdx-{}-{}",
            std::process::id(),
            what.replace(' ', "-")
        ));
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

/// `qemu-img`, if it is installed and can be run: see image_vhd.rs, which
/// says why the second half matters.
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

/// Bytes that are the same every run and not all alike.
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

/// A raw disk with data where `at` says and zeroes elsewhere.
fn a_raw_disk(size: usize, at: &[(usize, usize)]) -> Vec<u8> {
    let mut disk = vec![0u8; size];
    for (i, (from, len)) in at.iter().enumerate() {
        disk[*from..*from + *len].copy_from_slice(&pattern(*len, i as u64 + 1));
    }
    disk
}

/// Every byte of `disk`, in pieces that do not line up with its blocks.
fn read_whole<D: Disk>(disk: &D) -> Vec<u8> {
    let size = disk.size().unwrap() as usize;
    let mut whole = vec![0u8; size];
    let mut at = 0;
    while at < size {
        let want = 100_003.min(size - at);
        let read = disk.read_at(at as u64, &mut whole[at..at + want]).unwrap();
        assert!(read > 0, "the disk stopped answering at {at}");
        at += read;
    }
    whole
}

/// `raw` through `qemu-img` into a VHDX made with `options`, read by
/// `qemu-img` and by hivepack, and the two compared byte for byte. Answers
/// with what the image says a sector is.
fn through_qemu(what: &str, raw: &[u8], options: &[&str]) -> Option<u64> {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return None;
    };
    let s = Scratch::new(what);
    let source = s.0.join("disk.raw");
    let image = s.0.join("disk.vhdx");
    let back = s.0.join("back.raw");
    std::fs::write(&source, raw).unwrap();
    let mut args = vec!["convert", "-f", "raw", "-O", "vhdx"];
    args.extend_from_slice(options);
    args.push(source.to_str().unwrap());
    args.push(image.to_str().unwrap());
    run(&tool, &args);
    run(
        &tool,
        [
            "convert",
            "-f",
            "vhdx",
            "-O",
            "raw",
            image.to_str().unwrap(),
            back.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let theirs = std::fs::read(&back).unwrap();

    let file = std::fs::File::open(&image).unwrap();
    let vhdx = Vhdx::open(&file)
        .map_err(|e| format!("{what}: {e}"))
        .unwrap();
    assert_eq!(
        vhdx.size().unwrap(),
        theirs.len() as u64,
        "{what}: the disk is as long as qemu-img reads it"
    );
    let mine = read_whole(&vhdx);
    let differs = mine.iter().zip(&theirs).position(|(a, b)| a != b);
    assert!(
        differs.is_none() && mine.len() == theirs.len(),
        "{what}: differs from what qemu-img reads, at byte {differs:?}"
    );
    // What went in is at the front of it; VHDX rounds a disk up to a whole
    // sector, not to a cylinder as VHD does, so there is little to round.
    assert!(theirs.len() >= raw.len(), "{what}: the disk shrank");
    assert!(
        &theirs[..raw.len()] == raw,
        "{what}: the disk itself changed"
    );
    assert!(
        theirs[raw.len()..].iter().all(|b| *b == 0),
        "{what}: what the rounding added is not zeroes"
    );
    Some(vhdx.sector())
}

/// Data in two places and holes between, with a tail: holes, data and a
/// partial block all read.
fn sparse() -> Vec<u8> {
    a_raw_disk(
        16 << 20,
        &[(0, 1 << 20), (8 << 20, 5 << 20), ((16 << 20) - 512, 512)],
    )
}

#[test]
fn a_vhdx_reads_as_the_disk_it_holds() {
    through_qemu("plain", &sparse(), &[]);
}

#[test]
fn an_image_of_nothing_but_holes_reads_as_zeroes() {
    through_qemu("all holes", &vec![0u8; 16 << 20], &[]);
}

#[test]
fn an_image_full_of_data_reads_whole() {
    through_qemu("full", &pattern(12 << 20, 7), &[]);
}

/// The block size shapes the table, and with it how many entries of the
/// table are blocks of the disk before one that is a bitmap instead.
#[test]
fn a_block_size_of_its_own_is_read_in_it() {
    for block in ["1M", "2M", "8M"] {
        through_qemu(
            &format!("block {block}"),
            &sparse(),
            &["-o", &format!("block_size={block}")],
        );
    }
}

/// A VHDX is the only container here that says what a sector is on the disk
/// it holds, which is what `partitions_in` wants: a master boot record's own
/// numbers cannot tell, since counted in a smaller sector they come out
/// smaller and fit the disk either way.
///
/// `qemu-img` writes 512 and has no option for anything else (its vhdx
/// driver takes `block_size`, `block_state_zero`, `log_size`, `size` and
/// `subformat`, and that is all), so the image it writes is read and then
/// the one item is changed in a copy of it. The metadata table carries no
/// checksum of its own — only the headers and the region tables do — so
/// nothing else has to be put right, and what is being checked is that the
/// field is read rather than assumed.
#[test]
fn the_sector_size_the_image_says_is_what_the_table_is_read_in() {
    /// Logical Sector Size, as its GUID lies in the file.
    const ITEM: [u8; 16] = [
        0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB,
        0x5F,
    ];

    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: the sector size is not checked against it");
        return;
    };
    let s = Scratch::new("sector");
    // A table whose numbers are counted in the disk's own sectors.
    let start = 2048u32;
    let sectors = 4096u32;
    let mut raw = vec![0u8; 64 << 20];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    raw[entry + 4] = 0x83;
    raw[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
    raw[entry + 12..entry + 16].copy_from_slice(&sectors.to_le_bytes());
    let source = s.0.join("card.raw");
    let image = s.0.join("card.vhdx");
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "vhdx",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );

    // As qemu-img wrote it: sectors of 512 bytes, and a table read in them.
    let whole = std::fs::read(&image).unwrap();
    let vhdx = Vhdx::open(&whole).unwrap();
    assert_eq!(vhdx.sector(), 512, "what qemu-img writes");
    let as_usual = partitions(&vhdx).unwrap().unwrap();
    assert_eq!(as_usual.table, Table::Mbr);
    assert_eq!(as_usual.sector, 512);
    assert_eq!(as_usual.partitions[0].at, u64::from(start) * 512);
    assert_eq!(as_usual.partitions[0].size, u64::from(sectors) * 512);

    // The same image, with its one item saying the disk's sectors are its
    // own: the metadata region's entries say where each item is, counted
    // from that region's start, so the item is found rather than guessed.
    let metadata = region_at(&whole);
    let at = item_at(&whole, metadata, &ITEM);
    let mut changed = whole.clone();
    changed[at..at + 4].copy_from_slice(&4096u32.to_le_bytes());
    let vhdx = Vhdx::open(&changed).unwrap();
    assert_eq!(vhdx.sector(), 4096, "the image says, and it is read");
    // Read as every tool reads an image file, which is now the wrong
    // answer for this disk, and read in what it says, which is the right
    // one: the same bytes, eight times further in.
    assert_eq!(
        partitions(&vhdx).unwrap().unwrap().partitions[0].at,
        u64::from(start) * 512
    );
    let told = partitions_in(&vhdx, vhdx.sector()).unwrap().unwrap();
    assert_eq!(told.sector, 4096);
    assert_eq!(told.partitions[0].at, u64::from(start) * 4096);
    assert_eq!(told.partitions[0].size, u64::from(sectors) * 4096);
}

/// Where the metadata region of `image` is, from the region table at
/// 192 KiB: its entries are a GUID, where the region is, and how long.
fn region_at(image: &[u8]) -> usize {
    const METADATA: [u8; 16] = [
        0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88,
        0x6E,
    ];
    let table = 192 << 10;
    let count = u32::from_le_bytes(image[table + 8..table + 12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = table + 16 + i * 32;
        if image[e..e + 16] == METADATA {
            return u64::from_le_bytes(image[e + 16..e + 24].try_into().unwrap()) as usize;
        }
    }
    unreachable!("a VHDX qemu-img wrote has a metadata region")
}

/// Where the item `want` of the metadata region at `region` is, in the file.
fn item_at(image: &[u8], region: usize, want: &[u8; 16]) -> usize {
    let count = u16::from_le_bytes(image[region + 10..region + 12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = region + 32 + i * 32;
        if &image[e..e + 16] == want {
            let at = u32::from_le_bytes(image[e + 16..e + 20].try_into().unwrap()) as usize;
            return region + at;
        }
    }
    unreachable!("every VHDX says what a sector is")
}

#[test]
fn an_image_that_holds_only_what_changed_is_refused() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: what is refused is not checked against it");
        return;
    };
    let s = Scratch::new("refused");
    let parent = s.0.join("parent.vhdx");
    let child = s.0.join("child.vhdx");
    run(
        &tool,
        ["create", "-f", "vhdx", parent.to_str().unwrap(), "16M"].as_slice(),
    );
    let made = Command::new(&tool)
        .args([
            "create",
            "-f",
            "vhdx",
            "-b",
            parent.to_str().unwrap(),
            "-F",
            "vhdx",
            child.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    if !made.status.success() {
        eprintln!("qemu-img writes no differencing VHDX here: that refusal is checked by hand");
        return;
    }
    let file = std::fs::File::open(&child).unwrap();
    assert!(
        matches!(
            Vhdx::open(&file),
            Err(Error::Needs(hivepack::image::Unsupported::Backing))
        ),
        "an image with another behind it holds only what differs from it"
    );
}

#[test]
fn what_is_not_a_vhdx_is_told_from_one() {
    assert!(matches!(
        Vhdx::open(&vec![0u8; 512 << 10]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(Vhdx::open(&Vec::new()), Err(Error::Unrecognized)));
    // Its first bytes and nothing else: long enough to hold the headers,
    // and nothing in them.
    let mut head = vec![0u8; 512 << 10];
    head[..8].copy_from_slice(b"vhdxfile");
    assert!(matches!(Vhdx::open(&head), Err(Error::VhdxCheck)));
}
