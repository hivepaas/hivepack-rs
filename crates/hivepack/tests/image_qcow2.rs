//! QCOW2 images: the disk one holds, read against what `qemu-img` converts
//! the same image to, byte for byte — plain, compressed with zlib, compressed
//! with Zstandard, with holes and with clusters the image says are zeroes —
//! and against images built here so that the reader is checked where
//! `qemu-img` cannot be run.
//!
//! See crates/hivepack/src/image/qcow2.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{Disk, Error, Qcow2, Table, Unsupported, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("hivepack-qcow2-{}-{what}", std::process::id()));
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

/// Every byte of `disk`, in pieces that do not line up with its clusters.
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

/// `raw` through `qemu-img` into a QCOW2 image made with `options`, then read
/// by `qemu-img` and by hivepack, and the two compared byte for byte.
fn through_qemu(what: &str, raw: &[u8], options: &[&str]) {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(what);
    let source = s.0.join("disk.raw");
    let image = s.0.join("disk.qcow2");
    let back = s.0.join("back.raw");
    std::fs::write(&source, raw).unwrap();
    let mut args = vec!["convert", "-f", "raw", "-O", "qcow2"];
    args.extend_from_slice(options);
    args.push(source.to_str().unwrap());
    args.push(image.to_str().unwrap());
    run(&tool, &args);
    run(
        &tool,
        [
            "convert",
            "-f",
            "qcow2",
            "-O",
            "raw",
            image.to_str().unwrap(),
            back.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let theirs = std::fs::read(&back).unwrap();

    let file = std::fs::File::open(&image).unwrap();
    let qcow = Qcow2::open(&file)
        .map_err(|e| format!("{what}: {e}"))
        .unwrap();
    assert_eq!(
        qcow.size().unwrap(),
        theirs.len() as u64,
        "{what}: the disk is as long as qemu-img reads it"
    );
    let mine = read_whole(&qcow);
    let differs = mine.iter().zip(&theirs).position(|(a, b)| a != b);
    assert!(
        differs.is_none() && mine.len() == theirs.len(),
        "{what}: differs from what qemu-img reads, at byte {differs:?}"
    );
    // QCOW2 keeps the disk's size as it was asked for, so what went in is
    // what comes out, with no rounding as a VHD has.
    assert!(theirs == raw, "{what}: the disk itself changed");
}

/// Data in the first and third cluster-group and holes elsewhere, with a
/// tail, so that holes, data and a partial cluster are all read.
fn sparse() -> Vec<u8> {
    a_raw_disk(
        8 << 20,
        &[(0, 1 << 20), (4 << 20, 3 << 20), ((8 << 20) - 512, 512)],
    )
}

#[test]
fn a_qcow2_image_reads_as_the_disk_it_holds() {
    through_qemu("plain", &sparse(), &[]);
}

#[test]
fn an_image_of_nothing_but_holes_reads_as_zeroes() {
    through_qemu("all holes", &vec![0u8; 8 << 20], &[]);
}

#[test]
fn an_image_full_of_data_reads_whole() {
    through_qemu("full", &pattern(6 << 20, 7), &[]);
}

/// Compressed clusters are the part of QCOW2 that no other container here
/// has: each is a raw deflate stream that stops when a cluster has come out.
#[test]
fn clusters_compressed_with_zlib_read_as_their_data() {
    // Data that compresses, so that the clusters really are compressed.
    let mut disk = vec![0u8; 4 << 20];
    for (i, byte) in disk.iter_mut().enumerate() {
        *byte = (i / 4096) as u8;
    }
    through_qemu("zlib", &disk, &["-c"]);
}

#[test]
fn clusters_compressed_with_zstandard_read_as_their_data() {
    let mut disk = vec![0u8; 4 << 20];
    for (i, byte) in disk.iter_mut().enumerate() {
        *byte = (i / 4096) as u8;
    }
    through_qemu(
        "zstd",
        &disk,
        &["-c", "-o", "compat=v3,compression_type=zstd"],
    );
}

/// A cluster size that is not the 64 KiB every tool uses by default: the
/// tables' shape follows it, and so does where a compressed cluster's own
/// bits are in its entry.
#[test]
fn a_cluster_size_of_its_own_is_read_in_it() {
    for size in ["512", "4096", "2M"] {
        through_qemu(
            &format!("cluster {size}"),
            &sparse(),
            &["-o", &format!("cluster_size={size}")],
        );
    }
}

#[test]
fn the_partitions_of_a_disk_in_a_qcow2_image_are_its_own() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: partitions in a QCOW2 image are not checked");
        return;
    };
    let s = Scratch::new("partitions");
    let mut raw = vec![0u8; 16 << 20];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    raw[entry + 4] = 0x83;
    raw[entry + 8..entry + 12].copy_from_slice(&2048u32.to_le_bytes());
    raw[entry + 12..entry + 16].copy_from_slice(&4096u32.to_le_bytes());
    let source = s.0.join("card.raw");
    let image = s.0.join("card.qcow2");
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "qcow2",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&image).unwrap();
    let qcow = Qcow2::open(&file).unwrap();
    let found = partitions(&qcow).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions.len(), 1);
    assert_eq!(found.partitions[0].at, 2048 * 512);
    assert_eq!(found.partitions[0].size, 4096 * 512);
}

/// What is refused, and why each would otherwise be read as a disk of holes.
#[test]
fn an_image_that_needs_another_file_is_refused() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: what is refused is not checked against it");
        return;
    };
    let s = Scratch::new("refused");
    let parent = s.0.join("parent.qcow2");
    let child = s.0.join("child.qcow2");
    run(
        &tool,
        ["create", "-f", "qcow2", parent.to_str().unwrap(), "4M"].as_slice(),
    );
    run(
        &tool,
        [
            "create",
            "-f",
            "qcow2",
            "-b",
            parent.to_str().unwrap(),
            "-F",
            "qcow2",
            child.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&child).unwrap();
    assert!(
        matches!(Qcow2::open(&file), Err(Error::Needs(Unsupported::Backing))),
        "an image with another behind it holds only what differs from it"
    );

    // An image whose data is in a file of its own.
    let split = s.0.join("split.qcow2");
    let data = s.0.join("split.data");
    run(
        &tool,
        [
            "create",
            "-f",
            "qcow2",
            "-o",
            &format!("data_file={}", data.to_str().unwrap()),
            split.to_str().unwrap(),
            "4M",
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&split).unwrap();
    assert!(matches!(
        Qcow2::open(&file),
        Err(Error::Needs(Unsupported::ExternalData))
    ));
}

#[test]
fn what_is_not_a_qcow2_image_is_told_from_one() {
    assert!(matches!(
        Qcow2::open(&vec![0u8; 4096]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(Qcow2::open(&Vec::new()), Err(Error::Unrecognized)));
    // Its first bytes and nothing else.
    let mut head = vec![0u8; 4096];
    head[..4].copy_from_slice(b"QFI\xfb");
    assert!(matches!(Qcow2::open(&head), Err(Error::Unrecognized)));
}

/// Images built here, so that CI checks the reader where `qemu-img` cannot
/// be run.
mod by_hand {
    use super::*;

    const CLUSTER_BITS: u32 = 16;
    const CLUSTER: usize = 1 << CLUSTER_BITS;

    fn be32(into: &mut [u8], at: usize, value: u32) {
        into[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn be64(into: &mut [u8], at: usize, value: u64) {
        into[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }

    /// An image of `clusters` clusters, those in `written` holding data and
    /// those in `zeroes` marked as reading zeroes with the lowest bit of
    /// their entry, which version 3 gave it.
    fn an_image(clusters: usize, written: &[usize], zeroes: &[usize]) -> (Vec<u8>, Vec<u8>) {
        let l2_entries = CLUSTER / 8;
        assert!(
            clusters <= l2_entries,
            "one table of the second level is enough"
        );
        let size = clusters * CLUSTER;
        let mut disk = vec![0u8; size];

        // Cluster 0 is the header, 1 the first level, 2 the second, and the
        // data follows. The refcounts are not read, so there are none.
        let mut image = vec![0u8; 3 * CLUSTER];
        image[..4].copy_from_slice(b"QFI\xfb");
        be32(&mut image, 4, 3);
        be32(&mut image, 20, CLUSTER_BITS);
        be64(&mut image, 24, size as u64);
        be32(&mut image, 36, 1); // one entry in the first level
        be64(&mut image, 40, CLUSTER as u64);
        be32(&mut image, 100, 104); // header_length
        // The first level: its one entry says where the second is.
        be64(&mut image, CLUSTER, (2 * CLUSTER) as u64 | (1 << 63));

        for (i, cluster) in written.iter().enumerate() {
            let at = image.len();
            let data = pattern(CLUSTER, i as u64 + 1);
            disk[cluster * CLUSTER..(cluster + 1) * CLUSTER].copy_from_slice(&data);
            image.extend_from_slice(&data);
            be64(&mut image, 2 * CLUSTER + cluster * 8, at as u64 | (1 << 63));
        }
        for cluster in zeroes {
            // No data anywhere, and the lowest bit set: it reads as zeroes.
            be64(&mut image, 2 * CLUSTER + cluster * 8, 1);
        }
        (image, disk)
    }

    #[test]
    fn an_image_built_by_hand_reads_as_its_disk() {
        let (image, disk) = an_image(8, &[0, 3, 7], &[]);
        let qcow = Qcow2::open(&image).unwrap();
        assert_eq!(qcow.size().unwrap(), disk.len() as u64);
        assert_eq!(read_whole(&qcow), disk);
    }

    #[test]
    fn a_cluster_the_image_says_is_zeroes_reads_as_zeroes() {
        let (image, disk) = an_image(4, &[0], &[1, 2]);
        let qcow = Qcow2::open(&image).unwrap();
        assert_eq!(
            read_whole(&qcow),
            disk,
            "and not as whatever is in the file"
        );
    }

    #[test]
    fn a_layout_it_cannot_have_is_refused() {
        // A cluster size the format does not have.
        let (mut image, _) = an_image(4, &[0], &[]);
        be32(&mut image, 20, 30);
        assert!(matches!(Qcow2::open(&image), Err(Error::Qcow2Says)));
        // A first level too small for the disk.
        let (mut image, _) = an_image(4, &[0], &[]);
        be64(&mut image, 24, 1 << 40);
        assert!(matches!(Qcow2::open(&image), Err(Error::Qcow2Says)));
        // Encrypted.
        let (mut image, _) = an_image(4, &[0], &[]);
        be32(&mut image, 32, 1);
        assert!(matches!(
            Qcow2::open(&image),
            Err(Error::Needs(Unsupported::Encrypted))
        ));
        // Marked as damaged, and a feature nothing here knows.
        for (bit, needs) in [(1u32, Unsupported::Corrupt), (63, Unsupported::Feature)] {
            let (mut image, _) = an_image(4, &[0], &[]);
            be64(&mut image, 72, 1u64 << bit);
            assert!(
                matches!(Qcow2::open(&image), Err(Error::Needs(n)) if n == needs),
                "bit {bit}"
            );
        }
    }
}
