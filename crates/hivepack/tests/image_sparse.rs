//! Android sparse images: the disk one holds, read out of images built
//! byte by byte — which is what the format needs, since nothing writes an
//! image that says something impossible — and against `img2simg` and
//! `simg2img` where they are installed.
//!
//! See crates/hivepack/src/image/sparse.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{AndroidSparse, Disk, Error, Table, Unsupported, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("hivepack-sparse-{}-{what}", std::process::id()));
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

/// A tool, if it is installed **and** can be run: see image_vhd.rs, which
/// says why the second half matters.
fn tool(name: &str) -> Option<PathBuf> {
    let path = ["/usr/bin", "/usr/local/bin", "/bin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|p| p.exists())?;
    Command::new(&path).arg("--help").output().ok()?;
    Some(path)
}

/// Whether a missing tool is to fail the test rather than be said.
///
/// Android's own tools are what check this reader against something other
/// than its own reading of the format, and no runner image carries them,
/// so CI installs them on one job and gives that job this variable. Without
/// it a run that found no tools and a run that compared with them both
/// pass, and `cargo test` hides what a passing test printed.
///
/// **An empty value is not a value**: a workflow that sets the variable for
/// every system and fills it in for one leaves the others holding an empty
/// string, which is still set as far as the environment goes.
fn required() -> bool {
    std::env::var("HIVEPACK_SPARSE_REQUIRED").is_ok_and(|v| !v.is_empty())
}

/// Says `why` a test is not checking what it would, or fails where the
/// tools are required.
fn say_or_fail(why: &str) {
    assert!(!required(), "{why}");
    eprintln!("{why}");
}

/// Bytes that are the same every run, and not all alike.
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

/// Every byte of `disk`, read in pieces that do not line up with its
/// blocks, so that a read crossing a chunk is read too.
fn read_whole<D: Disk>(disk: &D) -> Vec<u8> {
    let size = disk.size().unwrap() as usize;
    let mut whole = vec![0u8; size];
    let mut at = 0;
    while at < size {
        // A size that is not a power of two and not a divisor of a block.
        let want = 3001.min(size - at);
        let read = disk.read_at(at as u64, &mut whole[at..at + want]).unwrap();
        assert!(read > 0, "the disk stopped answering at {at}");
        at += read;
    }
    whole
}

const BLOCK: usize = 4096;

/// What a chunk of an image under construction holds.
enum Chunk {
    /// These bytes, as a run of whole blocks.
    Raw(Vec<u8>),
    /// This four-byte value over this many blocks.
    Fill([u8; 4], u32),
    /// This many blocks that were never written.
    Hole(u32),
    /// A running checksum, which covers no blocks of its own.
    Crc(u32),
}

/// An image holding `chunks`, and the disk it stands for.
///
/// `blocks` is what the header says the disk is, which is the sum of the
/// chunks' blocks unless a test says otherwise.
fn build(chunks: &[Chunk], blocks: Option<u32>) -> (Vec<u8>, Vec<u8>) {
    let mut disk = Vec::new();
    let mut body = Vec::new();
    let mut count = 0u32;
    for chunk in chunks {
        let (kind, blocks, data): (u16, u32, Vec<u8>) = match chunk {
            Chunk::Raw(bytes) => {
                assert!(bytes.len().is_multiple_of(BLOCK));
                disk.extend_from_slice(bytes);
                ((0xCAC1), (bytes.len() / BLOCK) as u32, bytes.clone())
            }
            Chunk::Fill(four, blocks) => {
                for i in 0..(*blocks as usize * BLOCK) {
                    disk.push(four[i % 4]);
                }
                (0xCAC2, *blocks, four.to_vec())
            }
            Chunk::Hole(blocks) => {
                disk.extend(std::iter::repeat_n(0u8, *blocks as usize * BLOCK));
                (0xCAC3, *blocks, Vec::new())
            }
            Chunk::Crc(sum) => (0xCAC4, 0, sum.to_le_bytes().to_vec()),
        };
        count += 1;
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&blocks.to_le_bytes());
        body.extend_from_slice(&(12 + data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data);
    }
    let blocks = blocks.unwrap_or((disk.len() / BLOCK) as u32);
    let mut image = Vec::new();
    image.extend_from_slice(&0xed26_ff3au32.to_le_bytes());
    image.extend_from_slice(&1u16.to_le_bytes()); // major
    image.extend_from_slice(&0u16.to_le_bytes()); // minor
    image.extend_from_slice(&28u16.to_le_bytes());
    image.extend_from_slice(&12u16.to_le_bytes());
    image.extend_from_slice(&(BLOCK as u32).to_le_bytes());
    image.extend_from_slice(&blocks.to_le_bytes());
    image.extend_from_slice(&count.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes()); // the image's checksum
    image.extend_from_slice(&body);
    disk.resize(blocks as usize * BLOCK, 0);
    (image, disk)
}

/// Data, a fill, a hole and data again: what a ROM's image is made of.
fn a_mixed_image() -> (Vec<u8>, Vec<u8>) {
    build(
        &[
            Chunk::Raw(pattern(BLOCK * 2, 1)),
            Chunk::Fill([0xDE, 0xAD, 0xBE, 0xEF], 3),
            Chunk::Hole(5),
            Chunk::Crc(0x1234_5678),
            Chunk::Raw(pattern(BLOCK, 2)),
        ],
        None,
    )
}

#[test]
fn an_image_reads_as_the_disk_it_holds() {
    let (image, disk) = a_mixed_image();
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    assert_eq!(sparse.size().unwrap(), disk.len() as u64);
    assert_eq!(sparse.block_size(), BLOCK as u64);
    assert_eq!(read_whole(&sparse), disk);
}

/// A fill chunk is four bytes over and over, and a read that starts part
/// way through one gets the bytes of the places it asks for, not of the
/// places it has read.
#[test]
fn a_fill_chunk_repeats_its_four_bytes_wherever_it_is_read() {
    let (image, disk) = a_mixed_image();
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    for at in [
        BLOCK * 2,
        BLOCK * 2 + 1,
        BLOCK * 2 + 2,
        BLOCK * 2 + 3,
        BLOCK * 3 - 1,
        BLOCK * 3 + 7,
    ] {
        let mut buf = vec![0u8; 9];
        sparse.read_exact_at(at as u64, &mut buf).unwrap();
        assert_eq!(buf, disk[at..at + 9], "at {at}");
    }
}

/// Reads that cross from one chunk into the next, in every pair the image
/// has: a read is not allowed to stop being right at a seam.
#[test]
fn reads_across_the_seams_come_out_whole() {
    let (image, disk) = a_mixed_image();
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    for seam in [2, 5, 10] {
        let at = seam * BLOCK - 100;
        let mut buf = vec![0u8; 200];
        sparse.read_exact_at(at as u64, &mut buf).unwrap();
        assert_eq!(buf, disk[at..at + 200], "over the seam at block {seam}");
    }
}

/// A header saying the disk is longer than its chunks cover: what no chunk
/// covers reads as zeroes, as a hole does.
#[test]
fn what_no_chunk_covers_reads_as_zeroes() {
    let (image, disk) = build(&[Chunk::Raw(pattern(BLOCK, 3))], Some(4));
    assert_eq!(disk.len(), BLOCK * 4);
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    assert_eq!(sparse.size().unwrap(), (BLOCK * 4) as u64);
    let read = read_whole(&sparse);
    assert_eq!(read, disk);
    assert!(read[BLOCK..].iter().all(|b| *b == 0));
    // And a read that starts in the part no chunk covers.
    let mut buf = [0xffu8; 16];
    sparse.read_exact_at((BLOCK * 3) as u64, &mut buf).unwrap();
    assert!(buf.iter().all(|b| *b == 0));
}

/// The partitions of a disk inside a sparse image are its own: the
/// layering working, which is what reading the container is for.
#[test]
fn the_partitions_of_a_disk_in_a_sparse_image_are_its_own() {
    // A disk with a master boot record, as a card has.
    let mut raw = vec![0u8; BLOCK * 16];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    raw[entry + 4] = 0x83;
    raw[entry + 8..entry + 12].copy_from_slice(&8u32.to_le_bytes());
    raw[entry + 12..entry + 16].copy_from_slice(&16u32.to_le_bytes());
    // The table's own block, then a hole, so the table is read out of a
    // chunk and the rest of the disk out of nothing.
    let (image, _) = build(&[Chunk::Raw(raw[..BLOCK].to_vec()), Chunk::Hole(15)], None);
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    let found = partitions(&sparse).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions.len(), 1);
    assert_eq!(found.partitions[0].at, 8 * 512);
    assert_eq!(found.partitions[0].size, 16 * 512);
}

#[test]
fn what_is_not_a_sparse_image_is_not_opened_as_one() {
    assert!(matches!(
        AndroidSparse::open([].as_slice()),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(
        AndroidSparse::open(vec![0u8; 27].as_slice()),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(
        AndroidSparse::open(vec![0u8; 1 << 20].as_slice()),
        Err(Error::Unrecognized)
    ));
}

/// Each of these is a file that says it is a sparse image and then says
/// something that cannot be read. None may be read as a disk of holes.
#[test]
fn an_image_that_says_what_it_cannot_is_refused() {
    let says = |change: &dyn Fn(&mut Vec<u8>)| {
        let (mut image, _) = a_mixed_image();
        change(&mut image);
        AndroidSparse::open(image.as_slice()).map(|_| ()).err()
    };
    let cannot = |what: &str, change: &dyn Fn(&mut Vec<u8>)| {
        assert!(
            matches!(says(change), Some(Error::SparseSays)),
            "{what}: read, and it cannot be"
        );
    };
    let needs = |what: &str, change: &dyn Fn(&mut Vec<u8>)| {
        assert!(
            matches!(says(change), Some(Error::Needs(Unsupported::Feature))),
            "{what}: read, and what it needs is not here"
        );
    };

    needs("a major version past this one", &|image| {
        image[4..6].copy_from_slice(&2u16.to_le_bytes());
    });
    // A kind of chunk this does not know cannot be stepped over, because
    // the chunks are the disk in order: stepping over one would read its
    // blocks as holes and every chunk after it at the wrong place.
    needs("a kind of chunk this does not know", &|image| {
        image[28..30].copy_from_slice(&0xCAC9u16.to_le_bytes());
    });
    cannot("a header shorter than the format's", &|image| {
        image[8..10].copy_from_slice(&20u16.to_le_bytes());
    });
    cannot("a chunk header shorter than the format's", &|image| {
        image[10..12].copy_from_slice(&8u16.to_le_bytes());
    });
    cannot("a block of no length", &|image| image[12..16].fill(0));
    // A fill chunk's four bytes have to come out even over a block.
    cannot(
        "a block that is not a whole number of four bytes",
        &|image| {
            image[12..16].copy_from_slice(&4095u32.to_le_bytes());
        },
    );
    cannot("more chunks than are read at all", &|image| {
        image[20..24].copy_from_slice(&(1u32 << 23).to_le_bytes());
    });
    cannot(
        "a raw chunk of a length its blocks do not match",
        &|image| {
            image[32..36].copy_from_slice(&9u32.to_le_bytes());
        },
    );
    cannot("a chunk shorter than its own header", &|image| {
        image[36..40].copy_from_slice(&4u32.to_le_bytes());
    });
    cannot("a chunk reaching past the file's end", &|image| {
        image[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
    });
    cannot("chunks covering more of the disk than there is", &|image| {
        image[16..20].copy_from_slice(&1u32.to_le_bytes());
    });
}

/// A header may say the disk is far longer than the chunks cover, and that
/// is not an error: what no chunk covers reads as zeroes, and nothing is
/// allocated for it. A file of 40 KB saying 17 TB is read, and read as
/// zeroes past its chunks.
#[test]
fn a_disk_longer_than_its_chunks_is_read_as_far_as_it_says() {
    let (mut image, _) = a_mixed_image();
    image[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    let sparse = AndroidSparse::open(image.as_slice()).unwrap();
    assert_eq!(
        sparse.size().unwrap(),
        u64::from(u32::MAX) * BLOCK as u64,
        "the disk is as long as the header says"
    );
    // The chunks still read as they did, and the rest is zeroes.
    let mut buf = vec![0xffu8; 16];
    sparse.read_exact_at(0, &mut buf).unwrap();
    assert_ne!(buf, vec![0u8; 16]);
    sparse.read_exact_at(1 << 40, &mut buf).unwrap();
    assert_eq!(buf, vec![0u8; 16]);
}

/// A file cut short inside a chunk is told when it is opened: every chunk
/// is checked to be on the file there, which is the one pass over the
/// chunks the format makes necessary.
#[test]
fn a_file_cut_short_is_told_when_it_is_opened() {
    let (image, _) = a_mixed_image();
    for take in [image.len() - 1, image.len() - BLOCK / 2, 40, 29] {
        let cut = &image[..take];
        assert!(
            matches!(
                AndroidSparse::open(cut),
                Err(Error::SparseSays) | Err(Error::Io(_)) | Err(Error::Unrecognized)
            ),
            "cut to {take} bytes and opened anyway"
        );
    }
}

/// A disk that says it is longer than it can answer for: the read fails
/// rather than answering with zeroes for bytes that are not there.
///
/// Nothing but a disk shrinking under the reader does this — a file
/// truncated after it was opened, a device unplugged — and a file cut
/// short is caught when it is opened, so it takes a `Disk` of its own to
/// reach the error at all.
#[test]
fn a_disk_that_stops_answering_fails_the_read() {
    struct Shrunk {
        bytes: Vec<u8>,
        /// What it says it is, which is more than it holds.
        says: u64,
    }

    impl Disk for Shrunk {
        fn size(&self) -> std::io::Result<u64> {
            Ok(self.says)
        }

        fn read_at(&self, at: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.bytes.as_slice().read_at(at, buf)
        }
    }

    let (image, disk) = build(&[Chunk::Raw(pattern(BLOCK * 2, 5))], None);
    let says = image.len() as u64;
    let shrunk = Shrunk {
        bytes: image[..image.len() - BLOCK].to_vec(),
        says,
    };
    let sparse = AndroidSparse::open(shrunk).unwrap();
    assert_eq!(sparse.size().unwrap(), disk.len() as u64);
    // The first block is there; the second is not.
    let mut buf = vec![0u8; BLOCK];
    sparse.read_exact_at(0, &mut buf).unwrap();
    assert_eq!(buf, disk[..BLOCK]);
    let e = sparse
        .read_exact_at(BLOCK as u64, &mut buf)
        .expect_err("a disk that stopped answering was answered for");
    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// What `img2simg` and `simg2img` make of the same disk, where they are
/// installed: the tools are Android's own, and they are the oracle here as
/// `qemu-img` is for the other containers.
///
/// They are in Debian's `android-sdk-libsparse-utils`, which no runner
/// image carries; CI installs it on the job that installs the other tools.
#[test]
fn a_disk_through_the_android_tools_reads_the_same() {
    let (Some(img2simg), Some(simg2img)) = (tool("img2simg"), tool("simg2img")) else {
        say_or_fail(
            "img2simg and simg2img cannot be run here: Android's own tools are not the \
             oracle. The images built by hand are what check the reader everywhere.",
        );
        return;
    };
    let s = Scratch::new("tools");
    // Data, a long run of zeroes, and data again: what the writer turns
    // into a raw chunk, a fill or a hole, and a raw chunk.
    let mut raw = pattern(BLOCK * 3, 7);
    raw.extend(std::iter::repeat_n(0u8, BLOCK * 8));
    raw.extend(pattern(BLOCK * 2, 9));
    let flat = s.0.join("disk.img");
    let sparse_path = s.0.join("disk.sparse");
    let back = s.0.join("back.img");
    std::fs::write(&flat, &raw).unwrap();
    run(
        &img2simg,
        &[flat.to_str().unwrap(), sparse_path.to_str().unwrap()],
    );
    // Smaller than the disk, which is the point of the format.
    let sparse_len = std::fs::metadata(&sparse_path).unwrap().len();
    assert!(
        sparse_len < raw.len() as u64,
        "the sparse image is not smaller than the disk: {sparse_len}"
    );

    // What hivepack reads out of the tool's image is the disk that went in.
    let file = std::fs::File::open(&sparse_path).unwrap();
    let sparse = AndroidSparse::open(&file).unwrap();
    assert_eq!(sparse.size().unwrap(), raw.len() as u64);
    assert_eq!(read_whole(&sparse), raw);

    // And what `simg2img` reads out of it is the same thing again.
    run(
        &simg2img,
        &[sparse_path.to_str().unwrap(), back.to_str().unwrap()],
    );
    assert_eq!(std::fs::read(&back).unwrap(), raw);
}

fn run(tool: &Path, args: &[&str]) {
    let out = Command::new(tool).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{tool:?} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
