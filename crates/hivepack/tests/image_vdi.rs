//! VDI images: the disk one holds, read against what `qemu-img` converts the
//! same image to, byte for byte, and against an image built here by hand so
//! that the reader is checked where `qemu-img` is not installed.
//!
//! See crates/hivepack/src/image/vdi.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{Disk, Error, Table, Unsupported, Vdi, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("hivepack-vdi-{}-{what}", std::process::id()));
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
/// rather than failing for the want of one. The image built by hand is what
/// checks the reader there.
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

/// Every byte of `disk`, read in pieces that do not line up with its blocks,
/// so that a read crossing one is read too.
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

/// What `qemu-img` makes of `raw` as a VDI, read back by both: hivepack's
/// bytes are compared with the ones `qemu-img convert -O raw` gives for the
/// same image, which is what says the two agree and not only that each is
/// consistent with itself.
fn through_qemu(what: &str, raw: &[u8], options: &[&str]) {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(what);
    let source = s.0.join("disk.raw");
    let image = s.0.join("disk.vdi");
    std::fs::write(&source, raw).unwrap();
    let mut args = vec!["convert", "-f", "raw", "-O", "vdi"];
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
            "vdi",
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
    let vdi = Vdi::open(&file)
        .map_err(|e| format!("{what}: {e}"))
        .unwrap();
    assert_eq!(
        vdi.size().unwrap(),
        theirs.len() as u64,
        "{what}: the disk is as long as qemu-img reads it"
    );
    let mine = read_whole(&vdi);
    let differs = mine.iter().zip(&theirs).position(|(a, b)| a != b);
    assert!(
        differs.is_none() && mine.len() == theirs.len(),
        "{what}: differs from what qemu-img reads, at byte {differs:?}"
    );

    // And what was put in is at the front of it, anything after it being
    // zeroes: the image holds the disk, not something near it.
    assert!(theirs.len() >= raw.len(), "{what}: the disk shrank");
    assert!(
        &theirs[..raw.len()] == raw,
        "{what}: the disk itself changed"
    );
    assert!(
        theirs[raw.len()..].iter().all(|b| *b == 0),
        "{what}: what was added past the disk is not zeroes"
    );
}

/// Data in some blocks and holes in the others, over more than one 1 MiB
/// block, which is what a VDI that grows is for.
fn sparse() -> Vec<u8> {
    a_raw_disk(
        8 << 20,
        &[(0, 1 << 20), (4 << 20, 3 << 20), ((8 << 20) - 512, 512)],
    )
}

#[test]
fn a_vdi_that_grows_reads_as_the_disk_it_holds() {
    through_qemu("dynamic", &sparse(), &[]);
}

#[test]
fn a_vdi_that_does_not_grow_reads_as_the_disk_it_holds() {
    through_qemu("static", &sparse(), &["-o", "static=on"]);
}

#[test]
fn a_disk_of_nothing_but_holes_reads_as_zeroes() {
    through_qemu("all holes", &vec![0u8; 8 << 20], &[]);
}

#[test]
fn a_disk_whose_data_is_everywhere_reads_whole() {
    through_qemu("full", &pattern(6 << 20, 7), &[]);
}

/// A disk whose length is not a whole number of blocks: the last block is
/// partial, and the reader must stop where the disk does rather than at the
/// block's end.
#[test]
fn a_disk_of_no_whole_blocks_ends_where_it_says() {
    through_qemu("part of a block", &pattern((2 << 20) + 4096, 11), &[]);
}

#[test]
fn the_partitions_of_a_disk_in_a_vdi_are_its_own() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: partitions in a VDI are not checked");
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
    let image = s.0.join("card.vdi");
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "vdi",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&image).unwrap();
    let vdi = Vdi::open(&file).unwrap();
    let found = partitions(&vdi).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions.len(), 1);
    assert_eq!(found.partitions[0].at, 2048 * 512);
    assert_eq!(found.partitions[0].size, 4096 * 512);
    assert_eq!(found.partitions[0].kind.says(), Some("Linux file system"));
}

/// A VDI built here: the reader is checked where `qemu-img` is not
/// installed, which is what CI's 32-bit job has, and the images that say
/// something impossible are built here because no tool writes one.
mod by_hand {
    use super::*;

    const SIGNATURE: u32 = 0xbeda_107f;
    const VERSION_1_1: u32 = 0x0001_0001;
    const HEADER: usize = 0x200;
    const DYNAMIC: u32 = 1;
    const FREE: u32 = u32::MAX;
    const ZERO: u32 = u32::MAX - 1;

    /// What a block of the map holds: the disk's bytes, nothing ever
    /// written, or zeroes given back.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Block {
        Data,
        Free,
        Zero,
    }

    /// A VDI holding `disk`, each block of it as `blocks` says. The blocks
    /// that are written go into the file **backwards**, last block first, so
    /// that a reader taking them in order rather than through the map reads
    /// the wrong ones.
    struct Built {
        bytes: Vec<u8>,
        /// The disk as it must read back: what the file holds, with the
        /// blocks that are not in it as zeroes.
        disk: Vec<u8>,
    }

    fn build(disk: &[u8], block: usize, blocks: &[Block]) -> Built {
        build_with(disk, block, blocks, |_| {})
    }

    /// The same, with the header changed before it is written: what makes an
    /// image that says something no tool would write.
    fn build_with(
        disk: &[u8],
        block: usize,
        blocks: &[Block],
        change: impl FnOnce(&mut [u8]),
    ) -> Built {
        assert!(blocks.len() * block >= disk.len());
        let map_at = HEADER;
        let room = blocks.len() * 4;
        // The data starts at a whole sector after the map, as every image's
        // does.
        let data_at = (map_at + room).next_multiple_of(512);

        let mut header = vec![0u8; HEADER];
        header[..34].copy_from_slice(b"<<< hivepack test disk image >>>\n\0");
        header[0x40..0x44].copy_from_slice(&SIGNATURE.to_le_bytes());
        header[0x44..0x48].copy_from_slice(&VERSION_1_1.to_le_bytes());
        header[0x48..0x4c].copy_from_slice(&400u32.to_le_bytes());
        header[0x4c..0x50].copy_from_slice(&DYNAMIC.to_le_bytes());
        header[0x154..0x158].copy_from_slice(&(map_at as u32).to_le_bytes());
        header[0x158..0x15c].copy_from_slice(&(data_at as u32).to_le_bytes());
        header[0x168..0x16c].copy_from_slice(&512u32.to_le_bytes());
        header[0x170..0x178].copy_from_slice(&(disk.len() as u64).to_le_bytes());
        header[0x178..0x17c].copy_from_slice(&(block as u32).to_le_bytes());
        header[0x180..0x184].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        let written = blocks.iter().filter(|b| **b == Block::Data).count();
        header[0x184..0x188].copy_from_slice(&(written as u32).to_le_bytes());
        change(&mut header);

        // The map, and the data behind it: the written blocks backwards.
        let mut map = vec![0u8; room];
        let mut data = vec![0u8; written * block];
        let mut want = disk.to_vec();
        want.resize(blocks.len() * block, 0);
        let mut next = written;
        for (i, kind) in blocks.iter().enumerate() {
            let at = i * 4;
            match kind {
                Block::Data => {
                    next -= 1;
                    map[at..at + 4].copy_from_slice(&(next as u32).to_le_bytes());
                    data[next * block..(next + 1) * block]
                        .copy_from_slice(&want[i * block..(i + 1) * block]);
                }
                Block::Free => {
                    map[at..at + 4].copy_from_slice(&FREE.to_le_bytes());
                    want[i * block..(i + 1) * block].fill(0);
                }
                Block::Zero => {
                    map[at..at + 4].copy_from_slice(&ZERO.to_le_bytes());
                    want[i * block..(i + 1) * block].fill(0);
                }
            }
        }
        want.truncate(disk.len());

        let mut bytes = header;
        bytes.extend_from_slice(&map);
        bytes.resize(data_at, 0);
        bytes.extend_from_slice(&data);
        Built { bytes, disk: want }
    }

    /// Four blocks: one written, one never written, one given back, one
    /// written. The disk is a whole number of blocks and the blocks are in
    /// the file backwards.
    fn four() -> Built {
        build(
            &pattern(4 * 4096, 3),
            4096,
            &[Block::Data, Block::Free, Block::Zero, Block::Data],
        )
    }

    #[test]
    fn the_blocks_are_read_where_the_map_says_they_are() {
        let built = four();
        let vdi = Vdi::open(built.bytes.as_slice()).unwrap();
        assert_eq!(vdi.size().unwrap(), built.disk.len() as u64);
        assert_eq!(read_whole(&vdi), built.disk);
    }

    #[test]
    fn a_block_never_written_and_one_given_back_both_read_as_zeroes() {
        let built = four();
        let vdi = Vdi::open(built.bytes.as_slice()).unwrap();
        let mut buf = vec![0xffu8; 2 * 4096];
        vdi.read_exact_at(4096, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0), "a hole read something");
    }

    #[test]
    fn a_read_inside_one_block_takes_no_bytes_of_the_next() {
        let built = four();
        let vdi = Vdi::open(built.bytes.as_slice()).unwrap();
        // Over the seam between the first block and the hole after it.
        let mut buf = vec![0u8; 512];
        vdi.read_exact_at(4096 - 256, &mut buf).unwrap();
        assert_eq!(&buf[..256], &built.disk[4096 - 256..4096]);
        assert!(buf[256..].iter().all(|b| *b == 0));
    }

    /// A disk that ends inside its last block: the read stops at the disk's
    /// end, not the block's.
    #[test]
    fn a_disk_of_no_whole_blocks_ends_where_it_says() {
        let built = build(&pattern(4096 + 100, 5), 4096, &[Block::Data, Block::Data]);
        let vdi = Vdi::open(built.bytes.as_slice()).unwrap();
        assert_eq!(vdi.size().unwrap(), 4096 + 100);
        assert_eq!(read_whole(&vdi), built.disk);
        let mut buf = [0u8; 16];
        assert_eq!(vdi.read_at(4096 + 100, &mut buf).unwrap(), 0);
        assert_eq!(vdi.read_at(u64::MAX, &mut buf).unwrap(), 0);
    }

    /// A fixed image's map is the same map, filled in order: nothing in the
    /// reader tells the two apart, and this is what says so.
    #[test]
    fn an_image_written_whole_reads_through_its_map_too() {
        let disk = pattern(3 * 4096, 9);
        let built = build_with(&disk, 4096, &[Block::Data; 3], |header| {
            header[0x4c..0x50].copy_from_slice(&2u32.to_le_bytes());
        });
        let vdi = Vdi::open(built.bytes.as_slice()).unwrap();
        assert_eq!(read_whole(&vdi), disk);
    }

    #[test]
    fn what_is_not_a_vdi_is_not_opened_as_one() {
        // Nothing at all, and a file too short to hold a header.
        assert!(matches!(Vdi::open([].as_slice()), Err(Error::Unrecognized)));
        assert!(matches!(
            Vdi::open(vec![0u8; 0x100].as_slice()),
            Err(Error::Unrecognized)
        ));
        // The right length, the wrong signature: a raw disk of zeroes is
        // not read as a VDI of nothing.
        assert!(matches!(
            Vdi::open(vec![0u8; 1 << 20].as_slice()),
            Err(Error::Unrecognized)
        ));
    }

    /// Each of these is a file that says it is a VDI and then says something
    /// that cannot be read. None may be read as a disk of holes.
    #[test]
    fn an_image_that_says_what_it_cannot_is_refused() {
        let disk = pattern(2 * 4096, 13);
        let blocks = [Block::Data, Block::Data];
        // The image is opened and let go inside, so that what comes back
        // is why it was refused and not a reader borrowing the bytes.
        let says = |change: fn(&mut [u8])| -> Result<(), Error> {
            let built = build_with(&disk, 4096, &blocks, change);
            Vdi::open(built.bytes.as_slice()).map(|_| ())
        };

        // A version whose layout is not this one.
        assert!(matches!(
            says(|h| h[0x44..0x48].copy_from_slice(&0x0001_0000u32.to_le_bytes())),
            Err(Error::Needs(Unsupported::Feature))
        ));
        // Bytes of its own in front of every block.
        assert!(matches!(
            says(|h| h[0x17c..0x180].copy_from_slice(&64u32.to_le_bytes())),
            Err(Error::Needs(Unsupported::Feature))
        ));
        // A differencing image, and the undo image of a snapshot: each
        // holds only what changed from a file this cannot reach.
        for kind in [3u32, 4] {
            let built = build_with(&disk, 4096, &blocks, |h| {
                h[0x4c..0x50].copy_from_slice(&kind.to_le_bytes());
            });
            assert!(
                matches!(
                    Vdi::open(built.bytes.as_slice()).map(|_| ()),
                    Err(Error::Needs(Unsupported::Backing))
                ),
                "image type {kind}"
            );
        }
        // An image type the format does not have.
        assert!(matches!(
            says(|h| h[0x4c..0x50].copy_from_slice(&9u32.to_le_bytes())),
            Err(Error::VdiSays)
        ));
        // A disk of no length, and a block of none.
        assert!(matches!(
            says(|h| h[0x170..0x178].fill(0)),
            Err(Error::VdiSays)
        ));
        assert!(matches!(
            says(|h| h[0x178..0x17c].fill(0)),
            Err(Error::VdiSays)
        ));
        // A block that is not a whole number of sectors.
        assert!(matches!(
            says(|h| h[0x178..0x17c].copy_from_slice(&1000u32.to_le_bytes())),
            Err(Error::VdiSays)
        ));
        // A map of no blocks, and one that does not reach the whole disk.
        assert!(matches!(
            says(|h| h[0x180..0x184].fill(0)),
            Err(Error::VdiSays)
        ));
        assert!(matches!(
            says(|h| h[0x180..0x184].copy_from_slice(&1u32.to_le_bytes())),
            Err(Error::VdiSays)
        ));
        // A map that is not on the file: past its end, and so far out that
        // where it ends cannot be counted.
        assert!(matches!(
            says(|h| h[0x154..0x158].copy_from_slice(&u32::MAX.to_le_bytes())),
            Err(Error::VdiSays)
        ));
        // Data that starts past the file's end.
        assert!(matches!(
            says(|h| h[0x158..0x15c].copy_from_slice(&u32::MAX.to_le_bytes())),
            Err(Error::VdiSays)
        ));
        // More blocks than are read at all.
        assert!(matches!(
            says(|h| h[0x180..0x184].copy_from_slice(&(1u32 << 23).to_le_bytes())),
            Err(Error::VdiSays)
        ));
    }

    /// The file ends inside a block its map names: the read fails rather
    /// than answering with whatever is there, or with zeroes.
    #[test]
    fn a_file_cut_short_inside_a_block_it_names_fails_the_read() {
        let built = four();
        let mut cut = built.bytes.clone();
        cut.truncate(cut.len() - 4096);
        let vdi = Vdi::open(cut.as_slice()).unwrap();
        // The first block of the disk is the last in the file, and that is
        // the one the cut took.
        let mut buf = [0u8; 4096];
        let e = vdi.read_exact_at(0, &mut buf).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// A map naming a block far past the file's end: the read fails there
    /// rather than answering with zeroes, which is what a block that was
    /// never written answers with.
    #[test]
    fn a_block_named_past_the_file_fails_the_read() {
        let built = build(&pattern(4096, 17), 4096, &[Block::Data]);
        let mut bytes = built.bytes.clone();
        let map_at = 0x200;
        bytes[map_at..map_at + 4].copy_from_slice(&(u32::MAX - 2).to_le_bytes());
        let vdi = Vdi::open(bytes.as_slice()).unwrap();
        let mut buf = [0u8; 16];
        let e = vdi.read_at(0, &mut buf).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

/// A VDI written by VirtualBox itself, where `VBoxManage` is installed.
///
/// It is not the same shape as the one `qemu-img` writes, which is what
/// makes it worth a test of its own: VirtualBox puts the block map a whole
/// mebibyte into the file and the data a mebibyte after that, where QEMU
/// puts them at 512 and 2048 bytes, and its line of text says `<<< Oracle
/// VirtualBox Disk Image >>>` where QEMU's names QEMU. A reader that took
/// either for granted would read the wrong bytes, or refuse the image.
///
/// A new disk has no block written at all, so it reads as zeroes — which
/// is also the only thing a tool can write into a VDI without a virtual
/// machine to attach it to.
#[test]
fn a_vdi_virtualbox_wrote_itself_is_read() {
    let tool = ["/usr/bin/VBoxManage", "/usr/local/bin/VBoxManage"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists());
    let Some(tool) = tool else {
        eprintln!("VBoxManage is not installed here: VirtualBox's own shape is not checked");
        return;
    };
    let s = Scratch::new("virtualbox");
    let image = s.0.join("made-by-virtualbox.vdi");
    let out = Command::new(&tool)
        .args(["createmedium", "disk", "--format", "VDI", "--size", "64"])
        .arg("--filename")
        .arg(&image)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "VBoxManage wrote no image here: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    // Where it put its map and its data, which is not where QEMU puts
    // them: if this ever changes, the reader still follows the header, and
    // this test is what says the two are not the same.
    let bytes = std::fs::read(&image).unwrap();
    let at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    assert_eq!(at(0x154), 1 << 20, "the map is a mebibyte in");
    assert_eq!(at(0x158), 2 << 20, "the data is a mebibyte after it");
    assert!(
        bytes.starts_with(b"<<< Oracle"),
        "the text in front is not VirtualBox's: {:?}",
        String::from_utf8_lossy(&bytes[..32])
    );

    let file = std::fs::File::open(&image).unwrap();
    let vdi = Vdi::open(&file).unwrap();
    assert_eq!(vdi.size().unwrap(), 64 << 20);
    let whole = read_whole(&vdi);
    assert!(
        whole.iter().all(|b| *b == 0),
        "a disk with no block written read something"
    );
}
