//! VMDK images: the disk one holds, read against what `qemu-img` converts
//! the same image to, byte for byte — a sparse extent, a stream of
//! compressed grains, and a descriptor with the files it names beside it.
//!
//! See crates/hivepack/src/image/vmdk.rs and docs/image.md.

#![cfg(feature = "image")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::image::{Disk, Error, Table, Unsupported, Vmdk, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "hivepack-vmdk-{}-{}",
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

/// Data in two places and holes between, with a tail: holes, data and the
/// last grain of a disk all read.
fn sparse() -> Vec<u8> {
    a_raw_disk(
        16 << 20,
        &[(0, 1 << 20), (8 << 20, 5 << 20), ((16 << 20) - 512, 512)],
    )
}

/// Every byte of `disk`, in pieces that do not line up with its grains.
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

/// That `disk` holds `raw` and nothing else, as `qemu-img` reads it too.
fn same_as<D: Disk>(what: &str, disk: &D, raw: &[u8], theirs: &[u8]) {
    assert_eq!(
        disk.size().unwrap(),
        theirs.len() as u64,
        "{what}: the disk is as long as qemu-img reads it"
    );
    let mine = read_whole(disk);
    let differs = mine.iter().zip(theirs).position(|(a, b)| a != b);
    assert!(
        differs.is_none() && mine.len() == theirs.len(),
        "{what}: differs from what qemu-img reads, at byte {differs:?}"
    );
    // VMDK counts a disk in sectors of 512 bytes and rounds nothing up
    // beyond that, so what went in is the whole of what comes out.
    assert_eq!(theirs, raw, "{what}: the disk itself changed");
}

/// `raw` through `qemu-img` into a VMDK of `subformat`, read by `qemu-img`
/// and by hivepack, and the two compared byte for byte. The descriptor is
/// opened by path, which is the only way to reach the kinds that keep the
/// disk in files beside it.
fn through_qemu(what: &str, raw: &[u8], subformat: &str, options: &[&str]) {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(what);
    let source = s.0.join("disk.raw");
    let image = s.0.join("disk.vmdk");
    let back = s.0.join("back.raw");
    std::fs::write(&source, raw).unwrap();
    let with = format!("subformat={subformat}");
    let mut args = vec!["convert", "-f", "raw", "-O", "vmdk", "-o", &with];
    args.extend_from_slice(options);
    args.push(source.to_str().unwrap());
    args.push(image.to_str().unwrap());
    run(&tool, &args);
    run(
        &tool,
        [
            "convert",
            "-f",
            "vmdk",
            "-O",
            "raw",
            image.to_str().unwrap(),
            back.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let theirs = std::fs::read(&back).unwrap();

    let vmdk = Vmdk::beside(&image)
        .map_err(|e| format!("{what}: {e}"))
        .unwrap();
    assert_eq!(vmdk.disk_size(), theirs.len() as u64);
    same_as(what, &vmdk, raw, &theirs);
}

#[test]
fn a_sparse_vmdk_reads_as_the_disk_it_holds() {
    through_qemu("sparse", &sparse(), "monolithicSparse", &[]);
}

#[test]
fn an_image_of_nothing_but_holes_reads_as_zeroes() {
    through_qemu("all holes", &vec![0u8; 16 << 20], "monolithicSparse", &[]);
}

#[test]
fn an_image_full_of_data_reads_whole() {
    through_qemu("full", &pattern(12 << 20, 7), "monolithicSparse", &[]);
}

/// The grain table entry of a grain written as zeroes, which the format has
/// so that nothing need be written for it. It reads as zeroes either way,
/// which is what makes it worth checking: the entry is not an offset.
#[test]
fn an_image_whose_zeroes_are_in_its_tables_reads_as_zeroes() {
    through_qemu(
        "zeroed grains",
        &sparse(),
        "monolithicSparse",
        &["-o", "zeroed_grain=on"],
    );
}

/// A stream of compressed grains: what an OVA holds, each grain deflated
/// and behind a marker of its own.
#[test]
fn a_stream_of_compressed_grains_reads_as_the_disk() {
    through_qemu("stream", &sparse(), "streamOptimized", &[]);
}

/// A descriptor of plain text, and the whole disk in one file beside it.
#[test]
fn a_descriptor_and_the_flat_file_it_names_read_as_one_disk() {
    through_qemu("flat", &sparse(), "monolithicFlat", &[]);
}

/// The two kinds that cut a disk into 2 GiB pieces. A disk that large is
/// not written here, so each is one piece; several are checked by hand
/// below, where the descriptor is written rather than converted.
#[test]
fn the_kinds_that_cut_a_disk_into_pieces_read_as_one_disk() {
    through_qemu("two gb sparse", &sparse(), "twoGbMaxExtentSparse", &[]);
    through_qemu("two gb flat", &sparse(), "twoGbMaxExtentFlat", &[]);
}

/// The partitions of the disk an image holds are the disk's, read through
/// the container as they are read off a raw image.
#[test]
fn the_partitions_of_the_disk_are_read_through_the_image() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: the partitions are not checked against it");
        return;
    };
    let s = Scratch::new("partitions");
    // A master boot record of one partition, whose numbers are counted in
    // sectors of 512 bytes, which is what VMDK counts everything in.
    let (start, sectors) = (2048u32, 4096u32);
    let mut raw = vec![0u8; 16 << 20];
    raw[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    raw[entry + 4] = 0x83;
    raw[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
    raw[entry + 12..entry + 16].copy_from_slice(&sectors.to_le_bytes());
    let source = s.0.join("card.raw");
    let image = s.0.join("card.vmdk");
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "vmdk",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&image).unwrap();
    let vmdk = Vmdk::open(&file).unwrap();
    let found = partitions(&vmdk).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.sector, 512);
    assert_eq!(found.partitions.len(), 1);
    assert_eq!(found.partitions[0].at, u64::from(start) * 512);
    assert_eq!(found.partitions[0].size, u64::from(sectors) * 512);
}

/// An image holding only what changed from another one. Its own descriptor
/// says so, in the identifier of the disk it came from: reading it alone
/// would answer zeroes where that disk has data.
#[test]
fn an_image_that_holds_only_what_changed_is_refused() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: what is refused is not checked against it");
        return;
    };
    let s = Scratch::new("refused");
    let parent = s.0.join("parent.vmdk");
    let child = s.0.join("child.vmdk");
    run(
        &tool,
        ["create", "-f", "vmdk", parent.to_str().unwrap(), "16M"].as_slice(),
    );
    run(
        &tool,
        [
            "create",
            "-f",
            "vmdk",
            "-b",
            parent.to_str().unwrap(),
            "-F",
            "vmdk",
            child.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let file = std::fs::File::open(&child).unwrap();
    assert!(
        matches!(Vmdk::open(&file), Err(Error::Needs(Unsupported::Backing))),
        "an image with another behind it holds only what differs from it"
    );
    assert!(
        matches!(
            Vmdk::beside(&child),
            Err(Error::Needs(Unsupported::Backing))
        ),
        "and is refused by path as well as by reader"
    );
}

/// A stream of compressed grains as VMware writes one: the header it starts
/// with says the grain directory is at the file's end, because what wrote
/// it in one pass could not know where the directory would land. The real
/// header is in a footer between two markers at the end.
///
/// `qemu-img` writes the directory in place, so what it wrote is turned
/// into the other shape — the same grains, found through the footer rather
/// than through the header.
#[test]
fn a_stream_whose_directory_is_at_its_end_is_read_from_the_footer() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: the footer is not checked against it");
        return;
    };
    let s = Scratch::new("at the end");
    let source = s.0.join("disk.raw");
    let image = s.0.join("disk.vmdk");
    let raw = sparse();
    std::fs::write(&source, &raw).unwrap();
    run(
        &tool,
        [
            "convert",
            "-f",
            "raw",
            "-O",
            "vmdk",
            "-o",
            "subformat=streamOptimized",
            source.to_str().unwrap(),
            image.to_str().unwrap(),
        ]
        .as_slice(),
    );
    let as_written = std::fs::read(&image).unwrap();
    let in_place = Vmdk::open(&as_written).unwrap();
    let expected = read_whole(&in_place);
    assert_eq!(expected, raw, "what qemu-img wrote holds the disk");

    let moved = with_the_directory_at_the_end(&as_written);
    let through_footer = Vmdk::open(&moved).unwrap();
    assert_eq!(
        through_footer.disk_size(),
        in_place.disk_size(),
        "the footer says what the header no longer does"
    );
    assert_eq!(
        read_whole(&through_footer),
        expected,
        "the same grains, found through the footer"
    );

    // The same header, with no footer behind it: nothing says where the
    // grains are, and a disk of holes is not the answer.
    let mut headless = moved.clone();
    let end = headless.len() - 3 * 512;
    headless.truncate(end);
    assert!(matches!(Vmdk::open(&headless), Err(Error::VmdkSays)));
    // And one whose footer says the same as the header did, which would
    // send a reader back to the end for ever.
    let mut circular = moved.clone();
    let footer = circular.len() - 2 * 512;
    circular[footer + 56..footer + 64].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(Vmdk::open(&circular), Err(Error::VmdkSays)));
}

/// `image` with its header saying the grain directory is at the end, and a
/// footer there holding the header as it was: the grains do not move, so
/// what the footer says about them stays true.
fn with_the_directory_at_the_end(image: &[u8]) -> Vec<u8> {
    let mut made = image.to_vec();
    made[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
    // The marker that says a footer follows: one sector of its own, no
    // data, and the number that says which marker it is.
    let mut marker = vec![0u8; 512];
    marker[..8].copy_from_slice(&1u64.to_le_bytes());
    marker[12..16].copy_from_slice(&3u32.to_le_bytes());
    made.extend_from_slice(&marker);
    // The header as it was, directory and all.
    made.extend_from_slice(&image[..512]);
    // The marker that says the stream ends here, which is zeroes
    // throughout: no data, and the end is marker nothing.
    made.extend_from_slice(&vec![0u8; 512]);
    made
}

/// A descriptor naming several extents, which is what the kinds that cut a
/// disk into 2 GiB pieces write. The pieces here are small enough to run,
/// and are what `qemu-img` wrote for each half of the disk.
#[test]
fn a_disk_in_several_extents_reads_as_one() {
    let Some(tool) = qemu_img() else {
        eprintln!("qemu-img cannot be run here: several extents are not checked against it");
        return;
    };
    let raw = sparse();
    let half = raw.len() / 2;
    for kind in ["SPARSE", "FLAT"] {
        let s = Scratch::new(&format!("pieces {kind}"));
        for (name, part) in [("a", &raw[..half]), ("b", &raw[half..])] {
            let piece = s.0.join(format!("d-{name}.vmdk"));
            if kind == "FLAT" {
                std::fs::write(&piece, part).unwrap();
            } else {
                let source = s.0.join(format!("{name}.raw"));
                std::fs::write(&source, part).unwrap();
                run(
                    &tool,
                    [
                        "convert",
                        "-f",
                        "raw",
                        "-O",
                        "vmdk",
                        source.to_str().unwrap(),
                        piece.to_str().unwrap(),
                    ]
                    .as_slice(),
                );
            }
        }
        // A flat extent says where in its file it begins; a sparse one is
        // read from its own header, which says how long the disk it holds
        // is.
        let sectors = half / 512;
        let tail = if kind == "FLAT" { " 0" } else { "" };
        let descriptor = format!(
            "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n\
             createType=\"twoGbMaxExtent{}\"\n\n# Extent description\n\
             RW {sectors} {kind} \"d-a.vmdk\"{tail}\nRW {sectors} {kind} \"d-b.vmdk\"{tail}\n",
            if kind == "FLAT" { "Flat" } else { "Sparse" }
        );
        let path = s.0.join("d.vmdk");
        std::fs::write(&path, &descriptor).unwrap();
        let vmdk = Vmdk::beside(&path).unwrap();
        assert_eq!(vmdk.disk_size(), raw.len() as u64, "{kind}: the whole disk");
        assert_eq!(read_whole(&vmdk), raw, "{kind}: the pieces in order");
    }
}

/// What a descriptor may say beside extents that hold data: a run of the
/// disk nothing holds at all, and a flat file shorter than the extent it
/// is given, which is a disk whose end was never written.
#[test]
fn what_no_file_holds_reads_as_zeroes() {
    let s = Scratch::new("zeroes");
    let data = pattern(1 << 20, 3);
    std::fs::write(s.0.join("d-a.vmdk"), &data).unwrap();
    // Half the room the descriptor gives it.
    std::fs::write(s.0.join("d-b.vmdk"), &data[..(1 << 19)]).unwrap();
    let descriptor = "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\n\
         createType=\"monolithicFlat\"\n\n\
         RW 2048 FLAT \"d-a.vmdk\" 0\n\
         RW 2048 ZERO\n\
         RW 2048 FLAT \"d-b.vmdk\" 0\n";
    let path = s.0.join("d.vmdk");
    std::fs::write(&path, descriptor).unwrap();
    let vmdk = Vmdk::beside(&path).unwrap();
    assert_eq!(vmdk.disk_size(), 3 << 20);
    let whole = read_whole(&vmdk);
    assert_eq!(&whole[..1 << 20], &data[..], "the extent that holds data");
    assert!(
        whole[1 << 20..2 << 20].iter().all(|b| *b == 0),
        "the extent that holds nothing"
    );
    assert_eq!(
        &whole[2 << 20..(2 << 20) + (1 << 19)],
        &data[..1 << 19],
        "what the short file holds"
    );
    assert!(
        whole[(2 << 20) + (1 << 19)..].iter().all(|b| *b == 0),
        "and zeroes where its file ends before its extent does"
    );
}

/// A descriptor is text in a file, and the names in it are names: one that
/// is a path is refused, so that opening an image cannot be made to read a
/// file somewhere else.
#[test]
fn an_extent_named_as_a_path_is_refused() {
    let s = Scratch::new("elsewhere");
    std::fs::write(s.0.join("d-a.vmdk"), vec![0u8; 1 << 20]).unwrap();
    for name in [
        "../d-a.vmdk",
        "/etc/passwd",
        "sub/d-a.vmdk",
        "..\\d-a.vmdk",
        "",
        ".",
    ] {
        let descriptor = format!(
            "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\n\
             createType=\"monolithicFlat\"\n\nRW 2048 FLAT \"{name}\" 0\n"
        );
        let path = s.0.join("d.vmdk");
        std::fs::write(&path, &descriptor).unwrap();
        assert!(
            matches!(Vmdk::beside(&path), Err(Error::VmdkElsewhere)),
            "{name:?} is not a file beside the descriptor"
        );
    }
}

/// A descriptor of its own holds no data: a reader of one file cannot get
/// to the files it names, and says so rather than answering a disk of
/// holes.
#[test]
fn a_descriptor_of_its_own_needs_the_files_beside_it() {
    let text = b"# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\n\
        createType=\"monolithicFlat\"\n\nRW 2048 FLAT \"d-flat.vmdk\" 0\n";
    let mut raw = text.to_vec();
    raw.resize(1024, 0);
    assert!(matches!(
        Vmdk::open(&raw),
        Err(Error::Needs(Unsupported::Beside))
    ));
    // And the same where a header is written in front of it, which is what
    // a tool that cuts a disk into pieces writes: a header of no capacity
    // at all, holding nothing but the descriptor.
    let mut with_header = vec![0u8; 512];
    with_header[..4].copy_from_slice(b"KDMV");
    with_header[28..36].copy_from_slice(&1u64.to_le_bytes());
    with_header[36..44].copy_from_slice(&1u64.to_le_bytes());
    with_header.extend_from_slice(&raw[..512]);
    assert!(matches!(
        Vmdk::open(&with_header),
        Err(Error::Needs(Unsupported::Beside))
    ));
}

#[test]
fn an_extent_of_a_kind_that_is_not_read_is_refused() {
    let s = Scratch::new("sesparse");
    std::fs::write(s.0.join("d-a.vmdk"), vec![0u8; 1 << 20]).unwrap();
    let descriptor = "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\n\
         createType=\"seSparse\"\n\nRW 2048 SESPARSE \"d-a.vmdk\"\n";
    let path = s.0.join("d.vmdk");
    std::fs::write(&path, descriptor).unwrap();
    assert!(matches!(
        Vmdk::beside(&path),
        Err(Error::Needs(Unsupported::Feature))
    ));
}

#[test]
fn what_is_not_a_vmdk_is_told_from_one() {
    assert!(matches!(
        Vmdk::open(&vec![0u8; 64 << 10]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(Vmdk::open(&Vec::new()), Err(Error::Unrecognized)));
    assert!(matches!(
        Vmdk::open(&b"KDM".to_vec()),
        Err(Error::Unrecognized)
    ));
    // A header and nothing in it: what it says a disk is cannot be read.
    let mut head = vec![0u8; 64 << 10];
    head[..4].copy_from_slice(b"KDMV");
    head[12..20].copy_from_slice(&(1u64 << 15).to_le_bytes());
    assert!(matches!(Vmdk::open(&head), Err(Error::VmdkSays)));
    // A version past what the format has reached.
    let mut later = head.clone();
    later[4..8].copy_from_slice(&9u32.to_le_bytes());
    assert!(matches!(
        Vmdk::open(&later),
        Err(Error::Needs(Unsupported::Feature))
    ));
}

/// Grain sizes the format does not have, and a grain directory that is not
/// on the file: each would otherwise be read as a disk of something.
#[test]
fn a_layout_the_format_does_not_have_is_refused() {
    // A whole disk of 16 MiB in grains of 64 KiB, whose one grain table
    // the directory at sector 2 names.
    let made = |grain: u64, entries: u32, directory: u64| {
        let mut image = vec![0u8; 64 << 10];
        image[..4].copy_from_slice(b"KDMV");
        image[4..8].copy_from_slice(&1u32.to_le_bytes());
        image[12..20].copy_from_slice(&(1u64 << 15).to_le_bytes());
        image[20..28].copy_from_slice(&grain.to_le_bytes());
        image[44..48].copy_from_slice(&entries.to_le_bytes());
        image[56..64].copy_from_slice(&directory.to_le_bytes());
        image
    };
    // As it should be: a grain of 128 sectors, 512 entries to a table.
    assert!(Vmdk::open(&made(128, 512, 2)).is_ok());
    for (grain, entries, directory) in [
        (0, 512, 2),         // no grain at all
        (4, 512, 2),         // smaller than the format's least
        (100, 512, 2),       // not a power of two
        (1 << 20, 512, 2),   // larger than is read
        (128, 0, 2),         // a table of no entries
        (128, 1 << 20, 2),   // more entries than a table has
        (128, 512, 0),       // a directory at the header itself
        (128, 512, 1 << 40), // a directory that is not on the file
    ] {
        assert!(
            matches!(
                Vmdk::open(&made(grain, entries, directory)),
                Err(Error::VmdkSays)
            ),
            "grain {grain}, {entries} entries, directory at {directory}"
        );
    }
}
