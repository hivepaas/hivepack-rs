//! WIM archives that `wimlib-imagex` wrote, which is the only oracle for a
//! **compressed** one.
//!
//! 7-Zip reads XPRESS and LZX but writes neither — `7zz a -twim -mm=XPRESS`
//! fails with `E_INVALIDARG` — so `tests/wim.rs` can only check the
//! container and the tree of an uncompressed archive. wimlib writes all
//! four kinds, and these say what this reader does with each of them as
//! they really come, rather than as a header turned over by hand suggests.
//!
//! wimlib is GPL-3.0-or-later. It is built by `scripts/testdata.py` and run
//! as a program here, and nothing in this repository is read from it: the
//! formats are implemented from Microsoft's own specifications.
//!
//! See crates/hivepack/src/wim/mod.rs and docs/wim.md.

#![cfg(feature = "wim")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use hivepack::wim::{Compression, Error, Unsupported, Wim};

#[path = "wim_support/mod.rs"]
mod build;

use build::{Scratch, a_tree, a_tree_with_links, captured, captured_from, want, wimlib};

/// An archive wimlib wrote with no compression: the tree that went in comes
/// back, as it does from 7-Zip's in `tests/wim.rs`. Two writers of the same
/// format, so what is read is the format and not one tool's habits.
#[test]
fn an_archive_wimlib_wrote_uncompressed_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("none");
    let bytes = captured(&s, &tool, &["--compress=none"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::None);
    assert_eq!(wim.images().len(), 1);
    assert_eq!(wim.images()[0].name.as_deref(), Some("probe"));

    assert_eq!(read(&mut wim), want());
}

/// An archive wimlib wrote with XPRESS: the tree **and** every file come
/// back as they went in, chunk by chunk.
///
/// The tree matters as much as the files: an image's metadata is a
/// compressed resource too, so this is also the first test in which a
/// compressed metadata resource is read.
#[test]
fn an_xpress_archive_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("xpress");
    let bytes = captured(&s, &tool, &["--compress=XPRESS"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::Xpress);
    assert_eq!(wim.chunk_size(), 32_768);

    assert_eq!(read(&mut wim), want());
}

/// Everything in `wim`'s first image, as [`a_tree`] holds it: a path for
/// each entry, with its bytes where it is a file.
fn read(wim: &mut Wim<std::io::Cursor<Vec<u8>>>) -> BTreeMap<String, Option<Vec<u8>>> {
    let entries = wim.entries(1).unwrap();
    let mut found = BTreeMap::new();
    for entry in &entries {
        let what = if entry.is_dir() {
            None
        } else {
            Some(wim.read(entry).unwrap())
        };
        found.insert(entry.path.clone(), what);
    }
    found
}

/// Every field of every entry of `wim`'s first image, which is what an
/// image's metadata holds: the names, the times, the attributes, the
/// hashes and what is a hard link of what. Two archives of one tree give
/// the same lines, so this is how far a **compressed metadata resource**
/// is read -- field by field, and not only as far as the paths.
///
/// All but the time a file was last **read**, which is the one thing that
/// moves on its own: writing the second archive of a tree reads the tree
/// again, and that is a read.
fn described(wim: &mut Wim<std::io::Cursor<Vec<u8>>>) -> Vec<String> {
    let entries = wim.entries(1).unwrap();
    entries
        .iter()
        .map(|e| {
            format!(
                "{} {} {:?} {} {:?} {:?} {:?} {:?} {:#x} {:?} {:?} {}",
                e.path,
                e.name,
                e.short_name,
                e.size,
                e.hash,
                e.created,
                e.modified,
                e.unix_mode,
                e.attributes,
                e.reparse_tag,
                e.hard_link_group,
                e.extra_streams,
            )
        })
        .collect()
}

/// Archives wimlib wrote with LZX: the tree **and** every file come back
/// as they went in, over the three chunk sizes that read differently.
///
/// LZX is what a Windows disc's `install.wim` holds. These archives hold
/// what says the format is read rather than one shape of it: a file over
/// five chunks, one that does not compress at all, one whose first chunk
/// compresses and whose second is stored, an image's metadata, which is an
/// **aligned offset block** where the files are verbatim ones, and a file
/// of nothing but `E8` x86 calls, whose translation LZX undoes and the
/// other compressions do not.
///
/// The chunk size decides three things at once, so each one is read: how
/// wide the Block Size field is (16 bits up to 32768 and 24 above it), how
/// many position slots the window has (30, 32, 34), and whether a chunk
/// holds more than one block — wimlib ends a block every 100000 bytes, so
/// the 131072 chunks are the ones that hold two, each with its own trees
/// written as the difference from the trees of the block before.
#[test]
fn an_lzx_archive_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("lzx");
    // The same tree with nothing compressed, to hold the others against:
    // its metadata resource is the bytes theirs decompress to.
    let plain = captured(&s, &tool, &["--compress=none"]);
    let mut plain = Wim::open(std::io::Cursor::new(plain)).unwrap();
    let described_plain = described(&mut plain);

    for chunk in [32_768u32, 65_536, 131_072] {
        let size = format!("--chunk-size={chunk}");
        let bytes = captured(&s, &tool, &["--compress=LZX", &size]);

        let mut wim = Wim::open(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{chunk}: opening failed: {e:?}"));
        assert_eq!(wim.compression(), Compression::Lzx, "{chunk}");
        assert_eq!(wim.chunk_size(), chunk, "{chunk}");
        assert_eq!(read(&mut wim), want(), "{chunk}");
        // The tree itself, field by field: the metadata resource is
        // compressed too, and this is what says it came back whole.
        assert_eq!(described(&mut wim), described_plain, "{chunk}");
    }
}

/// A compressed archive whose compression has no decoder yet: **the tree
/// itself is compressed**, so it is not read, and the reader says which
/// compression it needs by name rather than guessing at bytes.
///
/// This is the shape a Windows disc's `install.wim` has, which is LZX.
/// What such an archive still tells without a decoder is checked here too,
/// because it is all it tells: the compression, the chunk size, how many
/// resources there are and how long each is, and the names of its images
/// from the XML.
#[test]
fn a_compressed_archive_says_which_compression_the_tree_needs() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("compressed");
    for (how, compression, chunk, needs) in [
        // XPRESS and LZX are decoded, each with a test of its own above.
        (
            &["--compress=LZMS"][..],
            Compression::Lzms,
            131_072,
            Unsupported::Lzms,
        ),
        // Solid blocks are LZMS, and the tree is compressed on its own
        // before any solid block is reached: LZMS is what it needs first.
        (
            &["--solid"][..],
            Compression::Lzms,
            131_072,
            Unsupported::Lzms,
        ),
    ] {
        let bytes = captured(&s, &tool, how);

        // The container reads: the table of resources is not compressed,
        // even where everything it names is.
        let mut wim = Wim::open(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{how:?}: opening failed: {e:?}"));
        assert_eq!(wim.compression(), compression, "{how:?}");
        assert_eq!(wim.chunk_size(), chunk, "{how:?}");
        assert_eq!(wim.images().len(), 1, "{how:?}");
        assert_eq!(wim.images()[0].name.as_deref(), Some("probe"), "{how:?}");
        assert!(
            wim.resources() >= a_tree().len() - 2,
            "{how:?}: the resources"
        );

        // The tree does not: it is a resource like any other, and a
        // compressed archive compresses it.
        let tree = wim.entries(1);
        assert!(
            matches!(tree.as_ref().err(), Some(Error::Needs(what)) if *what == needs),
            "{how:?}: wanted {needs:?}, got {:?}",
            tree.err()
        );
    }
}

/// A file read through [`Wim::file`] is the file [`Wim::read`] gives, and
/// it arrives **chunk by chunk**: read with a buffer of seven bytes, the
/// 132000-byte file of the tree comes out whole and the same, over the
/// five LZX chunks it is held in and across every boundary between them.
///
/// This is what lets an image of a Windows installation be extracted on a
/// machine that could not hold one of its files: the reader holds a chunk,
/// never the file.
#[test]
fn a_file_reads_through_a_small_buffer_as_it_reads_whole() {
    let Some(tool) = wimlib() else {
        return;
    };
    let s = Scratch::new("stream");
    let bytes = captured(&s, &tool, &["--compress=LZX"]);
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let long = entries
        .iter()
        .find(|entry| entry.path.ends_with("over and over again.txt"))
        .expect("the tree holds the long file")
        .clone();
    assert_eq!(long.size, 132_000);

    let whole = wim.read(&long).unwrap();
    let mut file = wim.file(&long).unwrap();
    assert_eq!(file.size(), 132_000);
    let mut piece = [0u8; 7];
    let mut read = Vec::new();
    loop {
        match file.pull(&mut piece).unwrap() {
            0 => break,
            n => read.extend_from_slice(&piece[..n]),
        }
    }
    assert_eq!(read, whole);

    // And through `Read`, which is what an extractor uses, with the
    // buffer that lands on no chunk boundary at all.
    use std::io::Read;
    let mut file = wim.file(&long).unwrap();
    let mut through = Vec::new();
    file.read_to_end(&mut through).unwrap();
    assert_eq!(through, whole);

    // A file of no bytes reads as none, and a directory is not a file.
    let empty = entries
        .iter()
        .find(|entry| entry.path.ends_with("empty.bin"))
        .expect("the tree holds an empty file")
        .clone();
    let mut file = wim.file(&empty).unwrap();
    assert_eq!(file.size(), 0);
    assert_eq!(file.pull(&mut piece).unwrap(), 0);
    let dir = entries
        .iter()
        .find(|entry| entry.is_dir())
        .expect("the tree holds a folder")
        .clone();
    assert!(matches!(wim.file(&dir), Err(Error::NotAFile)));
}

/// A file whose bytes were changed after the archive was written does not
/// read: the SHA-1 the tree names it by is the one check a WIM gives, and
/// a WIM gives no other -- no CRC beside a chunk, nothing beside a
/// resource -- so without this a damaged archive would hand back damaged
/// bytes and say nothing.
///
/// The archive is the uncompressed one, so that the file's bytes are in it
/// as themselves and one of them can be turned over where it lies.
#[test]
fn a_file_whose_bytes_were_changed_does_not_read() {
    let Some(tool) = wimlib() else {
        return;
    };
    let s = Scratch::new("hash");
    let mut bytes = captured(&s, &tool, &["--compress=none"]);
    let said = b"hello from a wim\n";
    let at = bytes
        .windows(said.len())
        .position(|at| at == said)
        .expect("the file's bytes are in the archive as themselves");
    bytes[at] ^= 0x20;

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let changed = entries
        .iter()
        .find(|entry| entry.path == "readme.txt")
        .expect("the tree holds it")
        .clone();
    assert!(
        matches!(wim.read(&changed), Err(Error::Hash)),
        "a changed file read as though it were the file"
    );
    // And every other file still reads: one resource was turned over, not
    // the archive.
    let note = entries
        .iter()
        .find(|entry| entry.path == "docs/note.txt")
        .expect("the tree holds it")
        .clone();
    assert_eq!(wim.read(&note).unwrap(), b"deeper\n");
}

/// An entry with **streams beside it** is read past, and the file's own
/// hash is taken from the unnamed one.
///
/// A WIM keeps the streams of an entry (`file.txt:stream`, and the reparse
/// data of a symbolic link) as stream entries in the metadata after the
/// entry itself, and the next entry of the list begins after them. A
/// reader that stepped over the entry alone would read the first stream
/// entry as an entry of the tree and refuse the whole image, and
/// `wimlib-imagex` writes two of them for every symbolic link it
/// captures, so without this an archive holding one does not read at all.
///
/// The hash is the other half: the field in such an entry is zeroes, and
/// the unnamed stream entry after it carries the SHA-1 of what the file
/// holds. Read from the field alone, a symbolic link here would have no
/// resource and a length of nothing, rather than the 44 bytes of reparse
/// data wimlib really wrote.
#[test]
#[cfg(unix)]
fn an_entry_with_streams_beside_it_is_read_past() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("streams");
    let tree = s.0.join("tree");
    a_tree_with_links(&tree);
    let bytes = captured_from(&tool, &tree, &s.0.join("streams.wim"), &["--compress=LZX"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        ["link.txt", "one.txt", "sub", "two.txt", "sub/note.txt"]
    );

    // The symbolic link: a reparse point, whose kind is the one Windows
    // gives a symbolic link, with its reparse data as the resource the
    // unnamed stream entry names. Its data is not a file's bytes, so
    // reading it is refused rather than handed back as the file.
    let link = &entries[0];
    assert_eq!(link.reparse_tag, Some(0xa000_000c));
    assert_eq!(link.size, 44);
    assert_ne!(link.hash, [0u8; 20]);
    // Both stream entries wimlib wrote are unnamed, so there is no named
    // stream beside the file.
    assert_eq!(link.extra_streams, 0);
    assert!(matches!(
        wim.read(link),
        Err(Error::Needs(Unsupported::Reparse { tag: 0xa000_000c }))
    ));

    // And the two names of one file say so, by the set they are both in.
    let (one, two) = (&entries[1], &entries[3]);
    assert_eq!(one.hard_link_group, two.hard_link_group);
    assert!(one.hard_link_group.is_some());
    assert_eq!(one.hash, two.hash);
    assert_eq!(wim.read(one).unwrap(), b"shared bytes\n");
    assert_eq!(wim.read(two).unwrap(), b"shared bytes\n");
}
