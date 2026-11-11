//! AppImages: where the program ends (`hivepack::appimage::elf_size`, the
//! type 2 runtime's `appimage_get_elf_size`), on ELF headers of 32 and 64
//! bits in both byte orders, ELF files that are no AppImage and damaged
//! headers; appimagetool 1.9.1's AppImage (`squashfs-real`), its image
//! read as squashfuse reads it from where the program ends; and AppImages
//! made here of `testdata/squashfs`'s images (type 2) and of libarchive's
//! ISO 9660 test image (type 1), told by `hivepack::open` and read as the
//! images they hold.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "squashfs_support/mod.rs"]
mod squashfs_support;

use std::io::{Cursor, Read};

use hivepack::appimage::{AppImageType, Error, appimage_type, elf_size, open_squashfs};
use hivepack::open::{Container, Detected, HEAD_LEN, detect};
use hivepack::squashfs::Squashfs;
use squashfs_support::{Oracle, WHOLE, port_list, repository, set};

/// An ELF header of `class` (1: 32 bits, 2: 64) and byte order (`big`),
/// with `ai` at byte 8, its section headers at `shoff`, `shnum` of
/// `shentsize` bytes, the last saying its section is at `offset` for
/// `size` bytes; `len` bytes in all, zeros where nothing is said.
#[allow(clippy::too_many_arguments)]
fn elf(
    class: u8,
    big: bool,
    ai: &[u8],
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    offset: u64,
    size: u64,
    len: usize,
) -> Vec<u8> {
    let mut f = vec![0u8; len];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = class;
    f[5] = if big { 2 } else { 1 };
    f[6] = 1;
    f[8..8 + ai.len()].copy_from_slice(ai);
    let put = |f: &mut Vec<u8>, at: usize, v: u64, n: usize| {
        let bytes = v.to_be_bytes();
        let be = &bytes[8 - n..];
        for i in 0..n {
            f[at + i] = if big { be[i] } else { be[n - 1 - i] };
        }
    };
    let last = shoff.wrapping_add(u64::from(shentsize) * u64::from(shnum.saturating_sub(1)));
    let fits = |n: u64| last.checked_add(n).is_some_and(|end| end <= len as u64);
    let last = last as usize;
    if class == 1 {
        put(&mut f, 32, shoff, 4);
        put(&mut f, 46, u64::from(shentsize), 2);
        put(&mut f, 48, u64::from(shnum), 2);
        if fits(40) {
            put(&mut f, last + 16, offset, 4);
            put(&mut f, last + 20, size, 4);
        }
    } else {
        put(&mut f, 40, shoff, 8);
        put(&mut f, 58, u64::from(shentsize), 2);
        put(&mut f, 60, u64::from(shnum), 2);
        if fits(64) {
            put(&mut f, last + 24, offset, 8);
            put(&mut f, last + 32, size, 8);
        }
    }
    f
}

fn size_of(file: &[u8]) -> Result<u64, Error> {
    elf_size(&mut Cursor::new(file))
}

#[test]
fn where_the_program_ends() {
    for (class, entsize) in [(1u8, 40u16), (2, 64)] {
        for big in [false, true] {
            let what = format!("class {class}, big-endian {big}");
            // Ends with its section headers.
            let f = elf(
                class,
                big,
                b"AI\x02",
                1000,
                entsize,
                5,
                200,
                100,
                1000 + 5 * entsize as usize,
            );
            assert_eq!(
                size_of(&f).unwrap(),
                1000 + 5 * u64::from(entsize),
                "{what}"
            );
            // Ends with its last section, after them.
            let f = elf(class, big, b"AI\x02", 1000, entsize, 5, 1400, 600, 2000);
            assert_eq!(size_of(&f).unwrap(), 2000, "{what}");
            // One section header.
            let f = elf(class, big, b"", 64, entsize, 1, 0, 0, 64 + entsize as usize);
            assert_eq!(size_of(&f).unwrap(), 64 + u64::from(entsize), "{what}");
        }
    }
}

#[test]
fn damaged_headers_fail() {
    let good = elf(2, false, b"AI\x02", 1000, 64, 5, 200, 100, 1320);
    assert_eq!(size_of(&good).unwrap(), 1320);
    // Cut short: in e_ident, in the header, in the last section header.
    for len in [0, 10, 16, 40, 63, 1300] {
        let e = size_of(&good[..len]).unwrap_err();
        assert!(matches!(e, Error::Elf(_)), "{len}: {e}");
    }
    // An unknown class or byte order.
    for (at, byte, why) in [
        (4, 3, "Unknown ELF class"),
        (4, 0, "Unknown ELF class"),
        (5, 0, "Unknown ELF data order"),
        (5, 3, "Unknown ELF data order"),
    ] {
        let mut f = good.clone();
        f[at] = byte;
        assert!(
            matches!(size_of(&f), Err(Error::Elf(w)) if w == why),
            "{at} {byte}"
        );
    }
    // No section headers; section headers past the file; a section past
    // the largest offset.
    let none = elf(2, false, b"", 1000, 64, 0, 0, 0, 1320);
    assert!(matches!(size_of(&none), Err(Error::Elf(_))));
    let past = elf(2, false, b"", 1 << 40, 64, 5, 0, 0, 1320);
    assert!(matches!(size_of(&past), Err(Error::Elf(_))));
    let wraps = elf(2, false, b"", u64::MAX - 10, 64, 5, 0, 0, 1320);
    assert!(matches!(size_of(&wraps), Err(Error::Elf(_))));
    let mut huge = good.clone();
    huge[1256 + 24..1256 + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    huge[1256 + 32..1256 + 40].copy_from_slice(&2u64.to_le_bytes());
    assert!(matches!(size_of(&huge), Err(Error::Elf(_))));
}

#[test]
fn elf_files_that_are_not_appimages() {
    let mut head = elf(2, false, b"", 1000, 64, 5, 200, 100, 1320);
    for ai in [&b"\0\0\0"[..], b"AI\x00", b"AI\x03", b"ai\x02", b"AJ\x02"] {
        head[8..11].copy_from_slice(ai);
        assert_eq!(appimage_type(&head), None, "{ai:?}");
        assert_eq!(
            detect(&head, None),
            Detected::Container(Container::Data),
            "{ai:?}"
        );
    }
    // This test's own program, on Linux and the BSDs.
    let program = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    if program.starts_with(b"\x7fELF") {
        assert_eq!(appimage_type(&program), None);
        let head = &program[..HEAD_LEN.min(program.len())];
        assert_eq!(detect(head, None), Detected::Container(Container::Data));
        // Its section headers or last section end it, or come before.
        let end = size_of(&program).unwrap();
        assert!(end <= program.len() as u64, "{end} {}", program.len());
        assert!(end > program.len() as u64 / 2, "{end} {}", program.len());
    }
}

/// A 64-bit ELF program of `len` bytes, its section headers at its end, of
/// `kind`, with `image` after it.
fn appimage(class: u8, big: bool, kind: u8, image: &[u8]) -> (Vec<u8>, u64) {
    let entsize: u16 = if class == 1 { 40 } else { 64 };
    let shoff = 4096;
    let shnum = 7;
    let end = shoff + u64::from(entsize) * u64::from(shnum);
    let mut file = elf(
        class,
        big,
        &[b'A', b'I', kind],
        shoff,
        entsize,
        shnum,
        2048,
        1024,
        end as usize,
    );
    file.extend_from_slice(image);
    (file, end)
}

#[test]
fn type_2_appimages_made_of_the_test_images() {
    for name in ["gzip.sqfs", "xz.sqfs", "zstd.sqfs", "uncompressed.sqfs"] {
        let image = std::fs::read(repository().join("testdata/squashfs").join(name)).unwrap();
        let alone = port_list(Cursor::new(&image), 0, WHOLE);
        for (class, big) in [(1, false), (1, true), (2, false), (2, true)] {
            let (file, end) = appimage(class, big, 2, &image);
            let what = format!("{name}, class {class}, big-endian {big}");
            assert_eq!(appimage_type(&file), Some(AppImageType::Two), "{what}");
            assert_eq!(
                detect(&file[..HEAD_LEN], None),
                Detected::Container(Container::AppImageType2),
                "{what}"
            );
            assert_eq!(size_of(&file).unwrap(), end, "{what}");
            // Read from where the program ends, as the image alone is.
            assert_eq!(port_list(Cursor::new(&file), end, WHOLE), alone, "{what}");
            let mut fs = open_squashfs(Cursor::new(file)).unwrap();
            assert_eq!(fs.offset(), end, "{what}");
            let root = fs.root().unwrap();
            assert!(fs.lookup(&root, b"hello.txt").unwrap().is_some(), "{what}");
        }
    }
    // The program cut where its image would start: no image.
    let image = std::fs::read(repository().join("testdata/squashfs/gzip.sqfs")).unwrap();
    let (file, end) = appimage(2, false, 2, &image);
    let e = open_squashfs(Cursor::new(file[..end as usize].to_vec())).unwrap_err();
    assert!(matches!(e, Error::Squashfs(_)), "{e}");
}

#[test]
fn a_type_1_appimage_is_an_iso_9660_image() {
    // libarchive's test image, the program in its system area.
    let xz =
        std::fs::read(repository().join("testdata/libarchive-iso/test_read_format_iso.iso.xz"))
            .unwrap();
    let iso = xz_decode(&xz);
    assert!(iso[..32768].iter().all(|&b| b == 0));
    let mut file = iso.clone();
    let program = elf(2, false, b"AI\x01", 512, 64, 4, 0, 0, 768);
    file[..768].copy_from_slice(&program);
    assert_eq!(appimage_type(&file), Some(AppImageType::One));
    assert_eq!(
        detect(&file[..HEAD_LEN], None),
        Detected::Container(Container::AppImageType1)
    );
    // hivepack::iso reads it as the image alone.
    assert_eq!(entries(&file), entries(&iso));
    assert!(!entries(&iso).is_empty());
}

fn entries(image: &[u8]) -> Vec<(Option<Vec<u8>>, Vec<u8>)> {
    let mut reader = hivepack::iso::Reader::new(Cursor::new(image));
    let mut out = Vec::new();
    while let Some(header) = reader.next().unwrap() {
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();
        out.push((header.path.clone(), data));
    }
    out
}

fn xz_decode(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Action, InBuffer, OutBuffer, Status, Stream};
    let mut stream = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = vec![0u8; 64 << 20];
    let mut input = InBuffer::new(data);
    let mut output = OutBuffer::new(&mut out);
    let status = stream
        .code(&mut output, &mut input, Action::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = output.pos;
    out.truncate(n);
    out
}

#[test]
fn appimagetool_reads_as_squashfuse_reads_it() {
    let Some(folder) = set("squashfs-real", "generated") else {
        return;
    };
    let path = folder.join("appimagetool-x86_64.AppImage");
    let file = std::fs::read(&path).unwrap();
    assert_eq!(appimage_type(&file), Some(AppImageType::Two));
    assert_eq!(
        detect(&file[..HEAD_LEN], None),
        Detected::Container(Container::AppImageType2)
    );
    let end = size_of(&file).unwrap();
    assert_eq!(end, 944_632);
    assert_eq!(&file[end as usize..end as usize + 4], b"hsqs");
    let mut fs = open_squashfs(std::fs::File::open(&path).unwrap()).unwrap();
    let root = fs.root().unwrap();
    assert!(fs.lookup(&root, b"AppRun").unwrap().is_some());
    drop(fs);
    // Under zstd, told by its header too.
    let mut zst = vec![0u8; hivepack::zstd::compress_bound(HEAD_LEN * 4).unwrap()];
    let n = hivepack::zstd::compress(&mut zst, &file[..HEAD_LEN * 4], 3).unwrap();
    let mut opener = hivepack::open::Opener::new(move || Ok(Cursor::new(zst[..n].to_vec())));
    let opened = opener.open().unwrap();
    assert_eq!(opened.container(), Container::AppImageType2);
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let expected = oracle.list(&path, end, WHOLE);
    assert_eq!(port_list(Cursor::new(&file), end, WHOLE), expected);
    let _ = Squashfs::open_at(Cursor::new(&file), end).unwrap();
}
