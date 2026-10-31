//! Opening files through their layers, made by the reference libraries:
//! each compressor alone, stacked, with several streams one after the
//! other, cut short or followed by other data, past the limits, and read a
//! byte at a time; then a tar archive under them extracted through the
//! opener.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::{self, Cursor, Read};

use hivepack_open::{Container, DecodeError, Error, Layer, Limits, Opener};
use support::{
    Scratch, bzip2, gzip, lz4, lz4_legacy, lzip, lzma, newc, pbzx, pbzx_chunk, pbzx_of, rpm,
    sample_tar, xz, xz_no_check, xz_preset, zstd,
};

/// A reference library's compressor.
type Compress = fn(&[u8]) -> Vec<u8>;

/// What `file` opens to: its layers, container and data.
fn open_named(file: &[u8], name: Option<&str>) -> Result<(Vec<Layer>, Container, Vec<u8>), Error> {
    let mut opener = Opener::new(|| Ok(Cursor::new(file.to_vec())));
    if let Some(name) = name {
        opener = opener.name(name);
    }
    let mut opened = opener.open()?;
    let mut data = Vec::new();
    opened.read_to_end(&mut data)?;
    Ok((opened.layers().to_vec(), opened.container(), data))
}

fn open(file: &[u8]) -> Result<(Vec<Layer>, Container, Vec<u8>), Error> {
    open_named(file, None)
}

/// pbzx in chunks of 64 KiB.
fn pbzx_64k(data: &[u8]) -> Vec<u8> {
    pbzx(data, 1 << 16)
}

/// The layer a read failed in.
fn failed_layer(result: Result<(Vec<Layer>, Container, Vec<u8>), Error>) -> Layer {
    match result {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
            e.get_ref()
                .and_then(|inner| inner.downcast_ref::<DecodeError>())
                .unwrap_or_else(|| panic!("not a DecodeError: {e}"))
                .layer
        }
        other => panic!("not a decoding error: {other:?}"),
    }
}

#[test]
fn each_layer_comes_off() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 8] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lz4, lz4),
        (Layer::Lz4, lz4_legacy),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Pbzx, pbzx_64k),
    ];
    for (layer, compress) in cases {
        let (layers, container, data) = open(&compress(&tar)).unwrap();
        assert_eq!(layers, [layer]);
        assert_eq!(container, Container::Tar, "{layer:?}");
        assert!(data == tar, "{layer:?}");
    }
    // The tar archive as it is.
    assert_eq!(open(&tar).unwrap(), (vec![], Container::Tar, tar));
}

#[test]
fn lzma_is_told_by_its_name() {
    let tar = sample_tar();
    let file = lzma(&tar);
    let (layers, container, data) = open_named(&file, Some("backup.tar.LZMA")).unwrap();
    assert_eq!((layers, container), (vec![Layer::Lzma], Container::Tar));
    assert!(data == tar);
    // Without its name, it is data.
    assert_eq!(
        open(&file).unwrap(),
        (vec![], Container::Data, file.clone())
    );
    // Under another layer, the name is the one without its extension.
    let (layers, _, data) = open_named(&gzip(&file), Some("backup.tar.lzma.gz")).unwrap();
    assert_eq!(layers, [Layer::Gzip, Layer::Lzma]);
    assert!(data == tar);
}

#[test]
fn layers_stack() {
    let tar = sample_tar();
    let file = gzip(&bzip2(&xz(&zstd(&tar))));
    let (layers, container, data) = open(&file).unwrap();
    assert_eq!(layers, [Layer::Gzip, Layer::Bzip2, Layer::Xz, Layer::Zstd]);
    assert_eq!(container, Container::Tar);
    assert!(data == tar);
    let (layers, _, data) = open(&lz4(&gzip(&lz4_legacy(&tar)))).unwrap();
    assert_eq!(layers, [Layer::Lz4, Layer::Gzip, Layer::Lz4]);
    assert!(data == tar);
}

/// The message of the layer `result` failed in.
fn failure(result: Result<(Vec<Layer>, Container, Vec<u8>), Error>) -> (Layer, String) {
    match result {
        Err(Error::Io(e)) => {
            let inner = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<DecodeError>())
                .unwrap_or_else(|| panic!("not a DecodeError: {e}"));
            (inner.layer, inner.message.clone())
        }
        other => panic!("not a decoding error: {other:?}"),
    }
}

/// pbzx, as macOS packages' payloads have it, read as Apple's tools read
/// it (`pkgutil --expand-full`, on files like these: see docs/open.md):
/// chunks to the end of the stream, short ones among them; stored chunks,
/// whatever their first bytes; chunks of nothing.
#[test]
fn pbzx_chunks_come_off() {
    let tar = sample_tar();
    let (layers, container, data) = open(&pbzx(&tar, 1 << 16)).unwrap();
    assert_eq!((layers, container), (vec![Layer::Pbzx], Container::Tar));
    assert!(data == tar);
    let xz_chunk = |c: &[u8]| pbzx_chunk(c.len() as u64, &xz_no_check(c));
    let stored = |c: &[u8]| pbzx_chunk(c.len() as u64, c);
    let (a, b) = tar.split_at(1000);
    let files = [
        // One chunk.
        pbzx(&tar, tar.len()),
        // Chunks of the block's size.
        pbzx_of(4096, &tar.chunks(4096).map(xz_chunk).collect::<Vec<_>>()),
        // A short chunk, then more.
        pbzx_of(1 << 24, &[xz_chunk(a), xz_chunk(b)]),
        // Stored chunks, and chunks of nothing, before and after.
        pbzx_of(
            1 << 16,
            &[
                stored(&[]),
                xz_chunk(&tar[..30_000]),
                stored(&tar[30_000..60_000]),
                stored(&[]),
                xz_chunk(&tar[60_000..]),
                stored(&[]),
            ],
        ),
        // A check in each stream.
        pbzx_of(
            1 << 24,
            &tar.chunks(50_000)
                .map(|c| pbzx_chunk(c.len() as u64, &xz(c)))
                .collect::<Vec<_>>(),
        ),
    ];
    for (i, file) in files.iter().enumerate() {
        assert_eq!(
            open(file).unwrap(),
            (vec![Layer::Pbzx], Container::Tar, tar.clone()),
            "file {i}"
        );
    }
    // A stored chunk that starts with xz's magic is stored.
    let mut text = b"some notes ".repeat(100);
    let at = text.len();
    text.extend(b"\xFD7zXZ\0 and then more notes");
    let file = pbzx_of(1 << 24, &[xz_chunk(&text[..at]), stored(&text[at..])]);
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Pbzx], Container::Data, text)
    );
    // Nothing but the header: nothing.
    assert_eq!(
        open(&pbzx_of(1 << 24, &[])).unwrap(),
        (vec![Layer::Pbzx], Container::Data, vec![])
    );
}

/// What Apple's tools refuse in pbzx (see docs/open.md) is refused.
#[test]
fn pbzx_refuses_what_apple_s_tools_refuse() {
    let text = b"Notes, in chunks.\n".repeat(2000);
    let chunks: Vec<_> = text
        .chunks(8192)
        .map(|c| pbzx_chunk(c.len() as u64, &xz_no_check(c)))
        .collect();
    let good = pbzx_of(1 << 24, &chunks);
    assert_eq!(open(&good).unwrap().2, text);
    let (part, more) = text.split_at(200);
    let cut_after = |n: usize| {
        let mut file = good.clone();
        file.truncate(file.len() - n);
        file
    };
    let then = |extra: &[u8]| {
        let mut file = good.clone();
        file.extend(extra);
        file
    };
    let two_streams = [xz_no_check(part), xz_no_check(&more[..100])].concat();
    let short_stream = {
        let stream = xz_no_check(part);
        stream[..stream.len() - 10].to_vec()
    };
    let cases: [(&str, Vec<u8>, &str); 12] = [
        (
            "chunks larger than the block",
            pbzx_of(4096, &chunks),
            "a chunk is larger than the block size",
        ),
        (
            "a stored chunk larger than the block",
            pbzx_of(100, &[pbzx_chunk(200, part)]),
            "a chunk is larger than the block size",
        ),
        (
            "a chunk that decompresses to more",
            pbzx_of(1 << 24, &[pbzx_chunk(199, &xz_no_check(part))]),
            "a chunk decompresses to more than its size",
        ),
        (
            "a chunk that decompresses to less",
            pbzx_of(1 << 24, &[pbzx_chunk(201, &xz_no_check(part))]),
            "a chunk decompresses to less than its size",
        ),
        (
            "two xz streams in a chunk",
            pbzx_of(1 << 24, &[pbzx_chunk(300, &two_streams)]),
            "data after a chunk's xz stream",
        ),
        (
            "a chunk neither stored nor xz",
            pbzx_of(1 << 24, &[pbzx_chunk(201, part)]),
            "file format not recognized",
        ),
        (
            "a chunk's header cut short",
            then(&[0; 8]),
            "the stream is cut short",
        ),
        (
            "a chunk cut short",
            cut_after(10),
            "the stream is cut short",
        ),
        (
            "an xz stream longer than its chunk",
            pbzx_of(1 << 24, &[pbzx_chunk(200, &short_stream)]),
            "a chunk's xz stream is cut short",
        ),
        (
            "a chunk's stored size past the end",
            cut_after(0)
                .into_iter()
                .chain(pbzx_chunk(100, &[1; 100]).into_iter().take(16 + 5))
                .collect(),
            "the stream is cut short",
        ),
        (
            "anything after the last chunk",
            then(b"and something after it"),
            "a chunk is larger than the block size",
        ),
        (
            "the header cut short",
            good[..8].to_vec(),
            "the stream is cut short",
        ),
    ];
    for (what, file, message) in cases {
        assert_eq!(
            failure(open(&file)),
            (Layer::Pbzx, message.to_string()),
            "{what}"
        );
    }
    // Zeros after the last chunk are chunks of nothing.
    assert_eq!(open(&then(&[0; 32])).unwrap().2, text);
}

/// A cpio archive under each layer, and an RPM package's payload under
/// each compressor rpm uses, LZMA's without magic among them: told as
/// libarchive tells them, then read by hivepack-cpio.
#[test]
fn cpio_archives_and_rpm_packages_open() {
    let tar = sample_tar();
    let cpio = newc(&[
        ("usr/", b""),
        ("usr/share/doc/README", b"Read me.\n"),
        ("usr/lib/big.bin", &tar),
    ]);
    assert_eq!(
        open(&cpio).unwrap(),
        (vec![], Container::Cpio, cpio.clone())
    );
    let cases: [(Layer, Compress); 5] = [
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Xz, xz),
        (Layer::Zstd, zstd),
        (Layer::Pbzx, pbzx_64k),
    ];
    for (layer, compress) in cases {
        let (layers, container, data) = open(&compress(&cpio)).unwrap();
        assert_eq!((layers, container), (vec![layer], Container::Cpio));
        assert!(data == cpio, "{layer:?}");
        // rpm's payload compressors, but pbzx.
        if layer == Layer::Pbzx {
            continue;
        }
        let (layers, container, data) = open(&rpm(&compress(&cpio))).unwrap();
        assert_eq!(
            (layers, container),
            (vec![Layer::Rpm, layer], Container::Cpio)
        );
        assert!(data == cpio, "{layer:?}");
    }
    // LZMA, which RPM packages had before xz, has no magic, and the
    // payload no name: its header tells it, as libarchive tells it.
    let (layers, container, data) = open(&rpm(&lzma(&cpio))).unwrap();
    assert_eq!(
        (layers, container),
        (vec![Layer::Rpm, Layer::Lzma], Container::Cpio)
    );
    assert!(data == cpio);
    assert_eq!(open(&lzma(&cpio)).unwrap().1, Container::Data);
    // A payload left uncompressed.
    assert_eq!(
        open(&rpm(&cpio)).unwrap(),
        (vec![Layer::Rpm], Container::Cpio, cpio.clone())
    );
    // What hivepack-cpio reads through the layers.
    let mut opener = Opener::new(|| Ok(Cursor::new(rpm(&xz(&cpio)))));
    let mut reader = hivepack_cpio::Reader::new(opener.open().unwrap());
    let mut entries = Vec::new();
    while let Some(h) = reader.next().unwrap() {
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();
        entries.push((h.path, data.len()));
    }
    assert_eq!(
        entries,
        [
            (b"usr".to_vec(), 0),
            (b"usr/share/doc/README".to_vec(), 9),
            (b"usr/lib/big.bin".to_vec(), tar.len()),
        ]
    );
}

/// An RPM package extracts through the opener: its payload's files, the
/// package's lead, headers and compression taken off.
#[test]
fn an_rpm_package_extracts_through_the_opener() {
    let cpio = newc(&[
        ("usr/", b""),
        ("usr/bin/", b""),
        ("usr/bin/hello", b"#!/bin/sh\necho hello\n"),
    ]);
    let package = rpm(&xz(&cpio));
    let scratch = Scratch::new();
    let out = scratch.path().join("out");
    let mut opener = Opener::new(|| Ok(Cursor::new(&package[..])));
    let summary = hivepack_extract::extract_cpio(
        || Ok(opener.open()?),
        &out,
        &hivepack_extract::Options::default(),
    )
    .unwrap();
    assert_eq!((summary.files, summary.directories), (1, 2));
    assert_eq!(
        std::fs::read(out.join("usr/bin/hello")).unwrap(),
        b"#!/bin/sh\necho hello\n"
    );
}

/// RPM packages that end before their payload, or have no header, fail
/// with libarchive's messages.
#[test]
fn rpm_packages_without_a_payload_fail() {
    let package = rpm(&gzip(&newc(&[("a", b"a")])));
    let header_end = 96 + 16 + 16 + 7 + 1 + 16;
    for (file, message) in [
        (
            package[..50].to_vec(),
            "Truncated input file (needed 96 bytes, only 50 available)",
        ),
        (package[..96].to_vec(), "the stream is cut short"),
        (
            package[..header_end - 4].to_vec(),
            "the stream is cut short",
        ),
        (
            [&package[..96], &gzip(b"no headers")[..]].concat(),
            "Unrecognized rpm header",
        ),
    ] {
        assert_eq!(failure(open(&file)), (Layer::Rpm, message.to_string()));
    }
    // An outer layer's error comes through the package as it is.
    let mut outer = gzip(&package);
    outer.truncate(outer.len() - 4);
    assert_eq!(failed_layer(open(&outer)), Layer::Gzip);
}

/// libarchive's own cpio archives and RPM packages, when the core sets are
/// there (`scripts/testdata.py fetch`): every format of cpio, and packages
/// with gzip and bzip2 payloads, told and their first entry read.
#[test]
fn libarchive_s_cpio_archives_and_packages_open() {
    let folder = support::testdata().join("libarchive-cpio");
    if !folder.join(".complete").exists() {
        eprintln!("skipping: the libarchive-cpio set is not fetched");
        return;
    }
    let cases: [(&str, &[Layer]); 8] = [
        ("cpio_bin_be.cpio", &[]),
        ("cpio_bin_le.cpio", &[]),
        // Its test's two parts make one archive.
        ("cpio_afio_header.part*.cpio", &[]),
        ("cpio_filename_utf8_jp.cpio", &[]),
        ("test_compat_cpio_1.cpio", &[]),
        ("test_write_disk_appledouble.cpio.gz", &[Layer::Gzip]),
        ("cpio_svr4_gzip_rpm.rpm", &[Layer::Rpm, Layer::Gzip]),
        ("cpio_svr4_bzip2_rpm.rpm", &[Layer::Rpm, Layer::Bzip2]),
    ];
    for (name, layers) in cases {
        let file = match name.split_once('*') {
            Some((stem, end)) => ["1", "2"]
                .iter()
                .flat_map(|part| std::fs::read(folder.join(format!("{stem}{part}{end}"))).unwrap())
                .collect(),
            None => std::fs::read(folder.join(name)).unwrap(),
        };
        let mut opener = Opener::new(|| Ok(Cursor::new(file.clone())));
        let opened = opener.open().unwrap();
        assert_eq!(
            (opened.layers(), opened.container()),
            (layers, Container::Cpio),
            "{name}"
        );
        // The first entry: afio's test is that header alone.
        let mut reader = hivepack_cpio::Reader::new(opened);
        assert!(reader.next().unwrap().is_some(), "{name}");
    }
}

/// XAR archives, macOS's packages among them (`testdata/xar`), are told,
/// under a layer too; a package's payload, under gzip, is cpio.
#[test]
fn xar_archives_and_package_payloads_open() {
    for name in ["default.xar", "none-sha256.xar", "tiny.pkg", "product.pkg"] {
        let file = std::fs::read(support::repository().join("testdata/xar").join(name)).unwrap();
        assert_eq!(open(&file).unwrap().1, Container::Xar, "{name}");
        let (layers, container, data) = open(&gzip(&file)).unwrap();
        assert_eq!(
            (layers, container),
            (vec![Layer::Gzip], Container::Xar),
            "{name}"
        );
        assert!(data == file, "{name}");
    }
    let file = std::fs::read(support::repository().join("testdata/xar/tiny.pkg")).unwrap();
    let mut xar = hivepack_xar::Reader::new(&file[..]);
    while let Some(h) = xar.next().unwrap() {
        if h.path.as_deref() != Some(b"Payload") {
            continue;
        }
        let mut once = Some(&mut xar);
        let mut opener = Opener::new(move || Ok(once.take().unwrap()));
        let opened = opener.open().unwrap();
        assert_eq!(
            (opened.layers(), opened.container()),
            (&[Layer::Gzip][..], Container::Cpio)
        );
        return;
    }
    panic!("no Payload");
}

#[test]
fn other_contents() {
    // One file, compressed.
    let text = b"Just some notes, not an archive.\n".repeat(50);
    assert_eq!(
        open(&zstd(&text)).unwrap(),
        (vec![Layer::Zstd], Container::Data, text.clone())
    );
    // A ZIP archive, compressed: the caller takes it out to a file.
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend([0; 100]);
    assert_eq!(
        open(&xz(&zip)).unwrap(),
        (vec![Layer::Xz], Container::Zip, zip.clone())
    );
    // Nothing at all.
    assert_eq!(open(b"").unwrap(), (vec![], Container::Data, vec![]));
    assert_eq!(
        open(&gzip(b"")).unwrap(),
        (vec![Layer::Gzip], Container::Data, vec![])
    );
}

/// An ISO 9660 image, as libarchive's tests have it (xz-compressed in
/// `testdata/libarchive-iso`): ISO 9660 in a layer, read in order.
#[test]
fn an_iso_image_under_layers_reads() {
    let path =
        support::repository().join("testdata/libarchive-iso/test_read_format_iso_joliet.iso.xz");
    let file = std::fs::read(path).unwrap();
    let (layers, container, image) = open(&file).unwrap();
    assert_eq!((layers, container), (vec![Layer::Xz], Container::Iso));
    for compressed in [gzip(&image), zstd(&image)] {
        let (_, container, data) = open(&compressed).unwrap();
        assert_eq!((container, data.len()), (Container::Iso, image.len()));
    }
    assert_eq!(open(&image).unwrap().1, Container::Iso);
    // What hivepack-iso reads through the layer is what it reads of the
    // image itself.
    let entries = |r: Box<dyn Read + Send + '_>| {
        let mut iso = hivepack_iso::Reader::new(r);
        let mut out = Vec::new();
        while let Some(h) = iso.next().unwrap() {
            let mut data = Vec::new();
            iso.read_to_end(&mut data).unwrap();
            out.push((h, data));
        }
        out
    };
    let mut opener = Opener::new(|| Ok(Cursor::new(file.clone())));
    let through_layer = entries(Box::new(opener.open().unwrap()));
    assert_eq!(through_layer, entries(Box::new(Cursor::new(image))));
    let names: Vec<_> = through_layer
        .iter()
        .filter_map(|(h, _)| h.path.clone())
        .collect();
    assert!(
        names.contains(&b"long-joliet-file-name.textfile".to_vec()),
        "{names:?}"
    );
}

/// UDF volumes, as `testdata/udf` has them (xz-compressed): UDF alone,
/// on a VAT, and beside ISO 9660, found under their layer and alone, and
/// mounted by hivepack-udf from what comes out.
#[test]
fn udf_volumes_under_layers_open() {
    for name in [
        "mkudffs-hd-0201",
        "mkudffs-hd-0201-bs4096",
        "mkudffs-cdr-0201",
        "genisoimage",
    ] {
        let path = support::repository().join(format!("testdata/udf/{name}.udf.xz"));
        let file = std::fs::read(path).unwrap();
        let (layers, container, image) = open(&file).unwrap();
        assert_eq!(
            (layers, container),
            (vec![Layer::Xz], Container::Udf),
            "{name}"
        );
        assert_eq!(open(&zstd(&image)).unwrap().1, Container::Udf, "{name}");
        assert_eq!(open(&image).unwrap().1, Container::Udf, "{name}");
        let udf = hivepack_udf::Udf::open(Cursor::new(image)).unwrap();
        assert!(!udf.volume().name.is_empty(), "{name}");
    }
}

/// 7z archives of `testdata/7z`, made by 7-Zip: found by their signature,
/// alone and under layers, and opened by hivepack-7z from what comes out.
#[test]
fn seven_zip_archives_under_layers_open() {
    for name in ["plain.7z", "encrypted.7z"] {
        let path = support::repository().join("testdata/7z").join(name);
        let archive = std::fs::read(path).unwrap();
        assert_eq!(
            open(&archive).unwrap(),
            (vec![], Container::SevenZip, archive.clone()),
            "{name}"
        );
        for (layer, compress) in [(Layer::Zstd, zstd as Compress), (Layer::Xz, xz)] {
            let (layers, container, data) = open(&compress(&archive)).unwrap();
            assert_eq!(
                (layers, container),
                (vec![layer], Container::SevenZip),
                "{name}"
            );
            assert!(data == archive, "{name}");
            let opened = hivepack_7z::Archive::open(Cursor::new(data)).unwrap();
            assert_eq!(opened.len(), 9, "{name}");
        }
    }
}

/// The volumes of the split archives of `testdata/zip-split`, made by
/// Info-ZIP's `zip -s`: the first by its split signature, the others,
/// which start anywhere in the archive, by their names; from any of them,
/// hivepack-zip's `Volumes::open` finds the rest and reads the archive.
#[test]
fn split_zip_volumes_open() {
    use hivepack_zip::{Archive, Flags, OpenFlags, Volumes, volume_paths};
    let folder = support::repository().join("testdata/zip-split");
    for last in ["infozip.zip", "infozip64.zip", "infozip-crypt.zip"] {
        let paths = volume_paths(&folder.join(last));
        assert!(paths.len() > 1, "{last}");
        for path in &paths {
            let name = path.file_name().unwrap().to_str().unwrap();
            let file = std::fs::read(path).unwrap();
            let (layers, container, _) = open_named(&file, Some(name)).unwrap();
            assert_eq!((layers, container), (vec![], Container::Zip), "{name}");
            let za = Archive::open(Volumes::open(path).unwrap(), OpenFlags::RDONLY).unwrap();
            assert!(za.get_num_entries(Flags::NONE) > 3, "{name}");
        }
        // Without its name, a volume that starts anywhere is data.
        let file = std::fs::read(folder.join(last)).unwrap();
        assert_eq!(open(&file).unwrap().1, Container::Data, "{last}");
    }
}

/// Data looked into for an ISO 9660 image, cut short in what is looked
/// at: it opens, and the error comes after the data before it, as without
/// the look.
#[test]
fn data_cut_short_where_an_iso_image_is_looked_for() {
    // Random bytes, which do not compress: half the stream is half of them.
    let mut x = 0x9e37_79b9u32;
    let text: Vec<u8> = (0..20_000)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect();
    let file = gzip(&text);
    let cut = &file[..file.len() / 2];
    let mut opener = Opener::new(|| Ok(Cursor::new(cut.to_vec())));
    let mut opened = opener.open().unwrap();
    assert_eq!(opened.container(), Container::Data);
    let mut data = Vec::new();
    let error = opened.read_to_end(&mut data).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(
        data.len() > 1570 && text.starts_with(&data),
        "{}",
        data.len()
    );
}

#[test]
fn streams_one_after_another() {
    let tar = sample_tar();
    let (a, b) = tar.split_at(30_000);
    // zstd frames, a skippable one between them.
    let mut file = zstd(a);
    file.extend([0x5E, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    file.extend(zstd(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Zstd], Container::Tar, tar.clone())
    );
    // A file that starts with a skippable frame.
    let mut file = vec![0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
    file.extend(zstd(&tar));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Zstd], Container::Tar, tar.clone())
    );
    // gzip members and bzip2 streams, zeros after them as tar's blocking
    // leaves them.
    for (layer, compress) in [(Layer::Gzip, gzip as Compress), (Layer::Bzip2, bzip2)] {
        let mut file = compress(a);
        file.extend(compress(b));
        file.extend([0; 3000]);
        assert_eq!(
            open(&file).unwrap(),
            (vec![layer], Container::Tar, tar.clone()),
            "{layer:?}"
        );
    }
    // LZ4 frames, a skippable one first and between them: the frame after
    // it tells LZ4 from zstd.
    let mut file = vec![0x50, 0x2A, 0x4D, 0x18, 2, 0, 0, 0, 7, 7];
    file.extend(lz4(a));
    file.extend([0x5A, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    file.extend(lz4(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lz4], Container::Tar, tar.clone())
    );
    // xz streams, Stream Padding between and after them.
    let mut file = xz(a);
    file.extend([0; 8]);
    file.extend(xz(b));
    file.extend([0; 4]);
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Xz], Container::Tar, tar.clone())
    );
    // lzip members, and what follows them, which lzip and xz ignore.
    let mut file = lzip(a);
    file.extend(lzip(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lzip], Container::Tar, tar.clone())
    );
    file.extend(b"\0\0\0\0appended after the last member");
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lzip], Container::Tar, tar.clone())
    );
    // It is read to its end: a layer around it is checked to its end.
    let mut outer = gzip(&file);
    outer.truncate(outer.len() - 4);
    assert_eq!(failed_layer(open(&outer)), Layer::Gzip);
}

#[test]
fn other_data_after_the_streams_fails() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 6] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lz4, lz4),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Pbzx, pbzx_64k),
    ];
    for (layer, compress) in cases {
        let mut file = compress(&tar);
        file.extend(b"\0\0\0\0junk after the end");
        assert_eq!(failed_layer(open(&file)), layer);
    }
}

#[test]
fn a_stream_cut_short_fails() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 9] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lz4, lz4),
        (Layer::Lz4, lz4_legacy),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Lzma, lzma),
        (Layer::Pbzx, pbzx_64k),
    ];
    for (layer, compress) in cases {
        let file = compress(&tar);
        for cut in [1, 4, file.len() / 2] {
            let result = open_named(&file[..file.len() - cut], Some("x.lzma"));
            assert_eq!(failed_layer(result), layer, "{layer:?} without {cut} bytes");
        }
    }
    // Under another layer, the inner one fails.
    let inner = zstd(&tar);
    assert_eq!(
        failed_layer(open(&gzip(&inner[..inner.len() - 3]))),
        Layer::Zstd
    );
    // The outer one's error comes through LZ4's reader as it is.
    let outer = gzip(&lz4(&tar));
    assert_eq!(failed_layer(open(&outer[..outer.len() - 3])), Layer::Gzip);
}

#[test]
fn damaged_data_fails() {
    let tar = sample_tar();
    let mut file = bzip2(&tar);
    let middle = file.len() / 2;
    file[middle] ^= 0x55;
    assert_eq!(failed_layer(open(&file)), Layer::Bzip2);
    let mut file = gzip(&tar);
    let end = file.len() - 6;
    file[end] ^= 1;
    assert_eq!(failed_layer(open(&file)), Layer::Gzip);
}

/// The data and how reading ended, in pieces of `size`.
fn read_in(file: &[u8], name: &str, size: usize) -> (Vec<u8>, String) {
    let mut opener = Opener::new(|| Ok(Cursor::new(file))).name(name);
    let mut opened = match opener.open() {
        Ok(opened) => opened,
        Err(e) => return (Vec::new(), e.to_string()),
    };
    let mut data = Vec::new();
    let mut buf = vec![0; size];
    loop {
        match opened.read(&mut buf) {
            Ok(0) => return (data, "end".into()),
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => return (data, e.to_string()),
        }
    }
}

#[test]
fn what_comes_before_an_error_is_given_out() {
    // The bytes a decoder produced in the call that failed are read before
    // its error, so that what is read does not depend on the size of the
    // reads (the fuzz target found it with a .lzma file).
    let tar = sample_tar();
    let cases: [(Layer, Compress); 7] = [
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lzma, lzma),
        (Layer::Lz4, lz4),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Pbzx, pbzx_64k),
    ];
    for (layer, compress) in cases {
        let mut file = compress(&tar);
        let at = file.len() * 2 / 3;
        file[at] ^= 0x10;
        let small = read_in(&file, "x.lzma", 1);
        assert_ne!(small.1, "end", "{layer:?}");
        assert!(!small.0.is_empty(), "{layer:?}");
        assert_eq!(read_in(&file, "x.lzma", 64 << 10), small, "{layer:?}");
        assert_eq!(read_in(&file, "x.lzma", 1000), small, "{layer:?}");
    }
}

#[test]
fn small_reads() {
    let tar = sample_tar();
    let file = xz(&gzip(&bzip2(&tar)));
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let mut opened = opener.open().unwrap();
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while opened.read(&mut byte).unwrap() == 1 {
        data.push(byte[0]);
    }
    assert!(data == tar);
    // A read into nothing reads nothing.
    assert_eq!(opened.read(&mut []).unwrap(), 0);
}

/// A reader that gives a byte at a time, and is interrupted between.
struct Trickle<'a>(&'a [u8], bool);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.1 = !self.1;
        if self.1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let Some((&first, rest)) = self.0.split_first() else {
            return Ok(0);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = first;
        self.0 = rest;
        Ok(1)
    }
}

#[test]
fn input_a_byte_at_a_time() {
    let tar = sample_tar();
    for file in [
        zstd(&tar),
        xz(&tar),
        gzip(&bzip2(&tar)),
        lzip(&tar),
        lz4(&tar),
        lz4_legacy(&tar),
        pbzx_64k(&tar),
    ] {
        let mut opener = Opener::new(|| Ok(Trickle(&file, false)));
        let mut opened = opener.open().unwrap();
        let mut data = Vec::new();
        opened.read_to_end(&mut data).unwrap();
        assert!(data == tar);
    }
}

#[test]
fn layers_are_limited() {
    let tar = sample_tar();
    let mut file = tar.clone();
    for _ in 0..9 {
        file = gzip(&file);
    }
    assert!(matches!(open(&file), Err(Error::TooManyLayers(8))));
    let mut limits = Limits::default();
    limits.max_layers = 9;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    let mut data = Vec::new();
    opener.open().unwrap().read_to_end(&mut data).unwrap();
    assert!(data == tar);
}

#[test]
fn decoders_memory_is_limited() {
    let tar = sample_tar();
    // A 128 MiB window is allowed, and a larger one is not: libzstd's own
    // limit.
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
    encoder.window_log(28).unwrap();
    io::copy(&mut &tar[..], &mut encoder).unwrap();
    let file = encoder.finish().unwrap();
    assert_eq!(failed_layer(open(&file)), Layer::Zstd);
    let mut limits = Limits::default();
    limits.zstd_window_log_max = 28;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    let mut data = Vec::new();
    opener.open().unwrap().read_to_end(&mut data).unwrap();
    assert!(data == tar);
    // xz -9's 64 MiB dictionary, past a limit of 16 MiB.
    let file = xz_preset(&tar, 9);
    let mut limits = Limits::default();
    limits.xz_memlimit = 16 << 20;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    // Its first bytes are needed to tell what is under it.
    let result = opener
        .open()
        .map(|o| (o.layers().to_vec(), o.container(), vec![]));
    assert_eq!(failed_layer(result), Layer::Xz);
    assert!(open(&file).is_ok());
}

#[test]
fn an_error_stays() {
    let tar = sample_tar();
    // The first frame tells what is under it; the second is cut short.
    let (a, b) = tar.split_at(10_240);
    let mut file = zstd(a);
    let second = zstd(b);
    file.extend(&second[..second.len() / 2]);
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let mut opened = opener.open().unwrap();
    let mut data = Vec::new();
    let first = opened.read_to_end(&mut data).unwrap_err().to_string();
    let again = opened.read(&mut [0; 100]).unwrap_err().to_string();
    assert_eq!(first, again);
}

#[test]
fn a_file_that_changed_fails() {
    let tar = sample_tar();
    let files = [zstd(&tar), gzip(&tar)];
    let mut next = 0;
    let mut opener = Opener::new(|| {
        next += 1;
        Ok(Cursor::new(files[(next - 1).min(1)].clone()))
    });
    opener.open().unwrap();
    assert!(matches!(opener.open(), Err(Error::Changed)));
}

#[test]
fn opening_fails_as_the_file_does() {
    let mut opener =
        Opener::new(|| -> io::Result<Cursor<Vec<u8>>> { Err(io::ErrorKind::NotFound.into()) });
    match opener.open() {
        Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_tar_archive_under_layers_extracts() {
    let tar = sample_tar();
    let file = xz(&zstd(&tar));
    let scratch = Scratch::new();
    let path = scratch.path().join("backup.tar.zst.xz");
    std::fs::write(&path, &file).unwrap();
    let mut opener = Opener::new(|| std::fs::File::open(&path)).name("backup.tar.zst.xz");
    assert_eq!(opener.open().unwrap().container(), Container::Tar);
    let out = scratch.path().join("out");
    let summary = hivepack_extract::extract_tar(
        || Ok(opener.open()?),
        &out,
        &hivepack_extract::Options::default(),
    )
    .unwrap();
    assert_eq!(summary.files, 2);
    assert_eq!(
        std::fs::read(out.join("docs/notes.txt")).unwrap(),
        b"Hello from inside the layers.\n"
    );
    assert_eq!(
        std::fs::read(out.join("docs/data.bin")).unwrap().len(),
        100_000
    );
}

/// libarchive's Rock Ridge and Joliet image, xz-compressed in
/// `testdata`, extracted through its layer.
#[test]
fn an_iso_image_under_layers_extracts() {
    let path = support::repository()
        .join("testdata/libarchive-iso/test_read_format_iso_joliet_rockridge.iso.xz");
    let mut opener = Opener::new(|| std::fs::File::open(&path)).name("disc.iso.xz");
    assert_eq!(opener.open().unwrap().container(), Container::Iso);
    let scratch = Scratch::new();
    let out = scratch.path().join("out");
    let mut options = hivepack_extract::Options::default();
    options.links = hivepack_extract::Links::AsFile;
    let summary = hivepack_extract::extract_iso(|| Ok(opener.open()?), &out, &options).unwrap();
    assert_eq!((summary.files, summary.directories), (3, 1));
    // The hard link's file and its copy hold the same data, and the
    // symbolic link its target.
    let file = std::fs::read(out.join("long-joliet-file-name.textfile")).unwrap();
    assert_eq!(std::fs::read(out.join("hardlink")).unwrap(), file);
    assert_eq!(
        std::fs::read(out.join("symlink")).unwrap(),
        b"long-joliet-file-name.textfile"
    );
}

#[test]
fn a_damaged_stream_stops_before_anything_is_written() {
    // gzip's stored blocks hold the data as it is: only the CRC-32 at the
    // end tells a byte changed, after the tar archive's end, which
    // extract_tar reads before it writes.
    let tar = sample_tar();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    io::Write::write_all(&mut encoder, &tar).unwrap();
    let mut file = encoder.finish().unwrap();
    let at = file
        .windows(5)
        .position(|w| w == b"Hello")
        .expect("the data as it is");
    file[at] = b'J';
    let scratch = Scratch::new();
    let out = scratch.path().join("out");
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let e = hivepack_extract::extract_tar(
        || Ok(opener.open()?),
        &out,
        &hivepack_extract::Options::default(),
    )
    .unwrap_err();
    match e.kind {
        hivepack_extract::ErrorKind::Io(e) => {
            let inner = e.get_ref().unwrap().downcast_ref::<DecodeError>().unwrap();
            assert_eq!(inner.layer, Layer::Gzip);
            assert_eq!(inner.message, "incorrect data check");
        }
        other => panic!("{other:?}"),
    }
    assert!(!out.exists());
}
