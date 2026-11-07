//! Sparse files written in PAX's GNU sparse format 1.0 (`Writer::write_sparse_header`):
//! read back by this crate's reader with their holes, and by GNU tar where it is
//! installed, which restores them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::process::Command;

use hivepack::tar::{Error, Format, Header, Reader, TYPE_DIR, TYPE_REG, Writer};

/// A file of `size` bytes whose `data` parts hold their offset's low byte plus
/// one, and zeros elsewhere: the whole of it, and the bytes of the parts.
fn sparse_file(size: i64, data: &[(i64, i64)]) -> (Vec<u8>, Vec<u8>) {
    let mut whole = vec![0u8; size as usize];
    let mut parts = Vec::new();
    for &(offset, length) in data {
        for at in offset..offset + length {
            let byte = (at as u8).wrapping_add(1).max(1);
            whole[at as usize] = byte;
            parts.push(byte);
        }
    }
    (whole, parts)
}

/// A tar archive of a folder, the sparse file `name` in it, and a file after.
fn archive(name: &str, size: i64, data: &[(i64, i64)]) -> Vec<u8> {
    let (_, parts) = sparse_file(size, data);
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        typeflag: TYPE_DIR,
        name: b"d/".to_vec(),
        mode: 0o755,
        ..Header::default()
    })
    .unwrap();
    tw.write_sparse_header(
        &Header {
            typeflag: TYPE_REG,
            name: name.as_bytes().to_vec(),
            size,
            mode: 0o644,
            ..Header::default()
        },
        data,
    )
    .unwrap();
    tw.write_all(&parts).unwrap();
    tw.write_header(&Header {
        typeflag: TYPE_REG,
        name: b"d/after".to_vec(),
        size: 5,
        mode: 0o644,
        ..Header::default()
    })
    .unwrap();
    tw.write_all(b"after").unwrap();
    tw.close().unwrap();
    tw.into_inner()
}

const MAPS: [&[(i64, i64)]; 5] = [
    // A hole, data, a hole, data, a hole at the end.
    &[(4096, 512), (1 << 20, 5120)],
    // Data at the start, and at the end, not a whole block.
    &[(0, 1024), ((3 << 20) - 512, 500)],
    // All holes.
    &[],
    // All data.
    &[(0, 70_000)],
    // Many small parts, over a block of map.
    &[
        (0, 512),
        (1024, 512),
        (2048, 512),
        (4096, 512),
        (8192, 512),
        (16384, 512),
        (32768, 512),
        (65536, 512),
        (131_072, 512),
        (262_144, 512),
        (524_288, 512),
        (1_048_576, 512),
        (2_097_152, 512),
        (3_000_320, 512),
        (3_001_344, 512),
        (3_002_368, 512),
        (3_003_392, 512),
        (3_004_416, 512),
        (3_005_440, 512),
        (3_006_464, 512),
        (3_007_488, 512),
        (3_008_512, 512),
        (3_009_536, 512),
        (3_010_560, 512),
        (3_011_584, 512),
        (3_012_608, 512),
        (3_013_632, 512),
        (3_014_656, 512),
        (3_015_680, 512),
        (3_016_704, 512),
        (3_017_728, 512),
        (3_018_752, 512),
        (3_019_776, 512),
        (3_020_800, 512),
        (3_021_824, 512),
        (3_022_848, 512),
        (3_023_872, 512),
        (3_024_896, 512),
        (3_025_920, 512),
        (3_026_944, 512),
        (3_027_968, 512),
        (3_028_992, 512),
        (3_030_016, 512),
        (3_031_040, 512),
    ],
];

fn size_for(data: &[(i64, i64)]) -> i64 {
    data.last().map_or(1 << 20, |&(o, l)| o + l + 4096)
}

#[test]
fn the_reader_takes_back_the_name_size_and_holes() {
    for (i, data) in MAPS.iter().enumerate() {
        let size = if i == 1 {
            (3 << 20) - 12
        } else if i == 3 {
            70_000
        } else {
            size_for(data)
        };
        let name = "d/disk image é.raw";
        let bytes = archive(name, size, data);
        let (whole, parts) = sparse_file(size, data);
        assert!(
            bytes.len() < parts.len() + 8 * 512 + 4096,
            "map {i}: holes stored"
        );
        let mut tr = Reader::new(bytes.as_slice());
        assert_eq!(tr.next().unwrap().unwrap().name, b"d/");
        let h = tr.next().unwrap().unwrap();
        assert_eq!(
            (h.name.as_slice(), h.size),
            (name.as_bytes(), size),
            "map {i}"
        );
        assert!(h.format.has(Format::PAX));
        assert!(tr.is_sparse(), "map {i}");
        let mut read = Vec::new();
        tr.read_to_end(&mut read).unwrap();
        assert!(read == whole, "map {i}: the data and its holes");
        let after = tr.next().unwrap().unwrap();
        assert_eq!(after.name, b"d/after");
        let mut read = Vec::new();
        tr.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"after");
        assert!(tr.next().unwrap().is_none());
    }
}

#[test]
fn a_map_out_of_order_or_past_the_size_is_refused() {
    let bad: [&[(i64, i64)]; 6] = [
        &[(1024, 512), (512, 512)],
        &[(0, 1024), (512, 512)],
        &[(0, 2048)],
        &[(-512, 512)],
        // Not on blocks, as GNU tar reads them.
        &[(100, 512)],
        &[(0, 100)],
    ];
    for data in bad {
        let mut tw = Writer::new(Vec::new());
        let header = Header {
            typeflag: TYPE_REG,
            name: b"f".to_vec(),
            size: 1000,
            ..Header::default()
        };
        assert!(
            matches!(
                tw.write_sparse_header(&header, data),
                Err(Error::CannotEncode(_))
            ),
            "{data:?}"
        );
    }
    let mut tw = Writer::new(Vec::new());
    let folder = Header {
        typeflag: TYPE_DIR,
        name: b"d/".to_vec(),
        ..Header::default()
    };
    assert!(tw.write_sparse_header(&folder, &[]).is_err());
}

#[test]
fn more_than_the_parts_is_not_written() {
    let mut tw = Writer::new(Vec::new());
    let header = Header {
        typeflag: TYPE_REG,
        name: b"f".to_vec(),
        size: 1000,
        ..Header::default()
    };
    tw.write_sparse_header(&header, &[(1000, 0)]).unwrap();
    assert!(tw.write_all(b"1").is_err());
    let mut tw = Writer::new(Vec::new());
    tw.write_sparse_header(&header, &[(0, 512)]).unwrap();
    tw.write_all(&[1; 512]).unwrap();
    assert!(tw.write_all(b"12345").is_err());
}

/// GNU tar restores the file, its holes as holes where the file system has them.
#[cfg(target_os = "linux")]
#[test]
fn gnu_tar_restores_the_holes() {
    let Ok(out) = Command::new("tar").arg("--version").output() else {
        eprintln!("skipping: no tar");
        return;
    };
    if !String::from_utf8_lossy(&out.stdout).contains("GNU tar") {
        eprintln!("skipping: tar is not GNU tar");
        return;
    }
    let dir = std::env::temp_dir().join(format!("hivepack-sparse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data: &[(i64, i64)] = &[(4096, 512), (8 << 20, 5120), ((16 << 20) + 4096, 100)];
    let size = (16 << 20) + 4196;
    let path = dir.join("a.tar");
    std::fs::write(&path, archive("d/image.raw", size, data)).unwrap();
    let out = Command::new("tar")
        .args(["-xf", "a.tar"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (whole, _) = sparse_file(size, data);
    let file = dir.join("d/image.raw");
    assert!(std::fs::read(&file).unwrap() == whole);
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.len(), size as u64);
    // Allocated: far less than its size, on a file system with holes.
    assert!(meta.blocks() * 512 < 1 << 20, "{} blocks", meta.blocks());
    std::fs::remove_dir_all(&dir).unwrap();
}
