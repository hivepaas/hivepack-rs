//! What NetBSD does where Linux is no oracle: errors, hidden entries,
//! broken directories, and damaged images, which must not panic or hang.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "udf_support/mod.rs"]
mod support;

use std::io::{Cursor, Read};

use hivepack::udf::{Errno, Error, Options, Udf, VType};
use support::image::{Entry, Kind, Layout, Map, Node, Volume, image};

fn file(data: &[u8]) -> Node {
    Node::new(Kind::File(data.to_vec(), Layout::Inline))
}

fn volume(bs: usize, map: Map) -> Volume {
    let many = (0..40)
        .map(|i| Entry::new(&format!("entry-{i:03}"), file(b"x")))
        .collect();
    let mut link = Vec::new();
    link.extend_from_slice(&[5, 2, 0, 0, 8, b'a']);
    Volume {
        bs,
        rev: 0x0250,
        map,
        root: Node::dir(vec![
            Entry::new("file", file(b"data")),
            Entry::new("big", Node::new(Kind::File(vec![7; 9000], Layout::Short))),
            Entry::new(
                "link",
                Node {
                    mode: 0o777,
                    ..Node::new(Kind::Symlink(link))
                },
            ),
            Entry {
                hidden: true,
                ..Entry::new("hidden", file(b"hidden"))
            },
            Entry::new("many", Node::dir(many)),
        ]),
        open: false,
        vat_outside: false,
    }
}

fn mount(img: Vec<u8>) -> Result<Udf<Cursor<Vec<u8>>>, Error> {
    Udf::open(Cursor::new(img))
}

fn errno<T>(r: Result<T, Error>) -> Errno {
    match r {
        Ok(_) => panic!("no error"),
        Err(e) => e.errno(),
    }
}

/// Recomputes the tag of the descriptor at byte `at`.
fn retag(img: &mut [u8], at: usize) {
    let crc_len = u16::from_le_bytes([img[at + 10], img[at + 11]]) as usize;
    let crc = support::image::crc(&img[at + 16..at + 16 + crc_len]);
    img[at + 8..at + 10].copy_from_slice(&crc.to_le_bytes());
    let mut sum: u8 = 0;
    for i in 0..16 {
        if i != 4 {
            sum = sum.wrapping_add(img[at + i]);
        }
    }
    img[at + 4] = sum;
}

/// The byte offsets of the descriptors with tag `id` at the start of a
/// sector.
fn tags(img: &[u8], bs: usize, id: u16) -> Vec<usize> {
    (0..img.len() / bs)
        .map(|s| s * bs)
        .filter(|&at| {
            let t = &img[at..at + 16];
            u16::from_le_bytes([t[0], t[1]]) == id
                && t[4]
                    == (0..16)
                        .filter(|&i| i != 4)
                        .fold(0u8, |a, i| a.wrapping_add(t[i]))
                && t.iter().any(|&b| b != 0)
        })
        .collect()
}

#[test]
fn mounts_every_map() {
    for map in [Map::Physical, Map::Metadata, Map::Virtual, Map::Sparable] {
        for bs in [512, 2048, 4096] {
            let mut udf =
                mount(image(&volume(bs, map))).unwrap_or_else(|e| panic!("{map:?} {bs}: {e}"));
            let v = udf.volume();
            assert_eq!(v.sector_size, bs as u32);
            assert_eq!(v.name, b"crafted");
            assert!(v.closed);
            let root = udf.root().clone();
            let names: Vec<_> = udf
                .read_dir(&root)
                .unwrap()
                .map(|e| e.unwrap().name)
                .collect();
            assert_eq!(
                names,
                [&b".."[..], b"file", b"big", b"link", b"many"],
                "{map:?} {bs}"
            );
        }
    }
}

#[test]
fn sector_size_given() {
    let img = image(&volume(2048, Map::Physical));
    let options = Options {
        sector_size: Some(512),
        ..Options::default()
    };
    assert_eq!(
        errno(Udf::with_options(Cursor::new(img.clone()), &options)),
        Errno::EINVAL
    );
    let options = Options {
        sector_size: Some(2048),
        ..Options::default()
    };
    assert!(Udf::with_options(Cursor::new(img.clone()), &options).is_ok());
    let options = Options {
        sector_size: Some(3000),
        ..Options::default()
    };
    assert_eq!(
        errno(Udf::with_options(Cursor::new(img), &options)),
        Errno::EIO
    );
}

#[test]
fn no_anchor() {
    let bs = 2048;
    let mut img = image(&volume(bs, Map::Physical));
    for at in tags(&img, bs, 2) {
        img[at..at + bs].fill(0);
    }
    match mount(img) {
        Err(Error::Udf {
            errno: Errno::EINVAL,
            what,
        }) => assert_eq!(what, "no anchor"),
        r => panic!("{r:?}"),
    }
    assert_eq!(errno(mount(vec![0; 1000])), Errno::EINVAL);
    assert_eq!(errno(mount(Vec::new())), Errno::EINVAL);
}

#[test]
fn open_integrity() {
    let img = image(&Volume {
        open: true,
        ..volume(2048, Map::Physical)
    });
    let udf = mount(img.clone()).unwrap();
    assert!(!udf.volume().closed);
    let strict = Options {
        strict: true,
        ..Options::default()
    };
    assert_eq!(
        errno(Udf::with_options(Cursor::new(img), &strict)),
        Errno::EPERM
    );
    // A VAT closes it.
    let udf = mount(image(&Volume {
        open: true,
        ..volume(2048, Map::Virtual)
    }))
    .unwrap();
    assert!(udf.volume().closed);
}

#[test]
fn not_osta_compliant() {
    let bs = 2048;
    let mut img = image(&volume(bs, Map::Physical));
    for at in tags(&img, bs, 6) {
        img[at + 217] = b'#';
        retag(&mut img, at);
    }
    match mount(img) {
        Err(Error::Udf {
            errno: Errno::EINVAL,
            what,
        }) => assert_eq!(what, "disc not OSTA UDF Compliant"),
        r => panic!("{r:?}"),
    }
}

#[test]
fn reserve_vds() {
    // The main sequence's first descriptor broken: the reserve is read.
    let bs = 2048;
    let mut img = image(&volume(bs, Map::Physical));
    let first = tags(&img, bs, 1)[0];
    img[first + 4] ^= 1;
    assert!(mount(img).is_ok());
}

#[test]
fn unsupported_strategy() {
    // A root of strategy 1, where NetBSD reads the same block for good.
    let bs = 2048;
    let mut img = image(&volume(bs, Map::Physical));
    let fsd = tags(&img, bs, 256)[0];
    let root_lb = u32::from_le_bytes(img[fsd + 404..fsd + 408].try_into().unwrap());
    let root = tags(&img, bs, 261)
        .into_iter()
        .chain(tags(&img, bs, 266))
        .find(|&at| u32::from_le_bytes(img[at + 12..at + 16].try_into().unwrap()) == root_lb)
        .unwrap();
    img[root + 20] = 1;
    retag(&mut img, root);
    match mount(img) {
        Err(Error::Udf {
            errno: Errno::ENOENT,
            what,
        }) => assert_eq!(what, "rootdirs failing"),
        r => panic!("{r:?}"),
    }
}

#[test]
fn kinds() {
    let mut udf = mount(image(&volume(2048, Map::Physical))).unwrap();
    let root = udf.root().clone();
    let file = udf.lookup(&root, b"file").unwrap().unwrap();
    let link = udf.lookup(&root, b"link").unwrap().unwrap();
    assert_eq!(file.kind(), VType::VREG);
    assert_eq!(link.kind(), VType::VLNK);
    assert_eq!(errno(udf.read_dir(&file)), Errno::ENOTDIR);
    let mut buf = [0; 16];
    assert_eq!(errno(udf.read_at(&root, 0, &mut buf)), Errno::EISDIR);
    assert_eq!(errno(udf.read_at(&link, 0, &mut buf)), Errno::EINVAL);
    assert_eq!(udf.read_at(&file, 0, &mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"data");
    assert_eq!(udf.read_at(&file, 2, &mut buf).unwrap(), 2);
    assert_eq!(udf.read_at(&file, 4, &mut buf).unwrap(), 0);
    assert_eq!(udf.read_at(&file, 1 << 40, &mut buf).unwrap(), 0);
    assert_eq!(udf.read_link(&link).unwrap(), b"a");
    assert_eq!(udf.stat(&link).size, 1);
    let big = udf.lookup(&root, b"big").unwrap().unwrap();
    let mut data = vec![0; 10000];
    assert_eq!(udf.read_at(&big, 100, &mut data).unwrap(), 8900);
    assert!(data[..8900].iter().all(|&b| b == 7));
    assert!(udf.lookup(&root, b"missing").unwrap().is_none());
    assert!(udf.lookup(&root, b"..").unwrap().is_some());
}

#[test]
fn hidden_entries() {
    let img = image(&volume(2048, Map::Physical));
    let mut udf = mount(img.clone()).unwrap();
    let root = udf.root().clone();
    let listed: Vec<_> = udf.read_dir(&root).unwrap().map(|e| e.unwrap()).collect();
    assert!(listed.iter().all(|e| !e.is_hidden()));
    assert!(udf.lookup(&root, b"hidden").unwrap().is_some());
    let unhide = Options {
        unhide: true,
        ..Options::default()
    };
    let mut udf = Udf::with_options(Cursor::new(img), &unhide).unwrap();
    let root = udf.root().clone();
    let hidden: Vec<_> = udf
        .read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.is_hidden())
        .collect();
    assert_eq!(hidden.len(), 1);
    assert_eq!(hidden[0].name, b"hidden");
}

#[test]
fn broken_directory() {
    // The FID of entry-020 broken: the entries before it, then EIO.
    let bs = 2048;
    let mut img = image(&volume(bs, Map::Physical));
    let name = b"\x08entry-020";
    let at = img.windows(name.len()).position(|w| w == name).unwrap() - 38;
    assert_eq!(&img[at..at + 2], &[1, 1]);
    img[at + 4] ^= 0x55;
    let mut udf = mount(img).unwrap();
    let root = udf.root().clone();
    let many = udf.lookup(&root, b"many").unwrap().unwrap();
    let entries: Vec<_> = udf.read_dir(&many).unwrap().collect();
    assert_eq!(entries.len(), 22);
    assert!(entries[..21].iter().all(Result::is_ok));
    assert_eq!(errno(entries.into_iter().nth(21).unwrap()), Errno::EIO);
    // Looking up reads the whole directory.
    assert_eq!(errno(udf.lookup(&many, b"entry-001")), Errno::EIO);
}

/// Walks the volume, reading everything, up to a bound.
fn walk(udf: &mut Udf<Cursor<Vec<u8>>>) {
    let mut dirs = vec![udf.root().clone()];
    let mut seen = 0;
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = udf.read_dir(&dir) else {
            continue;
        };
        let entries: Vec<_> = entries.filter_map(Result::ok).collect();
        for entry in entries {
            seen += 1;
            if entry.is_parent() || seen > 2000 {
                continue;
            }
            let Ok(node) = udf.node(entry.icb) else {
                continue;
            };
            let _ = udf.stat(&node);
            let _ = udf.lookup(&dir, &entry.name);
            match node.kind() {
                VType::VDIR => dirs.push(node),
                VType::VLNK => drop(udf.read_link(&node)),
                VType::VREG => {
                    let mut buf = vec![0; 1 << 16];
                    let _ = udf.read_at(&node, 0, &mut buf);
                }
                _ => {}
            }
        }
    }
}

#[test]
fn damaged_images() {
    let mut seed: u64 = 0x5eed;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    for (map, bs) in [
        (Map::Physical, 512),
        (Map::Metadata, 512),
        (Map::Virtual, 2048),
        (Map::Sparable, 2048),
    ] {
        let clean = image(&volume(bs, map));
        // The sectors that hold descriptors.
        let sectors: Vec<usize> = (0..clean.len() / bs)
            .filter(|&s| clean[s * bs..s * bs + 16].iter().any(|&b| b != 0))
            .collect();
        for _ in 0..150 {
            let mut img = clean.clone();
            for _ in 0..1 + next() % 4 {
                let s = sectors[next() % sectors.len()];
                let at = s * bs + next() % 64.min(bs);
                img[at] = next() as u8;
                if next() % 2 == 0 {
                    // Keep its tag good, to get past it.
                    let crc_len = u16::from_le_bytes([img[s * bs + 10], img[s * bs + 11]]) as usize;
                    if 16 + crc_len <= bs {
                        retag(&mut img, s * bs);
                    }
                }
            }
            if let Ok(mut udf) = mount(img) {
                walk(&mut udf);
            }
        }
    }
}

#[test]
fn check_data_as_reading() {
    // Cut short anywhere past the anchor: check_data fails where reading
    // fails.
    let bs = 2048;
    let full = image(&volume(bs, Map::Physical));
    let (mut ok, mut failed) = (0, 0);
    for cut in 257..full.len() / bs {
        let Ok(mut udf) = mount(full[..cut * bs].to_vec()) else {
            continue;
        };
        let root = udf.root().clone();
        let mut dirs = vec![root];
        while let Some(dir) = dirs.pop() {
            let entries: Vec<_> = udf.read_dir(&dir).unwrap().filter_map(Result::ok).collect();
            for entry in entries.iter().filter(|e| !e.is_parent()) {
                // A node past the cut does not read.
                let Ok(node) = udf.node(entry.icb) else {
                    continue;
                };
                match node.kind() {
                    VType::VDIR => dirs.push(node),
                    VType::VREG => {
                        let mut data = Vec::new();
                        let read = udf.file(&node).read_to_end(&mut data).is_ok();
                        assert_eq!(udf.check_data(&node).is_ok(), read, "{:?}", entry.name);
                        if read { ok += 1 } else { failed += 1 }
                    }
                    _ => assert!(udf.check_data(&node).is_err()),
                }
            }
        }
        assert_eq!(errno(udf.check_data(&udf.root().clone())), Errno::EISDIR);
    }
    assert!(ok > 0 && failed > 0, "{ok} {failed}");
}
