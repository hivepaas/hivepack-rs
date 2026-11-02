//! The port against Linux on the images tests/support/image.rs writes, of
//! what mkudffs and Linux do not record (metadata partitions with files,
//! files on a VAT, a remapped packet, allocation extents, strategy 4096,
//! hidden and deleted entries, names and links of every kind):
//! testdata/udf/crafted holds what Linux reads of each, which
//! tools/udf-images/crafted.sh records from the images
//! `write_crafted_images` writes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "udf_support/mod.rs"]
mod support;

use std::fs;

use support::image::{Entry, Kind, Layout, Map, Name, Node, Volume, image};
use support::{hex, linux_options, repository, transcript};

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u32 * 7 + u32::from(seed)) as u8 % 251)
        .collect()
}

fn file(data: Vec<u8>, layout: Layout) -> Node {
    Node::new(Kind::File(data, layout))
}

fn symlink(comps: &[(u8, &[u8])]) -> Node {
    let mut b = Vec::new();
    for (kind, ident) in comps {
        b.extend_from_slice(&[*kind, ident.len() as u8, 0, 0]);
        b.extend_from_slice(ident);
    }
    Node {
        mode: 0o777,
        ..Node::new(Kind::Symlink(b))
    }
}

/// A name in CS0 with 8 bits per character.
fn name8(s: &str) -> Vec<u8> {
    let mut b = vec![8];
    b.extend_from_slice(s.as_bytes());
    b
}

/// The tree most volumes hold: `bs` is their block size.
fn tree(bs: usize, efe: bool) -> Node {
    let mut entries = vec![
        Entry::new("inline", file(b"in the node\n".to_vec(), Layout::Inline)),
        Entry::new("short", file(pattern(10000, 1), Layout::Short)),
        Entry::new("long", file(pattern(10000, 2), Layout::Long)),
        Entry::new(
            "fragmented",
            file(pattern(60 * bs - 7, 3), Layout::Fragmented),
        ),
        Entry::new("sparse", file(pattern(12 * bs + 5, 4), Layout::Sparse)),
        Entry::new("empty", file(Vec::new(), Layout::Short)),
        Entry::new("rel", symlink(&[(5, &name8("a")), (5, &name8("b"))])),
        Entry::new(
            "abs",
            symlink(&[(1, b""), (5, &name8("etc")), (5, &name8("passwd"))]),
        ),
        Entry::new("dots", symlink(&[(4, b""), (3, b""), (5, &name8("x"))])),
        Entry::new("wide-link", symlink(&[(5, &[16, 0x4e, 0x2d, 0x65, 0x87])])),
        Entry::new("fifo", Node::new(Kind::Fifo)),
        Entry::new("socket", Node::new(Kind::Socket)),
        Entry::new("char", Node::new(Kind::CharDevice(1, 3))),
        Entry {
            hidden: true,
            ..Entry::new("hidden-file", file(b"hidden".to_vec(), Layout::Inline))
        },
        Entry {
            deleted: true,
            ..Entry::new("deleted-file", file(b"gone".to_vec(), Layout::Inline))
        },
        Entry::new("café", file(b"latin-1".to_vec(), Layout::Inline)),
        Entry {
            name: Name::Wide("日本語.txt".to_string()),
            ..Entry::new("", file(b"wide".to_vec(), Layout::Inline))
        },
        Entry {
            name: Name::Wide("😀".to_string()),
            ..Entry::new("", file(b"emoji".to_vec(), Layout::Inline))
        },
        Entry {
            node: Node {
                fid_impl_use: vec![1, 2, 3, 4, 5, 6, 7, 8],
                ..file(b"impl use".to_vec(), Layout::Inline)
            },
            ..Entry::new("with-impl-use", file(Vec::new(), Layout::Inline))
        },
        Entry {
            node: Node {
                strategy4096: true,
                ..file(pattern(3000, 5), Layout::Short)
            },
            ..Entry::new("strategy4096", file(Vec::new(), Layout::Inline))
        },
        Entry::new(
            "setuid",
            Node {
                mode: 0o4755,
                uid: 1000,
                gid: 100,
                ..file(b"#!/bin/sh\n".to_vec(), Layout::Inline)
            },
        ),
        Entry::new(
            "nobody",
            Node {
                uid: u32::MAX,
                gid: u32::MAX,
                ..file(b"anon".to_vec(), Layout::Inline)
            },
        ),
        Entry::new(
            "old",
            Node {
                mtime: (-14_182_940, 123_456),
                atime: (0, 1),
                attrtime: (4_102_444_799, 999_999),
                ..file(b"1969".to_vec(), Layout::Inline)
            },
        ),
        Entry::new(
            "dir",
            Node::dir(vec![
                Entry::new(
                    "sub",
                    Node::dir(vec![Entry::new(
                        "deep",
                        file(pattern(333, 6), Layout::Short),
                    )]),
                ),
                Entry::new(
                    "sticky",
                    Node {
                        mode: 0o1777,
                        ..Node::dir(Vec::new())
                    },
                ),
                Entry::new(
                    "chain",
                    Node {
                        strategy4096: true,
                        ..Node::dir(vec![Entry::new(
                            "in-chain",
                            file(b"x".to_vec(), Layout::Inline),
                        )])
                    },
                ),
            ]),
        ),
        Entry::new(
            "many",
            Node::dir(
                (0..120)
                    .map(|i| {
                        Entry::new(
                            &format!("entry-{i:03}"),
                            file(format!("{i}\n").into_bytes(), Layout::Inline),
                        )
                    })
                    .collect(),
            ),
        ),
    ];
    if efe {
        for entry in &mut entries {
            set_efe(&mut entry.node);
        }
    }
    let mut root = Node::dir(entries);
    if efe {
        set_efe(&mut root);
    }
    root
}

fn set_efe(node: &mut Node) {
    node.efe = true;
    if let Kind::Dir(entries) = &mut node.kind {
        for entry in entries {
            set_efe(&mut entry.node);
        }
    }
}

/// The crafted volumes, by name.
fn volumes() -> Vec<(&'static str, Volume)> {
    let volume = |bs, rev, map, efe| Volume {
        bs,
        rev,
        map,
        root: tree(bs, efe),
        open: false,
        vat_outside: false,
    };
    vec![
        (
            "physical-0150-fe",
            volume(2048, 0x0150, Map::Physical, false),
        ),
        (
            "physical-0201-efe-bs4096",
            volume(4096, 0x0201, Map::Physical, true),
        ),
        (
            "physical-0201-bs512",
            volume(512, 0x0201, Map::Physical, true),
        ),
        (
            "physical-0201-open",
            Volume {
                open: true,
                ..volume(2048, 0x0201, Map::Physical, true)
            },
        ),
        ("metadata-0250", volume(2048, 0x0250, Map::Metadata, true)),
        (
            "metadata-0260-bs512",
            volume(512, 0x0260, Map::Metadata, true),
        ),
        ("vat-0201", volume(2048, 0x0201, Map::Virtual, false)),
        (
            "vat-0250-outside",
            Volume {
                vat_outside: true,
                ..volume(2048, 0x0250, Map::Virtual, true)
            },
        ),
        ("sparable-0201", volume(2048, 0x0201, Map::Sparable, true)),
    ]
}

fn sha256(data: &[u8]) -> String {
    let mut h = hivepack::crypto::Sha256::new();
    h.update(data);
    hex(&h.out())
}

/// Writes the images to `$UDF_CRAFTED`, for tools/udf-images/crafted.sh.
#[test]
#[ignore]
fn write_crafted_images() {
    let out = std::env::var("UDF_CRAFTED").expect("UDF_CRAFTED: where to write the images");
    fs::create_dir_all(&out).unwrap();
    for (name, volume) in volumes() {
        fs::write(format!("{out}/{name}.udf"), image(&volume)).unwrap();
    }
}

/// Where NetBSD reads otherwise than Linux: (image, path, field, NetBSD's
/// value). Linux drops the `/` a link's target ends with; NetBSD keeps
/// it.
const DIFFERENCES: &[(&str, &str, usize, &str)] = &[];

#[test]
fn reads_what_linux_reads() {
    let dir = repository().join("testdata/udf/crafted");
    let mut failures = Vec::new();
    for (name, volume) in volumes() {
        let image = image(&volume);
        let Ok(linux) = fs::read_to_string(dir.join(format!("{name}.txt"))) else {
            failures.push(format!(
                "{name}: no answer; run tools/udf-images/crafted.sh"
            ));
            continue;
        };
        let mut lines = linux.lines();
        let head = lines.next().unwrap_or_default();
        if head != format!("# sha256 {}", sha256(&image)) {
            failures.push(format!(
                "{name}: the image changed; run tools/udf-images/crafted.sh"
            ));
            continue;
        }
        let mut expected: Vec<String> = lines.map(str::to_string).collect();
        for &(image_name, path, field, value) in DIFFERENCES {
            if image_name != name {
                continue;
            }
            let path = if path == "." {
                ".".to_string()
            } else {
                hex(path.as_bytes())
            };
            for line in &mut expected {
                let mut fields: Vec<String> = line.split('\t').map(str::to_string).collect();
                if fields[0] == path {
                    fields[field] = value.to_string();
                    *line = fields.join("\t");
                }
            }
        }
        let expected: String = expected.iter().map(|l| format!("{l}\n")).collect();
        match transcript(image, &linux_options()) {
            Ok(got) if got == expected => {}
            Ok(got) => {
                let diff: Vec<_> = expected
                    .lines()
                    .zip(got.lines())
                    .filter(|(a, b)| a != b)
                    .take(8)
                    .map(|(a, b)| format!("  linux {a}\n  port  {b}"))
                    .collect();
                failures.push(format!(
                    "{name}: {} lines, {} expected\n{}",
                    got.lines().count(),
                    expected.lines().count(),
                    diff.join("\n")
                ));
            }
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
