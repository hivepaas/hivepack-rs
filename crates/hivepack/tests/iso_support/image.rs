//! ISO 9660 images made here, with what libarchive's writer does not make:
//! every kind of Rock Ridge entry (names and links in pieces, devices,
//! 17-byte times), continuation areas, directories moved to `rr_moved`
//! with their CL and RE entries, files in several extents and out of
//! order, zisofs files, and Joliet names that are not UTF-16.

use super::Rng;
use hivepack::deflate::{Deflate, Flush, InBuffer, OutBuffer, Status};

const BLOCK: usize = 2048;

/// A file's content: plain, in several extents, or zisofs.
#[derive(Clone)]
enum Content {
    Plain(Vec<u8>),
    Extents(Vec<Vec<u8>>),
    Zisofs {
        data: Vec<u8>,
        log2: u8,
        packed: Vec<u8>,
    },
}

#[derive(Clone)]
enum Kind {
    Dir(Vec<usize>),
    File(Content),
    Symlink(Vec<Vec<u8>>),
    Device(u32, u32),
    /// A hard link to another node: the same extent and serial number.
    Link(usize),
}

#[derive(Clone)]
struct Node {
    name: Vec<u8>,
    /// The Joliet name, UTF-16BE, which may be broken on purpose.
    joliet: Vec<u8>,
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    ino: u32,
    /// Relocated to rr_moved, with a CL entry where it was.
    moved: bool,
    /// The extents of the node's data, and of its Joliet directory.
    extent: u32,
    size: u32,
    joliet_extent: u32,
    joliet_size: u32,
}

fn both32(v: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&v.to_le_bytes());
    b[4..].copy_from_slice(&v.to_be_bytes());
    b
}

fn both16(v: u16) -> [u8; 4] {
    let mut b = [0; 4];
    b[..2].copy_from_slice(&v.to_le_bytes());
    b[2..].copy_from_slice(&v.to_be_bytes());
    b
}

fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// A zlib stream of `data`.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut deflate = Deflate::new_default(6).unwrap();
    let mut out = vec![0; data.len() + data.len() / 8 + 64];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(data);
    let status = deflate
        .deflate(&mut output, &mut input, Flush::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = output.pos;
    out.truncate(n);
    out
}

/// A zisofs file's data: blocks of a pattern, of zeros, or of random
/// bytes that do not compress.
fn zisofs_data(rng: &mut Rng, log2: u8, salt: usize) -> Vec<u8> {
    let block = 1usize << log2;
    let len = match rng.below(5) {
        0 => rng.below(100) as usize,
        1 => block * (1 + rng.below(3) as usize),
        _ => rng.below(5 * block as u64) as usize,
    };
    let mut data = vec![0u8; len];
    for (b, chunk) in data.chunks_mut(block).enumerate() {
        match rng.below(4) {
            0 => {}
            1 => chunk.iter_mut().for_each(|x| *x = rng.next() as u8),
            _ => {
                for (k, x) in chunk.iter_mut().enumerate() {
                    *x = (k * 7 + b + salt) as u8;
                }
            }
        }
    }
    data
}

/// A file compressed with zisofs: the header, block pointers, and each
/// block as a zlib stream (none for a block of zeros). Some are spoiled.
fn zisofs(rng: &mut Rng, data: &[u8], log2: u8) -> Vec<u8> {
    let block = 1usize << log2;
    let blocks = data.len().div_ceil(block);
    let mut out = vec![0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&[4, log2, 0, 0]);
    let pointers_at = out.len();
    out.resize(pointers_at + (blocks + 1) * 4, 0);
    let mut offsets = vec![out.len() as u32];
    for chunk in data.chunks(block) {
        if !chunk.iter().all(|&b| b == 0) || rng.below(3) == 0 {
            let mut z = zlib(chunk);
            match rng.below(30) {
                // Bytes after the zlib stream, which libarchive never gets
                // past.
                0 => z.extend_from_slice(&[1, 2, 3]),
                // A stream that needs a dictionary.
                1 => z = vec![0x78, 0xbb, 0, 0, 0, 1, 3, 0],
                // Cut short.
                2 => z.truncate(z.len() / 2),
                _ => {}
            }
            out.extend_from_slice(&z);
        }
        offsets.push(out.len() as u32);
    }
    for (i, off) in offsets.iter().enumerate() {
        let at = pointers_at + 4 * i;
        out[at..at + 4].copy_from_slice(&off.to_le_bytes());
    }
    // Spoiled: the header, a pointer, or the end.
    match rng.below(12) {
        0 => {
            let i = rng.below(16) as usize;
            out[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = pointers_at + 4 * rng.below(blocks as u64 + 1) as usize;
            let any = rng.next() as u32;
            let v = rng.pick(&[0u32, 1, out.len() as u32, u32::MAX, any]);
            out[i..i + 4].copy_from_slice(&v.to_le_bytes());
        }
        2 => {
            let n = rng.below(out.len() as u64 + 1) as usize;
            out.truncate(n);
        }
        _ => {}
    }
    out
}

/// A name of ISO 9660 characters, sometimes with what they do not allow.
fn iso_name(rng: &mut Rng, i: usize) -> Vec<u8> {
    let mut name = format!("F{i}").into_bytes();
    for _ in 0..rng.below(8) {
        name.push(rng.pick(b"ABCXYZ0129_"));
    }
    match rng.below(10) {
        0 => name.extend_from_slice(b".TXT;1"),
        1 => name.push(b'.'),
        2 => name.extend_from_slice(b";1"),
        3 => name.push(0),
        _ => {}
    }
    name
}

/// A Rock Ridge name: anything but "/" and NUL, sometimes long.
fn rr_name(rng: &mut Rng, i: usize) -> Vec<u8> {
    let mut name = format!("n{i}-").into_bytes();
    let len = if rng.below(5) == 0 {
        100 + rng.below(200)
    } else {
        rng.below(20)
    };
    for _ in 0..len {
        name.push(rng.pick(b"abc XYZ.-_~\xc3\xa9\xe4\xb8\xad"));
    }
    if rng.below(30) == 0 {
        name = b"rr_moved".to_vec();
    }
    name
}

/// A Joliet name, which may be broken.
fn joliet_name(rng: &mut Rng, i: usize) -> Vec<u8> {
    let mut name = utf16be(&format!("j{i}"));
    let most = if rng.below(6) == 0 { 120 } else { 10 };
    for _ in 0..rng.below(most) {
        let unit: u16 = rng.pick(&[0x61, 0xe9, 0x4e2d, 0x20, 0x2e]);
        name.extend_from_slice(&unit.to_be_bytes());
    }
    match rng.below(12) {
        0 => name.extend_from_slice(&[0xd8, 0x3d, 0xde, 0x00]),
        1 => name.extend_from_slice(&[0xd8, 0x00]),
        2 => name.extend_from_slice(&[0xdc, 0x00, 0x00, 0x61]),
        3 => name.extend_from_slice(&[0, b';', 0, b'1']),
        4 => name.extend_from_slice(&[0, 0, 0, 0x62]),
        5 => name.push(0x41),
        _ => {}
    }
    name
}

/// A SUSP entry.
fn entry(name: &[u8; 2], version: u8, data: &[u8]) -> Vec<u8> {
    let mut e = vec![name[0], name[1], (4 + data.len()) as u8, version];
    e.extend_from_slice(data);
    e
}

/// A 7-byte date, sometimes out of range.
fn date7(rng: &mut Rng) -> [u8; 7] {
    if rng.below(12) == 0 {
        return [0; 7];
    }
    let mut d = [
        rng.below(256) as u8,
        1 + rng.below(12) as u8,
        1 + rng.below(31) as u8,
        rng.below(24) as u8,
        rng.below(60) as u8,
        rng.below(62) as u8,
        (rng.below(101) as i8 - 48) as u8,
    ];
    if rng.below(15) == 0 {
        let i = rng.below(7) as usize;
        d[i] = rng.next() as u8;
    }
    d
}

/// A 17-byte date, sometimes out of range.
fn date17(rng: &mut Rng) -> [u8; 17] {
    let mut d = [0u8; 17];
    if rng.below(12) == 0 {
        d[..16].fill(b'0');
        return d;
    }
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}{:02}",
        1880 + rng.below(440),
        1 + rng.below(12),
        1 + rng.below(31),
        rng.below(24),
        rng.below(60),
        rng.below(62),
        rng.below(100)
    );
    d[..16].copy_from_slice(text.as_bytes());
    d[16] = (rng.below(101) as i8 - 48) as u8;
    if rng.below(15) == 0 {
        let i = rng.below(17) as usize;
        d[i] = rng.next() as u8;
    }
    d
}

/// Rock Ridge's entries for a node; `moved` adds RE.
fn rock_ridge(rng: &mut Rng, nodes: &[Node], n: usize, re: bool, cl: Option<u32>) -> Vec<Vec<u8>> {
    let node = &nodes[n];
    let mut out = Vec::new();
    let mut px = Vec::new();
    for v in [node.mode, 1 + rng.below(3) as u32, node.uid, node.gid] {
        px.extend_from_slice(&both32(v));
    }
    if rng.below(4) != 0 {
        px.extend_from_slice(&both32(node.ino));
    }
    let px_len = if rng.below(10) == 0 {
        (8 * rng.below(6) as usize).min(px.len())
    } else {
        px.len()
    };
    out.push(entry(b"PX", 1, &px[..px_len]));

    // The name, in one or more NM entries.
    let mut name: &[u8] = &node.name;
    if rng.below(15) == 0 {
        out.push(entry(b"NM", 1, &[rng.pick(&[2u8, 4, 32, 8])]));
    }
    while !name.is_empty() || out.len() == 1 {
        let take = name.len().min(if rng.below(3) == 0 {
            1 + rng.below(40) as usize
        } else {
            200
        });
        let more = take < name.len();
        let mut data = vec![u8::from(more)];
        data.extend_from_slice(&name[..take]);
        out.push(entry(b"NM", 1, &data));
        name = &name[take..];
        if name.is_empty() {
            break;
        }
    }

    // The times.
    let flags = (rng.below(16) as u8) | if rng.below(2) == 0 { 0x80 } else { 0 };
    let mut tf = vec![flags];
    for bit in 0..4 {
        if flags & (1 << bit) != 0 {
            if flags & 0x80 != 0 {
                tf.extend_from_slice(&date17(rng));
            } else {
                tf.extend_from_slice(&date7(rng));
            }
        }
    }
    if rng.below(10) == 0 {
        tf.truncate(rng.below(tf.len() as u64 + 1) as usize);
    }
    out.push(entry(b"TF", 1, &tf));

    match &node.kind {
        Kind::Symlink(components) => {
            // The target in components, over one or more SL entries.
            let mut sl = vec![0u8];
            for (i, c) in components.iter().enumerate() {
                let piece: Vec<u8> = match c.as_slice() {
                    b"." => vec![0x02, 0],
                    b".." => vec![0x04, 0],
                    b"/" => vec![0x08, 0],
                    b"ROOT" => vec![0x10, 0],
                    b"HOST" => vec![0x20, 0],
                    text => {
                        let flag = u8::from(rng.below(8) == 0);
                        let mut p = vec![flag, text.len() as u8];
                        p.extend_from_slice(text);
                        p
                    }
                };
                if sl.len() + piece.len() > 200 || (i > 0 && rng.below(6) == 0) {
                    sl[0] = 1;
                    out.push(entry(b"SL", 1, &sl));
                    sl = vec![0u8];
                }
                sl.extend_from_slice(&piece);
            }
            if rng.below(15) == 0 {
                sl[0] = rng.pick(&[2u8, 1]);
            }
            out.push(entry(b"SL", 1, &sl));
        }
        Kind::Device(hi, lo) => {
            let mut pn = Vec::new();
            pn.extend_from_slice(&both32(*hi));
            pn.extend_from_slice(&both32(*lo));
            out.push(entry(b"PN", 1, &pn));
        }
        Kind::File(Content::Zisofs { data, log2, .. }) => {
            let mut zf = vec![b'p', b'z', 4, *log2];
            zf.extend_from_slice(&both32(data.len() as u32));
            if rng.below(15) == 0 {
                zf[3] = rng.pick(&[14u8, 18, 0]);
            }
            out.push(entry(b"ZF", 1, &zf));
        }
        _ => {}
    }
    if re {
        out.push(entry(b"RE", 1, &[]));
    }
    if let Some(lba) = cl {
        out.push(entry(b"CL", 1, &both32(lba)));
    }
    match rng.below(25) {
        0 => out.push(entry(b"PD", 1, &[0; 5])),
        1 => out.push(entry(b"RR", 1, &[0x81])),
        2 => out.push(entry(b"ST", 1, &[])),
        3 => out.push(entry(b"XX", 1, &[1, 2, 3])),
        _ => {}
    }
    out
}

/// A directory record.
fn record(
    rng: &mut Rng,
    extent: u32,
    size: u32,
    flags: u8,
    name: &[u8],
    system_use: &[u8],
) -> Vec<u8> {
    let pad = usize::from(name.len().is_multiple_of(2));
    let len = 33 + name.len() + pad + system_use.len();
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(size));
    r[18..25].copy_from_slice(&date7(rng));
    r[25] = flags;
    r[28..32].copy_from_slice(&both16(1));
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r[33 + name.len() + pad..].copy_from_slice(system_use);
    r
}

/// The image being laid out: sectors, given out in order.
struct Layout {
    image: Vec<u8>,
    next: u32,
}

impl Layout {
    fn take(&mut self, bytes: usize) -> u32 {
        let at = self.next;
        let blocks = bytes.div_ceil(BLOCK).max(1);
        self.next += blocks as u32;
        let end = self.next as usize * BLOCK;
        if self.image.len() < end {
            self.image.resize(end, 0);
        }
        at
    }

    fn put(&mut self, sector: u32, bytes: &[u8]) {
        let at = sector as usize * BLOCK;
        if self.image.len() < at + bytes.len() {
            self.image
                .resize((at + bytes.len()).div_ceil(BLOCK) * BLOCK, 0);
        }
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
    }
}

/// Records packed into blocks, none across a block's end.
fn pack(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut used = 0;
    for r in records {
        if used + r.len() > BLOCK {
            out.resize(out.len() + BLOCK - used, 0);
            used = 0;
        }
        out.extend_from_slice(r);
        used += r.len();
    }
    out
}

/// A random tree, laid out as an ISO 9660 image with Rock Ridge (mostly)
/// and Joliet (sometimes).
pub fn crafted(rng: &mut Rng) -> Vec<u8> {
    let rock_ridge_on = rng.below(6) != 0;
    let joliet_on = rng.below(3) != 0;
    let with_rr_moved = rock_ridge_on && rng.below(3) != 0;

    // The tree.
    let mut nodes = vec![Node {
        name: Vec::new(),
        joliet: Vec::new(),
        kind: Kind::Dir(Vec::new()),
        mode: 0o40755,
        uid: 0,
        gid: 0,
        ino: 1,
        moved: false,
        extent: 0,
        size: 0,
        joliet_extent: 0,
        joliet_size: 0,
    }];
    let count = 1 + rng.below(25) as usize;
    for i in 1..=count {
        let dirs: Vec<usize> = (0..nodes.len())
            .filter(|&n| matches!(nodes[n].kind, Kind::Dir(_)))
            .collect();
        let parent = dirs[rng.below(dirs.len() as u64) as usize];
        let files: Vec<usize> = (0..nodes.len())
            .filter(|&n| matches!(nodes[n].kind, Kind::File(Content::Plain(_))))
            .collect();
        let (kind, mode) = match rng.below(15) {
            0..=3 => (Kind::Dir(Vec::new()), 0o40000 | rng.below(0o1000) as u32),
            4 => {
                let mut components = Vec::new();
                for _ in 0..1 + rng.below(6) {
                    components.push(match rng.below(8) {
                        0 => b".".to_vec(),
                        1 => b"..".to_vec(),
                        2 => b"/".to_vec(),
                        3 => b"ROOT".to_vec(),
                        4 => b"HOST".to_vec(),
                        _ => rr_name(rng, i),
                    });
                }
                (Kind::Symlink(components), 0o120777)
            }
            5 => (
                Kind::Device(rng.next() as u32, rng.next() as u32),
                rng.pick(&[0o20644u32, 0o60600]),
            ),
            6 if !files.is_empty() => (
                Kind::Link(files[rng.below(files.len() as u64) as usize]),
                0o100644,
            ),
            7..=9 => {
                let log2 = rng.pick(&[15u8, 16, 17]);
                let data = zisofs_data(rng, log2, i);
                let packed = zisofs(rng, &data, log2);
                (Kind::File(Content::Zisofs { data, log2, packed }), 0o100644)
            }
            10 => {
                let mut parts = Vec::new();
                for p in 0..1 + rng.below(4) {
                    let any = rng.below(9000);
                    let len = rng.pick(&[0u64, 1, 2048, 5000, any]) as usize;
                    parts.push((0..len).map(|k| (k * 3 + p as usize) as u8).collect());
                }
                (Kind::File(Content::Extents(parts)), 0o100644)
            }
            _ => {
                let any = rng.below(20_000);
                let len = rng.pick(&[0u64, 1, 2047, 2048, 2049, any]) as usize;
                let data = (0..len).map(|k| (k * 5 + i) as u8).collect();
                (
                    Kind::File(Content::Plain(data)),
                    0o100000 | rng.below(0o10000) as u32,
                )
            }
        };
        let deep = nodes
            .iter()
            .filter(|n| matches!(n.kind, Kind::Dir(_)))
            .count();
        nodes.push(Node {
            name: rr_name(rng, i),
            joliet: joliet_name(rng, i),
            kind,
            mode,
            uid: rng.below(70000) as u32,
            gid: rng.below(70000) as u32,
            ino: if rng.below(10) == 0 {
                rng.next() as u32
            } else {
                100 + i as u32
            },
            moved: with_rr_moved && parent != 0 && deep > 1 && rng.below(3) == 0,
            extent: 0,
            size: 0,
            joliet_extent: 0,
            joliet_size: 0,
        });
        let child = nodes.len() - 1;
        if let Kind::Dir(children) = &mut nodes[parent].kind {
            children.push(child);
        }
    }
    // Only directories move.
    for n in &mut nodes {
        if !matches!(n.kind, Kind::Dir(_)) {
            n.moved = false;
        }
    }
    let moved: Vec<usize> = (0..nodes.len()).filter(|&n| nodes[n].moved).collect();

    let mut layout = Layout {
        image: vec![0; 16 * BLOCK],
        next: 16,
    };
    // Volume descriptors: the PVD, Joliet's SVD, sometimes a boot record,
    // then the terminator; path tables after.
    let pvd_at = layout.take(BLOCK);
    let svd_at = joliet_on.then(|| layout.take(BLOCK));
    let boot_at = (rng.below(4) == 0).then(|| layout.take(BLOCK));
    let term_at = layout.take(BLOCK);
    let path_table = layout.take(BLOCK);

    // File data, some before the directories and some after.
    let early = rng.below(3) == 0;
    let place_data = |layout: &mut Layout, nodes: &mut Vec<Node>, rng: &mut Rng| {
        for node in nodes.iter_mut() {
            let (extent, size) = match &node.kind {
                Kind::File(Content::Plain(data)) => {
                    let at = layout.take(data.len());
                    layout.put(at, data);
                    (at, data.len() as u32)
                }
                Kind::File(Content::Zisofs { packed, .. }) => {
                    let at = layout.take(packed.len());
                    layout.put(at, packed);
                    (at, packed.len() as u32)
                }
                Kind::File(Content::Extents(parts)) => {
                    // Each part in its own extent, sometimes backwards.
                    let mut first = 0;
                    for (p, part) in parts.iter().enumerate() {
                        let at = layout.take(part.len());
                        layout.put(at, part);
                        if p == 0 {
                            first = at;
                        }
                    }
                    (first, 0)
                }
                Kind::Symlink(_) => (
                    if rng.below(2) == 0 { 0 } else { layout.next },
                    rng.pick(&[0u32, 0, 10]),
                ),
                _ => continue,
            };
            node.extent = extent;
            node.size = size;
        }
    };
    if early {
        place_data(&mut layout, &mut nodes, rng);
    }

    // Directory extents: each directory's records take this many bytes.
    let rr_moved_node = (!moved.is_empty()).then_some(nodes.len());
    if let Some(rr) = rr_moved_node {
        nodes.push(Node {
            name: b"rr_moved".to_vec(),
            joliet: utf16be("rr_moved"),
            kind: Kind::Dir(moved.clone()),
            mode: 0o40555,
            uid: 0,
            gid: 0,
            ino: 99,
            moved: false,
            extent: 0,
            size: 0,
            joliet_extent: 0,
            joliet_size: 0,
        });
        if let Kind::Dir(children) = &mut nodes[0].kind {
            children.push(rr);
        }
    }
    let dirs: Vec<usize> = (0..nodes.len())
        .filter(|&n| matches!(nodes[n].kind, Kind::Dir(_)))
        .collect();
    let mut order = dirs.clone();
    if rng.below(5) == 0 {
        // Directories in another order than the tree's.
        for k in (1..order.len()).rev() {
            let j = rng.below(k as u64 + 1) as usize;
            order.swap(k, j);
        }
    }
    let mut ce_sectors = vec![None; nodes.len()];
    for &d in &order {
        let Kind::Dir(children) = &nodes[d].kind else {
            continue;
        };
        let children = children.len();
        let blocks = 1 + children / 6 + rng.below(2) as usize;
        nodes[d].extent = layout.take(blocks * BLOCK);
        nodes[d].size = (blocks * BLOCK) as u32;
        // The continuation area of the directory's records, after it
        // (and, for regular files, before their data, as libarchive wants).
        if rock_ridge_on && rng.below(3) == 0 {
            ce_sectors[d] = Some(layout.take(BLOCK));
        }
        if joliet_on {
            let jblocks = 1 + children / 8;
            nodes[d].joliet_extent = layout.take(jblocks * BLOCK);
            nodes[d].joliet_size = (jblocks * BLOCK) as u32;
        }
    }
    if !early {
        place_data(&mut layout, &mut nodes, rng);
    }
    let mut parents = vec![0usize; nodes.len()];
    for &d in &dirs {
        if let Kind::Dir(children) = &nodes[d].kind {
            for &c in children {
                parents[c] = d;
            }
        }
    }
    if let Some(rr) = rr_moved_node {
        for &m in &moved {
            parents[m] = rr;
        }
    }

    // The records of each directory.
    for &d in &dirs {
        let Kind::Dir(children) = nodes[d].kind.clone() else {
            continue;
        };
        let mut records = Vec::new();
        let mut root_susp = Vec::new();
        if d == 0 && rock_ridge_on {
            let mut sp = vec![0xbe, 0xef];
            sp.push(if rng.below(15) == 0 {
                rng.below(8) as u8
            } else {
                0
            });
            root_susp.extend(entry(b"SP", 1, &sp));
            for e in rock_ridge(rng, &nodes, 0, false, None) {
                if !e.starts_with(b"NM") {
                    root_susp.extend(e);
                }
            }
        }
        let dot = record(rng, nodes[d].extent, nodes[d].size, 2, &[0], &root_susp);
        records.push(dot);
        let parent = parents[d];
        records.push(record(
            rng,
            nodes[parent].extent,
            nodes[parent].size,
            2,
            &[1],
            &[],
        ));
        // Children of the original parent of moved directories keep a CL
        // record in their place.
        let mut listed: Vec<(usize, bool)> = children.iter().map(|&c| (c, false)).collect();
        if Some(d) != rr_moved_node {
            listed.retain(|&(c, _)| !nodes[c].moved);
            for &m in &moved {
                if let Some(orig) = (0..nodes.len()).find(|&p| match &nodes[p].kind {
                    Kind::Dir(ch) => ch.contains(&m) && Some(p) != rr_moved_node,
                    _ => false,
                }) && orig == d
                {
                    listed.push((m, true));
                }
            }
        }
        // The continuation area of this directory, if any.
        let mut ce_area: Vec<u8> = Vec::new();
        let ce_sector = ce_sectors[d];
        for (k, &(c, cl)) in listed.iter().enumerate() {
            let node = &nodes[c];
            let (extent, size, flags) = match &node.kind {
                Kind::Dir(_) if cl => (0, 0, 0),
                Kind::Dir(_) => (node.extent, node.size, 2),
                Kind::Link(target) => (nodes[*target].extent, nodes[*target].size, 0),
                Kind::Device(..) => (0, 0, 0),
                _ => (node.extent, node.size, 0),
            };
            let (extent, size) = if rng.below(40) == 0 {
                // At location 0, which libarchive does not check, and past
                // the end of the volume.
                (0, rng.pick(&[1u32 << 20, 1 << 30, u32::MAX]))
            } else {
                (extent, size)
            };
            let susp = if rock_ridge_on {
                // RE where it does not belong, now and then.
                let re = Some(d) == rr_moved_node || rng.below(60) == 0;
                let entries = rock_ridge(rng, &nodes, c, re, cl.then_some(node.extent));
                let mut here = Vec::new();
                let mut there = Vec::new();
                for e in entries {
                    if ce_sector.is_some()
                        && rng.below(3) == 0
                        && ce_area.len() + there.len() + e.len() < BLOCK - 40
                    {
                        there.extend(e);
                    } else {
                        here.extend(e);
                    }
                }
                if let Some(sector) = ce_sector
                    && !there.is_empty()
                {
                    let mut ce = Vec::new();
                    ce.extend_from_slice(&both32(sector));
                    ce.extend_from_slice(&both32(ce_area.len() as u32));
                    ce.extend_from_slice(&both32(there.len() as u32));
                    if rng.below(20) == 0 {
                        ce[..8].copy_from_slice(&both32(nodes[d].extent));
                    }
                    here.extend(entry(b"CE", 1, &ce));
                    ce_area.extend(there);
                }
                here.truncate(220 - 34 - 40);
                here
            } else {
                Vec::new()
            };
            let mut name = iso_name(rng, k);
            name.truncate(40);
            if let Kind::File(Content::Extents(parts)) = &node.kind {
                // One record per extent, all but the last with bit 7.
                let mut at = node.extent;
                for (p, part) in parts.iter().enumerate() {
                    let last = p + 1 == parts.len();
                    let flags = if last { 0 } else { 0x80 };
                    let rest;
                    let use_area = if p == 0 {
                        &susp[..]
                    } else {
                        rest = rock_ridge(rng, &nodes, c, false, None).concat();
                        &rest[..rest.len().min(150)]
                    };
                    records.push(record(rng, at, part.len() as u32, flags, &name, use_area));
                    at += part.len().div_ceil(BLOCK).max(1) as u32;
                }
            } else {
                records.push(record(rng, extent, size, flags, &name, &susp));
            }
        }
        let packed = pack(&records);
        let room = nodes[d].size as usize;
        layout.put(nodes[d].extent, &packed[..packed.len().min(room)]);
        if let Some(sector) = ce_sector {
            layout.put(sector, &ce_area);
        }

        if joliet_on {
            let mut jrecords = vec![
                record(
                    rng,
                    nodes[d].joliet_extent,
                    nodes[d].joliet_size,
                    2,
                    &[0],
                    &[],
                ),
                record(
                    rng,
                    nodes[parent].joliet_extent,
                    nodes[parent].joliet_size,
                    2,
                    &[1],
                    &[],
                ),
            ];
            for &c in &children {
                let node = &nodes[c];
                let (extent, size, flags) = match &node.kind {
                    Kind::Dir(_) => (node.joliet_extent, node.joliet_size, 2),
                    Kind::Link(target) => (nodes[*target].extent, nodes[*target].size, 0),
                    Kind::File(Content::Extents(_)) | Kind::Device(..) => (0, 0, 0),
                    _ => (node.extent, node.size, 0),
                };
                let mut name = node.joliet.clone();
                name.truncate(220);
                jrecords.push(record(rng, extent, size, flags, &name, &[]));
            }
            let packed = pack(&jrecords);
            let room = nodes[d].joliet_size as usize;
            layout.put(nodes[d].joliet_extent, &packed[..packed.len().min(room)]);
        }
    }

    // The volume descriptors, now that the volume's size is known.
    let volume = layout.next.max(26) + rng.below(3) as u32;
    let mut pvd = vec![0u8; BLOCK];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[8..40].fill(b' ');
    pvd[40..72].fill(b' ');
    pvd[80..88].copy_from_slice(&both32(volume));
    pvd[120..124].copy_from_slice(&both16(1));
    pvd[124..128].copy_from_slice(&both16(1));
    pvd[128..132].copy_from_slice(&both16(BLOCK as u16));
    pvd[132..140].copy_from_slice(&both32(10));
    pvd[140..144].copy_from_slice(&path_table.to_le_bytes());
    pvd[148..152].copy_from_slice(&path_table.to_be_bytes());
    let root = record(rng, nodes[0].extent, nodes[0].size, 2, &[0], &[]);
    pvd[156..156 + 34].copy_from_slice(&root[..34]);
    pvd[881] = 1;
    layout.put(pvd_at, &pvd);
    if let Some(at) = svd_at {
        let mut svd = pvd.clone();
        svd[0] = 2;
        svd[88..91].copy_from_slice(rng.pick(&[b"%/E", b"%/C", b"%/@"]));
        let root = record(
            rng,
            nodes[0].joliet_extent,
            nodes[0].joliet_size,
            2,
            &[0],
            &[],
        );
        svd[156..156 + 34].copy_from_slice(&root[..34]);
        layout.put(at, &svd);
    }
    if let Some(at) = boot_at {
        let mut boot = vec![0u8; BLOCK];
        boot[1..6].copy_from_slice(b"CD001");
        boot[6] = 1;
        boot[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
        layout.put(at, &boot);
    }
    let mut term = vec![0u8; BLOCK];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    layout.put(term_at, &term);
    let mut end = (volume as usize * BLOCK).max(layout.image.len());
    // libarchive looks at 48 KiB and more before it says an image is one.
    if rng.below(20) != 0 {
        end = end.max(26 * BLOCK);
    }
    layout.image.resize(end, 0);
    layout.image
}
