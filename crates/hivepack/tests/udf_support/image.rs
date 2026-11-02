//! A writer of UDF images, for what mkudffs and Linux do not record:
//! metadata partitions with files, files on a VAT, remapped packets of a
//! sparable partition, allocation extents, strategy 4096 chains with
//! indirect entries, hidden and deleted entries, names and symbolic links
//! of every kind. It writes what ECMA-167 and UDF 2.60 give, as Linux reads
//! it, so that Linux's answers are the ones to compare with.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// The partition the nodes are on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Map {
    /// One physical partition.
    Physical,
    /// A metadata partition on the physical one (UDF 2.50): nodes and
    /// directories in the metadata file, data in the physical partition.
    Metadata,
    /// A virtual partition (VAT) on the physical one.
    Virtual,
    /// A sparable partition, one of whose packets is remapped.
    Sparable,
}

/// How a file's data is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// In the node.
    Inline,
    /// Short allocation descriptors, on the node's partition.
    Short,
    /// Long allocation descriptors, on the data partition.
    Long,
    /// One block per extent, apart: as many as allocation extents take.
    Fragmented,
    /// Short descriptors with a hole (not recorded) and an extent allocated
    /// but not recorded, between data.
    Sparse,
}

/// A name, as recorded.
#[derive(Clone, Debug)]
pub enum Name {
    /// OSTA CS0 with 8 bits per character, the smallest that fits.
    Text(String),
    /// CS0 with 16 bits per character.
    Wide(String),
    /// CS0 bytes, compression ID first.
    Raw(Vec<u8>),
}

/// What a node is.
#[derive(Clone, Debug)]
pub enum Kind {
    File(Vec<u8>, Layout),
    Dir(Vec<Entry>),
    /// Path components, as recorded.
    Symlink(Vec<u8>),
    Fifo,
    Socket,
    /// A character device and its numbers, in a device specification.
    CharDevice(u32, u32),
}

/// A node.
#[derive(Clone, Debug)]
pub struct Node {
    pub kind: Kind,
    pub uid: u32,
    pub gid: u32,
    /// UNIX permissions, setuid, setgid and sticky.
    pub mode: u32,
    /// Seconds from 1970, UTC, and microseconds.
    pub mtime: (i64, u32),
    pub atime: (i64, u32),
    pub attrtime: (i64, u32),
    /// An extended file entry rather than a file entry.
    pub efe: bool,
    /// Recorded with strategy 4096: a first version, an indirect entry to
    /// the next, which is the one, and then a terminal entry.
    pub strategy4096: bool,
    /// Implementation use bytes of its FID.
    pub fid_impl_use: Vec<u8>,
}

/// An entry of a directory.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: Name,
    pub node: Node,
    /// Hidden, deleted.
    pub hidden: bool,
    pub deleted: bool,
}

/// A volume.
#[derive(Clone, Debug)]
pub struct Volume {
    pub bs: usize,
    pub rev: u16,
    pub map: Map,
    pub root: Node,
    /// The logical volume integrity is left open.
    pub open: bool,
    /// The VAT's own data, in allocation descriptors rather than the node.
    pub vat_outside: bool,
}

impl Node {
    pub fn new(kind: Kind) -> Node {
        let t = (1_600_000_000, 0);
        Node {
            kind,
            uid: 0,
            gid: 0,
            mode: 0o644,
            mtime: t,
            atime: t,
            attrtime: t,
            efe: false,
            strategy4096: false,
            fid_impl_use: Vec::new(),
        }
    }

    pub fn dir(entries: Vec<Entry>) -> Node {
        Node {
            mode: 0o755,
            ..Node::new(Kind::Dir(entries))
        }
    }
}

impl Entry {
    pub fn new(name: &str, node: Node) -> Entry {
        Entry {
            name: Name::Text(name.to_string()),
            node,
            hidden: false,
            deleted: false,
        }
    }
}

/* --------------------------------------------------------------------- */

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The CRC of descriptors: CRC-ITU-T, from 0.
pub fn crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// A descriptor's tag, over its first `len` bytes.
fn tag(b: &mut [u8], id: u16, version: u16, loc: u32, len: usize) {
    put16(b, 0, id);
    put16(b, 2, version);
    put16(b, 6, 0);
    let crc_len = len - 16;
    let c = crc(&b[16..len]);
    put16(b, 8, c);
    put16(b, 10, crc_len as u16);
    put32(b, 12, loc);
    let mut sum: u8 = 0;
    for (i, &x) in b[..16].iter().enumerate() {
        if i != 4 {
            sum = sum.wrapping_add(x);
        }
    }
    b[4] = sum;
}

/// A timestamp in UTC.
fn timestamp(b: &mut [u8], at: usize, (secs, usecs): (i64, u32)) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    put16(b, at, 1 << 12);
    put16(b, at + 2, y as u16);
    b[at + 4] = m as u8;
    b[at + 5] = d as u8;
    b[at + 6] = (rem / 3600) as u8;
    b[at + 7] = (rem / 60 % 60) as u8;
    b[at + 8] = (rem % 60) as u8;
    b[at + 9] = (usecs / 10000) as u8;
    b[at + 10] = (usecs / 100 % 100) as u8;
    b[at + 11] = (usecs % 100) as u8;
}

/// A regid: flags, identifier, suffix.
fn regid(b: &mut [u8], at: usize, id: &[u8], suffix: &[u8]) {
    b[at] = 0;
    b[at + 1..at + 1 + id.len()].copy_from_slice(id);
    b[at + 24..at + 24 + suffix.len()].copy_from_slice(suffix);
}

/// The bytes of a name in CS0.
pub fn cs0(name: &Name) -> Vec<u8> {
    match name {
        Name::Text(s) if s.chars().all(|c| (c as u32) < 256) => {
            let mut out = vec![8];
            out.extend(s.chars().map(|c| c as u8));
            out
        }
        Name::Text(s) | Name::Wide(s) => {
            let mut out = vec![16];
            for u in s.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        Name::Raw(b) => b.clone(),
    }
}

/// A dstring of `len` bytes.
fn dstring(b: &mut [u8], at: usize, len: usize, s: &str) {
    let bytes = cs0(&Name::Text(s.to_string()));
    b[at..at + bytes.len()].copy_from_slice(&bytes);
    b[at + len - 1] = bytes.len() as u8;
}

/// The OSTA character set.
fn charspec(b: &mut [u8], at: usize) {
    b[at] = 0;
    b[at + 1..at + 24].copy_from_slice(b"OSTA Compressed Unicode");
}

/// A long_ad.
fn long_ad(b: &mut [u8], at: usize, len: u32, lb: u32, part: u16) {
    put32(b, at, len);
    put32(b, at + 4, lb);
    put16(b, at + 8, part);
}

/* --------------------------------------------------------------------- */

const P: u32 = 257;

/// Where nodes and data go, and the blocks of the image.
struct Writer {
    bs: usize,
    rev: u16,
    map: Map,
    image: Vec<u8>,
    /// The next free block of the physical partition.
    phys_next: u32,
    /// The partition the nodes are on, and data.
    nref: u16,
    dref: u16,
    /// Metadata blocks: physical blocks of the metadata file, in order.
    meta: Vec<u32>,
    meta_next: u32,
    /// VAT: physical block of each virtual block.
    vat: Vec<u32>,
    /// Sparable: the remapped packet, and where it is.
    spare_org: u32,
    spare_map: u32,
    /// Unique IDs.
    unique: u64,
    files: u32,
    dirs: u32,
}

const PACKET: u32 = 32;

/// The blocks of each of the 2 extents of the metadata file.
const META: u32 = 512;

impl Writer {
    fn sector(&mut self, s: u32) -> &mut [u8] {
        let at = s as usize * self.bs;
        if self.image.len() < at + self.bs {
            self.image.resize(at + self.bs, 0);
        }
        &mut self.image[at..at + self.bs]
    }

    /// A free physical block.
    fn phys(&mut self) -> u32 {
        let lb = self.phys_next;
        self.phys_next += 1;
        // Leave the remapped packet alone: its blocks are elsewhere.
        if self.map == Map::Sparable && (self.spare_org..self.spare_org + PACKET).contains(&lb) {
            return lb;
        }
        lb
    }

    /// The sector of a block of a partition.
    fn sector_of(&self, part: u16, lb: u32) -> u32 {
        let phys = if part == self.nref && self.map == Map::Metadata && part == 1 {
            self.meta[lb as usize]
        } else if part == 1 && self.map == Map::Virtual {
            self.vat[lb as usize]
        } else {
            lb
        };
        if self.map == Map::Sparable && (self.spare_org..self.spare_org + PACKET).contains(&phys) {
            return self.spare_map + (phys - self.spare_org);
        }
        P + phys
    }

    /// A free block of the node partition.
    fn node_block(&mut self) -> u32 {
        match self.map {
            Map::Metadata => {
                let lb = self.meta_next;
                self.meta_next += 1;
                assert!((lb as usize) < self.meta.len(), "metadata partition full");
                lb
            }
            Map::Virtual => {
                let phys = self.phys();
                self.vat.push(phys);
                self.vat.len() as u32 - 1
            }
            Map::Physical | Map::Sparable => self.phys(),
        }
    }

    /// Writes a block of a partition.
    fn write(&mut self, part: u16, lb: u32, data: &[u8]) {
        let s = self.sector_of(part, lb);
        let bs = self.bs;
        self.sector(s)[..data.len().min(bs)].copy_from_slice(&data[..data.len().min(bs)]);
    }

    fn icb_version(&self) -> u16 {
        if self.rev >= 0x0200 { 3 } else { 2 }
    }

    /// Data blocks for `data`, in extents of `per` blocks, `gap` blocks
    /// apart, on partition `part`: (length, block) of each.
    fn data_extents(&mut self, part: u16, data: &[u8], per: usize, gap: usize) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for chunk in data.chunks(per.saturating_mul(self.bs)) {
            let first = if part == self.nref && self.nref != self.dref {
                // On the node partition: one block at a time, in order.
                let first = self.node_block();
                for _ in 1..chunk.len().div_ceil(self.bs) {
                    self.node_block();
                }
                first
            } else {
                let first = self.phys_next;
                self.phys_next += chunk.len().div_ceil(self.bs) as u32;
                first
            };
            for (i, block) in chunk.chunks(self.bs).enumerate() {
                self.write(part, first + i as u32, block);
            }
            out.push((chunk.len() as u32, first));
            for _ in 0..gap {
                if part == self.nref && self.nref != self.dref {
                    self.node_block();
                } else {
                    self.phys_next += 1;
                }
            }
        }
        out
    }

    /// The bytes of a FID.
    fn fid(&self, chars: u8, name: &[u8], icb: (u32, u16), impl_use: &[u8], loc: u32) -> Vec<u8> {
        let len = (38 + name.len() + impl_use.len() + 3) & !3;
        let mut f = vec![0; len];
        put16(&mut f, 16, 1);
        f[18] = chars;
        f[19] = name.len() as u8;
        long_ad(&mut f, 20, self.bs as u32, icb.0, icb.1);
        put16(&mut f, 36, impl_use.len() as u16);
        f[38..38 + impl_use.len()].copy_from_slice(impl_use);
        f[38 + impl_use.len()..38 + impl_use.len() + name.len()].copy_from_slice(name);
        tag(&mut f, 257, self.icb_version(), loc, len);
        f
    }

    /// Writes a node and what it holds: where it is.
    fn node(&mut self, node: &Node, parent: Option<(u32, u16)>) -> (u32, u16) {
        let nref = self.nref;
        // The first version of a strategy 4096 node, then its indirect
        // entry, at the next block.
        let lb = self.node_block();
        let first = if node.strategy4096 {
            let ie = self.node_block();
            Some((lb, ie))
        } else {
            None
        };
        let lb = if first.is_some() {
            self.node_block()
        } else {
            lb
        };
        let me = (first.map_or(lb, |(first_lb, _)| first_lb), nref);
        if first.is_some() {
            // The block after the one: a terminal entry.
            let te = self.node_block();
            let mut b = vec![0; self.bs];
            put16(&mut b, 16 + 4, 4096);
            tag(&mut b, 260, self.icb_version(), te, 36);
            self.write(nref, te, &b);
        }

        // What it holds.
        let (file_type, data, layout) = match &node.kind {
            Kind::File(data, layout) => {
                self.files += 1;
                (5u8, data.clone(), *layout)
            }
            Kind::Dir(entries) => {
                self.dirs += 1;
                // The directory's FIDs, in blocks of the node partition.
                let mut stream = Vec::new();
                let parent = parent.unwrap_or(me);
                // The FIDs' tags are at the blocks they start in: those
                // are only known once written, and Linux does not check
                // them; NetBSD does not either.
                stream.extend(self.fid(0x0a, &[], parent, &[], 0));
                let mut children = Vec::new();
                for entry in entries {
                    let icb = if entry.deleted {
                        (0, 0)
                    } else {
                        self.node(&entry.node, Some(me))
                    };
                    let mut chars = 0;
                    if entry.hidden {
                        chars |= 1;
                    }
                    if matches!(entry.node.kind, Kind::Dir(_)) {
                        chars |= 2;
                    }
                    if entry.deleted {
                        chars |= 4;
                    }
                    children.push((
                        chars,
                        cs0(&entry.name),
                        icb,
                        entry.node.fid_impl_use.clone(),
                    ));
                }
                for (chars, name, icb, iu) in children {
                    stream.extend(self.fid(chars, &name, icb, &iu, 0));
                }
                let layout = if stream.len() + 216 <= self.bs {
                    Layout::Inline
                } else {
                    Layout::Short
                };
                (4, stream, layout)
            }
            Kind::Symlink(comps) => (12, comps.clone(), Layout::Inline),
            Kind::Fifo => (9, Vec::new(), Layout::Short),
            Kind::Socket => (10, Vec::new(), Layout::Short),
            Kind::CharDevice(..) => (7, Vec::new(), Layout::Short),
        };

        // Its extended attributes: a device specification.
        let mut ea = Vec::new();
        if let Kind::CharDevice(major, minor) = node.kind {
            ea = vec![0; 24 + 24];
            put32(&mut ea, 16, 24);
            put32(&mut ea, 20, 0xffff_ffff);
            put32(&mut ea, 24, 12);
            ea[28] = 1;
            put32(&mut ea, 32, 24);
            put32(&mut ea, 36, 0);
            put32(&mut ea, 40, major);
            put32(&mut ea, 44, minor);
            tag(&mut ea, 262, self.icb_version(), lb, 24);
        }

        // Its allocation descriptors.
        let short = layout != Layout::Long;
        let (alloc, ads): (u16, Vec<u8>) = match layout {
            Layout::Inline => (3, data.clone()),
            _ if data.is_empty() => (if short { 0 } else { 1 }, Vec::new()),
            Layout::Short | Layout::Long | Layout::Fragmented | Layout::Sparse => {
                let part = if short { nref } else { self.dref };
                let part =
                    if self.map == Map::Metadata && short && matches!(node.kind, Kind::File(..)) {
                        // Data on the metadata partition, then.
                        nref
                    } else {
                        part
                    };
                let mut extents: Vec<(u32, u32, u32)> = Vec::new();
                match layout {
                    Layout::Fragmented => {
                        for (len, lb) in self.data_extents(part, &data, 1, 1) {
                            extents.push((0, len, lb));
                        }
                    }
                    Layout::Sparse => {
                        let half = data.len() / 2 / self.bs * self.bs;
                        for (len, lb) in self.data_extents(part, &data[..half], 1 << 20, 0) {
                            extents.push((0, len, lb));
                        }
                        // A hole of 3 blocks, not recorded nor allocated,
                        // and 2 blocks allocated but not recorded.
                        extents.push((2, 3 * self.bs as u32, 0));
                        let alloc_lb = self.phys_next;
                        self.phys_next += 2;
                        extents.push((1, 2 * self.bs as u32, alloc_lb));
                        let rest = &data[half + 5 * self.bs..];
                        for (len, lb) in self.data_extents(part, rest, 1 << 20, 0) {
                            extents.push((0, len, lb));
                        }
                    }
                    _ => {
                        let per = (1 << 30) / self.bs - 1;
                        for (len, lb) in self.data_extents(part, &data, per, 0) {
                            extents.push((0, len, lb));
                        }
                    }
                }
                let adlen = if short { 8 } else { 16 };
                let mut ads = Vec::new();
                for (flags, len, lb) in extents {
                    let mut ad = vec![0; adlen];
                    put32(&mut ad, 0, (flags << 30) | len);
                    put32(&mut ad, 4, lb);
                    if !short {
                        put16(&mut ad, 8, part);
                    }
                    ads.extend(ad);
                }
                (if short { 0 } else { 1 }, ads)
            }
        };

        let header = if node.efe { 216 } else { 176 };
        let room = self.bs - header - ea.len();
        let adlen = if alloc == 0 { 8 } else { 16 };
        let ads = if alloc != 3 && ads.len() > room {
            // Allocation extents: as many descriptors as fit, then a
            // redirect to the next.
            let mut chunks = Vec::new();
            let mut rest = &ads[..];
            let mut fit = (room / adlen - 1) * adlen;
            while rest.len() > fit + adlen {
                chunks.push(&rest[..fit]);
                rest = &rest[fit..];
                fit = ((self.bs - 24) / adlen - 1) * adlen;
            }
            chunks.push(rest);
            let blocks: Vec<u32> = (1..chunks.len()).map(|_| self.node_block()).collect();
            let bs = self.bs;
            let redirect = |b: &mut Vec<u8>, next: u32| {
                let mut ad = vec![0; adlen];
                put32(&mut ad, 0, (3 << 30) | bs as u32);
                put32(&mut ad, 4, next);
                if adlen == 16 {
                    put16(&mut ad, 8, nref);
                }
                b.extend(ad);
            };
            for (i, &blk) in blocks.iter().enumerate() {
                let mut body = chunks[i + 1].to_vec();
                if let Some(&next) = blocks.get(i + 1) {
                    redirect(&mut body, next);
                }
                let mut b = vec![0; self.bs];
                put32(&mut b, 16, if i == 0 { lb } else { blocks[i - 1] });
                put32(&mut b, 20, body.len() as u32);
                b[24..24 + body.len()].copy_from_slice(&body);
                tag(&mut b, 258, self.icb_version(), blk, 24 + body.len());
                self.write(nref, blk, &b);
            }
            let mut head = chunks[0].to_vec();
            redirect(&mut head, blocks[0]);
            head
        } else {
            ads
        };
        assert!(header + ea.len() + ads.len() <= self.bs, "node too large");

        let mut fe_flags = alloc;
        if node.mode & 0o4000 != 0 {
            fe_flags |= 1 << 6;
        }
        if node.mode & 0o2000 != 0 {
            fe_flags |= 1 << 7;
        }
        if node.mode & 0o1000 != 0 {
            fe_flags |= 1 << 8;
        }
        let perm = {
            let m = node.mode;
            (m & 0o7) | ((m & 0o70) << 2) | ((m & 0o700) << 4)
        };
        let blocks_recorded = if alloc == 3 {
            0
        } else {
            data.len().div_ceil(self.bs) as u64
        };
        let link_cnt = match &node.kind {
            Kind::Dir(entries) => {
                1 + entries
                    .iter()
                    .filter(|e| !e.deleted && matches!(e.node.kind, Kind::Dir(_)))
                    .count() as u16
            }
            _ => 1,
        };

        let build = |w: &Writer, at: u32, strategy: u16, mtime: (i64, u32)| -> Vec<u8> {
            let mut b = vec![0; w.bs];
            put16(&mut b, 16 + 4, strategy);
            put16(&mut b, 16 + 8, 1);
            b[16 + 11] = file_type;
            if let Some((plb, ppart)) = parent {
                put32(&mut b, 16 + 12, plb);
                put16(&mut b, 16 + 16, ppart);
            }
            put16(&mut b, 16 + 18, fe_flags);
            put32(&mut b, 36, node.uid);
            put32(&mut b, 40, node.gid);
            put32(&mut b, 44, perm);
            put16(&mut b, 48, link_cnt);
            put64(&mut b, 56, data.len() as u64);
            let unique = if parent.is_none() { 0 } else { w.unique };
            if node.efe {
                put64(&mut b, 64, data.len() as u64);
                put64(&mut b, 72, blocks_recorded);
                timestamp(&mut b, 80, node.atime);
                timestamp(&mut b, 92, mtime);
                timestamp(&mut b, 104, mtime);
                timestamp(&mut b, 116, node.attrtime);
                put32(&mut b, 128, 1);
                regid(&mut b, 168, b"*hivepack", &[]);
                put64(&mut b, 200, unique);
                put32(&mut b, 208, ea.len() as u32);
                put32(&mut b, 212, ads.len() as u32);
            } else {
                put64(&mut b, 64, blocks_recorded);
                timestamp(&mut b, 72, node.atime);
                timestamp(&mut b, 84, mtime);
                timestamp(&mut b, 96, node.attrtime);
                put32(&mut b, 108, 1);
                regid(&mut b, 128, b"*hivepack", &[]);
                put64(&mut b, 160, unique);
                put32(&mut b, 168, ea.len() as u32);
                put32(&mut b, 172, ads.len() as u32);
            }
            let mut ea = ea.clone();
            if !ea.is_empty() {
                tag(&mut ea, 262, w.icb_version(), at, 24);
            }
            b[header..header + ea.len()].copy_from_slice(&ea);
            b[header + ea.len()..header + ea.len() + ads.len()].copy_from_slice(&ads);
            let len = header + ea.len() + ads.len();
            tag(
                &mut b,
                if node.efe { 266 } else { 261 },
                w.icb_version(),
                at,
                len,
            );
            b
        };
        self.unique += 1;

        if let Some((first_lb, ie)) = first {
            // An older version, of 1990, then the indirect entry to the
            // one.
            let old = build(self, first_lb, 4096, (631_152_000, 0));
            self.write(nref, first_lb, &old);
            let mut b = vec![0; self.bs];
            put16(&mut b, 16 + 4, 4096);
            put16(&mut b, 16 + 8, 1);
            b[16 + 11] = 3;
            long_ad(&mut b, 36, self.bs as u32, lb, nref);
            tag(&mut b, 259, self.icb_version(), ie, 52);
            self.write(nref, ie, &b);
            let b = build(self, lb, 4096, node.mtime);
            self.write(nref, lb, &b);
            return me;
        }
        let b = build(self, lb, 4, node.mtime);
        self.write(nref, lb, &b);
        me
    }
}

/// The image of a volume.
pub fn image(volume: &Volume) -> Vec<u8> {
    let bs = volume.bs;
    let (nref, dref) = match volume.map {
        Map::Physical | Map::Sparable => (0, 0),
        Map::Metadata | Map::Virtual => (1, 0),
    };
    let mut w = Writer {
        bs,
        rev: volume.rev,
        map: volume.map,
        image: Vec::new(),
        phys_next: 0,
        nref,
        dref,
        meta: Vec::new(),
        meta_next: 0,
        vat: Vec::new(),
        spare_org: 0,
        spare_map: 0,
        unique: 16,
        files: 0,
        dirs: 0,
    };
    let ver = w.icb_version();

    // The metadata file: 2 extents of META blocks, apart, and its mirror's.
    let (meta_fe, mirror_fe) = if volume.map == Map::Metadata {
        let fe = w.phys();
        let mirror = w.phys();
        let a = w.phys_next;
        w.phys_next += META + 8;
        let b = w.phys_next;
        w.phys_next += META + 8;
        w.meta = (a..a + META).chain(b..b + META).collect();
        (fe, mirror)
    } else {
        (0, 0)
    };
    if volume.map == Map::Sparable {
        // The packet of blocks 64 to 95 is remapped, far after them.
        w.spare_org = 64;
        w.spare_map = P + 4096;
    }

    // The file set descriptor, its terminator, and the tree.
    let fsd_lb = w.node_block();
    let td_lb = w.node_block();
    let root = w.node(&volume.root, None);

    // The VAT, after the tree, in the last blocks of the partition: a
    // 2.00 VAT, in the node or in blocks before it.
    let mut vat = vec![0; 152];
    let (mut vat_fe, mut vat_ads, mut vat_alloc) = (0, Vec::new(), 3u16);
    if volume.map == Map::Virtual {
        put16(&mut vat, 0, 152);
        dstring(&mut vat, 4, 128, "crafted");
        put32(&mut vat, 132, 0xffff_ffff);
        put32(&mut vat, 136, w.files);
        put32(&mut vat, 140, w.dirs);
        put16(&mut vat, 144, volume.rev);
        put16(&mut vat, 146, volume.rev);
        put16(&mut vat, 148, volume.rev);
        for &phys in &w.vat.clone() {
            vat.extend_from_slice(&phys.to_le_bytes());
        }
        if volume.vat_outside || 216 + vat.len() > bs {
            let first = w.phys_next;
            for (i, chunk) in vat.clone().chunks(bs).enumerate() {
                let s = P + first + i as u32;
                w.sector(s)[..chunk.len()].copy_from_slice(chunk);
            }
            w.phys_next += vat.len().div_ceil(bs) as u32;
            vat_ads = vec![0; 8];
            put32(&mut vat_ads, 0, vat.len() as u32);
            put32(&mut vat_ads, 4, first);
            vat_alloc = 0;
        } else {
            vat_ads = vat.clone();
        }
        vat_fe = w.phys_next;
        w.phys_next += 1;
    }

    // The partition's length, and the sectors after it.
    let part_len = if volume.map == Map::Virtual {
        w.phys_next
    } else {
        w.phys_next.max(256) + 64
    };
    let sparing_at = P + part_len + 8;
    let n_sectors = match volume.map {
        Map::Virtual => P + part_len,
        Map::Sparable => {
            assert!(sparing_at < w.spare_map, "partition too large");
            w.spare_map + 4 * PACKET + 300
        }
        _ => P + part_len + 300,
    };
    if volume.map == Map::Sparable {
        // What was written to the remapped packet went to the spare
        // blocks; the original blocks hold garbage.
        for i in 0..PACKET {
            let s = P + w.spare_org + i;
            w.sector(s).fill(0xa5);
        }
    }

    let mut b = vec![0; bs];
    // FSD.
    timestamp(&mut b, 16, (1_600_000_000, 0));
    put16(&mut b, 28, 3);
    put16(&mut b, 30, 3);
    put32(&mut b, 32, 1);
    put32(&mut b, 36, 1);
    charspec(&mut b, 48);
    dstring(&mut b, 112, 128, "crafted");
    charspec(&mut b, 240);
    dstring(&mut b, 304, 32, "crafted");
    long_ad(&mut b, 400, bs as u32, root.0, root.1);
    regid(
        &mut b,
        416,
        b"*OSTA UDF Compliant",
        &[volume.rev as u8, (volume.rev >> 8) as u8, 3],
    );
    tag(&mut b, 256, ver, fsd_lb, 512);
    w.write(nref, fsd_lb, &b);
    let mut b = vec![0; bs];
    tag(&mut b, 8, ver, td_lb, 16);
    w.write(nref, td_lb, &b);

    // The metadata file and its mirror: extended file entries, of the
    // physical partition, with short allocation descriptors.
    if volume.map == Map::Metadata {
        for (lb, file_type) in [(meta_fe, 250u8), (mirror_fe, 251)] {
            let mut b = vec![0; bs];
            put16(&mut b, 16 + 4, 4);
            put16(&mut b, 16 + 8, 1);
            b[16 + 11] = file_type;
            put16(&mut b, 16 + 18, 0);
            put32(&mut b, 36, u32::MAX);
            put32(&mut b, 40, u32::MAX);
            put16(&mut b, 48, 1);
            let len = (2 * META as usize * bs) as u64;
            put64(&mut b, 56, len);
            put64(&mut b, 64, len);
            put64(&mut b, 72, 2 * u64::from(META));
            regid(&mut b, 168, b"*hivepack", &[]);
            put32(&mut b, 212, 16);
            put32(&mut b, 216, META * bs as u32);
            put32(&mut b, 220, w.meta[0]);
            put32(&mut b, 224, META * bs as u32);
            put32(&mut b, 228, w.meta[META as usize]);
            tag(&mut b, 266, ver, lb, 216 + 16);
            w.write(0, lb, &b);
        }
    }

    // Volume structures: the VRS, in units of at least 2048 bytes.
    let step = bs.max(2048);
    let vrs = 32768;
    for (i, id) in [
        b"BEA01",
        if volume.rev >= 0x0200 {
            b"NSR03"
        } else {
            b"NSR02"
        },
        b"TEA01",
    ]
    .iter()
    .enumerate()
    {
        let at = vrs + i * step;
        if w.image.len() < at + 2048 {
            w.image.resize(at + 2048, 0);
        }
        w.image[at + 1..at + 6].copy_from_slice(&id[..]);
        w.image[at + 6] = 1;
    }
    let vds = (vrs + 3 * step).div_ceil(bs) as u32;
    let reserve = vds + 16;
    let lvid = reserve + 16;
    let maps = match volume.map {
        Map::Physical => vec![{
            let mut m = vec![0; 6];
            m[0] = 1;
            m[1] = 6;
            put16(&mut m, 2, 1);
            m
        }],
        Map::Sparable => vec![{
            let mut m = vec![0; 64];
            m[0] = 2;
            m[1] = 64;
            regid(
                &mut m,
                4,
                b"*UDF Sparable Partition",
                &[volume.rev as u8, (volume.rev >> 8) as u8],
            );
            put16(&mut m, 36, 1);
            put16(&mut m, 38, 0);
            put16(&mut m, 40, PACKET as u16);
            m[42] = 1;
            put32(&mut m, 44, bs as u32);
            put32(&mut m, 48, sparing_at);
            m
        }],
        Map::Metadata | Map::Virtual => {
            let mut m1 = vec![0; 6];
            m1[0] = 1;
            m1[1] = 6;
            put16(&mut m1, 2, 1);
            let mut m2 = vec![0; 64];
            m2[0] = 2;
            m2[1] = 64;
            let id: &[u8] = if volume.map == Map::Metadata {
                b"*UDF Metadata Partition"
            } else {
                b"*UDF Virtual Partition"
            };
            regid(&mut m2, 4, id, &[volume.rev as u8, (volume.rev >> 8) as u8]);
            put16(&mut m2, 36, 1);
            put16(&mut m2, 38, 0);
            if volume.map == Map::Metadata {
                put32(&mut m2, 40, meta_fe);
                put32(&mut m2, 44, mirror_fe);
                put32(&mut m2, 48, u32::MAX);
                put32(&mut m2, 52, 32);
                put16(&mut m2, 56, 32);
            }
            vec![m1, m2]
        }
    };
    let maps_bytes: Vec<u8> = maps.concat();
    for (copy, at) in [(0, vds), (1, reserve)] {
        let _ = copy;
        // PVD.
        let mut b = vec![0; bs];
        put32(&mut b, 16, 1);
        dstring(&mut b, 24, 32, "crafted");
        put16(&mut b, 56, 1);
        put16(&mut b, 58, 1);
        put16(&mut b, 60, 2);
        put16(&mut b, 62, 3);
        put32(&mut b, 64, 1);
        put32(&mut b, 68, 1);
        dstring(&mut b, 72, 128, "0123456789abcdef crafted");
        charspec(&mut b, 200);
        charspec(&mut b, 264);
        timestamp(&mut b, 376, (1_600_000_000, 0));
        regid(&mut b, 388, b"*hivepack", &[]);
        tag(&mut b, 1, ver, at, 512);
        w.sector(at).copy_from_slice(&b);
        // PD.
        let mut b = vec![0; bs];
        put32(&mut b, 16, 2);
        put16(&mut b, 20, 1);
        put16(&mut b, 22, 0);
        regid(
            &mut b,
            24,
            if volume.rev >= 0x0200 {
                b"+NSR03"
            } else {
                b"+NSR02"
            },
            &[],
        );
        put32(&mut b, 184, 1);
        put32(&mut b, 188, P);
        put32(&mut b, 192, part_len);
        regid(&mut b, 196, b"*hivepack", &[]);
        tag(&mut b, 5, ver, at + 1, 512);
        w.sector(at + 1).copy_from_slice(&b);
        // LVD.
        let mut b = vec![0; bs];
        put32(&mut b, 16, 3);
        charspec(&mut b, 20);
        dstring(&mut b, 84, 128, "crafted");
        put32(&mut b, 212, bs as u32);
        regid(
            &mut b,
            216,
            b"*OSTA UDF Compliant",
            &[volume.rev as u8, (volume.rev >> 8) as u8, 3],
        );
        long_ad(&mut b, 248, bs as u32, fsd_lb, nref);
        put32(&mut b, 264, maps_bytes.len() as u32);
        put32(&mut b, 268, maps.len() as u32);
        regid(&mut b, 272, b"*hivepack", &[]);
        put32(&mut b, 432, (2 * bs) as u32);
        put32(&mut b, 436, lvid);
        b[440..440 + maps_bytes.len()].copy_from_slice(&maps_bytes);
        tag(&mut b, 6, ver, at + 2, 440 + maps_bytes.len());
        w.sector(at + 2).copy_from_slice(&b);
        // USD.
        let mut b = vec![0; bs];
        put32(&mut b, 16, 4);
        tag(&mut b, 7, ver, at + 3, 24);
        w.sector(at + 3).copy_from_slice(&b);
        // TD.
        let mut b = vec![0; bs];
        tag(&mut b, 8, ver, at + 4, 16);
        w.sector(at + 4).copy_from_slice(&b);
    }
    // LVID, and a terminator.
    let mut b = vec![0; bs];
    timestamp(&mut b, 16, (1_600_000_000, 0));
    put32(&mut b, 28, if volume.open { 0 } else { 1 });
    put64(&mut b, 40, w.unique);
    let n = maps.len();
    put32(&mut b, 72, n as u32);
    put32(&mut b, 76, 46);
    for i in 0..n {
        put32(&mut b, 80 + 4 * i, 0);
        put32(&mut b, 80 + 4 * (n + i), part_len);
    }
    let iu = 80 + 8 * n;
    regid(&mut b, iu, b"*hivepack", &[]);
    put32(&mut b, iu + 32, w.files);
    put32(&mut b, iu + 36, w.dirs);
    put16(&mut b, iu + 40, volume.rev.min(0x0250));
    put16(&mut b, iu + 42, volume.rev);
    put16(&mut b, iu + 44, volume.rev);
    tag(&mut b, 9, ver, lvid, iu + 46);
    w.sector(lvid).copy_from_slice(&b);
    let mut b = vec![0; bs];
    tag(&mut b, 8, ver, lvid + 1, 16);
    w.sector(lvid + 1).copy_from_slice(&b);

    // The sparing table, and the spare blocks.
    if volume.map == Map::Sparable {
        let mut b = vec![0; bs];
        regid(
            &mut b,
            16,
            b"*UDF Sparing Table",
            &[volume.rev as u8, (volume.rev >> 8) as u8],
        );
        put16(&mut b, 48, 4);
        put32(&mut b, 52, 1);
        put32(&mut b, 56, w.spare_org);
        put32(&mut b, 60, w.spare_map);
        for i in 1..4 {
            put32(&mut b, 56 + 8 * i, 0xffff_ffff);
            put32(&mut b, 60 + 8 * i, w.spare_map + PACKET * i as u32);
        }
        tag(&mut b, 0, ver, sparing_at, 56 + 32);
        w.sector(sparing_at).copy_from_slice(&b);
    }

    // The VAT's node, in the last block.
    if volume.map == Map::Virtual {
        let mut b = vec![0; bs];
        put16(&mut b, 16 + 4, 4);
        put16(&mut b, 16 + 8, 1);
        b[16 + 11] = 248;
        put16(&mut b, 16 + 18, vat_alloc);
        put32(&mut b, 36, u32::MAX);
        put32(&mut b, 40, u32::MAX);
        put16(&mut b, 48, 1);
        put64(&mut b, 56, vat.len() as u64);
        put64(&mut b, 64, vat.len() as u64);
        timestamp(&mut b, 92, (1_600_000_000, 0));
        regid(&mut b, 168, b"*hivepack", &[]);
        put32(&mut b, 212, vat_ads.len() as u32);
        b[216..216 + vat_ads.len()].copy_from_slice(&vat_ads);
        tag(&mut b, 266, ver, vat_fe, 216 + vat_ads.len());
        w.sector(P + vat_fe).copy_from_slice(&b);
    }

    // Anchors at 256 and at the end.
    let last = n_sectors - 1;
    for at in if volume.map == Map::Virtual {
        vec![256]
    } else {
        vec![256, last]
    } {
        let mut b = vec![0; bs];
        put32(&mut b, 16, (16 * bs) as u32);
        put32(&mut b, 20, vds);
        put32(&mut b, 24, (16 * bs) as u32);
        put32(&mut b, 28, reserve);
        tag(&mut b, 2, ver, at, 512);
        w.sector(at).copy_from_slice(&b);
    }
    w.image.resize(n_sectors as usize * bs, 0);
    w.image
}
