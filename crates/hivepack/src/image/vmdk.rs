//! VMDK, VMware's disk image (`.vmdk`): a descriptor that says what the disk
//! is made of, and the extents that hold it — flat, sparse, or a stream of
//! compressed grains.
//!
//! Nothing is ported here. The layout is VMware's published *Virtual Disk
//! Format* specification, and every number in it is little-endian; QEMU's
//! own driver is GPL-2.0, and this module is under the crate's own license.
//! How it is checked against `qemu-img` is in the repository: `docs/image.md`.
//!
//! A VMDK is one file or several. A sparse extent keeps its descriptor
//! inside it and is a disk on its own, which is what [`Vmdk::open`] reads:
//! `monolithicSparse`, and the `streamOptimized` stream an OVA holds. The
//! other kinds are a descriptor of plain text naming files beside it, which
//! only [`Vmdk::beside`] can reach, as it is given a path and not a reader:
//! `monolithicFlat`, and the two that cut a disk into 2 GiB pieces.

use std::io;
#[cfg(any(unix, windows))]
use std::path::{Path, PathBuf};

use super::disk::Disk;
use super::error::{Error, Unsupported};

/// The first four bytes of a sparse extent. A descriptor of its own has no
/// signature at all: it is text, and [`is_descriptor`] is what tells it.
const MAGIC: &[u8; 4] = b"KDMV";

/// How long a sparse extent's header is, and how long a sector is: the
/// format counts everything in sectors of 512 bytes, whatever the disk it
/// holds is made of.
const HEADER: usize = 512;
const SECTOR: u64 = 512;

/// The version of the format this reads, which is every version there is.
const MOST_VERSION: u32 = 3;

/// The header flag that says each grain is compressed, and the only way of
/// compressing them the format has: deflate, which VMware writes with a
/// zlib header in front of it.
const COMPRESSED: u32 = 1 << 16;
const DEFLATE: u16 = 1;

/// What a header says where its grain directory is at the file's end
/// instead: a stream of compressed grains is written in one pass, so what
/// wrote it could not know where the directory would land.
const AT_END: u64 = u64::MAX;

/// The end of such a stream: a marker saying a footer follows, the footer
/// itself, and a marker saying the stream ends there. A marker of no data
/// of its own says which of those it is.
const FOOTER: u64 = 3 * SECTOR;
const MARKER_EOS: u32 = 0;
const MARKER_FOOTER: u32 = 3;

/// How long a grain may be: the specification's least is 8 sectors, and 128
/// of them — 64 KiB — is what every tool writes. The most keeps a grain in
/// memory while it is decompressed.
const LEAST_GRAIN: u64 = 8;
const MOST_GRAIN: u64 = 16 << 20;

/// How many entries a grain table may hold. It is 512 in every image, and
/// read from the header all the same.
const MOST_ENTRIES: u64 = 1 << 16;

/// How many grain tables the directory may name, as it is read whole: a
/// disk of 2 TiB in 64 KiB grains has 64 Ki of them, which is as far as the
/// four bytes an entry gets reach.
const MOST_TABLES: u64 = 1 << 20;

/// How much of a descriptor is read, and how many extents it may name. A
/// disk cut into 2 GiB pieces needs one for each, and 1024 of them reach
/// 2 TiB.
const MOST_TEXT: u64 = 1 << 20;
const MOST_EXTENTS: usize = 1024;

/// A grain table entry of a grain nothing was ever written to, and one of a
/// grain written as zeroes, which the format has so that a stream need not
/// carry them. Both read as zeroes.
const NOTHING: u32 = 0;
const ZEROES: u32 = 1;

/// A VMDK image, as the disk it holds: reads of the disk are reads of the
/// extents it is made of, and zeroes wherever nothing has been written.
pub struct Vmdk<D> {
    /// How long the disk is: an extent's own header where it says, and what
    /// the descriptor says for the rest.
    size: u64,
    /// The extents in the order the descriptor names them, each covering
    /// the run of the disk after the one before it.
    pieces: Vec<Piece<D>>,
}

/// One extent, as the run of the disk it holds.
struct Piece<D> {
    /// Where the run begins on the disk, and how long it is.
    at: u64,
    len: u64,
    holds: Holds<D>,
}

/// What holds an extent's run of the disk.
enum Holds<D> {
    /// Nothing: a `ZERO` extent, which reads as zeroes and takes no room
    /// anywhere.
    Zero,
    /// The disk as it is, at an offset into a file.
    Flat { from: D, at: u64 },
    /// Grains, wherever the extent's own tables say they are.
    Sparse(Sparse<D>),
}

/// A sparse extent: a header, a directory of grain tables, and the grains
/// that have been written.
struct Sparse<D> {
    inner: D,
    /// How long the disk the extent holds is, in bytes.
    size: u64,
    /// How many bytes a grain is.
    grain: u64,
    /// How many entries a grain table holds.
    entries: u64,
    /// Where each grain table is, in sectors, or [`NOTHING`] where a whole
    /// table's worth of grains has never been written.
    directory: Vec<u32>,
    /// Whether each grain is deflated, and behind a marker saying how many
    /// bytes it takes.
    squeezed: bool,
}

#[cfg(any(unix, windows))]
impl Vmdk<std::fs::File> {
    /// The image at `path`, and the files beside it that hold the disk:
    /// each extent the descriptor names, opened in the folder it is in.
    ///
    /// This reads every kind of VMDK: one whose descriptor is inside it is
    /// read as [`Vmdk::open`] reads it, and the one file is the disk.
    ///
    /// A name in a descriptor is read as a name and never as a path: one
    /// with a folder in it is refused, so that opening an image cannot be
    /// made to read a file somewhere else.
    pub fn beside(path: &Path) -> Result<Vmdk<std::fs::File>, Error> {
        use std::fs::File;

        let file = File::open(path)?;
        let whole = file.size()?;
        let mut head = [0u8; HEADER];
        // What there is of a header: a descriptor of plain text is as long
        // as its text, and only the kinds with a header are padded.
        let read = file.read_at(0, &mut head)?;
        if read < MAGIC.len() {
            return Err(Error::Unrecognized);
        }
        let text = if &head[..4] == MAGIC {
            if read < HEADER {
                return Err(Error::Unrecognized);
            }
            if le64(&head, 12) != 0 {
                // A sparse extent holding a disk of its own: the grains are
                // in this file, and what the descriptor names is itself.
                return Vmdk::open(file);
            }
            // A header of no capacity holds no grains: it is a descriptor
            // with a header in front of it, as a tool that cuts a disk into
            // pieces writes.
            embedded(&file, &head, whole)?.ok_or(Error::VmdkSays)?
        } else {
            if !is_descriptor(&head[..read]) {
                return Err(Error::Unrecognized);
            }
            let mut raw = vec![0u8; whole.min(MOST_TEXT) as usize];
            file.read_exact_at(0, &mut raw)?;
            text_of(raw)
        };
        let said = said(&text);
        if said.parent {
            return Err(Error::Needs(Unsupported::Backing));
        }
        if said.extents.is_empty() || said.extents.len() > MOST_EXTENTS {
            return Err(Error::VmdkSays);
        }
        let folder = path.parent().unwrap_or(Path::new("."));
        let mut pieces = Vec::with_capacity(said.extents.len());
        let mut at = 0u64;
        for line in &said.extents {
            let holds = match line.kind {
                Kind::Zero => Holds::Zero,
                Kind::Flat => Holds::Flat {
                    from: File::open(beside_path(folder, line.name.as_deref())?)?,
                    at: sectors(line.at)?,
                },
                Kind::Sparse => {
                    let from = File::open(beside_path(folder, line.name.as_deref())?)?;
                    let room = from.size()?;
                    Holds::Sparse(Sparse::open(from, room)?)
                }
                // SESPARSE, the one VMware's newest tools write, keeps its
                // tables somewhere else again and is not read.
                Kind::Other => return Err(Error::Needs(Unsupported::Feature)),
            };
            // A sparse extent's own header says how long the disk it holds
            // is, which is what the descriptor's number should say; for the
            // other kinds the descriptor is all there is.
            let len = match &holds {
                Holds::Sparse(sparse) => sparse.size,
                _ => sectors(line.sectors)?,
            };
            pieces.push(Piece { at, len, holds });
            at = at.checked_add(len).ok_or(Error::VmdkSays)?;
        }
        Ok(Vmdk { size: at, pieces })
    }
}

impl<D: Disk> Vmdk<D> {
    /// The image in `inner`, if it is one that holds a whole disk on its
    /// own: a sparse extent, whose descriptor and grains are in the one
    /// file.
    ///
    /// A descriptor naming files beside it is refused, as is an image
    /// holding only what changed from another one: both are files a reader
    /// of one cannot reach. [`Vmdk::beside`] is given a path, and reads
    /// the first of them.
    pub fn open(inner: D) -> Result<Vmdk<D>, Error> {
        let whole = inner.size()?;
        let mut head = [0u8; HEADER];
        let read = inner.read_at(0, &mut head)?;
        if read < MAGIC.len() {
            return Err(Error::Unrecognized);
        }
        if &head[..4] != MAGIC {
            return Err(if is_descriptor(&head[..read]) {
                Error::Needs(Unsupported::Beside)
            } else {
                Error::Unrecognized
            });
        }
        if read < HEADER {
            return Err(Error::Unrecognized);
        }
        if le64(&head, 12) == 0 {
            return Err(Error::Needs(Unsupported::Beside));
        }
        // What its own descriptor says about another image behind it: the
        // holes of such an image are that image's data, not zeroes, so
        // reading it alone would answer a disk that never existed.
        if let Some(text) = embedded(&inner, &head, whole)?
            && said(&text).parent
        {
            return Err(Error::Needs(Unsupported::Backing));
        }
        let sparse = Sparse::open(inner, whole)?;
        let size = sparse.size;
        Ok(Vmdk {
            size,
            pieces: vec![Piece {
                at: 0,
                len: size,
                holds: Holds::Sparse(sparse),
            }],
        })
    }

    /// How long the disk is.
    pub fn disk_size(&self) -> u64 {
        self.size
    }
}

impl<D: Disk> Disk for Vmdk<D> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.size)
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.size.checked_sub(at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left) as usize;
        if want == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < want {
            let at = at + done as u64;
            let Some(piece) = self.pieces.iter().find(|p| p.at <= at && at - p.at < p.len) else {
                // The extents do not reach that far, which only an extent
                // of no length at all leaves room for.
                buf[done..want].fill(0);
                return Ok(want);
            };
            let into = at - piece.at;
            let take = (want - done).min((piece.len - into) as usize);
            let out = &mut buf[done..done + take];
            match &piece.holds {
                Holds::Zero => out.fill(0),
                Holds::Flat { from, at: from_at } => {
                    // A flat extent's file may be shorter than the
                    // descriptor says, as a disk whose end has never been
                    // written is given no room for it.
                    let read = from.read_at(from_at + into, out)?;
                    out[read..].fill(0);
                }
                Holds::Sparse(sparse) => {
                    let read = sparse.read_at(into, out)?;
                    out[read..].fill(0);
                }
            }
            done += take;
        }
        Ok(done)
    }
}

impl<D: Disk> Sparse<D> {
    /// The sparse extent in `inner`, which is `whole` bytes long.
    fn open(inner: D, whole: u64) -> Result<Sparse<D>, Error> {
        if whole < HEADER as u64 {
            return Err(Error::Unrecognized);
        }
        let mut head = [0u8; HEADER];
        inner.read_exact_at(0, &mut head)?;
        if &head[..4] != MAGIC {
            return Err(Error::Unrecognized);
        }
        if le32(&head, 4) > MOST_VERSION {
            return Err(Error::Needs(Unsupported::Feature));
        }
        // A stream of compressed grains says nothing useful in the header
        // it wrote first: what counts is the footer at its end, which is
        // the same structure written once everything was known.
        if le64(&head, 56) == AT_END {
            head = footer(&inner, whole)?;
        }
        let flags = le32(&head, 8);
        let squeezed = flags & COMPRESSED != 0;
        if squeezed && le16(&head, 77) != DEFLATE {
            return Err(Error::Needs(Unsupported::Feature));
        }
        let capacity = le64(&head, 12);
        let grain_sectors = le64(&head, 20);
        let entries = u64::from(le32(&head, 44));
        if capacity == 0
            || grain_sectors < LEAST_GRAIN
            || !grain_sectors.is_power_of_two()
            || grain_sectors > MOST_GRAIN / SECTOR
            || entries == 0
            || entries > MOST_ENTRIES
        {
            return Err(Error::VmdkSays);
        }
        let grain = grain_sectors * SECTOR;
        let size = sectors(capacity)?;
        // One entry for each grain, in tables of `entries` entries, and one
        // entry of the directory for each of those tables.
        let tables = size.div_ceil(grain).div_ceil(entries);
        if tables > MOST_TABLES {
            return Err(Error::VmdkSays);
        }
        let room = tables * 4;
        let at = sectors(le64(&head, 56))?;
        if at == 0 || at.checked_add(room).is_none_or(|end| end > whole) {
            return Err(Error::VmdkSays);
        }
        let mut raw = vec![0u8; room as usize];
        inner.read_exact_at(at, &mut raw)?;
        let directory = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|four| u32::from_le_bytes(*four))
            .collect();
        Ok(Sparse {
            inner,
            size,
            grain,
            entries,
            directory,
            squeezed,
        })
    }

    /// Where the grain holding the `at` byte of the extent is in the file,
    /// or none where nothing has been written there. The entry is read
    /// when it is wanted: four bytes, and nothing is kept, as what reads an
    /// image reads it in order.
    fn grain_at(&self, at: u64) -> io::Result<Option<u64>> {
        let grain = at / self.grain;
        let (table, into) = (grain / self.entries, grain % self.entries);
        let Some(sector) = self.directory.get(table as usize).copied() else {
            return Ok(None);
        };
        if sector == NOTHING {
            return Ok(None);
        }
        let mut raw = [0u8; 4];
        self.inner
            .read_exact_at(u64::from(sector) * SECTOR + into * 4, &mut raw)?;
        let entry = u32::from_le_bytes(raw);
        if entry == NOTHING || entry == ZEROES {
            return Ok(None);
        }
        Ok(Some(u64::from(entry) * SECTOR))
    }

    /// A compressed grain, from `want` bytes of it onwards: behind a marker
    /// saying which sectors of the disk it holds and how many bytes it
    /// takes, and deflated.
    fn squeezed_grain(&self, at: u64, want: usize) -> io::Result<Vec<u8>> {
        use crate::deflate::{InBuffer, Inflate, OutBuffer};

        let mut marker = [0u8; 12];
        self.inner.read_exact_at(at, &mut marker)?;
        let room = u64::from(le32(&marker, 8));
        // A marker of no data at all is one of the markers that say where a
        // stream's own parts are, which no grain table points at.
        if room == 0 || room > self.grain * 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a grain the tables name is not a grain",
            ));
        }
        let mut packed = vec![0u8; room as usize];
        self.inner.read_exact_at(at + 12, &mut packed)?;
        let mut grain = vec![0u8; self.grain as usize];
        // A zlib header, which is what VMware writes: the specification
        // names deflate, and the stream carries the wrapper around it.
        let mut inflate =
            Inflate::new(15).map_err(|_| io::Error::other("deflate could not be started"))?;
        let mut out = OutBuffer::new(&mut grain);
        let mut input = InBuffer::new(&packed);
        let _ = inflate.inflate(&mut out, &mut input, crate::deflate::Flush::Finish);
        // The last grain of a disk of no whole number of grains comes out
        // short, which is enough as long as what was asked for is there.
        if out.pos < want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a compressed grain came out short",
            ));
        }
        Ok(grain)
    }
}

impl<D: Disk> Disk for Sparse<D> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.size)
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.size.checked_sub(at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left) as usize;
        if want == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < want {
            let at = at + done as u64;
            let into = at % self.grain;
            // No read crosses a grain: the next one is somewhere else in
            // the file, or nowhere at all.
            let take = (want - done).min((self.grain - into) as usize);
            match self.grain_at(at)? {
                None => buf[done..done + take].fill(0),
                Some(there) if self.squeezed => {
                    let need = into as usize + take;
                    let grain = self.squeezed_grain(there, need)?;
                    buf[done..done + take].copy_from_slice(&grain[into as usize..need]);
                }
                Some(there) => {
                    let read = self
                        .inner
                        .read_at(there + into, &mut buf[done..done + take])?;
                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the extent ends inside a grain its tables name",
                        ));
                    }
                    done += read;
                    continue;
                }
            }
            done += take;
        }
        Ok(done)
    }
}

/// The header at the end of a stream of compressed grains, between the
/// marker that says it follows and the one that says the stream ends.
fn footer<D: Disk>(inner: &D, whole: u64) -> Result<[u8; HEADER], Error> {
    if whole < FOOTER {
        return Err(Error::VmdkSays);
    }
    let mut tail = [0u8; FOOTER as usize];
    inner.read_exact_at(whole - FOOTER, &mut tail)?;
    let last = 2 * HEADER;
    if le32(&tail, 8) != 0
        || le32(&tail, 12) != MARKER_FOOTER
        || le32(&tail, last + 8) != 0
        || le32(&tail, last + 12) != MARKER_EOS
    {
        return Err(Error::VmdkSays);
    }
    let mut head = [0u8; HEADER];
    head.copy_from_slice(&tail[HEADER..last]);
    if &head[..4] != MAGIC || le64(&head, 56) == AT_END {
        return Err(Error::VmdkSays);
    }
    Ok(head)
}

/// The descriptor inside a sparse extent, if it holds one: the room the
/// header gives it, up to where the text ends.
fn embedded<D: Disk>(inner: &D, head: &[u8; HEADER], whole: u64) -> Result<Option<String>, Error> {
    let at = sectors(le64(head, 28))?;
    let room = sectors(le64(head, 36))?.min(MOST_TEXT);
    if at == 0 || room == 0 {
        return Ok(None);
    }
    if at.checked_add(room).is_none_or(|end| end > whole) {
        return Err(Error::VmdkSays);
    }
    let mut raw = vec![0u8; room as usize];
    inner.read_exact_at(at, &mut raw)?;
    Ok(Some(text_of(raw)))
}

/// The text of a descriptor: what it says, up to the first byte that is
/// nothing, as the room it is given is padded with zeroes.
fn text_of(raw: Vec<u8>) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Whether what a file begins with is a descriptor of its own. It has no
/// signature: what every tool writes is the line VMware's own writes, and
/// what names the kind is there either way.
fn is_descriptor(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    text.contains("# Disk Descriptor") || text.contains("createType")
}

/// What a descriptor says, of what reading the disk needs.
struct Said {
    /// Whether another image is behind this one: a disk holding only what
    /// changed from it, which its parent's own identifier says.
    parent: bool,
    extents: Vec<Line>,
}

/// One extent description: how long it is, what holds it, and where.
struct Line {
    sectors: u64,
    kind: Kind,
    name: Option<String>,
    /// Where the extent begins in the file, in sectors, which only a flat
    /// one gives.
    at: u64,
}

/// What an extent description says holds it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Flat,
    Sparse,
    Zero,
    Other,
}

/// What a descriptor's text says.
fn said(text: &str) -> Said {
    let mut parent = false;
    let mut extents: Vec<Line> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = value_of(line, "parentCID") {
            // Every disk with nothing behind it writes the same.
            parent |= !value.eq_ignore_ascii_case("ffffffff");
            continue;
        }
        if let Some(value) = value_of(line, "parentFileNameHint") {
            parent |= !unquoted(value).is_empty();
            continue;
        }
        if let Some(found) = extent(line) {
            // One more than are read, so that a descriptor naming too many
            // is told apart from one naming as many as are read.
            if extents.len() <= MOST_EXTENTS {
                extents.push(found);
            }
        }
    }
    Said { parent, extents }
}

/// What a `name=value` line of a descriptor gives for `name`.
fn value_of<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(name)?.trim_start();
    Some(rest.strip_prefix('=')?.trim())
}

/// What is between a pair of double quotes, or the text as it is where
/// there is no pair.
fn unquoted(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|rest| rest.split('"').next())
        .unwrap_or(text)
        .trim()
}

/// One extent description, if the line is one: an access, a number of
/// sectors, what holds them, and for every kind but `ZERO` a file name and
/// where in it the extent begins.
fn extent(line: &str) -> Option<Line> {
    let mut words = line.split_whitespace();
    if !matches!(words.next()?, "RW" | "RDONLY" | "NOACCESS") {
        return None;
    }
    let sectors = words.next()?.parse::<u64>().ok()?;
    let kind = match words.next()? {
        // A VMFS extent is a flat one on VMware's own file system, which is
        // nothing to a reader of a file; RDM is a disk of its own that the
        // descriptor only points at, and is left to the flat path, where
        // the file it names is what there is.
        "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" => Kind::Flat,
        "SPARSE" | "VMFSSPARSE" => Kind::Sparse,
        "ZERO" => Kind::Zero,
        _ => Kind::Other,
    };
    // The name is in quotes, as it may have spaces in it, and what follows
    // it is where the extent begins in the file.
    let (name, rest) = quoted(line);
    let at = rest
        .split_whitespace()
        .next()
        .and_then(|word| word.parse().ok())
        .unwrap_or(0);
    Some(Line {
        sectors,
        kind,
        name,
        at,
    })
}

/// What is between the first pair of double quotes of a line, and what
/// follows them.
fn quoted(line: &str) -> (Option<String>, &str) {
    let Some(open) = line.find('"') else {
        return (None, "");
    };
    let after = &line[open + 1..];
    let Some(close) = after.find('"') else {
        return (None, "");
    };
    (Some(after[..close].to_owned()), &after[close + 1..])
}

/// The file a descriptor names, in the folder the descriptor is in. The
/// name is read as a name: a path of more than one part, or one naming a
/// folder of its own, is refused, so that a descriptor cannot send a read
/// anywhere but beside itself.
#[cfg(any(unix, windows))]
fn beside_path(folder: &Path, name: Option<&str>) -> Result<PathBuf, Error> {
    let name = name.ok_or(Error::VmdkSays)?;
    let mut parts = Path::new(name).components();
    let one = parts.next();
    if parts.next().is_some()
        || !matches!(one, Some(std::path::Component::Normal(_)))
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(Error::VmdkElsewhere);
    }
    Ok(folder.join(name))
}

/// How many bytes a number of sectors is, or that the image says a disk
/// longer than can be counted.
fn sectors(of: u64) -> Result<u64, Error> {
    of.checked_mul(SECTOR).ok_or(Error::VmdkSays)
}

fn le16(of: &[u8], at: usize) -> u16 {
    of.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
