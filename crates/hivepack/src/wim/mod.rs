//! Reading WIM archives in safe Rust, read-only: the Windows Imaging
//! Format, which is what `install.wim` on a Windows disc is, what
//! `boot.wim` and a `.esd` are, and what `DISM` and `wimlib` write.
//!
//! A WIM is not an archive of files one after another. It holds
//! **resources**, each named by the SHA-1 of what it holds, and
//! **images** — whole trees of names — that point at them. Two files with
//! the same bytes are one resource in the archive however many trees name
//! it, and a `.wim` of several Windows editions is mostly one set of
//! resources with several trees over it.
//!
//! What this reads now: the header, the table of resources, the XML that
//! names the images, and each image's tree, with every entry's name,
//! attributes, times, length and SHA-1, and the files whose resources are
//! **not compressed**. What a resource is compressed with is named rather
//! than guessed at ([`Unsupported`]), so a `.wim` from a Windows disc says
//! it needs LZX and a `.esd` says it needs LZMS, which are what comes
//! next.
//!
//! Nothing here is a port. The layout is Microsoft's published *Windows
//! Imaging File Format (WIM)* specification, and it is checked against
//! what 7-Zip reads and writes: `docs/wim.md`.
//!
//! ```no_run
//! use hivepack::wim::Wim;
//!
//! let mut wim = Wim::open(std::fs::File::open("install.wim")?)?;
//! for image in wim.images().to_vec() {
//!     println!("{} {:?}", image.index, image.name);
//!     for entry in wim.entries(image.index)? {
//!         println!("  {} {} bytes", entry.path, entry.size);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod chunks;
mod dentry;
mod error;
mod lookup;
mod xml;
mod xpress;

use std::io::{self, Read, Seek, SeekFrom};

pub use dentry::Entry;
pub use error::{Error, Unsupported};

use lookup::Resources;

/// What a WIM begins with.
const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";

/// How long the header is, as every tool writes it.
const HEADER: usize = 208;
/// The version every tool writes, and the one written instead where an
/// archive may hold LZMS or solid resources — measured: `wimlib-imagex`
/// writes `0x0e00` for `--compress=LZMS` and for `--solid`, which is what
/// a `.esd` is. Reading it is what lets such an archive be told apart and
/// say which compression it needs, rather than being refused as a version
/// nothing knows.
const VERSION: u32 = 0x0001_0d00;
const VERSION_SOLID: u32 = 0x0000_0e00;

/// The header's flags that matter here.
const COMPRESSION: u32 = 0x0000_0002;
const SPANNED: u32 = 0x0000_0008;
const XPRESS: u32 = 0x0002_0000;
const LZX: u32 = 0x0004_0000;
const LZMS: u32 = 0x0008_0000;
const XPRESS2: u32 = 0x0020_0000;
/// Every compression bit, so that one nothing knows is told from none.
const EVERY_COMPRESSION: u32 = 0x00FF_0000;

/// How much of a metadata resource is read: a tree of a million entries
/// takes a hundred megabytes of it, and it is read into memory whole.
const MOST_METADATA: u64 = 256 << 20;

/// How deep an image's directories may go, as deep a chain of them as the
/// readers beside this one walk. How many entries one image may hold is
/// `dentry`'s own.
pub const MAX_DEPTH: usize = 1024;

/// Which compression an archive's resources are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// None: every resource is the bytes themselves.
    None,
    Xpress,
    Lzx,
    Lzms,
}

impl Compression {
    /// What it is called, as every tool names it.
    pub fn says(&self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Xpress => "XPRESS",
            Compression::Lzx => "LZX",
            Compression::Lzms => "LZMS",
        }
    }

    /// What reading a resource in it needs, where that is not here yet.
    fn needs(&self) -> Option<Unsupported> {
        match self {
            Compression::None => None,
            // XPRESS is decoded: `wim::xpress`, from [MS-XCA].
            Compression::Xpress => None,
            Compression::Lzx => Some(Unsupported::Lzx),
            Compression::Lzms => Some(Unsupported::Lzms),
        }
    }
}

/// Where a resource is, how long it is in the archive, and how long what it
/// holds is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resource {
    pub(crate) at: u64,
    /// How many bytes it takes in the archive.
    pub(crate) packed: u64,
    /// How many bytes it holds.
    pub(crate) size: u64,
    pub(crate) flags: u8,
}

impl Resource {
    /// The 24 bytes a resource header is.
    fn of(raw: &[u8], at: usize) -> Resource {
        let packed_flags = le64(raw, at);
        Resource {
            packed: packed_flags & ((1 << 56) - 1),
            flags: (packed_flags >> 56) as u8,
            at: le64(raw, at + 8),
            size: le64(raw, at + 16),
        }
    }

    /// Whether the resource's bytes are compressed, which the flag says
    /// and the header's own compression names.
    fn compressed(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// Whether it is a solid block: many files compressed together, which
    /// an `.esd` holds.
    fn solid(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Whether it is on a file of `whole` bytes.
    fn on_the_file(&self, whole: u64) -> bool {
        self.at
            .checked_add(self.packed)
            .is_some_and(|end| end <= whole)
    }
}

/// One image of an archive: a whole tree of names over the resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// Counted from 1, as every tool counts images.
    pub index: u32,
    /// The name the XML gives it, where it has one: `Windows 11 Pro`.
    pub name: Option<String>,
    /// What the XML says it holds, where it says: the number of files and
    /// directories, and the bytes they take.
    pub files: Option<u64>,
    pub directories: Option<u64>,
    pub bytes: Option<u64>,
    /// Where its tree is: the metadata resource, in the order the table
    /// holds them.
    metadata: Resource,
}

/// A WIM archive, read-only.
pub struct Wim<R> {
    reader: R,
    whole: u64,
    compression: Compression,
    /// How many bytes a chunk of a compressed resource holds. Zero where
    /// nothing is compressed.
    chunk: u32,
    images: Vec<Image>,
    resources: Resources,
}

impl<R: Read + Seek> Wim<R> {
    /// The archive in `reader`, if it is one: its header, its table of
    /// resources and the XML that names its images.
    ///
    /// A part of a split archive (`.swm`) is refused
    /// ([`Unsupported::Spanned`]): the resources it names are in files
    /// this cannot reach.
    pub fn open(mut reader: R) -> Result<Wim<R>, Error> {
        let whole = reader.seek(SeekFrom::End(0))?;
        if whole < HEADER as u64 {
            return Err(Error::Unrecognized);
        }
        let mut header = [0u8; HEADER];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(Error::Unrecognized);
        }
        // Past here the file says it is a WIM, so what it says is wrong
        // rather than somebody else's.
        if le32(&header, 8) as usize != HEADER {
            return Err(Error::Says);
        }
        let version = le32(&header, 12);
        if version != VERSION && version != VERSION_SOLID {
            return Err(Error::Version { version });
        }
        let flags = le32(&header, 16);
        let chunk = le32(&header, 20);
        let parts = le16(&header, 42);
        if parts > 1 || flags & SPANNED != 0 {
            return Err(Error::Needs(Unsupported::Spanned));
        }
        let compression = compression_of(flags)?;
        let images_said = le32(&header, 44);

        let table = Resource::of(&header, 48);
        let xml = Resource::of(&header, 72);
        if !table.on_the_file(whole) || !xml.on_the_file(whole) {
            return Err(Error::Says);
        }

        let resources = lookup::read(&mut reader, &table, whole, compression, chunk)?;
        let names = xml::read(&mut reader, &xml, compression, chunk)?;

        // The images are the metadata resources, in the order the table
        // holds them, and the XML names them by the same order.
        let mut images = Vec::new();
        for (i, metadata) in resources.metadata().enumerate() {
            let index = i as u32 + 1;
            let said = names.iter().find(|image| image.index == index);
            images.push(Image {
                index,
                name: said.and_then(|i| i.name.clone()),
                files: said.and_then(|i| i.files),
                directories: said.and_then(|i| i.directories),
                bytes: said.and_then(|i| i.bytes),
                metadata,
            });
        }
        // The header's own count is a hint; what is there is what is read.
        // A `.wim` written by a tool that stopped half way says more
        // images than it holds, and the trees it has still read.
        let _ = images_said;

        Ok(Wim {
            reader,
            whole,
            compression,
            chunk,
            images,
            resources,
        })
    }

    /// Which compression the archive's resources are in.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// How many bytes a chunk of a compressed resource holds, where
    /// anything is compressed.
    pub fn chunk_size(&self) -> u32 {
        self.chunk
    }

    /// The images the archive holds, in order.
    pub fn images(&self) -> &[Image] {
        &self.images
    }

    /// How many resources the table holds, each named by the SHA-1 of what
    /// it holds.
    pub fn resources(&self) -> usize {
        self.resources.len()
    }

    /// The tree of the `index` image, parents before what they hold, each
    /// entry with the path to it.
    ///
    /// The length and the SHA-1 of a file come from the table of
    /// resources, which is where a WIM keeps them: an entry whose hash is
    /// in no resource is a file of no bytes, as every tool writes one.
    pub fn entries(&mut self, index: u32) -> Result<Vec<Entry>, Error> {
        let image = self
            .images
            .iter()
            .find(|image| image.index == index)
            .ok_or(Error::NoSuchImage { index })?;
        let metadata = image.metadata;
        let raw = read_resource(
            &mut self.reader,
            &metadata,
            self.whole,
            self.compression,
            self.chunk,
            MOST_METADATA,
        )?;
        dentry::tree(&raw, &self.resources)
    }

    /// A file's bytes, its chunks decompressed where its resource is
    /// compressed with a compression there is a decoder for.
    ///
    /// A file of no bytes reads as none. A directory is an error
    /// ([`Error::NotAFile`]), and so is a reparse point
    /// ([`Unsupported::Reparse`]), whose data is not a file's bytes.
    pub fn read(&mut self, entry: &Entry) -> Result<Vec<u8>, Error> {
        if entry.is_dir() {
            return Err(Error::NotAFile);
        }
        if let Some(tag) = entry.reparse_tag {
            return Err(Error::Needs(Unsupported::Reparse { tag }));
        }
        let Some(resource) = entry.resource else {
            return Ok(Vec::new());
        };
        read_resource(
            &mut self.reader,
            &resource,
            self.whole,
            self.compression,
            self.chunk,
            u64::MAX,
        )
    }

    /// The archive it was opened on.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// Which compression the header's flags say, or what it needs that is not
/// known here.
fn compression_of(flags: u32) -> Result<Compression, Error> {
    if flags & COMPRESSION == 0 {
        // Nothing is compressed. A tool that leaves a compression bit set
        // with this one clear means none of it: the bit that counts is
        // this one.
        return Ok(Compression::None);
    }
    match flags & EVERY_COMPRESSION {
        XPRESS | XPRESS2 => Ok(Compression::Xpress),
        LZX => Ok(Compression::Lzx),
        LZMS => Ok(Compression::Lzms),
        other => Err(Error::Needs(Unsupported::Compression { flags: other })),
    }
}

/// What a resource holds, up to `most` bytes of it.
///
/// A compressed resource is read chunk by chunk (`chunks`) where there is
/// a decoder for its compression, and refused by the name of that
/// compression where there is not. A solid one is refused by its own name:
/// read as the bytes it is, it would be read as rubbish.
pub(crate) fn read_resource<R: Read + Seek>(
    reader: &mut R,
    resource: &Resource,
    whole: u64,
    compression: Compression,
    chunk: u32,
    most: u64,
) -> Result<Vec<u8>, Error> {
    if !resource.on_the_file(whole) {
        return Err(Error::Resource);
    }
    if resource.solid() {
        return Err(Error::Needs(Unsupported::Solid));
    }
    if resource.compressed() {
        if let Some(needs) = compression.needs() {
            return Err(Error::Needs(needs));
        }
        if compression == Compression::None {
            // Flags that say compressed in an archive whose header says
            // nothing is compressed: the two disagree.
            return Err(Error::Needs(Unsupported::Compression {
                flags: EVERY_COMPRESSION,
            }));
        }
        return chunks::read(reader, resource, whole, compression, chunk, most);
    }
    // Not compressed: what it holds is what it takes, and nothing else is
    // a resource this can read.
    if resource.packed != resource.size {
        return Err(Error::Resource);
    }
    if resource.size > most {
        return Err(Error::TooMany);
    }
    let mut raw = vec![0u8; resource.size as usize];
    reader.seek(SeekFrom::Start(resource.at))?;
    reader.read_exact(&mut raw).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Error::Resource
        } else {
            Error::Io(e)
        }
    })?;
    Ok(raw)
}

pub(crate) fn le16(of: &[u8], at: usize) -> u16 {
    of.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

pub(crate) fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

pub(crate) fn le64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
