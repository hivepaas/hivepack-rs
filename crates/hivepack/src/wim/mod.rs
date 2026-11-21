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
//! What this reads: the header, the table of resources, the XML that
//! names the images, and each image's tree, with every entry's name,
//! attributes, times, length and SHA-1 — and the files themselves, their
//! chunks decompressed where the resource is compressed, read whole
//! ([`Wim::read`]) or a chunk at a time ([`Wim::file`]). With the feature
//! `extract`, `extract_wim` takes one image out to a folder.
//!
//! **Every file is held to the SHA-1 the image names it by** as it is
//! read. A WIM carries no other check — none beside a chunk, none beside a
//! resource — so that hash is the one thing that says a file came out as
//! it went in.
//!
//! **XPRESS** (`wim::xpress`, from Microsoft's [MS-XCA]) and **LZX**
//! (`wim::lzx`, from [MS-PATCH]) are decoded, so a `.wim` from a Windows
//! disc reads whole: its tree as well as its files, an image's metadata
//! being a compressed resource itself. **LZMS** and a **solid block** are
//! named rather than guessed at ([`Unsupported`]), so a `.esd` opens and says
//! what it needs; LZMS has no published specification and the only
//! implementation of it is GPL-3.0-or-later.
//!
//! Nothing here is a port. The layout is Microsoft's published *Windows
//! Imaging File Format (WIM)* specification and the compressions are its
//! [MS-XCA] and [MS-PATCH]; wimlib, which is GPL-3.0-or-later, is built
//! and run as a program to write the archives the tests read back, never
//! read. It is checked against what 7-Zip and `wimlib-imagex` read and
//! write: `docs/wim.md`.
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
mod lzx;
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
            // LZX is decoded: `wim::lzx`, from [MS-PATCH].
            Compression::Lzx => None,
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
    /// **The whole file is held in memory.** For one of an unknown length,
    /// which an image of a Windows installation holds plenty of, read it
    /// through [`Wim::file`] instead: that holds one chunk at a time.
    ///
    /// A file of no bytes reads as none. A directory is an error
    /// ([`Error::NotAFile`]), and so is a reparse point
    /// ([`Unsupported::Reparse`]), whose data is not a file's bytes.
    pub fn read(&mut self, entry: &Entry) -> Result<Vec<u8>, Error> {
        let mut file = self.file(entry)?;
        let mut out = vec![0u8; usize::try_from(file.size()).map_err(|_| Error::Resource)?];
        let mut at = 0;
        while at < out.len() {
            match file.pull(&mut out[at..])? {
                // The resource gave less than it says it holds.
                0 => return Err(Error::Resource),
                read => at += read,
            }
        }
        Ok(out)
    }

    /// A file of an image, as a reader over its bytes.
    ///
    /// **One chunk is held, never the file**: a chunk is decompressed as
    /// it is reached, so a file of 4 GiB is read through a buffer of the
    /// archive's chunk size (32768 bytes, where nothing says otherwise).
    /// That is what makes an image of a Windows installation extractable
    /// on a machine that could not hold one of its files.
    ///
    /// A file of no bytes reads as none. A directory is an error
    /// ([`Error::NotAFile`]), and so is a reparse point
    /// ([`Unsupported::Reparse`]), whose data is not a file's bytes.
    pub fn file(&mut self, entry: &Entry) -> Result<File<'_, R>, Error> {
        if entry.is_dir() {
            return Err(Error::NotAFile);
        }
        if let Some(tag) = entry.reparse_tag {
            return Err(Error::Needs(Unsupported::Reparse { tag }));
        }
        let Some(resource) = entry.resource else {
            return Ok(File {
                how: How::Nothing,
                size: 0,
                given: 0,
                want: None,
                sha1: sha1::Sha1::default(),
            });
        };
        let size = resource.size;
        let how = reading_of(
            &mut self.reader,
            &resource,
            self.whole,
            self.compression,
            self.chunk,
        )?;
        Ok(File {
            how,
            size,
            given: 0,
            // A directory and a file of no bytes carry zeroes where the
            // hash goes, and a tree that names a resource by zeroes is
            // not naming this file by anything: there is nothing to hold
            // it to.
            want: (entry.hash != [0u8; 20]).then_some(entry.hash),
            sha1: sha1::Sha1::default(),
        })
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

/// Where one resource's bytes come from.
enum How<'a, R> {
    /// An entry whose hash names no resource: a file of no bytes.
    Nothing,
    /// A resource held as it is, from where it begins on the file.
    Plain {
        reader: &'a mut R,
        /// How much of it is still to come.
        left: u64,
    },
    /// A compressed resource: its chunks, decompressed as they are
    /// reached. Boxed, since it holds a chunk and the table of them and
    /// the other two hold a reader and a length.
    Chunks(Box<chunks::Reading<'a, R>>),
}

/// One file of an image, as a reader over its bytes: see [`Wim::file`],
/// which is what makes one.
///
/// **What it gives is held to the SHA-1 the archive names it by.** A WIM
/// carries no other check of a file's data — no CRC beside a chunk, no
/// digest beside a resource — so the hash in the tree is the one thing
/// that says the bytes are the bytes that went in. Read the file whole and
/// it is checked; stop part way and there is nothing to check it against.
pub struct File<'a, R> {
    how: How<'a, R>,
    size: u64,
    /// How much has been given out, for telling when the file is whole.
    given: u64,
    /// The SHA-1 the tree names it by, where it names one, and what has
    /// been read hashed as it goes.
    want: Option<[u8; 20]>,
    sha1: sha1::Sha1,
}

impl<R: Read + Seek> File<'_, R> {
    /// How many bytes it holds.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The next bytes into `buf`, and 0 once the file is read whole.
    ///
    /// This is [`Read::read`] saying what a WIM says when it fails:
    /// through `Read` the same failure arrives as an [`io::Error`], since
    /// that is all `Read` can carry.
    ///
    /// The last bytes of the file are given once the SHA-1 of all of them
    /// matches the one the archive names the file by, and never where it
    /// does not ([`Error::Hash`]).
    pub fn pull(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let read = match &mut self.how {
            How::Nothing => 0,
            How::Plain { reader, left } => {
                if *left == 0 || buf.is_empty() {
                    0
                } else {
                    let want = buf.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                    match reader.read(&mut buf[..want])? {
                        // The file ends before the resource says it does.
                        0 => return Err(Error::Resource),
                        read => {
                            *left -= read as u64;
                            read
                        }
                    }
                }
            }
            How::Chunks(reading) => reading.pull(buf)?,
        };
        if read == 0 {
            return Ok(0);
        }
        if self.want.is_some() {
            use sha1::Digest;
            self.sha1.update(&buf[..read]);
        }
        self.given += read as u64;
        if self.given >= self.size
            && let Some(want) = self.want
        {
            use sha1::Digest;
            let got: [u8; 20] = self.sha1.clone().finalize().into();
            if got != want {
                return Err(Error::Hash);
            }
        }
        Ok(read)
    }
}

impl<R: Read + Seek> Read for File<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pull(buf).map_err(io::Error::from)
    }
}

/// Where a resource's bytes come from, with every refusal made before any
/// of them is read.
///
/// A compressed resource is read chunk by chunk (`chunks`) where there is
/// a decoder for its compression, and refused by the name of that
/// compression where there is not. A solid one is refused by its own name:
/// read as the bytes it is, it would be read as rubbish.
fn reading_of<'a, R: Read + Seek>(
    reader: &'a mut R,
    resource: &Resource,
    whole: u64,
    compression: Compression,
    chunk: u32,
) -> Result<How<'a, R>, Error> {
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
        let reading = chunks::Reading::new(reader, resource, whole, compression, chunk)?;
        return Ok(How::Chunks(Box::new(reading)));
    }
    // Not compressed: what it holds is what it takes, and nothing else is
    // a resource this can read.
    if resource.packed != resource.size {
        return Err(Error::Resource);
    }
    reader.seek(SeekFrom::Start(resource.at))?;
    Ok(How::Plain {
        reader,
        left: resource.size,
    })
}

/// What a resource holds, up to `most` bytes of it: [`reading_of`] read
/// through.
pub(crate) fn read_resource<R: Read + Seek>(
    reader: &mut R,
    resource: &Resource,
    whole: u64,
    compression: Compression,
    chunk: u32,
    most: u64,
) -> Result<Vec<u8>, Error> {
    if resource.size > most {
        return Err(Error::TooMany);
    }
    let size = usize::try_from(resource.size).map_err(|_| Error::Resource)?;
    // An image's metadata is a resource like any other, and the table
    // names it by a hash too — but the hash is the table's, not the
    // resource's own, and `Resource` does not carry it: what is held to
    // its hash is a file, through `Wim::file`.
    let mut file = File {
        how: reading_of(reader, resource, whole, compression, chunk)?,
        size: resource.size,
        given: 0,
        want: None,
        sha1: sha1::Sha1::default(),
    };
    let mut out = vec![0u8; size];
    let mut at = 0;
    while at < out.len() {
        match file.pull(&mut out[at..])? {
            // The resource gave less than it says it holds.
            0 => return Err(Error::Resource),
            read => at += read,
        }
    }
    Ok(out)
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
