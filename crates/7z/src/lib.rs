//! Reading 7z archives in safe Rust, ported from the 7z decoder of the LZMA
//! SDK (7-Zip 26.05), which is in the public domain, and writing them, from the
//! description of the format.
//!
//! [`Archive::open`] reads an archive's headers (`SzArEx_Open`), encoded
//! ones included, and lists its files: their names, sizes, attributes,
//! times and CRCs. A file's data comes from its folder, a stream that may
//! hold several files (a solid block), compressed with Copy, LZMA, LZMA2,
//! PPMd, Deflate, Deflate64, BZip2 or Zstandard, after a branch converter
//! (x86 BCJ, ARM, ARM-Thumb, ARM64, PowerPC, SPARC, IA-64, RISC-V), the delta
//! or swap filters or BCJ2, in any graph of coders. What the SDK decodes gets
//! its answers; the rest goes as far as 7-Zip's program does, AES included,
//! with a password ([`Options::password`], [`Archive::set_password`]):
//!
//! - [`Archive::extract`] decodes a file's whole folder, as
//!   `SzArEx_Extract` does, and keeps it for the folder's next file;
//! - [`Archive::files`] reads the files one after another, each folder
//!   decoded once, in pieces, so that a solid block of any size takes
//!   little memory.
//!
//! The rules the port follows, and how it is checked against the SDK and
//! 7-Zip, are in the repository: `docs/7z.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut archive = hivepack_7z::Archive::open(std::fs::File::open("backup.7z")?)?;
//! let mut files = archive.files();
//! while let Some(entry) = files.next()? {
//!     let mut data = Vec::new();
//!     files.read_to_end(&mut data)?;
//!     println!("{} {} bytes", entry.name, data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`Writer`] writes an archive: Copy, LZMA, LZMA2, Deflate or BZip2, with a
//! branch converter or the delta filter before LZMA and LZMA2, solid or not, and
//! AES with a password, the names too if wanted.
//!
//! ```no_run
//! use std::io::Write;
//!
//! let file = std::io::BufWriter::new(std::fs::File::create("backup.7z")?);
//! let mut archive = hivepack_7z::Writer::new(file)?;
//! archive.add_directory(hivepack_7z::NewEntry::new("notes"))?;
//! archive.start_file(hivepack_7z::NewEntry::new("notes/hello.txt"))?;
//! archive.write_all(b"hello\n")?;
//! archive.finish()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod aes7z;
mod arc_in;
mod bcj2;
mod bra;
mod dec;
mod error;
mod lzma_dec;
mod ppmd7;
mod writer;

use std::io::{self, Read, Seek};

pub use arc_in::SIGNATURE;
pub use error::{Error, Result};
pub use writer::{Filter, Method, NewEntry, RandomSource, WriteOptions, Writer};

use aes7z::{Decoding, MAX_KEY_CYCLES};
use arc_in::ArEx;
use dec::FolderDecoder;

/// The 7-Zip release whose LZMA SDK this crate follows.
pub const UPSTREAM_VERSION: &str = "26.05";

/// `CrcCalc`: the CRC-32 7z checks its headers and files with.
pub(crate) fn crc(data: &[u8]) -> u32 {
    hivepack_deflate::crc32(0, data)
}

/// How an archive is opened.
#[derive(Clone, PartialEq, Eq)]
pub struct Options {
    /// The most the description of the archive may take in memory, its
    /// headers decoded, in bytes: past it, the archive fails to open with
    /// [`Error::Mem`]. 1 GiB by default.
    pub memory_limit: u64,
    /// The most a folder's dictionaries and models may take, in bytes, and
    /// [`Archive::decode_folder`] and [`Archive::extract`] the folder they
    /// keep in memory: past it, they fail with [`Error::Mem`], as does
    /// reading the folder with [`Archive::files`]. An archive says how much
    /// it needs, and the SDK has no such limit. 4 GiB by default, the most
    /// LZMA's dictionary and PPMd's model can be.
    pub decoder_memory_limit: u64,
    /// The password of an encrypted archive; see also
    /// [`Archive::set_password`], for one whose names can be read without it.
    /// 7-Zip encrypts with AES, its key made by hashing the password.
    pub password: Option<String>,
    /// How many times a key may be hashed, as a power of 2: past it, the
    /// data is [`Error::Unsupported`]. An archive says how many, up to about
    /// a second for each key at 7-Zip's limit, 24, the default; 7-Zip writes
    /// 19.
    pub max_key_cycles: u32,
}

impl core::fmt::Debug for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options")
            .field("memory_limit", &self.memory_limit)
            .field("decoder_memory_limit", &self.decoder_memory_limit)
            .field("password", &self.password.as_ref().map(|_| "(hidden)"))
            .field("max_key_cycles", &self.max_key_cycles)
            .finish()
    }
}

impl Default for Options {
    fn default() -> Self {
        Options {
            memory_limit: 1 << 30,
            decoder_memory_limit: 1 << 32,
            password: None,
            max_key_cycles: MAX_KEY_CYCLES,
        }
    }
}

/// A file of an archive, as its headers describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its index in the archive.
    pub index: usize,
    /// Its name, as 7z keeps it: UTF-16 (`SzArEx_GetFileNameUtf16`).
    /// Empty when the archive has no names.
    pub name_utf16: Vec<u16>,
    /// Its name as text; what is not UTF-16 is U+FFFD.
    pub name: String,
    /// Its size, 0 for a directory.
    pub size: u64,
    /// `SzArEx_IsDir`: a directory (an empty stream that is not an empty
    /// file).
    pub is_dir: bool,
    /// The CRC of its data, if the archive has one.
    pub crc: Option<u32>,
    /// Its Windows attributes, if the archive has them; 7-Zip keeps a Unix
    /// mode in the high 16 bits, with bit 15 (`0x8000`) set.
    pub attributes: Option<u32>,
    /// When it was last written, in 100 ns since 1601 (an NTFS time).
    pub mtime: Option<u64>,
    /// When it was created, in the same units.
    pub ctime: Option<u64>,
    /// The folder its data is in; none for a file without data (empty, or
    /// a directory).
    pub folder: Option<usize>,
    /// Whether its data is encrypted.
    pub encrypted: bool,
}

/// A 7z archive, open for reading.
pub struct Archive<R> {
    reader: R,
    db: ArEx,
    decoding: Decoding,
    /// Which folders have an AES coder.
    encrypted: Vec<bool>,
    /// `SzArEx_Extract`'s cache: the folder last decoded, and its data.
    cache: Option<(usize, Vec<u8>)>,
}

impl<R: Read + Seek> Archive<R> {
    /// `SzArEx_Open`: the archive's headers, read with the default
    /// [`Options`].
    pub fn open(reader: R) -> Result<Self> {
        Archive::open_with(reader, &Options::default())
    }

    /// `SzArEx_Open`, with `options`.
    pub fn open_with(mut reader: R, options: &Options) -> Result<Self> {
        let decoding = Decoding::new(
            options.decoder_memory_limit,
            options.password.as_deref(),
            options.max_key_cycles,
        );
        let (db, decoding) = arc_in::open(&mut reader, options.memory_limit, decoding)?;
        let encrypted = (0..db.db.num_folders as usize)
            .map(|fo| dec::folder_is_encrypted(&db.db, fo))
            .collect();
        Ok(Archive {
            reader,
            db,
            decoding,
            encrypted,
            cache: None,
        })
    }

    /// The password for the encrypted files from now on. A wrong one shows as
    /// [`Error::WrongPassword`] when they are read: 7z has nothing to check it
    /// with but the data.
    pub fn set_password(&mut self, password: &str) {
        self.decoding.set_password(password);
        // What a wrong password decoded to is not the folder.
        self.cache = None;
    }

    /// The error for file `index`'s CRC not matching.
    fn crc_error(&self, index: usize) -> Error {
        let folder = self.db.file_to_folder[index] as usize;
        if self.encrypted.get(folder).copied().unwrap_or(false) {
            Error::WrongPassword
        } else {
            Error::Crc
        }
    }

    /// The number of files.
    pub fn len(&self) -> usize {
        self.db.num_files as usize
    }

    /// Whether the archive has no file.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of folders.
    pub fn folders(&self) -> usize {
        self.db.db.num_folders as usize
    }

    /// File `index`.
    ///
    /// # Panics
    ///
    /// If `index` is not below [`len`](Self::len).
    pub fn entry(&self, index: usize) -> Entry {
        let db = &self.db;
        let name_utf16 = db.file_name_utf16(index);
        let folder = db.file_to_folder[index];
        Entry {
            index,
            name: String::from_utf16_lossy(&name_utf16),
            name_utf16,
            size: db.file_size(index),
            is_dir: db.is_dir(index),
            crc: db.crcs.check(index).then(|| db.crcs.vals[index]),
            attributes: db.attribs.check(index).then(|| db.attribs.vals[index]),
            mtime: db.mtime.check(index).then(|| db.mtime.vals[index]),
            ctime: db.ctime.check(index).then(|| db.ctime.vals[index]),
            folder: (folder != u32::MAX).then_some(folder as usize),
            encrypted: self
                .encrypted
                .get(folder as usize)
                .copied()
                .unwrap_or(false),
        }
    }

    /// The files, in order.
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        (0..self.len()).map(|i| self.entry(i))
    }

    /// The archive's reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// The archive, closed: its reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// `SzAr_GetFolderUnpackSize`: folder `folder`'s unpacked size.
    pub fn folder_size(&self, folder: usize) -> u64 {
        self.db.db.folder_unpack_size(folder)
    }

    /// Not in the SDK: the bytes folder `folder`'s packed streams take in
    /// the archive, which it decodes to [`folder_size`](Self::folder_size)
    /// bytes. 0 for a folder that is not there.
    pub fn folder_packed_size(&self, folder: usize) -> u64 {
        let ar = &self.db.db;
        let stream = |fo: usize| ar.fo_start_pack_stream_index.get(fo).copied();
        let position = |s: u32| ar.pack_positions.get(s as usize).copied();
        match (stream(folder), stream(folder + 1)) {
            (Some(first), Some(end)) => match (position(first), position(end)) {
                (Some(start), Some(stop)) => stop.saturating_sub(start),
                _ => 0,
            },
            _ => 0,
        }
    }

    /// `SzAr_DecodeFolder`: all of folder `folder`, checked.
    pub fn decode_folder(&mut self, folder: usize) -> Result<Vec<u8>> {
        if folder >= self.folders() {
            return Err(Error::Param);
        }
        let size = self.folder_size(folder);
        if size > usize::MAX as u64 || size > self.decoding.limit {
            return Err(Error::Mem);
        }
        // That it can be had, before the allocation that cannot fail softly.
        let mut probe = Vec::<u8>::new();
        probe
            .try_reserve_exact(size as usize)
            .map_err(|_| Error::Mem)?;
        drop(probe);
        let mut out = vec![0; size as usize];
        dec::decode_folder(
            &self.db.db,
            folder,
            &mut self.reader,
            self.db.data_pos,
            &mut self.decoding,
            &mut out,
        )?;
        Ok(out)
    }

    /// `SzArEx_Extract`: file `index`'s data, its whole folder decoded and
    /// kept for the folder's next file, its CRC checked. A folder that fails
    /// fails all its files.
    pub fn extract(&mut self, index: usize) -> Result<Vec<u8>> {
        if index >= self.len() {
            return Err(Error::Param);
        }
        let folder_index = self.db.file_to_folder[index];
        if folder_index == u32::MAX {
            return Ok(Vec::new());
        }
        let folder_index = folder_index as usize;
        if self.cache.as_ref().is_none_or(|(f, _)| *f != folder_index) {
            self.cache = None;
            let data = self.decode_folder(folder_index)?;
            self.cache = Some((folder_index, data));
        }
        let Some((_, data)) = self.cache.as_ref() else {
            return Err(Error::Fail);
        };
        let db = &self.db;
        let unpack_pos = db.unpack_positions[index];
        let offset = unpack_pos - db.unpack_positions[db.folder_to_file[folder_index] as usize];
        let size = db.unpack_positions[index + 1] - unpack_pos;
        if offset.saturating_add(size) > data.len() as u64 {
            return Err(Error::Fail);
        }
        let file = &data[offset as usize..(offset + size) as usize];
        if db.crcs.check(index) && crc(file) != db.crcs.vals[index] {
            return Err(self.crc_error(index));
        }
        Ok(file.to_vec())
    }

    /// A reader of the files, one after another.
    pub fn files(&mut self) -> Files<'_, R> {
        Files {
            archive: self,
            next: 0,
            current: None,
            folder: None,
        }
    }
}

/// The current file of [`Files`].
struct Current {
    index: usize,
    /// What is left of its data.
    left: u64,
    crc: u32,
    expected: Option<u32>,
}

/// The files of an archive, one after another: [`next`](Files::next)
/// moves to the next file, whose data the reader then reads. Each folder is
/// decoded once, in pieces; a file's CRC is checked when its data is read
/// to its end, and its folder's checks when the folder's last file is.
pub struct Files<'a, R> {
    archive: &'a mut Archive<R>,
    next: usize,
    current: Option<Current>,
    /// The folder being read, and its index.
    folder: Option<(usize, FolderDecoder)>,
}

impl<R: Read + Seek> Files<'_, R> {
    /// The next file, the rest of the current one's data skipped; none at
    /// the end.
    ///
    /// Not an `Iterator`: the file's data is read from `Files` itself,
    /// until the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Entry>> {
        if self.current.is_some() {
            io::copy(self, &mut io::sink()).map_err(io_to_error)?;
        }
        if self.next >= self.archive.len() {
            self.end_folder()?;
            return Ok(None);
        }
        let index = self.next;
        self.next += 1;
        let entry = self.archive.entry(index);
        if let Some(fo) = entry.folder {
            if self.folder.as_ref().is_none_or(|(f, _)| *f != fo) {
                self.end_folder()?;
                let db = &self.archive.db;
                let decoding = &mut self.archive.decoding;
                self.folder = Some((fo, FolderDecoder::new(&db.db, fo, db.data_pos, decoding)?));
            }
            // Skip what is between: the folder's data no file holds.
            let db = &self.archive.db;
            let start =
                db.unpack_positions[index] - db.unpack_positions[db.folder_to_file[fo] as usize];
            self.skip_to(start)?;
        }
        self.current = Some(Current {
            index,
            left: entry.size,
            crc: 0,
            expected: entry.crc,
        });
        Ok(Some(entry))
    }

    /// The folder read up to `pos`.
    fn skip_to(&mut self, pos: u64) -> Result<()> {
        let Some((_, folder)) = self.folder.as_mut() else {
            return Ok(());
        };
        let mut buf = [0u8; 8192];
        while folder.position() < pos {
            let n = ((pos - folder.position()) as usize).min(buf.len());
            if folder.read(&mut self.archive.reader, &mut buf[..n])? == 0 {
                return Err(Error::Data);
            }
        }
        Ok(())
    }

    /// The current folder read to its end, and checked.
    fn end_folder(&mut self) -> Result<()> {
        let Some((_, mut folder)) = self.folder.take() else {
            return Ok(());
        };
        let size = folder.size();
        let mut buf = [0u8; 8192];
        loop {
            let n = ((size - folder.position()) as usize).clamp(1, buf.len());
            if folder.read(&mut self.archive.reader, &mut buf[..n])? == 0 {
                return Ok(());
            }
        }
    }

    /// The index of the current file, if any.
    pub fn index(&self) -> Option<usize> {
        self.current.as_ref().map(|c| c.index)
    }

    fn read_current(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Some(current) = self.current.as_mut() else {
            return Ok(0);
        };
        if current.left == 0 {
            if let Some(expected) = current.expected.take()
                && current.crc != expected
            {
                return Err(self.archive.crc_error(current.index));
            }
            // The folder's checks, once its last file is read.
            let is_last = self.next >= self.archive.len()
                || self.archive.db.file_to_folder[self.next]
                    != self.archive.db.file_to_folder[current.index];
            if is_last && self.archive.db.file_to_folder[current.index] != u32::MAX {
                self.end_folder()?;
            }
            return Ok(0);
        }
        let Some((_, folder)) = self.folder.as_mut() else {
            return Err(Error::Fail);
        };
        let n = (current.left.min(buf.len() as u64)) as usize;
        let n = folder.read(&mut self.archive.reader, &mut buf[..n])?;
        if n == 0 {
            return Err(Error::Data);
        }
        current.crc = hivepack_deflate::crc32(current.crc, &buf[..n]);
        current.left -= n as u64;
        Ok(n)
    }
}

fn io_to_error(e: io::Error) -> Error {
    match e.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
        Some(&e) => e,
        None => Error::Read,
    }
}

impl<R: Read + Seek> Read for Files<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        Ok(self.read_current(buf)?)
    }
}
