//! Reading NTFS file systems, read-only: the directories, the files, the
//! times each record carries, and the alternate data streams a file may
//! have beside its own data.
//!
//! [`Ntfs`] opens the file system on a [`Disk`] — a partition of a disk
//! image, or a file that holds one as it is — and walks it. This is what a
//! Windows installation, an external drive written on Windows, and the
//! data partition of a dual-boot machine hold.
//!
//! **This module is not a port.** Every other format in this crate is read
//! by code that is here; NTFS is read by the `ntfs` crate, because NTFS
//! has no published specification and the two implementations that could
//! be ported from are under the GPL. What is here is the layer that gives
//! the library a [`Disk`] to read, holds it to this crate's limits, and
//! turns what it answers into the entries and byte streams the rest of
//! this crate expects. Why that way, and what was measured before
//! choosing it, is in the repository: `docs/ntfs.md`.
//!
//! **A damaged image can still panic inside the library**, and not only
//! through a harness driving it directly: one of five images whose master
//! file table had been corrupted panics through [`Ntfs::walk`], at an
//! index entry shorter than its own header. The fix is not in a release.
//! That, and not only the compression, is why the feature is off by
//! default; `docs/ntfs.md` has every measurement.
//!
//! Two things the library does not do are refused here rather than passed
//! on. Compressed data it hands back still compressed, with no error at
//! all, so [`Ntfs::file`] refuses a compressed file instead of handing out
//! bytes that are not the file's. Encrypted data it cannot decrypt, as the
//! key is a Windows user's and is not in the image.
//!
//! ```no_run
//! use std::io::Read;
//!
//! use hivepack::ntfs::Ntfs;
//!
//! let fs = Ntfs::open(std::fs::File::open("windows.img")?)?;
//! println!("{:?}", fs.label());
//! let mut walk = fs.walk()?;
//! while let Some((path, entry)) = walk.next(&fs)? {
//!     println!("{path} {} bytes", entry.size);
//!     if entry.is_file() && !entry.compressed {
//!         let mut data = Vec::new();
//!         fs.file(&entry)?.read_to_end(&mut data)?;
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod cursor;
mod error;
mod time;

use std::collections::BTreeSet;
use std::io::{self, Read, Seek, SeekFrom};

use ::ntfs::attribute_value::NtfsAttributeValue;
use ::ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace};
use ::ntfs::{NtfsAttributeFlags, NtfsAttributeType};

use crate::image::Disk;

use cursor::Cursor;

pub use error::Error;
pub use time::Time;

/// What a boot sector names, where it names this file system. Where the
/// name is not there, this is not NTFS; the library only checks the
/// signature at the sector's end, which a partition table and a FAT file
/// system carry too, so the name is checked here.
const MAGIC: &[u8; 8] = b"NTFS    ";

/// How long the boot sector is. Every NTFS volume begins with one, and a
/// disk that does not hold a whole one is not a volume.
const SECTOR: usize = 512;

/// How many directories inside directories are walked, as deep a chain of
/// them as the FAT and squashfs readers walk.
pub const MAX_DEPTH: usize = 1024;

/// How many entries of one directory are read. NTFS keeps a directory as a
/// tree and a volume may hold millions of files, but one directory of more
/// than this is longer than any a tool writes, and the entries are held in
/// memory while they are given out.
const MOST_ENTRIES: usize = 1 << 20;

/// How many runs of one file's data are read: where its bytes are, which
/// is read whole before any of them. A file in this many pieces is more
/// fragmented than a volume a tool would leave behind, and each piece
/// costs 24 bytes here.
const MOST_EXTENTS: usize = 1 << 20;

/// How many records the master file table keeps for the file system's own
/// bookkeeping before anything that was put in it: `$MFT`, `$Bitmap`,
/// `$UpCase` and the rest. They are entries of the root directory like
/// any other, and no tool lists them, so they are left out here. The root
/// directory is record 5 and its entry for itself goes with them, which is
/// the only `.` an NTFS directory holds.
const RESERVED: u64 = 16;

/// Where a file's bytes are, as the file system says: a stretch of the
/// disk, or a stretch of nothing where a sparse file has a hole.
#[derive(Clone, Copy, Debug)]
struct Extent {
    /// How far into the file this stretch begins.
    from: u64,
    /// Where on the disk it begins, and none where it is a hole: a sparse
    /// file's bytes that were never written, which read as zero.
    at: Option<u64>,
    len: u64,
}

/// Whether an entry is a file or a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}

/// A file or a directory, as a directory of the file system holds it.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The name, as the record carries it. NTFS holds names as UTF-16, and
    /// what is not a name in Unicode is read with the replacement
    /// character in its place.
    pub name: String,
    /// How many bytes the file's own data holds, and 0 for a directory.
    /// This is the length its `$DATA` attribute says, not the length the
    /// directory repeats, which Windows updates late.
    pub size: u64,
    pub created: Option<Time>,
    pub modified: Option<Time>,
    pub accessed: Option<Time>,
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
    /// The data is compressed, and so is not read: [`Error::Compressed`].
    pub compressed: bool,
    /// The data is encrypted, and so is not read: [`Error::Encrypted`].
    pub encrypted: bool,
    /// The file has holes that were never written, which read as zero.
    pub sparse: bool,
    /// The file is a symbolic link, a junction, or a file Windows keeps
    /// through its overlay filter: [`Error::Reparse`].
    pub reparse: bool,
    /// How many names the file has. Two entries of the same file system
    /// whose [`Entry::record`] is the same are one file under two names.
    pub links: u16,
    kind: Kind,
    record: u64,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Directory
    }

    pub fn is_file(&self) -> bool {
        self.kind == Kind::File
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Which record of the master file table the file is: what says that
    /// two names are one file, and what [`Ntfs::file`] opens.
    pub fn record(&self) -> u64 {
        self.record
    }

    /// Whether the file's own data can be read, or why not — what
    /// [`Ntfs::file`] would answer, without going to the disk for it.
    ///
    /// This reads the flags the file's record carries. [`Ntfs::file`]
    /// checks the stream's own flags as well, which is where a file that
    /// holds one compressed stream beside a plain one is told apart.
    pub fn readable(&self) -> Result<(), Error> {
        match self.kind {
            Kind::Directory => Err(Error::NotAFile),
            Kind::File if self.reparse => Err(Error::Reparse),
            Kind::File if self.compressed => Err(Error::Compressed),
            Kind::File if self.encrypted => Err(Error::Encrypted),
            Kind::File => Ok(()),
        }
    }
}

/// An NTFS file system, read-only.
///
/// Reads are at offsets and never move a position, so one file system can
/// be read from more than one thread; nothing is cached, as the [`Disk`]
/// underneath may cache as it likes.
pub struct Ntfs<D> {
    disk: D,
    /// How long the disk is, read once: what a seek to its end needs.
    len: u64,
    inner: ::ntfs::Ntfs,
    label: Option<String>,
}

impl<D: Disk> Ntfs<D> {
    /// The file system on `disk`, if it holds one.
    pub fn open(disk: D) -> Result<Ntfs<D>, Error> {
        let len = disk.size()?;
        // The whole boot sector, and all of it: the library parses it as
        // one structure and *panics* where the stream ends inside it,
        // because the error binrw gives for a short read is not the one
        // its conversion expects (`error.rs:236`, an `unreachable!`).
        // Measured on disks of 11, 100, 256, 460 and 511 bytes, each
        // panicking, where 512 is refused properly: `docs/ntfs.md`. So
        // nothing shorter than a boot sector is handed over at all.
        //
        // The name in it is checked here for a second reason: the library
        // never looks at it, only at the two bytes at the sector's end,
        // which a FAT file system and a partition table carry too. They
        // reach it and are turned away by whichever of their fields
        // happens not to hold, which is luck rather than a check.
        let mut boot = [0u8; SECTOR];
        if disk.read_at(0, &mut boot)? != SECTOR || &boot[3..11] != MAGIC {
            return Err(Error::Unrecognized);
        }
        let mut cursor = Cursor::new(&disk, len);
        let mut inner = ::ntfs::Ntfs::new(&mut cursor).map_err(Error::says)?;
        // The table that says which letters are the same letter in another
        // case, which the library needs before it looks a name up.
        inner.read_upcase_table(&mut cursor).map_err(Error::says)?;
        let label = match inner.volume_name(&mut cursor) {
            Some(name) => Some(name.map_err(Error::says)?.name().to_string_lossy()),
            None => None,
        };
        Ok(Ntfs {
            disk,
            len,
            inner,
            label,
        })
    }

    /// The volume's name, where it has one.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// How many bytes a cluster holds: the unit the file system hands out
    /// space in.
    pub fn cluster_size(&self) -> u32 {
        self.inner.cluster_size()
    }

    /// How long the file system says it is, which may be shorter than the
    /// disk it is on.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// The disk back, as it was given.
    pub fn into_inner(self) -> D {
        self.disk
    }

    /// The entries of the root directory.
    pub fn read_root(&self) -> Result<Vec<Entry>, Error> {
        let mut cursor = self.cursor();
        let root = self
            .inner
            .root_directory(&mut cursor)
            .map_err(Error::says)?;
        let record = root.file_record_number();
        self.list(record)
    }

    /// The entries of a directory.
    pub fn read_dir(&self, entry: &Entry) -> Result<Vec<Entry>, Error> {
        if !entry.is_dir() {
            return Err(Error::NotADirectory);
        }
        self.list(entry.record)
    }

    /// The entry a path names, or none where the path names nothing. The
    /// parts are separated by `/`, and a leading one is allowed.
    pub fn lookup_path(&self, path: &str) -> Result<Option<Entry>, Error> {
        let mut entries = self.read_root()?;
        let mut found = None;
        for part in path.split('/').filter(|part| !part.is_empty()) {
            // NTFS names are case-insensitive as Windows writes them, and
            // the comparison that says which letters match is the table
            // the volume carries. Here the name has to be the name, as
            // this crate does not keep that table's rules.
            let Some(entry) = entries.iter().find(|entry| entry.name == part).cloned() else {
                return Ok(None);
            };
            if entry.is_dir() {
                entries = self.list(entry.record)?;
            } else {
                entries = Vec::new();
            }
            found = Some(entry);
        }
        Ok(found)
    }

    /// The bytes of a file.
    ///
    /// Refuses a file whose data is compressed or encrypted, which are not
    /// read, and a reparse point, whose content is not its own data.
    pub fn file(&self, entry: &Entry) -> Result<File<'_, D>, Error> {
        self.stream(entry, "")
    }

    /// The bytes of one of a file's streams: `""` for the file's own data,
    /// and the stream's name for an alternate data stream.
    ///
    /// A file's own data is what every tool shows; an alternate data
    /// stream is a second stretch of bytes under the same name, which
    /// Windows uses to mark where a file was downloaded from and which
    /// nothing outside Windows keeps.
    pub fn stream(&self, entry: &Entry, name: &str) -> Result<File<'_, D>, Error> {
        // What the record says, first: a compressed file is refused here
        // whichever stream was asked for, as the flag the record carries
        // is the one a caller can see on the entry.
        entry.readable()?;
        let mut cursor = self.cursor();
        let file = self
            .inner
            .file(&mut cursor, entry.record)
            .map_err(Error::says)?;
        let Some(item) = file.data(&mut cursor, name) else {
            // No such stream. A file's own data may be missing too, which
            // is a file of no bytes.
            return if name.is_empty() {
                Ok(File::empty(&self.disk))
            } else {
                Err(Error::NotAFile)
            };
        };
        let item = item.map_err(Error::says)?;
        let attribute = item.to_attribute().map_err(Error::says)?;
        // The flags of this stream, which are not the file's: a file may
        // hold a compressed stream beside an uncompressed one.
        let flags = attribute.flags();
        if flags.contains(NtfsAttributeFlags::COMPRESSED) {
            return Err(Error::Compressed);
        }
        if flags.contains(NtfsAttributeFlags::ENCRYPTED) {
            return Err(Error::Encrypted);
        }
        let len = attribute.value_length();
        let value = attribute.value(&mut cursor).map_err(Error::says)?;
        match value {
            // Short enough to be in the record itself, which is where a
            // file of a few hundred bytes is kept.
            NtfsAttributeValue::Resident(resident) => {
                let data = resident.data();
                let take = len.min(data.len() as u64) as usize;
                Ok(File {
                    disk: &self.disk,
                    resident: data[..take].to_vec(),
                    extents: Vec::new(),
                    len: take as u64,
                    at: 0,
                })
            }
            NtfsAttributeValue::NonResident(value) => {
                let mut extents = Vec::new();
                let mut covers = 0u64;
                for run in value.data_runs() {
                    let run = run.map_err(Error::says)?;
                    if extents.len() >= MOST_EXTENTS {
                        return Err(Error::TooMany);
                    }
                    let size = run.allocated_size();
                    if size == 0 {
                        continue;
                    }
                    extents.push(Extent {
                        from: covers,
                        at: run.data_position().value().map(|at| at.get()),
                        len: size,
                    });
                    covers = covers.saturating_add(size);
                }
                // The runs are whole clusters, so they cover at least the
                // length and usually a little more; less than the length
                // means the record and the runs do not agree, and there is
                // no telling which is right.
                if covers < len {
                    return Err(Error::Short { says: len, covers });
                }
                Ok(File {
                    disk: &self.disk,
                    resident: Vec::new(),
                    extents,
                    len,
                    at: 0,
                })
            }
            // The data is described by a list of attributes, which the
            // library reads but does not say where it put: refused rather
            // than read wrongly.
            NtfsAttributeValue::AttributeListNonResident(_) => Err(Error::AttributeList),
        }
    }

    /// The names of a file's alternate data streams, without the file's
    /// own data, which has no name.
    pub fn streams(&self, entry: &Entry) -> Result<Vec<String>, Error> {
        let mut cursor = self.cursor();
        let file = self
            .inner
            .file(&mut cursor, entry.record)
            .map_err(Error::says)?;
        let mut names = Vec::new();
        let mut attributes = file.attributes();
        while let Some(item) = attributes.next(&mut cursor) {
            let item = item.map_err(Error::says)?;
            let attribute = item.to_attribute().map_err(Error::says)?;
            if attribute.ty().map_err(Error::says)? != NtfsAttributeType::Data {
                continue;
            }
            let name = attribute.name().map_err(Error::says)?.to_string_lossy();
            if !name.is_empty() {
                if names.len() >= MOST_ENTRIES {
                    return Err(Error::TooMany);
                }
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Every file and directory, each with the path to it. The root's own
    /// entries come with no directory in front of them.
    pub fn walk(&self) -> Result<Walk, Error> {
        let root = self.read_root()?;
        let mut seen = BTreeSet::new();
        let mut cursor = self.cursor();
        if let Ok(at) = self.inner.root_directory(&mut cursor) {
            seen.insert(at.file_record_number());
        }
        Ok(Walk {
            stack: vec![(String::new(), root.into_iter())],
            seen,
        })
    }

    /// A cursor over the disk, for one call into the library.
    fn cursor(&self) -> Cursor<'_, D> {
        Cursor::new(&self.disk, self.len)
    }

    /// The entries a directory record holds.
    fn list(&self, record: u64) -> Result<Vec<Entry>, Error> {
        let mut cursor = self.cursor();
        let dir = self.inner.file(&mut cursor, record).map_err(Error::says)?;
        if !dir.is_directory() {
            return Err(Error::NotADirectory);
        }
        let index = dir.directory_index(&mut cursor).map_err(Error::says)?;
        let mut entries = index.entries();
        let mut names = Vec::new();
        while let Some(entry) = entries.next(&mut cursor) {
            let entry = entry.map_err(Error::says)?;
            // The last entry of a node carries no name.
            let Some(name) = entry.key() else {
                continue;
            };
            let name = name.map_err(Error::says)?;
            // A file Windows gave a long name also has the 8.3 name it
            // kept beside it, and the directory holds an entry for each.
            // The short one is left out, as the long name is the file's;
            // where the name is both at once the namespace says so, and it
            // is kept.
            if name.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let record = entry.file_reference().file_record_number();
            if record < RESERVED {
                continue;
            }
            if names.len() >= MOST_ENTRIES {
                return Err(Error::TooMany);
            }
            names.push((name.name().to_string_lossy(), record));
        }
        let mut out = Vec::with_capacity(names.len());
        for (name, record) in names {
            out.push(self.entry_of(name, record)?);
        }
        Ok(out)
    }

    /// What a record says about itself, as an [`Entry`].
    ///
    /// The directory repeats much of this beside the name, and Windows
    /// updates that copy late, so it is read from the record instead.
    fn entry_of(&self, name: String, record: u64) -> Result<Entry, Error> {
        let mut cursor = self.cursor();
        let file = self.inner.file(&mut cursor, record).map_err(Error::says)?;
        let info = file.info().map_err(Error::says)?;
        let flags = info.file_attributes();
        let kind = if file.is_directory() {
            Kind::Directory
        } else {
            Kind::File
        };
        let size = match kind {
            Kind::Directory => 0,
            Kind::File => match file.data(&mut cursor, "") {
                Some(item) => item
                    .map_err(Error::says)?
                    .to_attribute()
                    .map_err(Error::says)?
                    .value_length(),
                None => 0,
            },
        };
        Ok(Entry {
            name,
            size,
            created: Time::of(info.creation_time().nt_timestamp()),
            modified: Time::of(info.modification_time().nt_timestamp()),
            accessed: Time::of(info.access_time().nt_timestamp()),
            read_only: flags.contains(NtfsFileAttributeFlags::READ_ONLY),
            hidden: flags.contains(NtfsFileAttributeFlags::HIDDEN),
            system: flags.contains(NtfsFileAttributeFlags::SYSTEM),
            archive: flags.contains(NtfsFileAttributeFlags::ARCHIVE),
            compressed: flags.contains(NtfsFileAttributeFlags::COMPRESSED),
            encrypted: flags.contains(NtfsFileAttributeFlags::ENCRYPTED),
            sparse: flags.contains(NtfsFileAttributeFlags::SPARSE_FILE),
            reparse: flags.contains(NtfsFileAttributeFlags::REPARSE_POINT),
            links: file.hard_link_count(),
            record,
            kind,
        })
    }
}

/// The bytes of one stream of a file: what [`Ntfs::file`] gives.
///
/// Reading goes straight to the disk, at the places the file system said
/// the bytes are. A hole of a sparse file reads as zero, which is what it
/// holds.
pub struct File<'a, D> {
    disk: &'a D,
    /// The bytes themselves, where they are short enough to be in the
    /// record: then there are no extents.
    resident: Vec<u8>,
    extents: Vec<Extent>,
    len: u64,
    at: u64,
}

impl<'a, D: Disk> File<'a, D> {
    fn empty(disk: &'a D) -> File<'a, D> {
        File {
            disk,
            resident: Vec::new(),
            extents: Vec::new(),
            len: 0,
            at: 0,
        }
    }
}

impl<D: Disk> File<'_, D> {
    /// How many bytes it holds.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Which extent a position is in, where any is.
    fn extent(&self, at: u64) -> Option<&Extent> {
        let found = self
            .extents
            .binary_search_by(|extent| {
                if at < extent.from {
                    core::cmp::Ordering::Greater
                } else if at >= extent.from + extent.len {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .ok()?;
        self.extents.get(found)
    }
}

impl<D: Disk> Read for File<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len.saturating_sub(self.at);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(left);
        if !self.resident.is_empty() {
            let from = self.at as usize;
            let take = want as usize;
            buf[..take].copy_from_slice(&self.resident[from..from + take]);
            self.at += take as u64;
            return Ok(take);
        }
        let Some(extent) = self.extent(self.at) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the file system does not say where these bytes are",
            ));
        };
        let into = self.at - extent.from;
        // One read answers from one extent: the next call reads on from
        // the next, as a file on any other file system does.
        let take = want.min(extent.len - into) as usize;
        let read = match extent.at {
            Some(at) => self.disk.read_at(at + into, &mut buf[..take])?,
            None => {
                // A hole, which was never written: zero, and no read.
                buf[..take].fill(0);
                take
            }
        };
        self.at += read as u64;
        Ok(read)
    }
}

impl<D: Disk> Seek for File<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let at = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.len.checked_add_signed(by),
            SeekFrom::Current(by) => self.at.checked_add_signed(by),
        };
        match at {
            Some(at) => {
                self.at = at;
                Ok(at)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek to before the file's start",
            )),
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.at)
    }
}

/// Every file and directory of a file system, each with the path to it:
/// what [`Ntfs::walk`] gives, walked depth first in the order each
/// directory holds its entries.
pub struct Walk {
    /// For each directory on the way down: the path to it, and the entries
    /// of it that have not been given out yet.
    stack: Vec<(String, std::vec::IntoIter<Entry>)>,
    /// The records walked into, so that a directory leading back to one
    /// above it is told rather than walked for ever.
    seen: BTreeSet<u64>,
}

impl Walk {
    /// The next entry, and the path to it, or none at the end.
    pub fn next<D: Disk>(&mut self, fs: &Ntfs<D>) -> Result<Option<(String, Entry)>, Error> {
        let entry = loop {
            let Some((_, left)) = self.stack.last_mut() else {
                return Ok(None);
            };
            match left.next() {
                Some(entry) => break entry,
                None => {
                    self.stack.pop();
                }
            }
        };
        let here = self.stack.last().map_or("", |(path, _)| path.as_str());
        let path = if here.is_empty() {
            entry.name.clone()
        } else {
            format!("{here}/{}", entry.name)
        };
        if entry.is_dir() {
            if self.stack.len() >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            if !self.seen.insert(entry.record) {
                return Err(Error::Again { at: entry.record });
            }
            let entries = fs.read_dir(&entry)?;
            self.stack.push((path.clone(), entries.into_iter()));
        }
        Ok(Some((path, entry)))
    }
}
