//! Reading FAT file systems in safe Rust, read-only: FAT12, FAT16 and
//! FAT32, with the long names VFAT added.
//!
//! [`Fat`] opens the file system on a [`Disk`] — a partition of a card or
//! of a disk image, or a file that holds one as it is — and reads its
//! directories and files: the 8.3 names MS-DOS had, the long names Windows
//! writes in front of them, the times each record carries, and the chain of
//! clusters a file's data is in. This is what a camera's card, a Raspberry
//! Pi's boot partition and an EFI system partition hold.
//!
//! Nothing here is a port. The layout is Microsoft's published *FAT32 File
//! System Specification*, which gives FAT12 and FAT16 with it, and the long
//! names are what that specification and VFAT's own published description
//! say. How it is checked is in the repository: `docs/fat.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! use hivepack::fat::Fat;
//!
//! let fat = Fat::open(std::fs::File::open("boot.img")?)?;
//! println!("{} {:?}", fat.kind().says(), fat.label());
//! let mut walk = fat.walk()?;
//! while let Some((path, entry)) = walk.next(&fat)? {
//!     println!("{path} {} bytes", entry.size);
//!     if entry.is_file() {
//!         let mut data = Vec::new();
//!         fat.file(&entry)?.read_to_end(&mut data)?;
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod boot;
mod dir;
mod error;
mod time;

use std::collections::BTreeSet;
use std::io::{self, Read, Seek, SeekFrom};

use crate::image::Disk;

use boot::Boot;

pub use boot::Kind;
pub use dir::Entry;
pub use error::Error;
pub use time::Time;

/// How many directories inside directories are walked, as deep a chain of
/// them as squashfs' own reader walks.
pub const MAX_DEPTH: usize = 1024;

/// How many clusters a chain may hold, which is what a file of the 4 GiB a
/// FAT32 file system allows takes in clusters of the smallest size there
/// is. A chain is read whole before the data it names is.
const MOST_CHAIN: usize = 1 << 24;

/// How many bytes of a directory are read: a directory of records of 32
/// bytes, which is half a million entries and more than any tool writes.
const MOST_DIR: u64 = 16 << 20;

/// How much of the root directory is read to find the volume's label,
/// which a tool writes as its first record.
const LABEL_IN: u64 = 32 << 10;

/// A FAT file system, read-only.
///
/// Reads are at offsets and never move a position, so one file system can
/// be read from more than one thread; nothing is cached, as the [`Disk`]
/// underneath may cache as it likes.
pub struct Fat<D> {
    disk: D,
    boot: Boot,
    label: Option<String>,
}

impl<D: Disk> Fat<D> {
    /// The file system on `disk`, if it holds one.
    pub fn open(disk: D) -> Result<Fat<D>, Error> {
        let boot = Boot::read(&disk)?;
        let mut fat = Fat {
            disk,
            boot,
            label: None,
        };
        // The label a tool shows is a record of the root directory; the one
        // in the boot sector is what is left where there is no record, and
        // what a tool writes to both but reads from the record.
        fat.label = fat.root_label()?.or_else(|| fat.boot.label.clone());
        Ok(fat)
    }

    /// Which of the three it is, which how many clusters there are says and
    /// nothing else does.
    pub fn kind(&self) -> Kind {
        self.boot.kind
    }

    /// The volume's label, where it has one.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// How many bytes a cluster is: the smallest room a file takes.
    pub fn cluster_size(&self) -> u32 {
        self.boot.cluster
    }

    /// How many clusters the file system has, which are numbered 2 upwards.
    pub fn clusters(&self) -> u32 {
        self.boot.clusters
    }

    /// The disk it was opened on.
    pub fn into_inner(self) -> D {
        self.disk
    }

    /// The entries of the root directory.
    pub fn read_root(&self) -> Result<Vec<Entry>, Error> {
        Ok(dir::listing(&self.root_bytes(MOST_DIR)?)?.entries)
    }

    /// The entries of a directory.
    pub fn read_dir(&self, entry: &Entry) -> Result<Vec<Entry>, Error> {
        if !entry.is_dir() {
            return Err(Error::NotADirectory);
        }
        let raw = self.chain_bytes(entry.first_cluster(), MOST_DIR)?;
        Ok(dir::listing(&raw)?.entries)
    }

    /// What is at `path`, or none where there is nothing there. The parts
    /// are told apart by `/` and by `\`, and each is looked for by its long
    /// name and by its 8.3 name, without regard to case, as every system
    /// that reads a FAT file system does.
    pub fn lookup_path(&self, path: &str) -> Result<Option<Entry>, Error> {
        let mut found: Option<Entry> = None;
        for part in path
            .split(['/', '\\'])
            .filter(|p| !p.is_empty() && *p != ".")
        {
            let here = match &found {
                None => self.read_root()?,
                Some(entry) if entry.is_dir() => self.read_dir(entry)?,
                // A part of the path that is a file: there is nothing
                // inside it to go on to.
                Some(_) => return Ok(None),
            };
            let want = part.to_lowercase();
            let Some(next) = here
                .into_iter()
                .find(|e| e.name.to_lowercase() == want || e.short.to_lowercase() == want)
            else {
                return Ok(None);
            };
            found = Some(next);
        }
        Ok(found)
    }

    /// A file's data, to read and to seek in.
    pub fn file<'a>(&'a self, entry: &Entry) -> Result<File<'a, D>, Error> {
        if entry.is_dir() {
            return Err(Error::NotAFile);
        }
        // A file of no bytes is given no cluster at all, which is not a
        // chain that goes wrong.
        let chain = if entry.size == 0 || entry.first_cluster() == 0 {
            Vec::new()
        } else {
            self.chain(entry.first_cluster())?
        };
        Ok(File {
            fat: self,
            chain,
            size: entry.size,
            at: 0,
        })
    }

    /// Every file and directory, each with the path to it. The root's own
    /// entries come with no directory in front of them.
    pub fn walk(&self) -> Result<Walk, Error> {
        let root = self.read_root()?;
        Ok(Walk {
            stack: vec![(String::new(), root.into_iter())],
            seen: BTreeSet::new(),
        })
    }

    /// The clusters of the chain that begins at `first`, in order.
    fn chain(&self, first: u32) -> Result<Vec<u32>, Error> {
        let mut chain = Vec::new();
        let mut at = first;
        loop {
            if self.boot.at(at).is_none() {
                return Err(Error::Chain { at });
            }
            if chain.len() >= MOST_CHAIN {
                return Err(Error::Chain { at });
            }
            chain.push(at);
            let next = self.entry(at)?;
            if ends(self.boot.kind, next) {
                return Ok(chain);
            }
            // A chain cannot be longer than there are clusters, so one that
            // is has led back into itself: that is told by its length and
            // not by keeping every cluster it has been through, which for a
            // file of millions of clusters would cost more than the data.
            if chain.len() > self.boot.clusters as usize {
                return Err(Error::Chain { at });
            }
            at = next;
        }
    }

    /// What the table says follows the `cluster` cluster.
    fn entry(&self, cluster: u32) -> Result<u32, Error> {
        let (at, wide) = match self.boot.kind {
            // Twelve bits to an entry, so two entries share a byte: the
            // one that begins half way through it is the high twelve bits
            // of the two bytes there.
            Kind::Fat12 => (u64::from(cluster) + u64::from(cluster) / 2, 2),
            Kind::Fat16 => (u64::from(cluster) * 2, 2),
            Kind::Fat32 => (u64::from(cluster) * 4, 4),
        };
        let room = u64::from(self.boot.fat_sectors) * u64::from(self.boot.sector);
        if at + wide > room {
            return Err(Error::Chain { at: cluster });
        }
        let mut raw = [0u8; 4];
        self.disk
            .read_exact_at(self.boot.fat() + at, &mut raw[..wide as usize])?;
        let value = match self.boot.kind {
            Kind::Fat12 => {
                let pair = u32::from(u16::from_le_bytes([raw[0], raw[1]]));
                if cluster.is_multiple_of(2) {
                    pair & 0x0FFF
                } else {
                    pair >> 4
                }
            }
            Kind::Fat16 => u32::from(u16::from_le_bytes([raw[0], raw[1]])),
            Kind::Fat32 => u32::from_le_bytes(raw) & 0x0FFF_FFFF,
        };
        // A cluster the file system has marked as not to be used is not a
        // cluster a chain can go through.
        if value == bad(self.boot.kind) {
            return Err(Error::Chain { at: cluster });
        }
        Ok(value)
    }

    /// The bytes of the root directory, up to `most` of them.
    fn root_bytes(&self, most: u64) -> Result<Vec<u8>, Error> {
        match self.boot.root() {
            // FAT12 and FAT16 keep the root in an area of its own, as many
            // records as the boot sector says and no chain at all.
            Some((at, room)) => {
                let room = room.min(most);
                let mut raw = vec![0u8; room as usize];
                let read = self.disk.read_at(at, &mut raw)?;
                raw.truncate(read);
                Ok(raw)
            }
            None => self.chain_bytes(self.boot.root_cluster, most),
        }
    }

    /// The root directory's own first records, which is where the label is.
    ///
    /// Only the start of the root directory is read: the label is the first
    /// record every tool writes, and a root of thousands of files should
    /// not have to be read to open the file system. Where a file system
    /// keeps it further in, the boot sector's own copy is what answers,
    /// which every tool writes to as well.
    fn root_label(&self) -> Result<Option<String>, Error> {
        let at = match self.boot.root() {
            // FAT12 and FAT16: the area the root has to itself.
            Some((at, _)) => at,
            // FAT32: the root's first cluster, without following its chain.
            None => match self.boot.at(self.boot.root_cluster) {
                Some(at) => at,
                None => return Ok(None),
            },
        };
        let room = match self.boot.root() {
            Some((_, room)) => room.min(LABEL_IN),
            None => u64::from(self.boot.cluster).min(LABEL_IN),
        };
        let mut raw = vec![0u8; room as usize];
        let read = self.disk.read_at(at, &mut raw)?;
        raw.truncate(read);
        Ok(dir::listing(&raw)?.label)
    }

    /// The bytes of the chain that begins at `first`, up to `most` of them.
    fn chain_bytes(&self, first: u32, most: u64) -> Result<Vec<u8>, Error> {
        if first == 0 {
            return Ok(Vec::new());
        }
        let cluster = u64::from(self.boot.cluster);
        let mut raw = Vec::new();
        for at in self.chain(first)? {
            if raw.len() as u64 >= most {
                return Err(Error::TooMany);
            }
            let from = raw.len();
            raw.resize(from + cluster as usize, 0);
            let Some(where_) = self.boot.at(at) else {
                return Err(Error::Chain { at });
            };
            let read = self.disk.read_at(where_, &mut raw[from..])?;
            if read < cluster as usize {
                // The disk ends inside a cluster the chain names.
                raw.truncate(from + read);
                break;
            }
        }
        Ok(raw)
    }
}

/// Whether what the table says is the end of a chain. The highest values of
/// an entry are kept for this, and anything at or above the first of them
/// says there is no cluster after this one.
fn ends(kind: Kind, value: u32) -> bool {
    value
        >= match kind {
            Kind::Fat12 => 0x0FF8,
            Kind::Fat16 => 0xFFF8,
            Kind::Fat32 => 0x0FFF_FFF8,
        }
}

/// What the table says of a cluster that is not to be used.
fn bad(kind: Kind) -> u32 {
    match kind {
        Kind::Fat12 => 0x0FF7,
        Kind::Fat16 => 0xFFF7,
        Kind::Fat32 => 0x0FFF_FFF7,
    }
}

/// A file's data: `io::Read` and `io::Seek` over the chain of clusters it
/// is in. Clusters that follow one another are read in one go, which is
/// what a file written in one piece is made of.
pub struct File<'a, D> {
    fat: &'a Fat<D>,
    chain: Vec<u32>,
    size: u64,
    at: u64,
}

impl<D: Disk> File<'_, D> {
    /// How many bytes the file holds.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl<D: Disk> Read for File<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.size.checked_sub(self.at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left);
        if want == 0 {
            return Ok(0);
        }
        let cluster = u64::from(self.fat.boot.cluster);
        let which = self.at / cluster;
        let into = self.at % cluster;
        let Some(&first) = self.chain.get(which as usize) else {
            // The chain is shorter than the length the record says: what
            // is not in the file system is not read as zeroes.
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the file's chain of clusters ends before the file does",
            ));
        };
        // As many clusters after this one as follow it in the file system,
        // so that a file written in one piece is read in one go.
        let mut run = 1u64;
        while (run + 1) * cluster - into <= want {
            match self.chain.get((which + run) as usize) {
                Some(&next) if next == first + run as u32 => run += 1,
                _ => break,
            }
        }
        let take = (run * cluster - into).min(want) as usize;
        let at = self.fat.boot.at(first).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "a cluster that is not one")
        })? + into;
        let read = self.fat.disk.read_at(at, &mut buf[..take])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the disk ends inside a cluster the file is in",
            ));
        }
        self.at += read as u64;
        Ok(read)
    }
}

impl<D: Disk> Seek for File<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let at = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.size.checked_add_signed(by),
            SeekFrom::Current(by) => self.at.checked_add_signed(by),
        };
        let Some(at) = at else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a place before the file's start",
            ));
        };
        self.at = at;
        Ok(at)
    }
}

/// Every file and directory of a file system, each with the path to it:
/// what [`Fat::walk`] gives, walked depth first in the order each directory
/// holds its records.
pub struct Walk {
    /// For each directory on the way down: the path to it, and the entries
    /// of it that have not been given out yet.
    stack: Vec<(String, std::vec::IntoIter<Entry>)>,
    /// The directories walked into, so that one whose records lead back to
    /// a directory above it is told rather than walked for ever.
    seen: BTreeSet<u32>,
}

impl Walk {
    /// The next entry, and the path to it, or none at the end.
    pub fn next<D: Disk>(&mut self, fat: &Fat<D>) -> Result<Option<(String, Entry)>, Error> {
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
            // A directory whose records lead back to one already walked
            // into: a cluster of 2 upwards, as a directory given no
            // cluster at all is no directory to come back to.
            let first = entry.first_cluster();
            if first >= 2 && !self.seen.insert(first) {
                return Err(Error::Chain { at: first });
            }
            let entries = fat.read_dir(&entry)?;
            self.stack.push((path.clone(), entries.into_iter()));
        }
        Ok(Some((path, entry)))
    }
}
