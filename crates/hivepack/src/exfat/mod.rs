//! Reading exFAT file systems in safe Rust, read-only.
//!
//! [`Exfat`] opens the file system on a [`Disk`] — a partition of a card or
//! of a disk image, or a file that holds one as it is — and reads its
//! directories and files. This is what a memory card larger than 32 GB
//! holds: the size where Windows stops offering FAT32, so every large SD
//! card, camera card and USB stick sold formatted is this.
//!
//! It is not FAT with larger numbers. A file is a **set** of directory
//! entries rather than one record, the set carries a checksum of itself,
//! names are UTF-16 with no 8.3 name beside them, a file written in one
//! piece says so and keeps nothing in the table at all, a file knows how
//! much of it has ever been written, and each time says what the offset
//! from UTC was where it was written.
//!
//! Nothing here is a port. The layout is Microsoft's *exFAT file system
//! specification*, published in 2019 under its Open Specification Promise.
//! How it is checked is in the repository: `docs/exfat.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! use hivepack::exfat::Exfat;
//!
//! let exfat = Exfat::open(std::fs::File::open("card.img")?)?;
//! println!("{:?}", exfat.label());
//! let mut walk = exfat.walk()?;
//! while let Some((path, entry)) = walk.next(&exfat)? {
//!     println!("{path} {} bytes", entry.size);
//!     if entry.is_file() {
//!         let mut data = Vec::new();
//!         exfat.file(&entry)?.read_to_end(&mut data)?;
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

use boot::{Boot, FIRST_CLUSTER};

pub use dir::Entry;
pub use error::Error;
pub use time::Time;

/// How many directories inside directories are walked, as deep a chain of
/// them as the readers beside this one walk.
pub const MAX_DEPTH: usize = 1024;

/// How many clusters a chain may hold. A file of the largest size exFAT
/// allows, in the smallest cluster there is, takes more than this: the
/// chain is read whole before the data it names is, so it is bounded by a
/// number of its own rather than by the file's length.
const MOST_CHAIN: usize = 1 << 24;

/// How many bytes of a directory are read: entries of 32 bytes, so half a
/// million of them, and more than any tool writes.
const MOST_DIR: u64 = 16 << 20;

/// The table entries that are not a cluster: the end of a chain, and a
/// cluster the file system has marked as not to be used.
const END_OF_CHAIN: u32 = 0xFFFF_FFFF;
const BAD_CLUSTER: u32 = 0xFFFF_FFF7;

/// An exFAT file system, read-only.
///
/// Reads are at offsets and never move a position, so one file system can
/// be read from more than one thread; nothing is cached, as the [`Disk`]
/// underneath may cache as it likes.
pub struct Exfat<D> {
    disk: D,
    boot: Boot,
    label: Option<String>,
}

impl<D: Disk> Exfat<D> {
    /// The file system on `disk`, if it holds one.
    ///
    /// Where the boot region at the volume's start fails the checksum the
    /// format keeps over it, the backup region after it is read instead,
    /// and [`Exfat::from_backup`] says so. That is the one repair this
    /// does: a volume whose start was overwritten still reads.
    pub fn open(disk: D) -> Result<Exfat<D>, Error> {
        let boot = Boot::read(&disk)?;
        let mut exfat = Exfat {
            disk,
            boot,
            label: None,
        };
        exfat.label = exfat.root_label()?;
        Ok(exfat)
    }

    /// The volume's label, where it has one. It is an entry of the root
    /// directory, and exFAT keeps it nowhere else.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// How many bytes a cluster is: the smallest room a file takes.
    pub fn cluster_size(&self) -> u32 {
        self.boot.cluster
    }

    /// How many bytes a sector is, as the volume says.
    pub fn sector_size(&self) -> u32 {
        self.boot.sector
    }

    /// How many clusters the file system has, which are numbered 2 upwards.
    pub fn clusters(&self) -> u32 {
        self.boot.clusters
    }

    /// The volume's serial number, as every tool shows it.
    pub fn serial(&self) -> u32 {
        self.boot.serial
    }

    /// Whether the volume was left mounted, or being written, when
    /// whatever had it stopped. What is read is what is there; a file
    /// written at that moment may be a length without the bytes.
    pub fn dirty(&self) -> bool {
        self.boot.dirty
    }

    /// Whether whatever last wrote the volume found part of the disk it
    /// could not use. Reading goes on: where the damage is, reading it
    /// fails and says so.
    pub fn media_failure(&self) -> bool {
        self.boot.media_failure
    }

    /// Whether the volume was opened from its backup boot region, the one
    /// at its start having failed its checksum.
    pub fn from_backup(&self) -> bool {
        self.boot.backup
    }

    /// The disk it was opened on.
    pub fn into_inner(self) -> D {
        self.disk
    }

    /// The entries of the root directory.
    pub fn read_root(&self) -> Result<Vec<Entry>, Error> {
        let raw = self.chain_bytes(self.boot.root, false, MOST_DIR)?;
        Ok(dir::listing(&raw)?.entries)
    }

    /// The entries of a directory.
    pub fn read_dir(&self, entry: &Entry) -> Result<Vec<Entry>, Error> {
        if !entry.is_dir() {
            return Err(Error::NotADirectory);
        }
        let raw = self.chain_bytes(entry.first_cluster(), entry.is_contiguous(), MOST_DIR)?;
        Ok(dir::listing(&raw)?.entries)
    }

    /// What is at `path`, or none where there is nothing there. The parts
    /// are told apart by `/` and by `\`.
    ///
    /// Names are matched without regard to case, as every system that
    /// reads an exFAT volume does. **The volume's own upcase table is not
    /// read**: Rust's own case folding is what decides, which differs from
    /// the table only for characters whose case changes between Unicode
    /// versions. Nothing of what is read depends on it — the table matters
    /// to a writer, which has to hash names the way the volume does.
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
            let Some(next) = here.into_iter().find(|e| e.name.to_lowercase() == want) else {
                return Ok(None);
            };
            found = Some(next);
        }
        Ok(found)
    }

    /// A file's data, to read and to seek in.
    ///
    /// **Past what has ever been written, the file reads as zeroes.** exFAT
    /// keeps two lengths for a file: how long it is, and how much of it has
    /// been written (`ValidDataLength`). Room given to a file and never
    /// filled holds whatever was in those clusters before, so reading it
    /// from the disk would hand back somebody else's deleted data; the file
    /// is as long as it says, and the rest of it is zeroes.
    pub fn file<'a>(&'a self, entry: &Entry) -> Result<File<'a, D>, Error> {
        if entry.is_dir() {
            return Err(Error::NotAFile);
        }
        Ok(File {
            exfat: self,
            clusters: self.clusters_of(entry, entry.valid)?,
            size: entry.size,
            valid: entry.valid,
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

    /// The clusters holding the first `bytes` of what `entry` names.
    ///
    /// A file written in one piece says so in its set of entries, and the
    /// table holds nothing for it: its clusters are the run that begins
    /// where it begins. Any other file is a chain, as a FAT file is.
    fn clusters_of(&self, entry: &Entry, bytes: u64) -> Result<Vec<u32>, Error> {
        let first = entry.first_cluster();
        // A file of no bytes is given no cluster at all, which is not a
        // chain that goes wrong.
        if bytes == 0 || first == 0 {
            return Ok(Vec::new());
        }
        let wanted = bytes.div_ceil(u64::from(self.boot.cluster));
        if entry.is_contiguous() {
            let run = u32::try_from(wanted).map_err(|_| Error::Chain { at: first })?;
            let last = first
                .checked_add(run - 1)
                .ok_or(Error::Chain { at: first })?;
            if self.boot.at_cluster(first).is_none() || self.boot.at_cluster(last).is_none() {
                return Err(Error::Chain { at: first });
            }
            return Ok((first..=last).collect());
        }
        self.chain(first, Some(wanted as usize))
    }

    /// The clusters of the chain that begins at `first`, in order, up to
    /// `most` of them where a number is given.
    fn chain(&self, first: u32, most: Option<usize>) -> Result<Vec<u32>, Error> {
        let mut chain = Vec::new();
        let mut at = first;
        loop {
            if self.boot.at_cluster(at).is_none() {
                return Err(Error::Chain { at });
            }
            if chain.len() >= MOST_CHAIN {
                return Err(Error::Chain { at });
            }
            chain.push(at);
            if most.is_some_and(|most| chain.len() >= most) {
                return Ok(chain);
            }
            let next = self.entry(at)?;
            if next == END_OF_CHAIN {
                return Ok(chain);
            }
            // A chain cannot be longer than there are clusters, so one
            // that is has led back into itself. That is told by its length
            // and not by keeping every cluster it has been through, which
            // for a file of millions of clusters would cost more than the
            // data.
            if chain.len() > self.boot.clusters as usize {
                return Err(Error::Chain { at });
            }
            at = next;
        }
    }

    /// What the table says follows the `cluster` cluster.
    fn entry(&self, cluster: u32) -> Result<u32, Error> {
        let at = u64::from(cluster) * 4;
        if at + 4 > self.boot.fat_len {
            return Err(Error::Chain { at: cluster });
        }
        let mut raw = [0u8; 4];
        self.disk.read_exact_at(self.boot.fat_at + at, &mut raw)?;
        let value = u32::from_le_bytes(raw);
        // A cluster the file system has marked as not to be used is not a
        // cluster a chain can go through.
        if value == BAD_CLUSTER {
            return Err(Error::Chain { at: cluster });
        }
        Ok(value)
    }

    /// The root directory's own first cluster, which is where the volume's
    /// label is.
    ///
    /// Only that cluster is read: the label is an entry at the start of the
    /// root directory, and a card of thousands of files in its root should
    /// not have to be read through to open it.
    fn root_label(&self) -> Result<Option<String>, Error> {
        let Some(at) = self.boot.at_cluster(self.boot.root) else {
            return Ok(None);
        };
        let mut raw = vec![0u8; self.boot.cluster as usize];
        let read = self.disk.read_at(at, &mut raw)?;
        raw.truncate(read);
        // A set of entries cut in half by the cluster's end is not read
        // here; the label is in front of the files, and reading the
        // directory properly is what `read_root` does.
        Ok(match dir::listing(&raw) {
            Ok(listing) => listing.label,
            Err(_) => None,
        })
    }

    /// The bytes of what begins at cluster `first`, up to `most` of them.
    fn chain_bytes(&self, first: u32, contiguous: bool, most: u64) -> Result<Vec<u8>, Error> {
        if first == 0 {
            return Ok(Vec::new());
        }
        let cluster = u64::from(self.boot.cluster);
        let clusters = if contiguous {
            // A directory written in one piece says how long it is nowhere:
            // its length is its own entry's, and reading it is reading the
            // run until the entries end. The run is bounded by what is
            // read of a directory at all.
            let mut run = Vec::new();
            let mut at = first;
            while (run.len() as u64) * cluster < most && self.boot.at_cluster(at).is_some() {
                run.push(at);
                match at.checked_add(1) {
                    Some(next) => at = next,
                    None => break,
                }
            }
            if run.is_empty() {
                return Err(Error::Chain { at: first });
            }
            run
        } else {
            self.chain(first, None)?
        };
        let mut raw = Vec::new();
        for at in clusters {
            if raw.len() as u64 >= most {
                return Err(Error::TooMany);
            }
            let from = raw.len();
            raw.resize(from + cluster as usize, 0);
            let Some(where_) = self.boot.at_cluster(at) else {
                return Err(Error::Chain { at });
            };
            let read = self.disk.read_at(where_, &mut raw[from..])?;
            if read < cluster as usize {
                // The disk ends inside a cluster the chain names.
                raw.truncate(from + read);
                break;
            }
            // A directory in one run ends at its first unused entry, and
            // nothing says how many clusters it was given: reading stops
            // where the entries do.
            if contiguous
                && raw[from..]
                    .as_chunks::<{ dir::ENTRY }>()
                    .0
                    .iter()
                    .any(|e| e[0] == 0)
            {
                break;
            }
        }
        Ok(raw)
    }
}

/// A file's data: `io::Read` and `io::Seek` over the clusters it is in.
/// Clusters that follow one another are read in one go, which is what a
/// file written in one piece is made of.
pub struct File<'a, D> {
    exfat: &'a Exfat<D>,
    /// The clusters holding what has been written of it; a file whose
    /// length is past that has none for the rest.
    clusters: Vec<u32>,
    size: u64,
    valid: u64,
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

    /// How many bytes of it have ever been written. What is past this is
    /// room the file was given, and reads as zeroes.
    pub fn valid(&self) -> u64 {
        self.valid
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
        // Past what has ever been written: zeroes, and never the clusters
        // themselves, which hold whatever was in them before.
        if self.at >= self.valid {
            let take = want as usize;
            buf[..take].fill(0);
            self.at += take as u64;
            return Ok(take);
        }
        let want = want.min(self.valid - self.at);
        let cluster = u64::from(self.exfat.boot.cluster);
        let which = self.at / cluster;
        let into = self.at % cluster;
        let Some(&first) = self.clusters.get(which as usize) else {
            // The clusters are fewer than the length says: what is not in
            // the file system is not read as zeroes.
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the file's clusters end before the file does",
            ));
        };
        // As many clusters after this one as follow it in the file system,
        // so that a file written in one piece is read in one go.
        let mut run = 1u64;
        while (run + 1) * cluster - into <= want {
            match self.clusters.get((which + run) as usize) {
                Some(&next) if next == first + run as u32 => run += 1,
                _ => break,
            }
        }
        let take = (run * cluster - into).min(want) as usize;
        let at = self.exfat.boot.at_cluster(first).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "a cluster that is not one")
        })? + into;
        let read = self.exfat.disk.read_at(at, &mut buf[..take])?;
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
/// what [`Exfat::walk`] gives, walked depth first in the order each
/// directory holds its entries.
pub struct Walk {
    /// For each directory on the way down: the path to it, and the entries
    /// of it that have not been given out yet.
    stack: Vec<(String, std::vec::IntoIter<Entry>)>,
    /// The directories walked into, so that one whose entries lead back to
    /// a directory above it is told rather than walked for ever.
    seen: BTreeSet<u32>,
}

impl Walk {
    /// The next entry, and the path to it, or none at the end.
    pub fn next<D: Disk>(&mut self, exfat: &Exfat<D>) -> Result<Option<(String, Entry)>, Error> {
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
            // A directory whose entries lead back to one already walked
            // into: a cluster of 2 upwards, as a directory given no
            // cluster at all is no directory to come back to.
            let first = entry.first_cluster();
            if first >= FIRST_CLUSTER && !self.seen.insert(first) {
                return Err(Error::Chain { at: first });
            }
            let entries = exfat.read_dir(&entry)?;
            self.stack.push((path.clone(), entries.into_iter()));
        }
        Ok(Some((path, entry)))
    }
}
