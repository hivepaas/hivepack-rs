//! Reading ext2, ext3 and ext4 file systems in safe Rust, read-only.
//!
//! [`Ext`] opens the file system on a [`Disk`] — a partition of a card or
//! of a disk image, or a file that holds one as it is — and reads its
//! directories, its inodes and its files: the block numbers ext2 had and
//! the extents ext4 brought, files with holes, symbolic links, devices,
//! what each inode says about owner, mode, links and times, and the whole
//! tree. This is where most of what anyone wants out of a disk image is: a
//! Raspberry Pi's root, WSL2's `ext4.vhdx`, a Linux machine's QCOW2.
//!
//! Nothing here is a port. The layout is what the kernel's own
//! documentation and e2fsprogs' on-disk description give, and Linux's
//! reader is GPL-2.0, so this module is under the crate's own license.
//! What it refuses, and how it is checked against `debugfs` and
//! `e2fsck`, is in the repository: `docs/ext.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! use hivepack::ext::Ext;
//!
//! let fs = Ext::open(std::fs::File::open("root.img")?)?;
//! println!("{} {:?}", fs.kind().says(), fs.label());
//! let mut walk = fs.walk()?;
//! while let Some(step) = walk.next(&fs)? {
//!     println!("{} {} bytes", step.entry.name_text(), step.node.size);
//!     if step.node.is_file() {
//!         let mut data = Vec::new();
//!         fs.file(&step.node)?.read_to_end(&mut data)?;
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod block;
mod dir;
mod error;
mod inode;
mod sb;

use std::collections::BTreeSet;
use std::io::{self, Read, Seek, SeekFrom};

use crate::image::Disk;

use sb::Super;

pub use dir::Entry;
pub use error::{Error, Unsupported};
pub use inode::{Node, Time, What};
pub use sb::Kind;

/// Which inode the root directory is, in every ext file system there has
/// ever been.
pub const ROOT: u32 = 2;

/// How many directories inside directories are walked, as deep a chain of
/// them as squashfs' own reader walks.
pub const MAX_DEPTH: usize = 1024;

/// How long a symbolic link's target may be: a block, which is as much
/// room as the format gives one.
const MOST_LINK: u64 = 64 << 10;

/// An ext2, ext3 or ext4 file system, read-only.
///
/// Reads are at offsets and never move a position, so one file system can
/// be read from more than one thread; nothing is cached, as the [`Disk`]
/// underneath may cache as it likes.
pub struct Ext<D> {
    disk: D,
    sb: Super,
}

impl<D: Disk> Ext<D> {
    /// The file system on `disk`, if it holds one.
    pub fn open(disk: D) -> Result<Ext<D>, Error> {
        let sb = Super::read(&disk)?;
        let fs = Ext { disk, sb };
        // The root is inode 2 and is a directory in every ext file system
        // there is: a file whose first bytes happen to be a superblock's
        // has no such inode, and is told from one here rather than read as
        // a file system of nothing.
        if !fs.root()?.is_dir() {
            return Err(Error::Says);
        }
        Ok(fs)
    }

    /// Which of the three it is, read off the features it has: nothing in
    /// the file system says what it is called.
    pub fn kind(&self) -> Kind {
        self.sb.kind
    }

    /// The volume's label, where it has one.
    pub fn label(&self) -> Option<&str> {
        self.sb.label.as_deref()
    }

    /// The volume's own identifier, as `blkid` shows it.
    pub fn uuid(&self) -> &[u8; 16] {
        &self.sb.uuid
    }

    /// The identifier written as every tool writes one.
    pub fn uuid_text(&self) -> String {
        use core::fmt::Write;

        let mut text = String::with_capacity(36);
        for (i, byte) in self.sb.uuid.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                text.push('-');
            }
            // A write to a String cannot fail.
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// How many bytes a block is.
    pub fn block_size(&self) -> u32 {
        self.sb.block
    }

    /// How many blocks the file system holds, and how many inodes.
    pub fn blocks(&self) -> u64 {
        self.sb.blocks
    }

    pub fn inodes(&self) -> u32 {
        self.sb.inodes
    }

    /// The disk it was opened on.
    pub fn into_inner(self) -> D {
        self.disk
    }

    /// The root directory.
    pub fn root(&self) -> Result<Node, Error> {
        self.node(ROOT)
    }

    /// One inode, by its number.
    pub fn node(&self, ino: u32) -> Result<Node, Error> {
        if ino == 0 || ino > self.sb.inodes {
            return Err(Error::NoSuchInode { ino });
        }
        let group = (ino - 1) / self.sb.inodes_per_group;
        let into = u64::from((ino - 1) % self.sb.inodes_per_group);
        let table = self.inode_table(group)?;
        let Some(at) = self.sb.at(table) else {
            return Err(Error::PastTheEnd { block: table });
        };
        let mut raw = vec![0u8; self.sb.inode_size as usize];
        self.disk
            .read_exact_at(at + into * u64::from(self.sb.inode_size), &mut raw)?;
        Node::of(&raw, ino, &self.sb)
    }

    /// The entries of a directory, in the order its records hold them.
    pub fn read_dir(&self, node: &Node) -> Result<Vec<Entry>, Error> {
        if !node.is_dir() {
            return Err(Error::NotADirectory);
        }
        let raw = self.data(node, dir::MOST_ROOM)?;
        dir::entries(&raw, self.sb.block as usize, self.sb.filetype)
    }

    /// What is at `path`, or none where there is nothing there. The parts
    /// are told apart by `/`, and a name is compared as the bytes it is.
    ///
    /// A symbolic link in the middle of a path is not followed: what comes
    /// back is what the path names, and following it is the caller's to
    /// decide, which is what keeps a file system from sending a reader
    /// somewhere it did not mean to go.
    pub fn lookup_path(&self, path: impl AsRef<[u8]>) -> Result<Option<Node>, Error> {
        let mut at = self.root()?;
        for part in path
            .as_ref()
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
        {
            if !at.is_dir() {
                // A part of the path that is not a directory: there is
                // nothing inside it to go on to.
                return Ok(None);
            }
            let Some(entry) = self.read_dir(&at)?.into_iter().find(|e| e.name == part) else {
                return Ok(None);
            };
            at = self.node(entry.ino)?;
        }
        Ok(Some(at))
    }

    /// A file's data, to read and to seek in. A hole reads as zeroes, as
    /// what a file with holes holds there is zeroes.
    pub fn file<'a>(&'a self, node: &Node) -> Result<File<'a, D>, Error> {
        if !node.is_file() {
            return Err(Error::NotAFile);
        }
        Ok(File {
            fs: self,
            node: node.clone(),
            at: 0,
        })
    }

    /// What a symbolic link points at, which is bytes and not text: a
    /// short one is kept in the inode itself, where the block numbers
    /// would be.
    pub fn read_link(&self, node: &Node) -> Result<Vec<u8>, Error> {
        if !node.is_symlink() {
            return Err(Error::NotALink);
        }
        if node.link_in_inode() {
            let end = node.size as usize;
            return Ok(node.map[..end.min(node.map.len())].to_vec());
        }
        if node.size > MOST_LINK {
            return Err(Error::TooMany);
        }
        self.data(node, MOST_LINK)
    }

    /// Every file and directory, each with the path to it, depth first.
    pub fn walk(&self) -> Result<Walk, Error> {
        let root = self.root()?;
        let entries = self.read_dir(&root)?;
        Ok(Walk {
            stack: vec![(Vec::new(), entries.into_iter())],
            seen: BTreeSet::from([ROOT]),
        })
    }

    /// Where the inode table of the `group` group is, in blocks.
    fn inode_table(&self, group: u32) -> Result<u64, Error> {
        if group >= self.sb.groups {
            return Err(Error::Says);
        }
        let mut raw = [0u8; 64];
        let room = self.sb.desc_size.min(64) as usize;
        self.disk.read_exact_at(
            self.sb.descriptors() + u64::from(group) * u64::from(self.sb.desc_size),
            &mut raw[..room],
        )?;
        let lo = u64::from(sb::le32(&raw, 8));
        // Where a group descriptor is 64 bytes, the high half of each of
        // its block numbers is in the second half of it.
        let hi = if room >= 64 {
            u64::from(sb::le32(&raw, 40)) << 32
        } else {
            0
        };
        Ok(lo | hi)
    }

    /// A whole block, which is what an indirect block and a node of a tree
    /// of extents are read as.
    fn block(&self, block: u64) -> Result<Vec<u8>, Error> {
        let Some(at) = self.sb.at(block) else {
            return Err(Error::PastTheEnd { block });
        };
        let mut raw = vec![0u8; self.sb.block as usize];
        self.disk.read_exact_at(at, &mut raw)?;
        Ok(raw)
    }

    /// The whole of a node's data, where it is no longer than `most`.
    fn data(&self, node: &Node, most: u64) -> Result<Vec<u8>, Error> {
        if node.size > most {
            return Err(Error::TooMany);
        }
        let mut raw = vec![0u8; node.size as usize];
        let mut reading = File {
            fs: self,
            node: node.clone(),
            at: 0,
        };
        reading.read_exact(&mut raw)?;
        Ok(raw)
    }
}

/// A file's data: `io::Read` and `io::Seek` over the blocks it is in.
/// Blocks that follow one another are read in one go, and a hole reads as
/// zeroes.
pub struct File<'a, D> {
    fs: &'a Ext<D>,
    node: Node,
    at: u64,
}

impl<D: Disk> File<'_, D> {
    /// How many bytes the file holds.
    pub fn len(&self) -> u64 {
        self.node.size
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.node.size == 0
    }
}

impl<D: Disk> Read for File<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.node.size.checked_sub(self.at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left);
        if want == 0 {
            return Ok(0);
        }
        let block = u64::from(self.fs.sb.block);
        let into = self.at % block;
        // How many blocks the read may run over: what is wanted, and no
        // more of the file than there is.
        let most = (into + want).div_ceil(block);
        let (where_, run) = self.fs.run(&self.node, self.at / block, most)?;
        let take = want.min(run * block - into) as usize;
        match where_ {
            None => buf[..take].fill(0),
            Some(first) => {
                let Some(at) = self.fs.sb.at(first) else {
                    return Err(Error::PastTheEnd { block: first }.into());
                };
                let read = self.fs.disk.read_at(at + into, &mut buf[..take])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the disk ends inside a block the file is in",
                    ));
                }
                self.at += read as u64;
                return Ok(read);
            }
        }
        self.at += take as u64;
        Ok(take)
    }
}

impl<D: Disk> Seek for File<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let at = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.node.size.checked_add_signed(by),
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

/// One thing a walk came to: where it is, what the directory called it, and
/// the inode behind the name.
#[derive(Clone, Debug)]
pub struct Step {
    /// The path from the root, with no `/` in front of it.
    pub path: Vec<u8>,
    pub entry: Entry,
    pub node: Node,
}

/// Every file and directory of a file system: what [`Ext::walk`] gives,
/// walked depth first in the order each directory holds its records.
pub struct Walk {
    /// For each directory on the way down: the path to it, and the entries
    /// of it that have not been given out yet.
    stack: Vec<(Vec<u8>, std::vec::IntoIter<Entry>)>,
    /// The directories walked into, so that one whose records lead back to
    /// a directory above it is told rather than walked for ever.
    seen: BTreeSet<u32>,
}

impl Walk {
    /// The next step, or none at the end.
    pub fn next<D: Disk>(&mut self, fs: &Ext<D>) -> Result<Option<Step>, Error> {
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
        let mut path = self
            .stack
            .last()
            .map_or_else(Vec::new, |(at, _)| at.clone());
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&entry.name);
        let node = fs.node(entry.ino)?;
        if node.is_dir() {
            if self.stack.len() >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            // A directory already walked into: ext gives a directory one
            // name and one parent, so a second way in is a file system
            // that would be walked round for ever.
            if !self.seen.insert(entry.ino) {
                return Err(Error::TooDeep);
            }
            let entries = fs.read_dir(&node)?;
            self.stack.push((path.clone(), entries.into_iter()));
        }
        Ok(Some(Step { path, entry, node }))
    }
}
