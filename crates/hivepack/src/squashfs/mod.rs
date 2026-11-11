//! Reading SquashFS images in safe Rust, ported from squashfuse's library,
//! read-only.
//!
//! [`Squashfs`] opens a SquashFS 4.0 image as squashfuse 0.6.5 does: snap
//! packages, the image inside an AppImage (from where it starts in the
//! file), Linux live systems' root file systems, and what `mksquashfs`
//! makes. Every inode type is read (directories, with their index, files,
//! with fragments, holes and the block index, symbolic links, devices,
//! FIFOs and sockets, basic and extended), with owners, extended attributes
//! and the export table, through the same caches; data compressed with
//! zlib, LZMA, LZO, xz, LZ4 or zstd, by hivepack's own decoders, or stored
//! as it is. Where squashfuse would read past its buffers or
//! loop for good, the port has bounds instead, which `docs/squashfs.md` in
//! the repository lists, with how the port is checked against squashfuse.
//!
//! ```no_run
//! use std::io::Read;
//!
//! use hivepack::squashfs::{Squashfs, Step};
//!
//! let mut fs = Squashfs::open(std::fs::File::open("app.snap")?)?;
//! let root = fs.root()?;
//! let mut walk = fs.traverse(&root)?;
//! while let Some(step) = walk.next(&mut fs)? {
//!     if let Step::Entry { path, entry } = step {
//!         let inode = fs.inode(entry.inode)?;
//!         let stat = fs.stat(&inode)?;
//!         println!("{} {:o} {} bytes", String::from_utf8_lossy(&path), stat.mode, stat.size);
//!         if inode.is_file() {
//!             let mut data = Vec::new();
//!             fs.file(&inode).read_to_end(&mut data)?;
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod cache;
mod decompress;
mod dir;
mod error;
mod file;
mod fs;
mod nonstd;
mod squashfs_fs;
mod stat;
mod swap;
mod table;
mod traverse;
mod xattr;

use std::io::{self, Read, Seek, SeekFrom};

pub use decompress::Compression;
pub use dir::DirEntry;
pub use error::{Error, SqfsErr};
pub use fs::{Inode, InodeId, MdCursor};
pub use squashfs_fs::{BaseInode, SuperBlock};
pub use stat::Stat;
pub use traverse::{MAX_DEPTH, Step};

use dir::Dir;
use error::err;
pub(crate) use file::{BlockIndex, DataPlace};
use fs::Sqfs;
pub(crate) use fs::{Block, DataAhead};
use nonstd::{S_IFMT, s_isblk, s_ischr, s_isdir, s_islnk, s_isreg};
use xattr::XattrIter;

/// The squashfuse release this module follows.
pub const UPSTREAM_VERSION: &str = "0.6.5";

/// The SquashFS magic, `hsqs`: the first four bytes of an image.
pub const MAGIC: [u8; 4] = *b"hsqs";

/// An open SquashFS image.
#[derive(Debug)]
pub struct Squashfs<R> {
    fs: Sqfs<R>,
}

impl<R: Read + Seek> Squashfs<R> {
    /// Opens the image that `reader` holds from its start (`sqfs_init`).
    pub fn open(reader: R) -> Result<Squashfs<R>, Error> {
        Squashfs::open_at(reader, 0)
    }

    /// Opens the image that starts at `offset` in `reader`, as in an
    /// AppImage, whose image follows its program (`sqfs_init`'s `offset`).
    /// Every place the image records is from there.
    pub fn open_at(reader: R, offset: u64) -> Result<Squashfs<R>, Error> {
        Ok(Squashfs {
            fs: Sqfs::sqfs_init(reader, offset)?,
        })
    }

    /// The superblock.
    pub fn superblock(&self) -> &SuperBlock {
        &self.fs.sb
    }

    /// The compressor (`sqfs_compression`).
    pub fn compression(&self) -> Compression {
        Compression::from_id(self.fs.sb.compression)
    }

    /// Where the image starts in the reader.
    pub fn offset(&self) -> u64 {
        self.fs.offset
    }

    /// The root directory's inode id (`sqfs_inode_root`).
    pub fn root_id(&self) -> InodeId {
        self.fs.sqfs_inode_root()
    }

    /// The root directory's inode.
    pub fn root(&mut self) -> Result<Inode, Error> {
        let id = self.fs.sqfs_inode_root();
        self.fs.sqfs_inode_get(id)
    }

    /// The inode at `id`, a directory entry's (`sqfs_inode_get`).
    pub fn inode(&mut self, id: InodeId) -> Result<Inode, Error> {
        self.fs.sqfs_inode_get(id)
    }

    /// The entries of a directory, in their order, which is by name
    /// (`sqfs_dir_open`, `sqfs_dir_next`). SquashFS has no `.` nor `..`.
    /// After an error, there are no more.
    pub fn read_dir(&mut self, dir: &Inode) -> Result<ReadDir<'_, R>, Error> {
        self.read_dir_at(dir, 0)
    }

    /// The entries of a directory from `offset`, an entry's `next_offset`,
    /// as a FUSE `readdir` goes on (`sqfs_dir_open` with an offset).
    pub fn read_dir_at(&mut self, dir: &Inode, offset: i64) -> Result<ReadDir<'_, R>, Error> {
        let stream = self.fs.sqfs_dir_open(dir, offset)?;
        Ok(ReadDir {
            fs: self,
            dir: stream,
            done: false,
        })
    }

    /// The entry of a directory named `name`, if there is one
    /// (`sqfs_dir_lookup`).
    pub fn lookup(&mut self, dir: &Inode, name: &[u8]) -> Result<Option<DirEntry>, Error> {
        self.fs.sqfs_dir_lookup(dir, name)
    }

    /// The inode at `path` from `from`, with its id, its parts separated
    /// by `/`; `None` if a part is not there (`sqfs_lookup_path_with_id`).
    /// An empty path is `from` itself, with no id.
    pub fn lookup_path(
        &mut self,
        from: &Inode,
        path: &[u8],
    ) -> Result<Option<(Option<InodeId>, Inode)>, Error> {
        let mut inode = *from;
        let mut id = None;
        if self
            .fs
            .sqfs_lookup_path_with_id(&mut inode, path, &mut id)?
        {
            Ok(Some((id, inode)))
        } else {
            Ok(None)
        }
    }

    /// The attributes of an inode (`sqfs_stat`).
    pub fn stat(&mut self, inode: &Inode) -> Result<Stat, Error> {
        self.fs.sqfs_stat(inode)
    }

    /// The target of a symbolic link (`sqfs_readlink`).
    pub fn read_link(&mut self, inode: &Inode) -> Result<Vec<u8>, Error> {
        self.fs.sqfs_readlink(inode)
    }

    /// The extended attributes of an inode, in their order
    /// (`sqfs_xattr_open`, then `sqfs_xattr_read`, `sqfs_xattr_name` and
    /// `sqfs_xattr_value` for each).
    pub fn xattrs(&mut self, inode: &Inode) -> Result<Xattrs<'_, R>, Error> {
        let iter = self.fs.sqfs_xattr_open(inode)?;
        Ok(Xattrs {
            fs: self,
            iter,
            done: false,
        })
    }

    /// The value of the extended attribute `name`, with its prefix
    /// (`user.`, `trusted.` or `security.`), if the inode has it
    /// (`sqfs_xattr_lookup`).
    pub fn xattr(&mut self, inode: &Inode, name: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.fs.sqfs_xattr_lookup(inode, name)
    }

    /// Reads a regular file's data at `offset` (`sqfs_read_range`): as much
    /// as fits in `buf`, to the end of the file, as many bytes as were
    /// read. At the end it reads nothing; anywhere else, reading nothing is
    /// an error, as in squashfuse.
    pub fn read_at(&mut self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.fs.sqfs_read_range(inode, offset, buf)
    }

    /// Not in squashfuse: checks that all of a regular file's data is on
    /// the image, without reading it: its block sizes read, and each block
    /// and its fragment within the image. What does not decompress is only
    /// found when it is read.
    pub fn check_data(&mut self, inode: &Inode) -> Result<(), Error> {
        self.fs.check_data(inode)
    }

    /// Not in squashfuse: [`Squashfs::check_data`], telling `each` every
    /// place the file's data is read from, in order: each data block but its
    /// holes, then its fragment's block.
    pub(crate) fn check_data_with(
        &mut self,
        inode: &Inode,
        each: &mut dyn FnMut(DataPlace),
    ) -> Result<(), Error> {
        self.fs.check_data_with(inode, each)
    }

    /// Not in squashfuse: the block index reading a file makes and keeps,
    /// if it makes one, and whether it leads where the block sizes do.
    pub(crate) fn block_index(&mut self, inode: &Inode) -> BlockIndex {
        self.fs.sqfs_blockidx_check(inode)
    }

    /// Not in squashfuse: the data block at `pos` of header `hdr`, read and
    /// decompressed, past the caches (`sqfs_data_block_read`).
    pub(crate) fn data_block(&mut self, pos: u64, hdr: u32) -> Result<Block, Error> {
        self.fs.sqfs_data_block_read(pos as i64, hdr)
    }

    /// Not in squashfuse: the image opened again over `reader`, which holds
    /// the same bytes, without reading it again, its caches empty: for
    /// another thread to read it.
    pub(crate) fn with_reader<S>(&self, reader: S) -> Squashfs<S> {
        Squashfs {
            fs: self.fs.with_reader(reader),
        }
    }

    /// Not in squashfuse: the reader, to read from elsewhere.
    pub(crate) fn reader_mut(&mut self) -> &mut R {
        self.fs.reader_mut()
    }

    /// Not in squashfuse: where data blocks decoded ahead by other threads
    /// are taken from, before they are read; `None` to read them all here.
    pub(crate) fn set_ahead(&mut self, ahead: Option<Box<dyn DataAhead + Send>>) {
        self.fs.set_ahead(ahead);
    }

    /// The data of a regular file, to read and seek.
    pub fn file<'a>(&'a mut self, inode: &'a Inode) -> File<'a, R> {
        File {
            fs: self,
            inode,
            pos: 0,
        }
    }

    /// A walk of everything under a directory (`sqfs_traverse_open`), in
    /// order, depth first, at most [`MAX_DEPTH`] levels down.
    pub fn traverse(&mut self, dir: &Inode) -> Result<Traverse, Error> {
        Ok(Traverse {
            inner: traverse::Traverse::open(&mut self.fs, dir)?,
        })
    }

    /// Whether the image has an export table (`sqfs_export_ok`).
    pub fn export_ok(&self) -> bool {
        self.fs.sqfs_export_ok()
    }

    /// The inode of number `n`, from the export table
    /// (`sqfs_export_inode`): [`SqfsErr::Unsup`] without one.
    pub fn export_inode(&mut self, n: u32) -> Result<InodeId, Error> {
        self.fs.sqfs_export_inode(n)
    }

    /// The reader.
    pub fn into_inner(self) -> R {
        self.fs.into_reader()
    }
}

impl Inode {
    /// Its mode's type bits (`S_IFMT`).
    fn format(&self) -> u16 {
        self.base.mode & S_IFMT
    }

    /// Whether it is a regular file, by its mode.
    pub fn is_file(&self) -> bool {
        s_isreg(self.base.mode)
    }

    /// Whether it is a directory, by its mode.
    pub fn is_dir(&self) -> bool {
        s_isdir(self.base.mode)
    }

    /// Whether it is a symbolic link, by its mode.
    pub fn is_symlink(&self) -> bool {
        s_islnk(self.base.mode)
    }

    /// Whether it is a block or character device, by its mode.
    pub fn is_device(&self) -> bool {
        s_isblk(self.base.mode) || s_ischr(self.base.mode)
    }

    /// The `S_IF*` bits of its mode.
    pub fn file_type(&self) -> u32 {
        u32::from(self.format())
    }

    /// A regular file's length (`xtra.reg.file_size`).
    pub fn file_size(&self) -> u64 {
        self.xtra.reg_file_size()
    }

    /// A regular file's first block (`xtra.reg.start_block`).
    pub fn start_block(&self) -> u64 {
        self.xtra.reg_start_block()
    }

    /// A regular file's fragment, `0xffffffff` for none, and where its tail
    /// is in it (`xtra.reg.frag_idx`, `frag_off`).
    pub fn fragment(&self) -> (u32, u32) {
        (self.xtra.reg_frag_idx(), self.xtra.reg_frag_off())
    }

    /// A directory's listing: its metadata block from the directory
    /// table's start, offset, size (three more than the listing's), index
    /// entries and parent's inode number (`xtra.dir`).
    pub fn dir_info(&self) -> (u32, u16, u32, u16, u32) {
        let x = &self.xtra;
        (
            x.dir_start_block(),
            x.dir_offset(),
            x.dir_size(),
            x.dir_idx_count(),
            x.dir_parent_inode(),
        )
    }

    /// A symbolic link's target's length (`xtra.symlink_size`).
    pub fn symlink_size(&self) -> u64 {
        self.xtra.symlink_size()
    }

    /// A device's major and minor numbers (`xtra.dev`).
    pub fn device(&self) -> (u32, u32) {
        (self.xtra.dev_major(), self.xtra.dev_minor())
    }
}

/// The entries of a directory: [`Squashfs::read_dir`].
#[derive(Debug)]
pub struct ReadDir<'a, R> {
    fs: &'a mut Squashfs<R>,
    dir: Dir,
    done: bool,
}

impl<R: Read + Seek> Iterator for ReadDir<'_, R> {
    type Item = Result<DirEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.fs.fs.sqfs_dir_next(&mut self.dir, true) {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// An extended attribute: its name, with its prefix, and its value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// The extended attributes of an inode: [`Squashfs::xattrs`].
#[derive(Debug)]
pub struct Xattrs<'a, R> {
    fs: &'a mut Squashfs<R>,
    iter: XattrIter,
    done: bool,
}

impl<R> Xattrs<'_, R> {
    /// How many are left, as recorded.
    pub fn remaining(&self) -> u64 {
        if self.done { 0 } else { self.iter.remain }
    }
}

impl<R: Read + Seek> Iterator for Xattrs<'_, R> {
    type Item = Result<Xattr, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.iter.remain == 0 {
            return None;
        }
        let fs = &mut self.fs.fs;
        let x = &mut self.iter;
        let result = (|| {
            fs.sqfs_xattr_read(x)?;
            let mut name = Vec::with_capacity(fs.sqfs_xattr_name_size(x));
            fs.sqfs_xattr_name(x, Some(&mut name), true)?;
            fs.sqfs_xattr_value_size(x)?;
            let mut value = Vec::new();
            fs.sqfs_xattr_value(x, Some(&mut value))?;
            Ok(Xattr { name, value })
        })();
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

/// A walk of a tree: [`Squashfs::traverse`].
#[derive(Clone, Debug)]
pub struct Traverse {
    inner: traverse::Traverse,
}

impl Traverse {
    /// The next entry, with its path, or the end of a directory; `None` at
    /// the end (`sqfs_traverse_next`). An entry that is a directory is
    /// gone into next, unless [`Traverse::prune`]. After an error, there is
    /// nothing more.
    pub fn next<R: Read + Seek>(&mut self, fs: &mut Squashfs<R>) -> Result<Option<Step>, Error> {
        self.inner.next(&mut fs.fs)
    }

    /// Does not go into the directory just given (`sqfs_traverse_prune`).
    pub fn prune(&mut self) {
        self.inner.prune();
    }
}

/// The data of a regular file: [`Squashfs::file`]. A failure is an
/// `io::Error` that holds an [`Error`].
#[derive(Debug)]
pub struct File<'a, R> {
    fs: &'a mut Squashfs<R>,
    inode: &'a Inode,
    pos: u64,
}

impl<R: Read + Seek> Read for File<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.inode.file_size() {
            if !self.inode.is_file() {
                return Err(err("not a regular file").into());
            }
            return Ok(0);
        }
        let n = self.fs.read_at(self.inode, self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for File<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(to) => Some(to),
            SeekFrom::End(by) => self.inode.file_size().checked_add_signed(by),
            SeekFrom::Current(by) => self.pos.checked_add_signed(by),
        };
        match to {
            Some(to) => {
                self.pos = to;
                Ok(to)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start",
            )),
        }
    }
}
