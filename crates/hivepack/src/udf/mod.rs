//! Reading UDF volumes in safe Rust, ported from NetBSD's UDF file system
//! (`sys/fs/udf`), read-only.
//!
//! [`Udf`] mounts the volume of a DVD, Blu-ray or hard disk image as
//! NetBSD does: UDF 1.02 to 2.60, on physical, sparable (CD-RW, DVD-RW),
//! virtual (VAT, for write-once discs) and metadata partitions, with block
//! sizes from 512 to 4096 bytes. Directories are listed, attributes given,
//! symbolic links and files read as NetBSD has them, and the same errors
//! returned; where NetBSD would loop, crash or read past its buffers, the
//! port has bounds instead, which `docs/udf.md` in the repository lists,
//! with how the port is checked against what Linux reads.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut udf = hivepack::udf::Udf::open(std::fs::File::open("disc.iso")?)?;
//! let root = udf.root().clone();
//! let entries: Vec<_> = udf.read_dir(&root)?.collect::<Result<_, _>>()?;
//! for entry in entries {
//!     if entry.is_parent() {
//!         continue;
//!     }
//!     let node = udf.node(entry.icb)?;
//!     let stat = udf.stat(&node);
//!     println!("{} {} bytes", String::from_utf8_lossy(&entry.name), stat.size);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod clock_subr;
mod ecma167_udf;
mod error;
mod udf;
mod udf_allocation;
mod udf_osta;
mod udf_readwrite;
mod udf_subr;
mod udf_vfsops;
mod udf_vnops;

use std::io::{self, Read, Seek, SeekFrom};

pub use ecma167_udf::LongAd;
pub use error::{Errno, Error};
pub use udf::{UdfNode as Node, VType};
pub use udf_subr::Timespec;
pub use udf_vnops::{DirEntry, Stat};

use ecma167_udf::{FE_INF_LEN, rd64};
use udf::{
    Device, UDF_VTOP_TYPE_META, UDF_VTOP_TYPE_PHYS, UDF_VTOP_TYPE_SPARABLE, UDF_VTOP_TYPE_VIRT,
    UdfMount,
};
use udf_subr::{udf_check_read, udf_get_node, udf_read, udf_to_unix_name};
use udf_vfsops::{MountArgs, udf_logvol_closed, udf_mountfs};
use udf_vnops::{DirStream, udf_do_readlink, udf_getattr, udf_lookup_name_in_dir};

/// The NetBSD sources this crate follows: `sys/fs/udf` of the netbsd-11
/// branch at this commit.
pub const UPSTREAM_COMMIT: &str = "83fb854bf81acb43fbc9e3b1b0c5db8d21926d8e";

/// The sector sizes tried, in order, when [`Options::sector_size`] does not
/// give one.
pub const SECTOR_SIZES: [u32; 4] = [2048, 512, 1024, 4096];

/// How to mount: NetBSD's mount arguments (`struct udf_args`), and what is
/// not in NetBSD.
#[derive(Clone, Debug)]
pub struct Options {
    /// The sector size of the device, which the volume's blocks must be
    /// (NetBSD takes the device's); `None` tries [`SECTOR_SIZES`].
    pub sector_size: Option<u32>,
    /// Seconds east of UTC, for the times that do not give their time
    /// zone (`gmtoff`).
    pub gmtoff: i32,
    /// The owner of the nodes that record none (-1): `anon_uid`.
    pub anon_uid: u32,
    /// The group of the nodes that record none (-1): `anon_gid`.
    pub anon_gid: u32,
    /// Where the volume is mounted, for the symbolic links that start
    /// there (`f_mntonname`).
    pub mount_point: Vec<u8>,
    /// Not in NetBSD: list hidden entries too, as Linux's `unhide` does.
    pub unhide: bool,
    /// Refuse a volume whose logical volume integrity is not closed, as
    /// NetBSD does (EPERM, "please fsck"); by default it is read, and
    /// [`Volume::closed`] says so.
    pub strict: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            sector_size: None,
            gmtoff: 0,
            anon_uid: u32::MAX,
            anon_gid: u32::MAX,
            mount_point: Vec::new(),
            unhide: false,
            strict: false,
        }
    }
}

/// The kind of a partition map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartitionMap {
    /// A physical partition (type 1).
    Physical,
    /// A virtual partition, through the VAT of write-once media.
    Virtual,
    /// A sparable partition, of rewritable media with remapped packets.
    Sparable,
    /// A metadata partition (UDF 2.50), through the metadata file.
    Metadata,
}

/// What the mounted volume is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    /// The sector size, which is its block size.
    pub sector_size: u32,
    /// The logical volume's identifier, as a name: from the VAT if it has
    /// one.
    pub name: Vec<u8>,
    /// Whether its logical volume integrity is closed (or a VAT closes
    /// it): if not, it was not unmounted cleanly.
    pub closed: bool,
    /// Its partition maps.
    pub maps: Vec<PartitionMap>,
}

/// A mounted UDF volume.
#[derive(Debug)]
pub struct Udf<R> {
    dev: Device<R>,
    ump: UdfMount,
    root: Node,
}

impl<R: Read + Seek> Udf<R> {
    /// Mounts the volume of the image.
    pub fn open(reader: R) -> Result<Udf<R>, Error> {
        Udf::with_options(reader, &Options::default())
    }

    /// Mounts the volume of the image, with options.
    pub fn with_options(mut reader: R, options: &Options) -> Result<Udf<R>, Error> {
        let size = reader.seek(SeekFrom::End(0))?;
        let args = MountArgs {
            gmtoff: options.gmtoff,
            anon_uid: options.anon_uid,
            anon_gid: options.anon_gid,
            unhide: options.unhide,
            strict: options.strict,
            mntonname: options.mount_point.clone(),
        };
        let sizes = match options.sector_size {
            Some(size) => vec![size],
            None => SECTOR_SIZES.to_vec(),
        };
        let mut dev = Device {
            reader,
            size,
            sector_size: 0,
        };
        let mut first_error = None;
        for sector_size in sizes {
            dev.sector_size = sector_size;
            match udf_mountfs(&mut dev, &args) {
                Ok((ump, root)) => return Ok(Udf { dev, ump, root }),
                Err(e) => {
                    // The error of the first size that has anchors, else
                    // of the first.
                    let anchors = !matches!(
                        e,
                        Error::Udf {
                            what: "no anchor",
                            ..
                        }
                    );
                    match &first_error {
                        None => first_error = Some((anchors, e)),
                        Some((false, _)) if anchors => first_error = Some((anchors, e)),
                        Some(_) => {}
                    }
                }
            }
        }
        Err(first_error.map_or_else(|| Error::new(Errno::EINVAL, "no anchor"), |(_, e)| e))
    }

    /// What the volume is.
    pub fn volume(&self) -> Volume {
        let ump = &self.ump;
        // A dstring: its length in its last byte.
        let id = &ump.logvol_id;
        let len = id
            .last()
            .map_or(0, |&l| usize::from(l))
            .min(id.len().saturating_sub(1));
        let name = udf_to_unix_name(udf::NAME_MAX, id, len, udf_subr::udf_is_osta_typ0(ump));
        let n_pm = ump
            .logical_vol
            .as_deref()
            .map_or(0, |lvd| ecma167_udf::rd32(lvd, ecma167_udf::LVD_N_PM));
        let maps = ump.vtop_tp[..(n_pm as usize).min(udf::UDF_PMAPS)]
            .iter()
            .filter_map(|&tp| match tp {
                UDF_VTOP_TYPE_PHYS => Some(PartitionMap::Physical),
                UDF_VTOP_TYPE_VIRT => Some(PartitionMap::Virtual),
                UDF_VTOP_TYPE_SPARABLE => Some(PartitionMap::Sparable),
                UDF_VTOP_TYPE_META => Some(PartitionMap::Metadata),
                _ => None,
            })
            .collect();
        Volume {
            sector_size: ump.sector_size,
            name,
            closed: udf_logvol_closed(ump),
            maps,
        }
    }

    /// The root directory.
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// The node at `icb`: a directory entry's.
    pub fn node(&mut self, icb: LongAd) -> Result<Node, Error> {
        udf_get_node(&mut self.dev, &self.ump, &icb)
    }

    /// The entries of a directory, as NetBSD lists them, but `.`: those
    /// that are not deleted, nor hidden (but with [`Options::unhide`]),
    /// with `..` first. After an error, there are no more.
    pub fn read_dir(&mut self, dir: &Node) -> Result<ReadDir<'_, R>, Error> {
        Ok(ReadDir {
            udf: self,
            stream: DirStream::new(dir)?,
        })
    }

    /// The node an entry of a directory is, by its name: of all the
    /// entries that are not deleted, hidden ones too.
    pub fn lookup(&mut self, dir: &Node, name: &[u8]) -> Result<Option<Node>, Error> {
        match udf_lookup_name_in_dir(&mut self.dev, &self.ump, dir, name)? {
            Some(icb) => self.node(icb).map(Some),
            None => Ok(None),
        }
    }

    /// The attributes of a node.
    pub fn stat(&mut self, node: &Node) -> Stat {
        udf_getattr(&mut self.dev, &self.ump, node)
    }

    /// The target of a symbolic link.
    pub fn read_link(&mut self, node: &Node) -> Result<Vec<u8>, Error> {
        udf_do_readlink(&mut self.dev, &self.ump, node)
    }

    /// Reads the data of a regular file at `offset`: as much as fits in
    /// `buf`, to the end of the file.
    pub fn read_at(&mut self, node: &Node, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let mut out = Vec::with_capacity(buf.len());
        udf_read(
            &mut self.dev,
            &self.ump,
            node,
            offset,
            buf.len(),
            false,
            &mut out,
        )?;
        buf[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    /// Not in NetBSD: checks that all the data of a regular file reads,
    /// without reading it: each of its blocks is on the image, or zeros
    /// (not recorded), or in the node. What reading it would fail with,
    /// but an error of the image's reader, comes out here: a block past
    /// the end of an image cut short, or allocation descriptors that do not
    /// cover the file.
    pub fn check_data(&mut self, node: &Node) -> Result<(), Error> {
        udf_check_read(&self.dev, &self.ump, node)
    }

    /// The data of a regular file, to read and seek.
    pub fn file<'a>(&'a mut self, node: &'a Node) -> File<'a, R> {
        File {
            udf: self,
            node,
            pos: 0,
        }
    }

    /// The image.
    pub fn into_inner(self) -> R {
        self.dev.reader
    }
}

impl Node {
    /// What the node is.
    pub fn kind(&self) -> VType {
        self.v_type
    }

    /// The length of its data.
    pub fn size(&self) -> u64 {
        rd64(self.dscr(), FE_INF_LEN)
    }

    /// Where it is.
    pub fn location(&self) -> LongAd {
        self.loc
    }
}

/// The entries of a directory: [`Udf::read_dir`].
#[derive(Debug)]
pub struct ReadDir<'a, R> {
    udf: &'a mut Udf<R>,
    stream: DirStream,
}

impl<R: Read + Seek> Iterator for ReadDir<'_, R> {
    type Item = Result<DirEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let fid = self
            .stream
            .next_fid(&mut self.udf.dev, &self.udf.ump, true)?;
        Some(fid.map(DirEntry::from))
    }
}

/// The data of a regular file: [`Udf::file`]. A failure is an
/// `io::Error` that holds an [`Error`].
#[derive(Debug)]
pub struct File<'a, R> {
    udf: &'a mut Udf<R>,
    node: &'a Node,
    pos: u64,
}

impl<R: Read + Seek> Read for File<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.udf.read_at(self.node, self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for File<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(to) => Some(to),
            SeekFrom::End(by) => self.node.size().checked_add_signed(by),
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
