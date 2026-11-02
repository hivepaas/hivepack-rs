//! Port of NetBSD's `udf.h`: the mount (`struct udf_mount`) and node
//! (`struct udf_node`) structures, for reading, and the device they are
//! read from.

use std::io::{Read, Seek, SeekFrom};

use crate::udf::ecma167_udf::LongAd;
use crate::udf::error::{Errno, Error, Result};

pub(crate) const UDF_MAX_MAPPINGS: u32 = 128;
pub(crate) const UDF_SYMLINKBUFLEN: usize = 64 * 1024;
pub(crate) const UDF_MAX_INDIRS_FOLLOW: u32 = 1024;
pub(crate) const UDF_PARTITIONS: usize = 4;
pub(crate) const UDF_PMAPS: usize = 5;
pub(crate) const UDF_MAX_ALLOC_EXTENTS: usize = 50;
pub(crate) const UDF_TRANS_ZERO: u64 = u64::MAX;
pub(crate) const UDF_TRANS_INTERN: u64 = u64::MAX - 2;

/// `MAXPHYS`: the most a transfer reads.
pub(crate) const MAXPHYS: u32 = 64 * 1024;
/// `NAME_MAX`, which names of entries are cut to.
pub(crate) const NAME_MAX: usize = 511;
/// `PATH_MAX`, which symbolic links' targets are cut to.
pub(crate) const PATH_MAX: usize = 1024;
/// `MAXPATHLEN`.
pub(crate) const MAXPATHLEN: usize = 1024;

/// `[0..UDF_PMAPS>` are normal.
pub(crate) const UDF_VTOP_RAWPART: u16 = UDF_PMAPS as u16;

// Partition mapping types; RAW and UNKNOWN are the same.
pub(crate) const UDF_VTOP_TYPE_RAW: u8 = 0;
pub(crate) const UDF_VTOP_TYPE_UNKNOWN: u8 = 0;
pub(crate) const UDF_VTOP_TYPE_PHYS: u8 = 1;
pub(crate) const UDF_VTOP_TYPE_VIRT: u8 = 2;
pub(crate) const UDF_VTOP_TYPE_SPARABLE: u8 = 3;
pub(crate) const UDF_VTOP_TYPE_META: u8 = 4;

/// The most descriptors one sequence is read for (VDS, integrity, file
/// sets), and the most a descriptor is long: the C has no bounds there.
pub(crate) const UDF_MAX_SEQUENCE: u32 = 1024;
pub(crate) const UDF_MAX_DSCR_LEN: u32 = 1 << 20;

/// `enum vtype`: what a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VType {
    /// No type: the system files of the VAT and metadata partition, and
    /// the file types NetBSD does not know.
    VNON,
    /// A regular file.
    VREG,
    /// A directory (or a stream directory).
    VDIR,
    /// A block device.
    VBLK,
    /// A character device.
    VCHR,
    /// A symbolic link.
    VLNK,
    /// A socket.
    VSOCK,
    /// A FIFO.
    VFIFO,
}

/// The image, read in sectors: the device NetBSD mounts.
#[derive(Debug)]
pub(crate) struct Device<R> {
    pub(crate) reader: R,
    /// Its length in bytes.
    pub(crate) size: u64,
    /// `discinfo.sector_size`.
    pub(crate) sector_size: u32,
}

impl<R: Read + Seek> Device<R> {
    /// The number of whole sectors: `last_possible_lba`.
    pub(crate) fn sectors(&self) -> u64 {
        self.size / u64::from(self.sector_size)
    }

    /// `udf_read_phys_sectors`: `sectors` sectors from `start`; reading
    /// past the end of the device is a read error.
    pub(crate) fn read_phys_sectors(&mut self, start: u32, sectors: u32) -> Result<Vec<u8>> {
        self.check(u64::from(start), u64::from(sectors))?;
        let mut blob = vec![0; sectors as usize * self.sector_size as usize];
        self.read_phys_into(u64::from(start), &mut blob)?;
        Ok(blob)
    }

    /// Whether `sectors` sectors from `start` are on the device.
    fn check(&self, start: u64, sectors: u64) -> Result<()> {
        if start
            .checked_add(sectors)
            .is_none_or(|end| end > self.sectors())
        {
            return Err(Error::new(Errno::EIO, "read past the end of the device"));
        }
        Ok(())
    }

    /// Whole sectors from `start` into `blob`.
    pub(crate) fn read_phys_into(&mut self, start: u64, blob: &mut [u8]) -> Result<()> {
        let sector_size = u64::from(self.sector_size);
        self.check(start, blob.len() as u64 / sector_size)?;
        self.reader.seek(SeekFrom::Start(start * sector_size))?;
        self.reader.read_exact(blob)?;
        Ok(())
    }
}

/// `struct udf_node`, as read: its file entry or extended file entry, and
/// its allocation extents.
#[derive(Clone, Debug)]
pub struct UdfNode {
    /// Where its (first) descriptor is: `loc`, with the length of a block.
    pub(crate) loc: LongAd,
    /// The file entry, one block.
    pub(crate) fe: Option<Vec<u8>>,
    /// The extended file entry, one block.
    pub(crate) efe: Option<Vec<u8>>,
    /// The allocation extent descriptors, one block each.
    pub(crate) ext: Vec<Vec<u8>>,
    /// The type of its vnode.
    pub(crate) v_type: VType,
    /// The partition its short allocation descriptors are on: its own,
    /// but for the VAT.
    pub(crate) short_part: u16,
}

impl UdfNode {
    /// Its descriptor: the file entry, else the extended one.
    pub(crate) fn dscr(&self) -> &[u8] {
        match (&self.fe, &self.efe) {
            (Some(fe), _) => fe,
            (None, Some(efe)) => efe,
            (None, None) => &[],
        }
    }

    /// `inf_len`.
    pub(crate) fn file_size(&self) -> u64 {
        use crate::udf::ecma167_udf::{FE_INF_LEN, rd64};
        rd64(self.dscr(), FE_INF_LEN)
    }
}

/// `struct udf_mount`, for reading.
#[derive(Clone, Debug, Default)]
pub(crate) struct UdfMount {
    /// `discinfo.sector_size`.
    pub(crate) sector_size: u32,
    /// The anchors read: `anchors[]`.
    pub(crate) anchors: Vec<Vec<u8>>,

    // The VDS: the last of each.
    pub(crate) primary_vol: Option<Vec<u8>>,
    pub(crate) logical_vol: Option<Vec<u8>>,
    pub(crate) unallocated: Option<Vec<u8>>,
    pub(crate) implementation: Option<Vec<u8>>,
    pub(crate) partitions: [Option<Vec<u8>>; UDF_PARTITIONS],

    /// The logical volume integrity descriptor, and where its
    /// implementation use (`logvol_info`) starts.
    pub(crate) logvol_integrity: Option<Vec<u8>>,
    pub(crate) logvol_info: usize,
    /// The logical volume's identifier, updated from the VAT.
    pub(crate) logvol_id: Vec<u8>,

    // The partition maps: logical partition to physical, and their types.
    pub(crate) vtop: [usize; UDF_PMAPS + 1],
    pub(crate) vtop_tp: [u8; UDF_PMAPS + 1],
    pub(crate) data_part: u16,
    pub(crate) node_part: u16,
    pub(crate) fids_part: u16,

    // VAT.
    pub(crate) first_possible_vat_location: u32,
    pub(crate) last_possible_vat_location: u32,
    pub(crate) vat_table: Vec<u8>,
    pub(crate) vat_offset: u32,
    pub(crate) vat_entries: u32,
    pub(crate) vat_node: Option<UdfNode>,

    // Sparable partition.
    pub(crate) sparable_packet_size: u32,
    pub(crate) sparing_table: Option<Vec<u8>>,

    // Metadata partition.
    pub(crate) metadata_node: Option<UdfNode>,
    pub(crate) metadatamirror_node: Option<UdfNode>,
    pub(crate) metadatabitmap_node: Option<UdfNode>,

    /// The file set descriptor.
    pub(crate) fileset_desc: Option<Vec<u8>>,

    /// `packet_size`.
    pub(crate) packet_size: u32,

    // `mount_args`.
    pub(crate) gmtoff: i32,
    pub(crate) anon_uid: u32,
    pub(crate) anon_gid: u32,
    pub(crate) unhide: bool,
    pub(crate) mntonname: Vec<u8>,
}

impl UdfMount {
    /// `logical_vol->lb_size`.
    pub(crate) fn lb_size(&self) -> u32 {
        use crate::udf::ecma167_udf::{LVD_LB_SIZE, rd32};
        self.logical_vol
            .as_deref()
            .map_or(0, |lvd| rd32(lvd, LVD_LB_SIZE))
    }
}
