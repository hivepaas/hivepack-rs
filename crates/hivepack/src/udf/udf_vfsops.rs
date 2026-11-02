//! Port of NetBSD's `udf_vfsops.c`, for reading: `udf_mountfs`, the
//! sequence a volume is mounted in.

use std::io::{Read, Seek};

use crate::udf::ecma167_udf::{LVID_INTEGRITY_TYPE, UDF_INTEGRITY_CLOSED, rd32};
use crate::udf::error::{Errno, Error, Result};
use crate::udf::udf::{Device, UdfMount, UdfNode};
use crate::udf::udf_subr::{
    udf_process_vds, udf_read_anchors, udf_read_rootdirs, udf_read_vds_space, udf_read_vds_tables,
};

/// What `udf_mountfs` takes from `struct udf_args`, and what is not in
/// NetBSD: whether to refuse a volume that is not closed.
pub(crate) struct MountArgs {
    pub(crate) gmtoff: i32,
    pub(crate) anon_uid: u32,
    pub(crate) anon_gid: u32,
    pub(crate) unhide: bool,
    pub(crate) strict: bool,
    pub(crate) mntonname: Vec<u8>,
}

/// `udf_mountfs`: the volume on the device, as its sector size gives it,
/// and its root directory.
pub(crate) fn udf_mountfs<R: Read + Seek>(
    dev: &mut Device<R>,
    args: &MountArgs,
) -> Result<(UdfMount, UdfNode)> {
    // Inspect sector size.
    let sector_size = dev.sector_size;
    if !sector_size.is_power_of_two() || sector_size < 512 {
        return Err(Error::new(
            Errno::EIO,
            "hit NetBSD implementation fence on sector size",
        ));
    }

    // Temporary check to overcome sectorsize >= 8192 bytes panic.
    if sector_size >= 8192 {
        return Err(Error::new(
            Errno::EIO,
            "hit implementation limit, sectorsize to big",
        ));
    }

    let mut ump = UdfMount {
        sector_size,
        gmtoff: args.gmtoff,
        anon_uid: args.anon_uid,
        anon_gid: args.anon_gid,
        unhide: args.unhide,
        mntonname: args.mntonname.clone(),
        ..UdfMount::default()
    };

    // Read all anchors to get volume descriptor sequence.
    let num_anchors = udf_read_anchors(dev, &mut ump);
    if num_anchors == 0 {
        return Err(Error::new(Errno::EINVAL, "no anchor"));
    }

    // Read in volume descriptor sequence.
    udf_read_vds_space(dev, &mut ump)?;

    // Check consistency and completeness.
    udf_process_vds(dev, &mut ump)?;

    // The logical volume's name, which the VAT can update.
    ump.logvol_id = ump
        .logical_vol
        .as_deref()
        .and_then(|lvd| lvd.get(84..212))
        .unwrap_or(&[])
        .to_vec();

    // Read vds support tables like VAT, sparable etc.
    udf_read_vds_tables(dev, &mut ump)?;

    // Check if volume integrity is closed otherwise its dirty; NetBSD
    // refuses it, here only when asked to.
    if args.strict && !udf_logvol_closed(&ump) {
        return Err(Error::new(Errno::EPERM, "file system is not clean"));
    }

    // Read root directory.
    let root = udf_read_rootdirs(dev, &mut ump)?;

    // Success!
    Ok((ump, root))
}

/// Whether the logical volume integrity is closed.
pub(crate) fn udf_logvol_closed(ump: &UdfMount) -> bool {
    ump.logvol_integrity
        .as_deref()
        .is_some_and(|lvid| rd32(lvid, LVID_INTEGRITY_TYPE) == UDF_INTEGRITY_CLOSED)
}
