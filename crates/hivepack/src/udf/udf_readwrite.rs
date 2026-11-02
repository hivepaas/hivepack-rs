//! Port of NetBSD's `udf_readwrite.c`, for reading: the descriptors read
//! from sectors, and the node descriptors of the logical volume, as the
//! disc strategies read them (`udf_strat_direct.c`, `udf_strat_rmw.c`).

use std::io::{Read, Seek};

use crate::udf::ecma167_udf::LongAd;
use crate::udf::error::{Errno, Error, Result};
use crate::udf::udf::{Device, UDF_MAX_DSCR_LEN, UdfMount};
use crate::udf::udf_allocation::udf_translate_vtop;
use crate::udf::udf_subr::{udf_check_tag, udf_check_tag_payload, udf_tagsize};

/// `udf_read_phys_dscr`: the descriptor at `sector`, `None` for a blank
/// sector. A descriptor longer than a sector is read whole, its length in
/// sectors.
pub(crate) fn udf_read_phys_dscr<R: Read + Seek>(
    dev: &mut Device<R>,
    sector: u32,
) -> Result<Option<Vec<u8>>> {
    let sector_size = dev.sector_size;

    // Read initial piece.
    let mut dst = dev.read_phys_sectors(sector, 1)?;

    // Check if its a valid tag.
    let mut error = udf_check_tag(&dst);
    if error.is_err() {
        // Check if its an empty block.
        if dst.iter().all(|&b| b == 0) {
            // Return no error but with no dscrptr.
            return Ok(None);
        }
    }
    // Calculate descriptor size; an int in the C.
    let dscrlen = udf_tagsize(&dst, sector_size) as i32;

    if error.is_ok() && dscrlen > sector_size as i32 {
        // Read the rest of descriptor; not in NetBSD, a bound on it.
        if dscrlen as u32 > UDF_MAX_DSCR_LEN {
            return Err(Error::new(Errno::EIO, "descriptor too long"));
        }
        let sectors = (dscrlen as u32).div_ceil(sector_size);
        match dev.read_phys_sectors(sector.wrapping_add(1), sectors - 1) {
            Ok(rest) => dst.extend_from_slice(&rest),
            Err(e) => error = Err(e),
        }
    }
    error?;
    udf_check_tag_payload(&dst, dscrlen as u32)?;
    Ok(Some(dst))
}

/// `udf_read_logvol_dscr`: a node descriptor in the logical volume, at
/// `icb`, as the strategies read it: one block of it, `None` for a blank
/// block.
///
/// The direct strategy copies the descriptor it reads from a blank block,
/// which it has not (a null pointer); here it is `None`, as the read-modify
/// -write strategy gives.
pub(crate) fn udf_read_logvol_dscr<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    icb: &LongAd,
) -> Result<Option<Vec<u8>>> {
    let lb_size = ump.lb_size() as usize;

    let (sector, _) = udf_translate_vtop(ump, icb)?;

    // Try to read in fe/efe.
    let Some(mut dscr) = udf_read_phys_dscr(dev, sector)? else {
        return Ok(None);
    };
    dscr.resize(lb_size, 0);
    Ok(Some(dscr))
}
