//! Port of NetBSD's `udf_subr.c`, for reading: the descriptors' tags, the
//! anchors, the volume descriptor sequence, the logical volume integrity,
//! the partition maps (virtual, sparable, metadata), the file set and the
//! root directory, the nodes, and the conversions of what they record.

use std::io::{Read, Seek};

use crate::udf::clock_subr::{ClockYmdhms, clock_ymdhms_to_secs};
use crate::udf::ecma167_udf::{
    AVDP_MAIN_VDS_EX, AVDP_RESERVE_VDS_EX, DSCRPTR_SIZE, EA_A_L, EA_ENTRY_SIZE, EA_TYPE,
    EAHDR_APPL_ATTR_LOC, EAHDR_IMPL_ATTR_LOC, EFE_L_EA, EFE_UNIQUE_ID, EXTENT_AD_SIZE, FE_ICBTAG,
    FE_INF_LEN, FE_L_EA, FE_MTIME, FE_UNIQUE_ID, FID_DATA, FID_FILE_CHAR, FID_ICB, FID_L_FI,
    FID_L_IU, FSD_NEXT_EX, FSD_ROOTDIR_ICB, FSD_SIZE, FSD_STREAMDIR_ICB, ICBTAG_FILE_TYPE,
    ICBTAG_STRAT_TYPE, IMPLEXT_DATA, IMPLEXT_IMP_ID, IMPLEXT_IU_L, INDE_INDIRECT_ICB,
    LVD_DESC_CHARSET, LVD_DOMAIN_ID, LVD_FSD_LOC, LVD_INTEGRITY_SEQ_LOC, LVD_LB_SIZE, LVD_MAPS,
    LVD_MT_L, LVD_N_PM, LVD_SIZE, LVID_INTEGRITY_TYPE, LVID_L_IU, LVID_NUM_PART, LVID_SIZE,
    LVID_TABLES, LongAd, OLDVAT_TAIL_SIZE, PD_FLAGS, PD_PART_NUM, PM_LEN, PM_TYPE, PM1_PART_NUM,
    PM2_PART_ID, PM2_PART_NUM, PMM_META_BITMAP_FILE_LBN, PMM_META_FILE_LBN,
    PMM_META_MIRROR_FILE_LBN, PMS_N_ST, PMS_PACKET_LEN, PMS_ST_LOC, REGID_ID, SBD_NUM_BYTES,
    SBD_SIZE, SPT_RT_L, SPT_SIZE, TAG_CKSUM, TAG_DESC_CRC, TAG_DESC_CRC_LEN, TAG_ID,
    TAGID_ALLOCEXTENT, TAGID_ANCHOR, TAGID_EXTATTR_HDR, TAGID_EXTFENTRY, TAGID_FENTRY, TAGID_FID,
    TAGID_FSD, TAGID_ICB_TERM, TAGID_IMP_VOL, TAGID_INDIRECTENTRY, TAGID_LOGVOL,
    TAGID_LOGVOL_INTEGRITY, TAGID_PARTITION, TAGID_PRI_VOL, TAGID_SPACE_BITMAP,
    TAGID_SPARING_TABLE, TAGID_TERM, TAGID_UNALLOC_SPACE, UDF_APPL_ATTR_LOC_NOT_PRESENT,
    UDF_DESC_TAG_LENGTH, UDF_EXT_REDIRECT, UDF_EXTFENTRY_SIZE, UDF_FENTRY_PERM_GRP_MASK,
    UDF_FENTRY_PERM_OWNER_MASK, UDF_FENTRY_PERM_USER_MASK, UDF_FENTRY_SIZE, UDF_FID_SIZE,
    UDF_FILE_CHAR_PAR, UDF_ICB_FILETYPE_BLOCKDEVICE, UDF_ICB_FILETYPE_CHARDEVICE,
    UDF_ICB_FILETYPE_DIRECTORY, UDF_ICB_FILETYPE_FIFO, UDF_ICB_FILETYPE_META_MAIN,
    UDF_ICB_FILETYPE_META_MIRROR, UDF_ICB_FILETYPE_RANDOMACCESS, UDF_ICB_FILETYPE_REALTIME,
    UDF_ICB_FILETYPE_SOCKET, UDF_ICB_FILETYPE_STREAMDIR, UDF_ICB_FILETYPE_SYMLINK,
    UDF_ICB_FILETYPE_UNKNOWN, UDF_ICB_FILETYPE_VAT, UDF_ICB_INTERN_ALLOC, UDF_ICB_TAG_FLAGS_SETGID,
    UDF_ICB_TAG_FLAGS_SETUID, UDF_ICB_TAG_FLAGS_STICKY, UDF_IMPL_ATTR_LOC_NOT_PRESENT,
    UDF_INTEGRITY_CLOSED, UDF_PART_FLAG_ALLOCATED, UDF_REGID_ID_SIZE, UDF_TIMESTAMP_SIZE,
    USD_ALLOC_DESC_NUM, USD_SIZE, VAT_HEADER_LEN, VAT_SIZE, rd8, rd16, rd32, rd64, udf_ext_flags,
    udf_ext_len,
};
use crate::udf::error::{Errno, Error, Result};
use crate::udf::udf::{
    Device, MAXPHYS, UDF_MAX_ALLOC_EXTENTS, UDF_MAX_INDIRS_FOLLOW, UDF_MAX_MAPPINGS,
    UDF_MAX_SEQUENCE, UDF_PARTITIONS, UDF_PMAPS, UDF_TRANS_INTERN, UDF_TRANS_ZERO,
    UDF_VTOP_RAWPART, UDF_VTOP_TYPE_META, UDF_VTOP_TYPE_PHYS, UDF_VTOP_TYPE_SPARABLE,
    UDF_VTOP_TYPE_UNKNOWN, UDF_VTOP_TYPE_VIRT, UdfMount, UdfNode, VType,
};
use crate::udf::udf_allocation::{
    udf_addr_type, udf_get_adslot, udf_translate_file_extent, udf_translate_vtop,
};
use crate::udf::udf_osta::{
    udf_cksum, udf_ea_cksum, udf_trans_name, udf_uncompress_unicode, unicode_length,
};
use crate::udf::udf_readwrite::{udf_read_logvol_dscr, udf_read_phys_dscr};

fn err(errno: Errno, what: &'static str) -> Error {
    Error::new(errno, what)
}

/// The C string at `at` of `b`: up to its NUL, or the end of `b`.
pub(crate) fn c_str(b: &[u8], at: usize) -> &[u8] {
    let s = b.get(at..).unwrap_or(&[]);
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// `strncmp(s1, s2, n) == 0` for `s1` at `at` of `b`.
fn strncmp_eq(b: &[u8], at: usize, s2: &[u8], n: usize) -> bool {
    for i in 0..n {
        let c1 = rd8(b, at + i);
        let c2 = s2.get(i).copied().unwrap_or(0);
        if c1 != c2 {
            return false;
        }
        if c1 == 0 {
            return true;
        }
    }
    true
}

/// `n` bytes at `at` of `b`, zeros past its end: what the C reads past
/// its buffers.
fn bytes_at(b: &[u8], at: usize, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    if let Some(s) = b.get(at..) {
        let k = s.len().min(n);
        out[..k].copy_from_slice(&s[..k]);
    }
    out
}

/* --------------------------------------------------------------------- */

/// `udf_check_tag`: whether the blob starts with a good UDF tag, by the
/// checksum over its header but the checksum itself.
pub(crate) fn udf_check_tag(blob: &[u8]) -> Result<()> {
    // Check TAG header checksum.
    let mut sum: u8 = 0;
    for cnt in 0..16 {
        if cnt != TAG_CKSUM {
            sum = sum.wrapping_add(rd8(blob, cnt));
        }
    }
    if sum != rd8(blob, TAG_CKSUM) {
        // Bad tag header checksum; this is not a valid tag.
        return Err(err(Errno::EINVAL, "bad tag checksum"));
    }
    Ok(())
}

/// `udf_check_tag_payload`: the descriptor's CRC as its tag gives it, EIO
/// if it is longer than `max_length`.
pub(crate) fn udf_check_tag_payload(blob: &[u8], max_length: u32) -> Result<()> {
    let crc_len = rd16(blob, TAG_DESC_CRC_LEN);

    // Check payload CRC if applicable.
    if crc_len == 0 {
        return Ok(());
    }

    if u32::from(crc_len) > max_length {
        return Err(err(Errno::EIO, "descriptor longer than its CRC"));
    }

    let crc = udf_cksum(&bytes_at(blob, UDF_DESC_TAG_LENGTH, usize::from(crc_len)));
    if crc != rd16(blob, TAG_DESC_CRC) {
        // Bad payload CRC; this is a broken tag.
        return Err(err(Errno::EINVAL, "bad descriptor CRC"));
    }
    Ok(())
}

/// `udf_tagsize`: the length of the descriptor, in whole blocks of
/// `lb_size` (for FIDs too, unlike `udf_fidsize`).
pub(crate) fn udf_tagsize(dscr: &[u8], lb_size: u32) -> u32 {
    let tag_id = rd16(dscr, TAG_ID);

    let size: u32 = match tag_id {
        TAGID_LOGVOL => (LVD_SIZE - 1).wrapping_add(rd32(dscr, LVD_MT_L)),
        TAGID_UNALLOC_SPACE => {
            let elmsz = EXTENT_AD_SIZE as u32;
            (USD_SIZE - elmsz).wrapping_add(rd32(dscr, USD_ALLOC_DESC_NUM).wrapping_mul(elmsz))
        }
        TAGID_FID => {
            let size = (UDF_FID_SIZE as u32)
                .wrapping_add(u32::from(rd8(dscr, FID_L_FI)))
                .wrapping_add(u32::from(rd16(dscr, FID_L_IU)));
            size.wrapping_add(3) & !3
        }
        TAGID_LOGVOL_INTEGRITY => (LVID_SIZE - 4)
            .wrapping_add(rd32(dscr, LVID_L_IU))
            .wrapping_add(rd32(dscr, LVID_NUM_PART).wrapping_mul(2).wrapping_mul(4)),
        TAGID_SPACE_BITMAP => (SBD_SIZE - 1).wrapping_add(rd32(dscr, SBD_NUM_BYTES)),
        TAGID_SPARING_TABLE => {
            let elmsz = 8;
            (SPT_SIZE - elmsz).wrapping_add(u32::from(rd16(dscr, SPT_RT_L)) * elmsz)
        }
        TAGID_FENTRY => (UDF_FENTRY_SIZE as u32 + 1).wrapping_add(
            rd32(dscr, FE_L_EA)
                .wrapping_add(rd32(dscr, crate::udf::ecma167_udf::FE_L_AD))
                .wrapping_sub(1),
        ),
        TAGID_EXTFENTRY => (UDF_EXTFENTRY_SIZE as u32 + 1).wrapping_add(
            rd32(dscr, EFE_L_EA)
                .wrapping_add(rd32(dscr, crate::udf::ecma167_udf::EFE_L_AD))
                .wrapping_sub(1),
        ),
        TAGID_FSD => FSD_SIZE,
        _ => DSCRPTR_SIZE,
    };

    if size == 0 || lb_size == 0 {
        return 0;
    }

    if lb_size == 1 {
        return size;
    }

    // Round up in sectors.
    let num_lb = size.wrapping_add(lb_size - 1) / lb_size;
    num_lb.wrapping_mul(lb_size)
}

/// `udf_fidsize`: the length of a FID, to a multiple of 4.
pub(crate) fn udf_fidsize(fid: &[u8]) -> u32 {
    let size = UDF_FID_SIZE as u32 + u32::from(rd8(fid, FID_L_FI)) + u32::from(rd16(fid, FID_L_IU));
    (size + 3) & !3
}

/* --------------------------------------------------------------------- */

/// `udf_read_anchor`.
fn udf_read_anchor<R: Read + Seek>(dev: &mut Device<R>, sector: u32) -> Result<Vec<u8>> {
    match udf_read_phys_dscr(dev, sector)? {
        // Blank terminator blocks are not allowed here.
        None => Err(err(Errno::ENOENT, "blank anchor")),
        Some(dst) if rd16(&dst, TAG_ID) != TAGID_ANCHOR => Err(err(Errno::ENOENT, "not an anchor")),
        Some(dst) => Ok(dst),
    }
}

/// `udf_read_anchors`: the anchors at 256, at the end less 256, at the end
/// and at 512, of the device as one track, as a disc partition or file
/// is; how many there are.
pub(crate) fn udf_read_anchors<R: Read + Seek>(dev: &mut Device<R>, ump: &mut UdfMount) -> usize {
    // The track of a disc partition (`udf_update_trackinfo`): from 0 to
    // the last block, `last_possible_lba` in 32 bits.
    let last_possible_lba = dev.sectors() as u32;
    let track_start: u32 = 0;
    let track_end = track_start.wrapping_add(last_possible_lba).wrapping_sub(1);

    // Get our packet size: 1 for a partition, so the most there is.
    ump.packet_size = (MAXPHYS / dev.sector_size).min(64);

    // Read anchors start+256, start+512, end-256, end.
    let positions = [
        track_start.wrapping_add(256),
        track_end.wrapping_sub(256),
        track_end,
        track_start.wrapping_add(512), // [UDF 2.60/6.11.2]
    ];

    for position in positions {
        if let Ok(anchor) = udf_read_anchor(dev, position) {
            ump.anchors.push(anchor);
        }
    }

    // VATs are only recorded on sequential media, but initialise.
    ump.first_possible_vat_location = track_start.wrapping_add(2);
    ump.last_possible_vat_location = track_end;

    ump.anchors.len()
}

/* --------------------------------------------------------------------- */

/// `udf_find_raw_phys`: the physical partition with number
/// `raw_phys_part`, else the first free one, else `UDF_PARTITIONS`.
fn udf_find_raw_phys(ump: &UdfMount, raw_phys_part: u16) -> usize {
    let mut phys_part = 0;
    while phys_part < UDF_PARTITIONS {
        let Some(part) = &ump.partitions[phys_part] else {
            break;
        };
        if rd16(part, PD_PART_NUM) == raw_phys_part {
            break;
        }
        phys_part += 1;
    }
    phys_part
}

/// `udf_process_vds_descriptor`: we don't try to be smart; we just record
/// the parts.
fn udf_process_vds_descriptor(ump: &mut UdfMount, dscr: Vec<u8>) -> Result<()> {
    match rd16(&dscr, TAG_ID) {
        TAGID_PRI_VOL => ump.primary_vol = Some(dscr),
        TAGID_LOGVOL => ump.logical_vol = Some(dscr),
        TAGID_UNALLOC_SPACE => ump.unallocated = Some(dscr),
        TAGID_IMP_VOL => ump.implementation = Some(dscr),
        TAGID_PARTITION => {
            // Not much use if its not allocated.
            if rd16(&dscr, PD_FLAGS) & UDF_PART_FLAG_ALLOCATED == 0 {
                return Ok(());
            }

            // BUGALERT: some rogue implementations use random physical
            // partition numbers to break other implementations so lookup
            // the number.
            let raw_phys_part = rd16(&dscr, PD_PART_NUM);
            let phys_part = udf_find_raw_phys(ump, raw_phys_part);

            if phys_part == UDF_PARTITIONS {
                return Err(err(Errno::EINVAL, "too many partitions"));
            }

            ump.partitions[phys_part] = Some(dscr);
        }
        // Volume space extender, and others: ignored.
        _ => {}
    }
    Ok(())
}

/// `udf_read_vds_extent`: the descriptors from sector `loc`, `len` bytes
/// of them.
fn udf_read_vds_extent<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
    mut loc: u32,
    mut len: u32,
) -> Result<()> {
    let sector_size = dev.sector_size;

    // loc is sectornr, len is in bytes.
    let mut error = Err(err(Errno::EIO, "empty volume descriptor sequence"));
    let mut count = 0;
    while len != 0 {
        // Not in NetBSD: a bound, where the C loops on a length that is
        // not a multiple of the descriptors'.
        count += 1;
        if count > UDF_MAX_SEQUENCE {
            break;
        }
        let Some(dscr) = udf_read_phys_dscr(dev, loc)? else {
            // Blank block is a terminator.
            return Ok(());
        };

        // TERM descriptor is a terminator.
        if rd16(&dscr, TAG_ID) == TAGID_TERM {
            return Ok(());
        }

        // Process all others.
        let dscr_size = udf_tagsize(&dscr, sector_size);
        error = udf_process_vds_descriptor(ump, dscr);
        if error.is_err() {
            break;
        }

        len = len.wrapping_sub(dscr_size);
        loc = loc.wrapping_add(dscr_size / sector_size);
    }
    error
}

/// `udf_read_vds_space`: the volume descriptor sequence of the anchors,
/// else its reserve.
pub(crate) fn udf_read_vds_space<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
) -> Result<()> {
    // Read in VDS space provided by the anchors; if one descriptor read
    // fails, try the mirror sector.
    //
    // Check if 2nd anchor is different from 1st; if so, go for 2nd. This
    // avoids the `compatibility features' of DirectCD that may confuse
    // stuff completely.
    let mut anchor = ump.anchors.first().cloned().unwrap_or_default();
    if let Some(anchor2) = ump.anchors.get(1) {
        let main = AVDP_MAIN_VDS_EX..AVDP_MAIN_VDS_EX + EXTENT_AD_SIZE;
        if anchor.get(main.clone()) != anchor2.get(main) {
            anchor = anchor2.clone();
        }
        // Reserve is specified to be a literal copy of main.
    }

    let main_len = rd32(&anchor, AVDP_MAIN_VDS_EX);
    let main_loc = rd32(&anchor, AVDP_MAIN_VDS_EX + 4);

    let reserve_len = rd32(&anchor, AVDP_RESERVE_VDS_EX);
    let reserve_loc = rd32(&anchor, AVDP_RESERVE_VDS_EX + 4);

    if udf_read_vds_extent(dev, ump, main_loc, main_len).is_err() {
        // Reading in reserve VDS extent.
        udf_read_vds_extent(dev, ump, reserve_loc, reserve_len)?;
    }
    Ok(())
}

/* --------------------------------------------------------------------- */

/// `udf_retrieve_lvint`: the logical volume integrity sequence of the
/// logical volume descriptor; its last descriptor is the one.
///
/// The sequence can be extended through `next_extent`, which the C never
/// follows: it only does when it still has the descriptor it has just
/// taken, which it has let go of.
fn udf_retrieve_lvint<R: Read + Seek>(dev: &mut Device<R>, ump: &mut UdfMount) -> Result<()> {
    let lvd = ump.logical_vol.as_deref().unwrap_or(&[]);
    let lb_size = rd32(lvd, LVD_LB_SIZE);
    let mut len = rd32(lvd, LVD_INTEGRITY_SEQ_LOC);
    let mut lbnum = rd32(lvd, LVD_INTEGRITY_SEQ_LOC + 4);

    let mut lvint: Option<Vec<u8>> = None;
    let mut error: Result<()> = Ok(());
    let mut count = 0;
    while len != 0 {
        // Not in NetBSD: a bound, where the C loops on a length that is
        // not a multiple of the blocks'.
        count += 1;
        if count > UDF_MAX_SEQUENCE {
            break;
        }

        // Read in our integrity descriptor.
        match udf_read_phys_dscr(dev, lbnum) {
            Ok(None) => {
                error = Ok(());
                break; // empty terminates
            }
            Ok(Some(dscr)) => {
                error = Ok(());
                let dscr_type = rd16(&dscr, TAG_ID);
                if dscr_type == TAGID_TERM {
                    break; // clean terminator
                }
                if dscr_type != TAGID_LOGVOL_INTEGRITY {
                    // Fatal... corrupt disc.
                    error = Err(err(
                        Errno::ENOENT,
                        "not a logical volume integrity descriptor",
                    ));
                    break;
                }
                lvint = Some(dscr);
            }
            // Hope for the best... maybe the next is ok.
            Err(e) => error = Err(e),
        }

        // Proceed sequential.
        lbnum = lbnum.wrapping_add(1);
        len = len.wrapping_sub(lb_size);
    }

    // Clean up the mess, esp. when there is an error.
    if error.is_err() {
        lvint = None;
    }
    if lvint.is_none() {
        error = Err(err(Errno::ENOENT, "no logical volume integrity descriptor"));
    }

    ump.logvol_integrity = lvint;
    error
}

/// `udf_process_vds`: check consistency and completeness of the volume
/// descriptor sequence, and set up the partition maps.
pub(crate) fn udf_process_vds<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
) -> Result<()> {
    // We need at least an anchor (trivial, but for safety).
    if ump.anchors.is_empty() {
        return Err(err(Errno::EINVAL, "no anchor"));
    }

    // We need at least one primary and one logical volume descriptor.
    if ump.primary_vol.is_none() || ump.logical_vol.is_none() {
        return Err(err(
            Errno::EINVAL,
            "no primary or logical volume descriptor",
        ));
    }

    // We need at least one partition descriptor.
    if ump.partitions[0].is_none() {
        return Err(err(Errno::EINVAL, "no partition descriptor"));
    }

    // Check logical volume sector size verses device sector size.
    if ump.lb_size() != dev.sector_size {
        return Err(err(
            Errno::EINVAL,
            "format violation, lb_size != sector size",
        ));
    }

    // Check domain name.
    let lvd = ump.logical_vol.clone().unwrap_or_default();
    if !strncmp_eq(&lvd, LVD_DOMAIN_ID + REGID_ID, b"*OSTA UDF Compliant", 20) {
        return Err(err(Errno::EINVAL, "disc not OSTA UDF Compliant"));
    }

    // Retrieve logical volume integrity sequence.
    let _ = udf_retrieve_lvint(dev, ump);

    // We need at least one logvol integrity descriptor recorded. Note
    // that its OK to have an open logical volume integrity here. The VAT
    // will close/update the integrity.
    if ump.logvol_integrity.is_none() {
        return Err(err(Errno::EINVAL, "no logical volume integrity descriptor"));
    }

    // Process derived structures.
    let n_pm = rd32(&lvd, LVD_N_PM); // num partmaps
    ump.logvol_info = LVID_TABLES.wrapping_add((n_pm as usize).wrapping_mul(8));

    // Check logvol mappings: effective virt->log partmap translation
    // check and recording of the mapping results.
    if n_pm as usize > UDF_PMAPS {
        return Err(err(Errno::EINVAL, "too many mappings"));
    }

    // Count types and set partition numbers.
    ump.data_part = 0;
    ump.node_part = 0;
    ump.fids_part = 0;
    let (mut n_phys, mut n_virt, mut n_spar, mut n_meta) = (0, 0, 0, 0);
    let mut pmap_pos = LVD_MAPS;
    for log_part in 0..n_pm as usize {
        let pmap_stype = rd8(&lvd, pmap_pos + PM_TYPE);
        let pmap_size = rd8(&lvd, pmap_pos + PM_LEN);
        let raw_phys_part;
        let mut pmap_type;
        match pmap_stype {
            1 => {
                // Physical mapping.
                raw_phys_part = rd16(&lvd, pmap_pos + PM1_PART_NUM);
                pmap_type = UDF_VTOP_TYPE_PHYS;
                n_phys += 1;
                ump.data_part = log_part as u16;
                ump.node_part = log_part as u16;
                ump.fids_part = log_part as u16;
            }
            2 => {
                // Virtual/sparable/meta mapping.
                let map_name = pmap_pos + PM2_PART_ID + REGID_ID;
                raw_phys_part = rd16(&lvd, pmap_pos + PM2_PART_NUM);
                pmap_type = UDF_VTOP_TYPE_UNKNOWN;
                let len = UDF_REGID_ID_SIZE;

                if strncmp_eq(&lvd, map_name, b"*UDF Virtual Partition", len) {
                    pmap_type = UDF_VTOP_TYPE_VIRT;
                    n_virt += 1;
                    ump.node_part = log_part as u16;
                } else if strncmp_eq(&lvd, map_name, b"*UDF Sparable Partition", len) {
                    pmap_type = UDF_VTOP_TYPE_SPARABLE;
                    n_spar += 1;
                    ump.data_part = log_part as u16;
                    ump.node_part = log_part as u16;
                    ump.fids_part = log_part as u16;
                } else if strncmp_eq(&lvd, map_name, b"*UDF Metadata Partition", len) {
                    pmap_type = UDF_VTOP_TYPE_META;
                    n_meta += 1;
                    ump.node_part = log_part as u16;
                    ump.fids_part = log_part as u16;
                }
            }
            _ => return Err(err(Errno::EINVAL, "bad partition map")),
        }

        // BUGALERT: some rogue implementations use random physical
        // partition numbers to break other implementations so lookup the
        // number.
        let phys_part = udf_find_raw_phys(ump, raw_phys_part);

        if phys_part == UDF_PARTITIONS {
            return Err(err(Errno::EINVAL, "partition map on no partition"));
        }
        if pmap_type == UDF_VTOP_TYPE_UNKNOWN {
            return Err(err(Errno::EINVAL, "unknown partition map"));
        }

        ump.vtop[log_part] = phys_part;
        ump.vtop_tp[log_part] = pmap_type;

        pmap_pos += usize::from(pmap_size);
    }

    // Test some basic UDF assertions/requirements.
    if n_virt > 1 || n_spar > 1 || n_meta > 1 {
        return Err(err(
            Errno::EINVAL,
            "more than one virtual, sparable or metadata partition",
        ));
    }

    if n_virt != 0 && (n_phys == 0 || n_spar != 0 || n_meta != 0) {
        return Err(err(
            Errno::EINVAL,
            "virtual partition not on its own physical one",
        ));
    }
    if n_spar + n_phys == 0 {
        return Err(err(Errno::EINVAL, "no physical or sparable partition"));
    }

    // Signal its OK for now.
    Ok(())
}

/* --------------------------------------------------------------------- */

/// `udf_impl_extattr_check`: the checksum of a UDF implementation use
/// extended attribute at `at` of `blob`.
fn udf_impl_extattr_check(blob: &[u8], at: usize) -> Result<()> {
    if strncmp_eq(blob, at + IMPLEXT_IMP_ID + REGID_ID, b"*UDF", 4) {
        // Checksum valid?
        if rd16(blob, at + IMPLEXT_DATA) != udf_ea_cksum(&bytes_at(blob, at, 48)) {
            return Err(err(Errno::EINVAL, "bad extended attribute checksum"));
        }
    }
    Ok(())
}

/// `udf_extattr_search_intern`: the extended attribute of type `sattr`
/// (named `sattrname` for implementation and application use ones) in the
/// node: its offset from the start of the extended attributes, and its
/// length.
pub(crate) fn udf_extattr_search_intern(
    ump: &UdfMount,
    node: &UdfNode,
    sattr: u32,
    sattrname: &[u8],
) -> Result<(u32, u32)> {
    let sector_size = ump.sector_size;
    let enoent = || err(Errno::ENOENT, "no such extended attribute");
    let einval = || err(Errno::EINVAL, "bad extended attributes");

    // Get information from fe/efe; an int32 in the C, here as its bits.
    let (dscr, mut l_ea, eahdr) = match (&node.fe, &node.efe) {
        (Some(fe), _) => (fe, rd32(fe, FE_L_EA), UDF_FENTRY_SIZE),
        (None, Some(efe)) => (efe, rd32(efe, EFE_L_EA), UDF_EXTFENTRY_SIZE),
        (None, None) => return Err(enoent()),
    };

    // Something recorded here?
    if l_ea == 0 {
        return Err(enoent());
    }

    // Check extended attribute tag; what to do if it fails?
    let hdr = bytes_at(
        dscr,
        eahdr,
        dscr.len().saturating_sub(eahdr).max(UDF_DESC_TAG_LENGTH),
    );
    udf_check_tag(&hdr).map_err(|_| einval())?;
    if rd16(&hdr, TAG_ID) != TAGID_EXTATTR_HDR {
        return Err(einval());
    }
    udf_check_tag_payload(&hdr, crate::udf::ecma167_udf::EAHDR_SIZE).map_err(|_| einval())?;

    // Looking for Ecma-167 attributes?
    let mut offset = crate::udf::ecma167_udf::EAHDR_SIZE;

    // Looking for either implementation use or application use.
    if sattr == 2048 {
        // [4/48.10.8]
        offset = rd32(&hdr, EAHDR_IMPL_ATTR_LOC);
        if offset == UDF_IMPL_ATTR_LOC_NOT_PRESENT {
            return Err(enoent());
        }
    }
    if sattr == 65536 {
        // [4/48.10.9]
        offset = rd32(&hdr, EAHDR_APPL_ATTR_LOC);
        if offset == UDF_APPL_ATTR_LOC_NOT_PRESENT {
            return Err(enoent());
        }
    }

    // Paranoia check offset and l_ea.
    if u64::from(l_ea.wrapping_add(offset)) >= u64::from(sector_size) - u64::from(EA_ENTRY_SIZE) {
        return Err(einval());
    }

    // Find our extended attribute.
    l_ea = l_ea.wrapping_sub(offset);
    let mut pos = eahdr as u64 + u64::from(offset);

    while l_ea >= EA_ENTRY_SIZE {
        let at = usize::try_from(pos).unwrap_or(usize::MAX);
        // Get complete attribute length and check for roque values.
        let a_l = rd32(dscr, at.saturating_add(EA_A_L));
        if a_l == 0 || a_l > l_ea {
            return Err(einval());
        }

        let attr_type = rd32(dscr, at.saturating_add(EA_TYPE));
        if attr_type == sattr {
            // We might have found it!
            if attr_type < 2048 {
                // Ecma-167 attribute.
                return Ok((offset, a_l));
            }

            // Implementation use and application use extended attributes
            // have a name to identify. They share the same structure only
            // UDF implementation use extended attributes have a checksum
            // we need to check.
            if c_str(dscr, at.saturating_add(IMPLEXT_IMP_ID + REGID_ID)) == sattrname {
                // We have found our appl/implementation attribute.
                return Ok((offset, a_l));
            }
        }

        // Next attribute.
        pos += u64::from(a_l);
        l_ea -= a_l;
        offset = offset.wrapping_add(a_l);
    }
    // Not found.
    Err(enoent())
}

/// `udf_update_lvid_from_vat_extattr`: the name of the logical volume from
/// the UDF 1.50 VAT's "*UDF VAT LVExtension" extended attribute, if it is
/// up to date.
fn udf_update_lvid_from_vat_extattr(ump: &mut UdfMount, vat_node: &UdfNode) -> Result<()> {
    let extstr = b"*UDF VAT LVExtension";

    // Get information from fe/efe.
    let (dscr, vat_uniqueid, ea_start) = match (&vat_node.fe, &vat_node.efe) {
        (Some(fe), _) => (fe, rd64(fe, FE_UNIQUE_ID), UDF_FENTRY_SIZE),
        (None, Some(efe)) => (efe, rd64(efe, EFE_UNIQUE_ID), UDF_EXTFENTRY_SIZE),
        (None, None) => return Err(err(Errno::ENOENT, "no VAT")),
    };

    let (offset, a_l) = udf_extattr_search_intern(ump, vat_node, 2048, extstr)?;

    let implext = ea_start + offset as usize;
    udf_impl_extattr_check(dscr, implext)?;

    // Paranoia.
    let iu_l = rd32(dscr, implext + IMPLEXT_IU_L);
    if u64::from(a_l) != 48 + u64::from(iu_l) + 144 {
        return Err(err(Errno::EINVAL, "VAT LVExtension size doesn't compute"));
    }

    // We have found our "VAT LVExtension attribute.
    let lvextpos = implext + IMPLEXT_DATA + iu_l as usize;

    // Check if it was updated the last time.
    if rd64(dscr, lvextpos) == vat_uniqueid {
        ump.logvol_id = bytes_at(dscr, lvextpos + 16, 128);
    }
    Ok(())
}

/// `udf_check_for_vat`: whether the node is a VAT; if it is, it is read
/// in, and closes the logical volume integrity.
fn udf_check_for_vat<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
    vat_node: &mut UdfNode,
) -> Result<()> {
    // Set vnode type to regular file or we can't read from it!
    vat_node.v_type = VType::VREG;

    // Get information from fe/efe; vat_length is really 64 bits though
    // impossible.
    let dscr = vat_node.dscr().to_vec();
    let vat_length = rd64(&dscr, FE_INF_LEN) as u32;
    let unique_id = rd64(
        &dscr,
        if vat_node.fe.is_some() {
            FE_UNIQUE_ID
        } else {
            EFE_UNIQUE_ID
        },
    );
    let mtime_at = if vat_node.fe.is_some() {
        FE_MTIME
    } else {
        crate::udf::ecma167_udf::EFE_MTIME
    };

    // Check icb filetype! it has to be 0 or UDF_ICB_FILETYPE_VAT.
    let filetype = rd8(&dscr, FE_ICBTAG + ICBTAG_FILE_TYPE);
    if filetype != 0 && filetype != UDF_ICB_FILETYPE_VAT {
        return Err(err(Errno::ENOENT, "not a VAT"));
    }

    let vat_offset;
    let vat_entries;
    if filetype == 0 {
        // The old 1.50 VAT, with its regid at its end.
        vat_offset = 0;
        vat_entries = vat_length.wrapping_sub(36) / 4;

        // Read in tail of virtual allocation table file.
        let tail = vn_rdwr(
            dev,
            ump,
            vat_node,
            u64::from(vat_entries.wrapping_mul(4)),
            OLDVAT_TAIL_SIZE,
            false,
        )?;

        // Check 1.50 VAT.
        if !strncmp_eq(&tail, REGID_ID, b"*UDF Virtual Alloc Tbl", 22) {
            return Err(err(Errno::ENOENT, "VAT format 1.50 rejected"));
        }

        // Update LVID from "*UDF VAT LVExtension" extended attribute if
        // present.
        let _ = udf_update_lvid_from_vat_extattr(ump, vat_node);
    } else {
        // Read in head of virtual allocation table file.
        let vat = vn_rdwr(dev, ump, vat_node, 0, VAT_SIZE, false)?;

        vat_offset = u32::from(rd16(&vat, VAT_HEADER_LEN));
        vat_entries = vat_length.wrapping_sub(vat_offset) / 4;

        ump.logvol_id = bytes_at(&vat, 4, 128);
    }

    // Read in complete VAT file.
    let vat_table = vn_rdwr(dev, ump, vat_node, 0, vat_length as usize, false)?;

    // VAT format accepted, marking it closed.
    if let Some(lvint) = ump.logvol_integrity.as_mut() {
        if lvint.len() < 48 {
            lvint.resize(48, 0);
        }
        lvint[40..48].copy_from_slice(&unique_id.to_le_bytes());
        lvint[LVID_INTEGRITY_TYPE..LVID_INTEGRITY_TYPE + 4]
            .copy_from_slice(&UDF_INTEGRITY_CLOSED.to_le_bytes());
        let mtime = bytes_at(&dscr, mtime_at, UDF_TIMESTAMP_SIZE);
        lvint[16..16 + UDF_TIMESTAMP_SIZE].copy_from_slice(&mtime);
    }

    ump.vat_table = vat_table;
    ump.vat_offset = vat_offset;
    ump.vat_entries = vat_entries;
    Ok(())
}

/// `udf_search_vat`: the last VAT in the last 64 sectors of the track,
/// else in the 64 before them, and so on.
///
/// The C goes on for good once it is at the start of the track, and its
/// sector numbers wrap; here it stops after the first sectors.
fn udf_search_vat<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
    phys_part: u16,
) -> Result<()> {
    // Start reading forward in blocks from the first possible vat
    // location. If not found in this block, start again a bit before
    // until we get a hit.
    let first = ump.first_possible_vat_location;
    let last = ump.last_possible_vat_location;
    let mut late_vat_loc = last;
    let mut early_vat_loc = late_vat_loc.saturating_sub(64).max(first);

    let mut accepted_vat_node: Option<UdfNode> = None;
    let mut error = Err(err(Errno::ENOENT, "no VAT"));
    loop {
        let mut vat_loc = early_vat_loc;
        while vat_loc <= late_vat_loc {
            let icb_loc = LongAd {
                len: 0,
                lb_num: vat_loc,
                part_num: UDF_VTOP_RAWPART,
            };
            // Not in NetBSD, which reads the VAT's short allocation
            // descriptors as sectors, of the raw partition its node is
            // read from: they are on the physical partition, as NetBSD
            // records them and Linux reads them.
            error = udf_get_node_on(dev, ump, &icb_loc, phys_part)
                .and_then(|mut vat_node| {
                    udf_check_for_vat(dev, ump, &mut vat_node)?;
                    Ok(vat_node)
                })
                .map(|vat_node| accepted_vat_node = Some(vat_node));
            // Walk forward.
            match vat_loc.checked_add(1) {
                Some(next) => vat_loc = next,
                None => break,
            }
        }
        if accepted_vat_node.is_some() || early_vat_loc <= first {
            break;
        }

        early_vat_loc = early_vat_loc.saturating_sub(64).max(first);
        late_vat_loc = early_vat_loc.saturating_add(64).min(last);
        if late_vat_loc <= first {
            break;
        }
    }

    // Keep our last accepted VAT node around.
    if let Some(vat_node) = accepted_vat_node {
        ump.vat_node = Some(vat_node);
        return Ok(());
    }
    error
}

/// `udf_read_sparables`: the first of the sparing tables of the sparable
/// partition map at `mapping` of the logical volume descriptor.
fn udf_read_sparables<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
    mapping: usize,
) -> Result<()> {
    let lvd = ump.logical_vol.clone().unwrap_or_default();
    ump.sparable_packet_size = u32::from(rd16(&lvd, mapping + PMS_PACKET_LEN));

    for spar in 0..usize::from(rd8(&lvd, mapping + PMS_N_ST)) {
        let lb_num = rd32(&lvd, mapping + PMS_ST_LOC + 4 * spar);
        if let Ok(Some(dscr)) = udf_read_phys_dscr(dev, lb_num)
            && rd16(&dscr, TAG_ID) == TAGID_SPARING_TABLE
        {
            ump.sparing_table = Some(dscr);
            break; // we're done
        }
    }

    if ump.sparing_table.is_some() {
        return Ok(());
    }
    Err(err(Errno::ENOENT, "no sparing table"))
}

/// `udf_read_metadata_nodes`: the metadata file of the metadata partition
/// map at `mapping`, else its mirror (mounted read-only).
fn udf_read_metadata_nodes<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
    mapping: usize,
) -> Result<()> {
    let lvd = ump.logical_vol.clone().unwrap_or_default();

    // BUGALERT: some rogue implementations use random physical partition
    // numbers to break other implementations so lookup the number.
    let raw_phys_part = rd16(&lvd, mapping + PM2_PART_NUM);
    let phys_part = udf_find_raw_phys(ump, raw_phys_part);

    // The index of the physical partition, as a logical one.
    let mut icb_loc = LongAd {
        len: 0,
        lb_num: rd32(&lvd, mapping + PMM_META_FILE_LBN),
        part_num: phys_part as u16,
    };
    ump.metadata_node = udf_get_node(dev, ump, &icb_loc).ok();

    icb_loc.lb_num = rd32(&lvd, mapping + PMM_META_MIRROR_FILE_LBN);
    if icb_loc.lb_num != u32::MAX {
        ump.metadatamirror_node = udf_get_node(dev, ump, &icb_loc).ok();
    }

    icb_loc.lb_num = rd32(&lvd, mapping + PMM_META_BITMAP_FILE_LBN);
    if icb_loc.lb_num != u32::MAX {
        ump.metadatabitmap_node = udf_get_node(dev, ump, &icb_loc).ok();
    }

    // If we're mounting read-only we relax the requirements.
    if ump.metadata_node.is_some() {
        return Ok(());
    }
    if ump.metadatamirror_node.is_some() {
        // Metadata file not readable, substituting Metadata copy file.
        ump.metadata_node = ump.metadatamirror_node.take();
        return Ok(());
    }
    Err(err(Errno::EFAULT, "failed to read metadata files"))
}

/// `udf_read_vds_tables`: the tables of the partition maps: VAT,
/// sparing table, metadata files.
pub(crate) fn udf_read_vds_tables<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
) -> Result<()> {
    let lvd = ump.logical_vol.clone().unwrap_or_default();

    // Iterate (again) over the part mappings for locations.
    let n_pm = rd32(&lvd, LVD_N_PM) as usize; // num partmaps
    let mut pmap_pos = LVD_MAPS;

    for log_part in 0..n_pm {
        let enoent = |_| err(Errno::ENOENT, "VDS tables failing");
        match ump.vtop_tp[log_part] {
            UDF_VTOP_TYPE_PHYS => {}
            // Search and load VAT.
            UDF_VTOP_TYPE_VIRT => {
                // The physical partition map the virtual one is on.
                let phys_part = (0..n_pm)
                    .find(|&p| {
                        ump.vtop_tp[p] == UDF_VTOP_TYPE_PHYS && ump.vtop[p] == ump.vtop[log_part]
                    })
                    .unwrap_or(0) as u16;
                udf_search_vat(dev, ump, phys_part).map_err(enoent)?
            }
            // Load one of the sparable tables.
            UDF_VTOP_TYPE_SPARABLE => udf_read_sparables(dev, ump, pmap_pos).map_err(enoent)?,
            // Load the associated file descriptors.
            UDF_VTOP_TYPE_META => udf_read_metadata_nodes(dev, ump, pmap_pos).map_err(enoent)?,
            _ => {}
        }
        pmap_pos += usize::from(rd8(&lvd, pmap_pos + PM_LEN));
    }

    // Space tables are only read in when writing.
    Ok(())
}

/// `udf_read_rootdirs`: the file set descriptor (the last of its
/// sequence), and the root directory it gives.
pub(crate) fn udf_read_rootdirs<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &mut UdfMount,
) -> Result<UdfNode> {
    let lvd = ump.logical_vol.clone().unwrap_or_default();

    // Get fileset descriptor sequence.
    let mut fsd_loc = LongAd::at(&lvd, LVD_FSD_LOC);
    let mut fsd_len = fsd_loc.len;

    let mut count = 0;
    while fsd_len != 0 {
        // Not in NetBSD: a bound, where the C loops on a length that is
        // not a multiple of the sectors', or a chain of extents that does.
        count += 1;
        if count > UDF_MAX_SEQUENCE {
            break;
        }
        // Translate fsd_loc to lb_num.
        let Ok((lb_num, _)) = udf_translate_vtop(ump, &fsd_loc) else {
            break;
        };
        // End markers.
        let Ok(Some(dscr)) = udf_read_phys_dscr(dev, lb_num) else {
            break;
        };

        // Analyse.
        let dscr_type = rd16(&dscr, TAG_ID);
        if dscr_type == TAGID_TERM {
            break;
        }
        if dscr_type != TAGID_FSD {
            return Err(err(Errno::ENOENT, "not a file set descriptor"));
        }

        // Continue to the next fsd.
        fsd_len = fsd_len.wrapping_sub(dev.sector_size);
        fsd_loc.lb_num = fsd_loc.lb_num.wrapping_add(1);

        // Follow up to fsd->next_ex (long_ad) if its not null.
        let next_ex = LongAd::at(&dscr, FSD_NEXT_EX);
        if next_ex.len != 0 {
            fsd_loc = next_ex;
            fsd_len = next_ex.len;
        }

        // Update.
        ump.fileset_desc = Some(dscr);
    }

    // There has to be one.
    let Some(fsd) = ump.fileset_desc.clone() else {
        return Err(err(Errno::ENOENT, "no file set descriptor"));
    };

    // Try to read in the rootdir.
    let rootdir_node = udf_get_node(dev, ump, &LongAd::at(&fsd, FSD_ROOTDIR_ICB))
        .map_err(|_| err(Errno::ENOENT, "rootdirs failing"))?;

    // Try the system stream directory; ignored.
    let streamdir_icb = LongAd::at(&fsd, FSD_STREAMDIR_ICB);
    if streamdir_icb.len != 0 {
        let _ = udf_get_node(dev, ump, &streamdir_icb);
    }

    Ok(rootdir_node)
}

/* --------------------------------------------------------------------- */

/// `udf_loadvnode`: the node at `node_icb_loc` (its block and partition):
/// its (extended) file entry, the last of a strategy 4096 chain, through
/// indirect entries, and its allocation extents.
pub(crate) fn udf_get_node<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    node_icb_loc: &LongAd,
) -> Result<UdfNode> {
    udf_get_node_on(dev, ump, node_icb_loc, node_icb_loc.part_num)
}

/// `udf_loadvnode`, for a node whose short allocation descriptors are on
/// partition `short_part`.
fn udf_get_node_on<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    node_icb_loc: &LongAd,
    short_part: u16,
) -> Result<UdfNode> {
    let lb_size = ump.lb_size();
    let einval = || err(Errno::EINVAL, "bad node");
    let node_icb_loc = LongAd {
        len: lb_size,
        lb_num: node_icb_loc.lb_num,
        part_num: node_icb_loc.part_num,
    };

    // Garbage check: translate udf_node_icb_loc to sectornr.
    udf_translate_vtop(ump, &node_icb_loc).map_err(|_| einval())?;

    // Build udf_node.
    let mut udf_node = UdfNode {
        loc: node_icb_loc,
        fe: None,
        efe: None,
        ext: Vec::new(),
        v_type: VType::VNON,
        short_part,
    };

    let mut icb_loc = node_icb_loc;
    let mut strat4096 = false;
    let mut udf_file_type = UDF_ICB_FILETYPE_UNKNOWN;
    let mut num_indir_followed = 0;

    // Start reading descriptors.
    let mut error: Result<()> = Ok(());
    while error.is_ok() {
        // Try to read in fe/efe.
        let dscr = match udf_read_logvol_dscr(dev, ump, &icb_loc) {
            Ok(dscr) => dscr,
            Err(e) => {
                error = Err(e);
                break;
            }
        };

        // Blank sector marks end of sequence, check this.
        let Some(dscr) = dscr else {
            if !strat4096 {
                error = Err(err(Errno::ENOENT, "blank node"));
            }
            break;
        };

        // Process descriptor based on the descriptor type.
        let dscr_type = rd16(&dscr, TAG_ID);

        // If dealing with an indirect entry, follow the link.
        if dscr_type == TAGID_INDIRECTENTRY {
            icb_loc = LongAd::at(&dscr, INDE_INDIRECT_ICB);
            num_indir_followed += 1;
            if num_indir_followed > UDF_MAX_INDIRS_FOLLOW {
                error = Err(err(Errno::EMLINK, "too many indirect entries"));
                break;
            }
            continue;
        }

        // Not in NetBSD, which only ends a strategy 4096 chain with a
        // blank block, though it says a terminator ends it too: a
        // terminal entry, as mkudffs records, or a terminating
        // descriptor, as Linux reads them.
        if strat4096 && (dscr_type == TAGID_ICB_TERM || dscr_type == TAGID_TERM) {
            break;
        }

        // Only file entries and extended file entries allowed here.
        if dscr_type != TAGID_FENTRY && dscr_type != TAGID_EXTFENTRY {
            error = Err(err(Errno::ENOENT, "not a file entry"));
            break;
        }

        // Not in NetBSD, which only asserts it: an (extended) file entry
        // longer than its block.
        if udf_tagsize(&dscr, lb_size) != lb_size {
            error = Err(einval());
            break;
        }

        // Record and process/update (ext)fentry.
        let strat = rd16(&dscr, FE_ICBTAG + ICBTAG_STRAT_TYPE);
        udf_file_type = rd8(&dscr, FE_ICBTAG + ICBTAG_FILE_TYPE);
        if dscr_type == TAGID_FENTRY {
            udf_node.fe = Some(dscr);
        } else {
            udf_node.efe = Some(dscr);
        }

        // Check recording strategy (structure).
        //
        // Strategy 4096 is a daisy linked chain terminating with an
        // unrecorded sector or a TERM descriptor. The next descriptor is
        // to be found in the sector that follows the current sector.
        if strat == 4096 {
            strat4096 = true;
            icb_loc.lb_num = icb_loc.lb_num.wrapping_add(1);
        } else if strat == 4 {
            // Strategy 4 is the normal strategy and terminates, but if
            // we're in strategy 4096, we can't have strategy 4 mixed in.
            if strat4096 {
                error = Err(einval());
            }
            break; // done
        } else {
            // Not in NetBSD, which reads the same descriptor again for
            // good: the other strategies, as Linux has them.
            error = Err(err(Errno::EINVAL, "unsupported strategy"));
        }
    }

    // First round of cleanup code.
    if error.is_err() {
        return Err(einval());
    }

    // Go through all allocations extents of this descriptor and when
    // encountering a redirect read in the allocation extension. These are
    // daisy-chained.
    let mut slot = 0;
    while let Some(icb_loc) = udf_get_adslot(&udf_node, slot) {
        slot += 1;

        if udf_ext_flags(icb_loc.len) != UDF_EXT_REDIRECT {
            continue;
        }

        // Got redirect extent.
        if udf_node.ext.len() >= UDF_MAX_ALLOC_EXTENTS {
            // Implementation limit, too many allocation extensions on
            // udf_node.
            return Err(einval());
        }

        // Length can only be *one* lb : UDF 2.50/2.3.7.1.
        if udf_ext_len(icb_loc.len) != lb_size {
            return Err(einval());
        }

        // Load in allocation extent.
        let Some(dscr) = udf_read_logvol_dscr(dev, ump, &icb_loc).map_err(|_| einval())? else {
            break;
        };

        // Process read-in descriptor.
        if rd16(&dscr, TAG_ID) != TAGID_ALLOCEXTENT {
            return Err(einval());
        }

        // Recording redirect extent.
        udf_node.ext.push(dscr);
    }

    // Translate UDF filetypes into vnode types.
    //
    // Systemfiles like the meta main and mirror files are not treated as
    // normal files, so we type them as having no type. UDF dictates that
    // they are not allowed to be visible.
    udf_node.v_type = match udf_file_type {
        UDF_ICB_FILETYPE_DIRECTORY | UDF_ICB_FILETYPE_STREAMDIR => VType::VDIR,
        UDF_ICB_FILETYPE_BLOCKDEVICE => VType::VBLK,
        UDF_ICB_FILETYPE_CHARDEVICE => VType::VCHR,
        UDF_ICB_FILETYPE_SOCKET => VType::VSOCK,
        UDF_ICB_FILETYPE_FIFO => VType::VFIFO,
        UDF_ICB_FILETYPE_SYMLINK => VType::VLNK,
        UDF_ICB_FILETYPE_VAT | UDF_ICB_FILETYPE_META_MAIN | UDF_ICB_FILETYPE_META_MIRROR => {
            VType::VNON
        }
        UDF_ICB_FILETYPE_RANDOMACCESS | UDF_ICB_FILETYPE_REALTIME => VType::VREG,
        // YIKES, something else.
        _ => VType::VNON,
    };

    Ok(udf_node)
}

/* --------------------------------------------------------------------- */

pub(crate) const S_ISUID: u32 = 0o4000;
pub(crate) const S_ISGID: u32 = 0o2000;
pub(crate) const S_ISVTX: u32 = 0o1000;
pub(crate) const S_IFIFO: u32 = 0o010000;
pub(crate) const S_IFCHR: u32 = 0o020000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFBLK: u32 = 0o060000;
pub(crate) const S_IFREG: u32 = 0o100000;
pub(crate) const S_IFLNK: u32 = 0o120000;
pub(crate) const S_IFSOCK: u32 = 0o140000;

/// `udf_perm_to_unix_mode`.
fn udf_perm_to_unix_mode(perm: u32) -> u32 {
    let mut mode = perm & UDF_FENTRY_PERM_USER_MASK;
    mode |= (perm & UDF_FENTRY_PERM_GRP_MASK) >> 2;
    mode |= (perm & UDF_FENTRY_PERM_OWNER_MASK) >> 4;
    mode
}

/// `udf_icb_to_unix_filetype`.
fn udf_icb_to_unix_filetype(icbftype: u8) -> u32 {
    match icbftype {
        UDF_ICB_FILETYPE_DIRECTORY | UDF_ICB_FILETYPE_STREAMDIR => S_IFDIR,
        UDF_ICB_FILETYPE_FIFO => S_IFIFO,
        UDF_ICB_FILETYPE_CHARDEVICE => S_IFCHR,
        UDF_ICB_FILETYPE_BLOCKDEVICE => S_IFBLK,
        UDF_ICB_FILETYPE_RANDOMACCESS | UDF_ICB_FILETYPE_REALTIME => S_IFREG,
        UDF_ICB_FILETYPE_SYMLINK => S_IFLNK,
        UDF_ICB_FILETYPE_SOCKET => S_IFSOCK,
        // No idea what this is.
        _ => 0,
    }
}

/// `udf_getaccessmode`: the permissions, with setuid, setgid and sticky
/// from the ICB tag's flags, and the file type.
pub(crate) fn udf_getaccessmode(udf_node: &UdfNode) -> u32 {
    let dscr = udf_node.dscr();
    let udf_perm = rd32(dscr, crate::udf::ecma167_udf::FE_PERM);
    let icbftype = rd8(dscr, FE_ICBTAG + ICBTAG_FILE_TYPE);
    let icbflags = rd16(dscr, FE_ICBTAG + crate::udf::ecma167_udf::ICBTAG_FLAGS);

    let mut mode = udf_perm_to_unix_mode(udf_perm);
    let ftype = udf_icb_to_unix_filetype(icbftype);

    // Set suid, sgid, sticky from flags in fe/efe.
    if icbflags & UDF_ICB_TAG_FLAGS_SETUID != 0 {
        mode |= S_ISUID;
    }
    if icbflags & UDF_ICB_TAG_FLAGS_SETGID != 0 {
        mode |= S_ISGID;
    }
    if icbflags & UDF_ICB_TAG_FLAGS_STICKY != 0 {
        mode |= S_ISVTX;
    }

    mode | ftype
}

/// Whether the logical volume's names are OSTA compressed Unicode: its
/// character set is type 0, "OSTA Compressed Unicode".
pub(crate) fn udf_is_osta_typ0(ump: &UdfMount) -> bool {
    let lvd = ump.logical_vol.as_deref().unwrap_or(&[]);
    rd8(lvd, LVD_DESC_CHARSET) == 0
        && c_str(lvd, LVD_DESC_CHARSET + 1) == b"OSTA Compressed Unicode"
}

/// One character in UTF-8, as NetBSD's `wput_utf8` writes it (in
/// `sys/fs/unicode.h`), as long as it fits in `n` bytes. NetBSD writes the
/// two halves of a surrogate pair on their own (CESU-8); here a pair is one
/// character, of 4 bytes, as Linux writes it. A lone half is written on its
/// own, as NetBSD does (WTF-8).
fn wput_utf8(out: &mut Vec<u8>, n: usize, wc: u32) -> usize {
    let mut buf = [0u8; 4];
    let bytes: &[u8] = match char::from_u32(wc) {
        Some(c) => c.encode_utf8(&mut buf).as_bytes(),
        None => {
            // A surrogate: 3 bytes, as the characters around it.
            buf = [
                0xE0 | (wc >> 12) as u8,
                0x80 | ((wc >> 6) & 0x3F) as u8,
                0x80 | (wc & 0x3F) as u8,
                0,
            ];
            &buf[..3]
        }
    };
    if n < bytes.len() {
        // Bound check failure.
        return 0;
    }
    out.extend_from_slice(bytes);
    bytes.len()
}

/// `udf_to_unix_name`: a name recorded as `id` (`len` bytes of it, with
/// more after it, as far as the C reads), to the bytes of a UNIX name, at
/// most `result_len` of them: from OSTA compressed Unicode to UTF-8
/// through `UDFTransName`, else 8-bit characters copied as they are.
pub(crate) fn udf_to_unix_name(
    result_len: usize,
    id: &[u8],
    len: usize,
    is_osta_typ0: bool,
) -> Vec<u8> {
    let mut result = Vec::new();
    if is_osta_typ0 {
        let mut raw_name = Vec::new();
        let ucode_chars = udf_uncompress_unicode(&bytes_at(id, 0, len), &mut raw_name);
        let ucode_chars = if ucode_chars < 0 {
            0
        } else {
            (ucode_chars as usize).min(unicode_length(&raw_name))
        };
        let unix_name = udf_trans_name(&raw_name[..ucode_chars]);
        // Output UTF8.
        let mut result_len = result_len;
        let mut i = 0;
        while i < unix_name.len() {
            let mut ch = u32::from(unix_name[i]);
            if (0xD800..0xDC00).contains(&ch)
                && let Some(&low) = unix_name
                    .get(i + 1)
                    .filter(|&&low| (0xDC00..0xE000).contains(&low))
            {
                ch = 0x10000 + ((ch - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                i += 1;
            }
            let nout = wput_utf8(&mut result, result_len, ch);
            result_len -= nout;
            if ch == 0 {
                result.pop();
                break;
            }
            i += 1;
        }
    } else {
        // Assume 8bit char length byte latin-1.
        let name = c_str(id, 1);
        result.extend_from_slice(&name[..name.len().min(result_len)]);
    }
    result
}

/// A time: seconds from 1970, UTC, and nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timespec {
    /// Seconds from 1970-01-01 00:00 UTC; before it for earlier times.
    pub sec: i64,
    /// Nanoseconds, from the centiseconds, hundreds of microseconds and
    /// microseconds recorded: up to 2 570 000 000 for their largest values.
    pub nsec: u32,
}

/// `udf_timestamp_to_timespec`: a timestamp, in its time zone, or in
/// `gmtoff` seconds east of UTC if it does not give one.
pub(crate) fn udf_timestamp_to_timespec(ump: &UdfMount, timestamp: &[u8]) -> Timespec {
    let type_tz = rd16(timestamp, 0);
    // Fill in ymdhms structure from timestamp.
    let ymdhms = ClockYmdhms {
        dt_year: rd16(timestamp, 2),
        dt_mon: rd8(timestamp, 4),
        dt_day: rd8(timestamp, 5),
        dt_hour: rd8(timestamp, 6),
        dt_min: rd8(timestamp, 7),
        dt_sec: rd8(timestamp, 8),
    };

    let mut secs = clock_ymdhms_to_secs(&ymdhms);
    let usecs = u32::from(rd8(timestamp, 11))
        + 100 * u32::from(rd8(timestamp, 10))
        + 10000 * u32::from(rd8(timestamp, 9));
    let nsecs = usecs * 1000;

    // Calculate the time zone. The timezone is 12 bit signed 2's
    // compliment, so we gotta do some extra magic to handle it right.
    let mut tz = type_tz & 0x0fff; // only lower 12 bits are significant
    if tz & 0x0800 != 0 {
        tz |= 0xf000; // sign extension
    }

    // Check if we are specified a timezone to convert.
    if type_tz & 0x1000 != 0 {
        if tz as i16 != -2047 {
            secs -= i64::from(tz as i16) * 60;
        }
    } else {
        secs -= i64::from(ump.gmtoff);
    }

    Timespec {
        sec: secs,
        nsec: nsecs,
    }
}

/* --------------------------------------------------------------------- */

/// A FID read from a directory's stream, as `udf_read_fid_stream` gives
/// it.
#[derive(Clone, Debug)]
pub(crate) struct Fid {
    pub(crate) name: Vec<u8>,
    pub(crate) file_char: u8,
    pub(crate) icb: LongAd,
}

/// The blocks of a directory, read once: `vn_rdwr` of its FIDs.
#[derive(Debug, Default)]
pub(crate) struct DirBlocks {
    /// The last blocks read, by number.
    cache: Vec<(u32, Vec<u8>)>,
}

impl DirBlocks {
    /// `len` bytes at `offset` of the directory.
    fn read<R: Read + Seek>(
        &mut self,
        dev: &mut Device<R>,
        ump: &UdfMount,
        dir_node: &UdfNode,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let lb_size = u64::from(ump.lb_size());
        let mut out = Vec::with_capacity(len);
        let mut at = offset;
        let end = offset + len as u64;
        while at < end {
            let block =
                u32::try_from(at / lb_size).map_err(|_| err(Errno::EINVAL, "offset too large"))?;
            if !self.cache.iter().any(|(b, _)| *b == block) {
                let data = udf_read_filebuf(dev, ump, dir_node, block, 1)?;
                if self.cache.len() >= 4 {
                    self.cache.remove(0);
                }
                self.cache.push((block, data));
            }
            let data = self
                .cache
                .iter()
                .find(|(b, _)| *b == block)
                .map(|(_, d)| d.as_slice())
                .unwrap_or(&[]);
            let from = (at % lb_size) as usize;
            let n = ((end - at) as usize).min(data.len().saturating_sub(from));
            if n == 0 {
                return Err(err(Errno::EIO, "short read"));
            }
            out.extend_from_slice(&data[from..from + n]);
            at += n as u64;
        }
        Ok(out)
    }
}

/// `udf_read_fid_stream`: the FID at `*offset` of the directory, which it
/// moves past.
pub(crate) fn udf_read_fid_stream<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    dir_node: &UdfNode,
    blocks: &mut DirBlocks,
    offset: &mut u64,
    is_osta_typ0: bool,
) -> Result<Fid> {
    // Check if we're past the end of the directory.
    let file_size = dir_node.file_size();
    if *offset >= file_size {
        return Err(err(Errno::EINVAL, "past the end of the directory"));
    }

    // Get maximum length of FID descriptor.
    let lb_size = ump.lb_size() as usize;

    let enough = file_size - *offset >= UDF_FID_SIZE as u64;
    if !enough {
        // Short dir ...
        return Err(err(Errno::EIO, "short directory"));
    }

    let len = (file_size - *offset).min(lb_size as u64) as usize;
    let mut fid = blocks.read(dev, ump, dir_node, *offset, len)?;
    fid.resize(lb_size, 0);

    // Check if we got a whole descriptor.
    let broken = || err(Errno::EIO, "broken directory entry");

    // Check if our FID header is OK.
    udf_check_tag(&fid).map_err(|_| broken())?;
    if rd16(&fid, TAG_ID) != TAGID_FID {
        return Err(broken());
    }

    // Check for length.
    let fid_size = udf_fidsize(&fid);
    let enough = file_size - *offset >= u64::from(fid_size);
    if !enough {
        return Err(broken());
    }

    // Check FID contents.
    udf_check_tag_payload(&fid, lb_size as u32).map_err(|_| broken())?;

    // We got a whole and valid descriptor! Create resulting dirent
    // structure.
    let file_char = rd8(&fid, FID_FILE_CHAR);
    let fid_name = FID_DATA + usize::from(rd16(&fid, FID_L_IU));
    let mut name = udf_to_unix_name(
        crate::udf::udf::NAME_MAX,
        fid.get(fid_name..).unwrap_or(&[]),
        usize::from(rd8(&fid, FID_L_FI)),
        is_osta_typ0,
    );

    // '..' has no name, so provide one.
    if file_char & UDF_FILE_CHAR_PAR != 0 {
        name = b"..".to_vec();
    }

    // Advance.
    *offset += u64::from(fid_size);

    Ok(Fid {
        name,
        file_char,
        icb: LongAd::at(&fid, FID_ICB),
    })
}

/* --------------------------------------------------------------------- */

/// `udf_read_internal`: the data recorded in the node, in a block.
fn udf_read_internal(ump: &UdfMount, node: &UdfNode) -> Result<Vec<u8>> {
    let sector_size = ump.sector_size as usize;
    let dscr = node.dscr();
    let (dscr_size, l_ea) = match node.fe {
        Some(_) => (UDF_FENTRY_SIZE, rd32(dscr, FE_L_EA)),
        None => (UDF_EXTFENTRY_SIZE, rd32(dscr, EFE_L_EA)),
    };
    let inflen = node.file_size();
    debug_assert_eq!(udf_addr_type(node), UDF_ICB_INTERN_ALLOC);

    // Not in NetBSD, which notes there should be: bounds on l_ea and
    // inf_len.
    let srcpos = dscr_size as u64 + u64::from(l_ea);
    if inflen >= sector_size as u64 || srcpos + inflen > dscr.len() as u64 {
        return Err(err(Errno::EINVAL, "internal data past its node"));
    }

    // Copy out info.
    let mut blob = vec![0; sector_size];
    let (srcpos, inflen) = (srcpos as usize, inflen as usize);
    blob[..inflen].copy_from_slice(&dscr[srcpos..srcpos + inflen]);
    Ok(blob)
}

/// `udf_read_filebuf`: `sectors` blocks of the node from block `from`.
pub(crate) fn udf_read_filebuf<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    udf_node: &UdfNode,
    from: u32,
    sectors: u32,
) -> Result<Vec<u8>> {
    let sector_size = ump.sector_size;

    if sectors > UDF_MAX_MAPPINGS {
        return Err(err(Errno::EIO, "implementation limit on bufsize"));
    }

    let mut mapping = Vec::with_capacity(sectors as usize);
    udf_translate_file_extent(ump, udf_node, from, sectors, &mut mapping)?;

    let mut buf = vec![0; sectors as usize * sector_size as usize];

    // Pre-check if its an internal.
    if mapping.first() == Some(&UDF_TRANS_INTERN) {
        let blob = udf_read_internal(ump, udf_node)?;
        buf[..blob.len()].copy_from_slice(&blob);
        return Ok(buf);
    }

    // Request read-in of data from disc scheduler.
    let mut sector = 0;
    while sector < mapping.len() {
        let buf_offset = sector * sector_size as usize;
        // Check if its zero or unmapped to stop reading.
        if mapping[sector] == UDF_TRANS_ZERO {
            // The block is zeros already.
            sector += 1;
            continue;
        }
        let run_start = mapping[sector];
        let mut run_length = 1;
        while sector + 1 < mapping.len() && mapping[sector + 1] == mapping[sector] + 1 {
            run_length += 1;
            sector += 1;
        }
        let rbuflen = run_length * sector_size as usize;
        dev.read_phys_into(run_start, &mut buf[buf_offset..buf_offset + rbuflen])?;
        sector += 1;
    }
    Ok(buf)
}

/// `vn_rdwr` of `len` bytes at `offset` of the node, as `udf_read` reads
/// them: with `alt_semantics` (`IO_ALTSEMANTICS`) from any node, else
/// only from a regular file; a read past the end is EIO.
pub(crate) fn vn_rdwr<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    node: &UdfNode,
    offset: u64,
    len: usize,
    alt_semantics: bool,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    udf_read(dev, ump, node, offset, len, alt_semantics, &mut out)?;
    if out.len() != len {
        return Err(err(Errno::EIO, "short read"));
    }
    Ok(out)
}

/// `udf_read`: up to `len` bytes at `offset` of the node, to its end,
/// appended to `out`.
pub(crate) fn udf_read<R: Read + Seek>(
    dev: &mut Device<R>,
    ump: &UdfMount,
    node: &UdfNode,
    offset: u64,
    len: usize,
    alt_semantics: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // Protect against rogue programs reading raw directories and links.
    if !alt_semantics {
        if node.v_type == VType::VDIR {
            return Err(err(Errno::EISDIR, "a directory"));
        }
        // All but regular files just give EINVAL.
        if node.v_type != VType::VREG {
            return Err(err(Errno::EINVAL, "not a regular file"));
        }
    }

    // Get file/directory filesize.
    let file_size = node.file_size();
    if file_size <= offset {
        return Ok(());
    }
    let end = offset + (file_size - offset).min(len as u64);

    // Read the blocks, as many as a transfer has at a time.
    let lb_size = u64::from(ump.lb_size());
    let per_read = u64::from((MAXPHYS / ump.lb_size()).clamp(1, UDF_MAX_MAPPINGS));
    let mut at = offset;
    while at < end {
        let from = at / lb_size;
        let last = (end - 1) / lb_size;
        let sectors = (last - from + 1).min(per_read);
        let from32 = u32::try_from(from).map_err(|_| err(Errno::EINVAL, "offset too large"))?;
        let data = udf_read_filebuf(dev, ump, node, from32, sectors as u32)?;
        let skip = (at - from * lb_size) as usize;
        let n = ((end - at) as usize).min(data.len() - skip);
        out.extend_from_slice(&data[skip..skip + n]);
        at += n as u64;
    }
    Ok(())
}

/// Not in NetBSD: whether all of a regular file's data reads, as
/// `udf_read` would read it, without reading it: each block translated to
/// a sector of the device, or zeros, or data in the node, within it.
pub(crate) fn udf_check_read<R: Read + Seek>(
    dev: &Device<R>,
    ump: &UdfMount,
    node: &UdfNode,
) -> Result<()> {
    if node.v_type == VType::VDIR {
        return Err(err(Errno::EISDIR, "a directory"));
    }
    if node.v_type != VType::VREG {
        return Err(err(Errno::EINVAL, "not a regular file"));
    }
    let file_size = node.file_size();
    if file_size == 0 {
        return Ok(());
    }
    let lb_size = u64::from(ump.lb_size());
    let per_read = u64::from((MAXPHYS / ump.lb_size()).clamp(1, UDF_MAX_MAPPINGS));
    let blocks = file_size.div_ceil(lb_size);
    let sectors = dev.sectors();
    let mut mapping = Vec::new();
    let mut from = 0;
    while from < blocks {
        let n = (blocks - from).min(per_read);
        let from32 = u32::try_from(from).map_err(|_| err(Errno::EINVAL, "offset too large"))?;
        udf_translate_file_extent(ump, node, from32, n as u32, &mut mapping)?;
        if mapping.first() == Some(&UDF_TRANS_INTERN) {
            return udf_read_internal(ump, node).map(|_| ());
        }
        for &sector in &mapping {
            if sector != UDF_TRANS_ZERO && sector >= sectors {
                return Err(err(Errno::EIO, "read past the end of the device"));
            }
        }
        from += n;
    }
    Ok(())
}
