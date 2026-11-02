//! Port of NetBSD's `udf_allocation.c`, for reading: logical blocks to
//! sectors, through the partition maps, and the extents of files.

use crate::udf::ecma167_udf::{
    AEE_DATA, AEE_L_AD, EFE_L_AD, EFE_L_EA, FE_ICBTAG, FE_L_AD, FE_L_EA, ICBTAG_FLAGS,
    LONG_AD_SIZE, LongAd, PD_PART_LEN, PD_START_LOC, SHORT_AD_SIZE, SPT_ENTRIES, SPT_RT_L,
    UDF_EXT_ALLOCATED, UDF_EXT_ALLOCATED_BUT_NOT_USED, UDF_EXT_FREE, UDF_EXT_REDIRECT,
    UDF_EXTFENTRY_SIZE, UDF_FENTRY_SIZE, UDF_ICB_INTERN_ALLOC, UDF_ICB_LONG_ALLOC,
    UDF_ICB_SHORT_ALLOC, UDF_ICB_TAG_FLAGS_ALLOC_MASK, rd16, rd32, udf_ext_flags, udf_ext_len,
};
use crate::udf::error::{Errno, Error, Result};
use crate::udf::udf::{
    UDF_TRANS_INTERN, UDF_TRANS_ZERO, UDF_VTOP_RAWPART, UDF_VTOP_TYPE_META, UDF_VTOP_TYPE_PHYS,
    UDF_VTOP_TYPE_RAW, UDF_VTOP_TYPE_SPARABLE, UDF_VTOP_TYPE_VIRT, UdfMount, UdfNode,
};

/// How many times a translation goes through the metadata partition: the
/// C goes on for as long as the metadata file maps on itself.
const UDF_MAX_TRANSLATE_AGAIN: u32 = 4;

fn einval(what: &'static str) -> Error {
    Error::new(Errno::EINVAL, what)
}

/// `udf_translate_vtop`: a logical block in a partition (`icb_loc`) to the
/// sector it is in, and how many blocks follow it in the same extent.
pub(crate) fn udf_translate_vtop(ump: &UdfMount, icb_loc: &LongAd) -> Result<(u32, u32)> {
    let mut vpart = icb_loc.part_num;
    let mut lb_num = icb_loc.lb_num;
    if vpart > UDF_VTOP_RAWPART {
        return Err(einval("bad partition"));
    }

    let mut again = 0;
    loop {
        // Not in NetBSD: the partition a metadata extent maps on is not
        // checked.
        let Some(&tp) = ump.vtop_tp.get(usize::from(vpart)) else {
            return Err(einval("bad partition"));
        };
        let part = ump.vtop[usize::from(vpart)];
        let pdesc = ump
            .partitions
            .get(part)
            .and_then(Option::as_deref)
            .unwrap_or(&[]);

        match tp {
            UDF_VTOP_TYPE_RAW => {
                // 1:1 to the end of the device.
                return Ok((lb_num, i32::MAX as u32));
            }
            UDF_VTOP_TYPE_PHYS => {
                // Transform into its disc logical block.
                if lb_num > rd32(pdesc, PD_PART_LEN) {
                    return Err(einval("block past its partition"));
                }
                // Extent from here to the end of the partition.
                return Ok((
                    lb_num.wrapping_add(rd32(pdesc, PD_START_LOC)),
                    rd32(pdesc, PD_PART_LEN) - lb_num,
                ));
            }
            UDF_VTOP_TYPE_VIRT => {
                // Only maps one logical block, lookup in VAT.
                if lb_num >= ump.vat_entries {
                    return Err(einval("block past the VAT"));
                }

                // Lookup in virtual allocation table file.
                let at = u64::from(ump.vat_offset) + u64::from(lb_num) * 4;
                let lbmap = usize::try_from(at)
                    .ok()
                    .and_then(|at| ump.vat_table.get(at..at.checked_add(4)?))
                    .ok_or_else(|| einval("block past the VAT"))?;
                lb_num = rd32(lbmap, 0);

                // Transform into its disc logical block.
                if lb_num > rd32(pdesc, PD_PART_LEN) {
                    return Err(einval("block past its partition"));
                }
                // Just one logical block.
                return Ok((lb_num.wrapping_add(rd32(pdesc, PD_START_LOC)), 1));
            }
            UDF_VTOP_TYPE_SPARABLE => {
                // Not in NetBSD: a packet length of 0 divides by zero.
                let packet_size = ump.sparable_packet_size;
                if packet_size == 0 {
                    return Err(einval("sparable packets of no blocks"));
                }
                // Check if the packet containing the lb_num is remapped.
                let lb_rel = lb_num % packet_size;
                // NetBSD compares the packet's number, lb_num / packet
                // size, with the entries' original location, which is
                // the first block of the packet [UDF 2.01, 2.2.11], as Linux
                // does here.
                let lb_packet = lb_num - lb_rel;

                let spt = ump.sparing_table.as_deref().unwrap_or(&[]);
                for rel in 0..usize::from(rd16(spt, SPT_RT_L)) {
                    let sme = SPT_ENTRIES + rel * 8;
                    if lb_packet == rd32(spt, sme) {
                        // NOTE maps to absolute disc logical block!
                        return Ok((
                            rd32(spt, sme + 4).wrapping_add(lb_rel),
                            packet_size - lb_rel,
                        ));
                    }
                }

                // Transform into its disc logical block.
                if lb_num > rd32(pdesc, PD_PART_LEN) {
                    return Err(einval("block past its partition"));
                }
                // Rest of block.
                return Ok((
                    lb_num.wrapping_add(rd32(pdesc, PD_START_LOC)),
                    packet_size - lb_rel,
                ));
            }
            UDF_VTOP_TYPE_META => {
                // We have to look into the file's allocation descriptors.
                let lb_size = ump.lb_size();
                let Some(metadata_node) = ump.metadata_node.as_ref() else {
                    return Err(einval("no metadata file"));
                };

                // Get first overlapping extent.
                let mut foffset: u64 = 0;
                let mut slot = 0;
                let (s_icb_loc, flags) = loop {
                    let Some(s_icb_loc) = udf_get_adslot(metadata_node, slot) else {
                        return Err(einval(
                            "metadata partition translation failed: can't seek location",
                        ));
                    };
                    let flags = udf_ext_flags(s_icb_loc.len);
                    let len = udf_ext_len(s_icb_loc.len);

                    if flags == UDF_EXT_REDIRECT {
                        slot += 1;
                        continue;
                    }

                    let end_foffset = foffset + u64::from(len);

                    if end_foffset > u64::from(lb_num) * u64::from(lb_size) {
                        break (s_icb_loc, flags); // found
                    }
                    foffset = end_foffset;
                    slot += 1;
                };
                // Found overlapping slot.
                let ext_offset = (u64::from(lb_num) * u64::from(lb_size) - foffset) as u32;

                // Process extent offset.
                lb_num = s_icb_loc.lb_num;
                vpart = s_icb_loc.part_num;
                lb_num = lb_num.wrapping_add(ext_offset.wrapping_add(lb_size - 1) / lb_size);

                if flags != UDF_EXT_ALLOCATED {
                    return Err(einval(
                        "metadata partition translation failed: not allocated",
                    ));
                }

                // vpart and lb_num are updated, translate again since we
                // might be mapped on sparable media.
                again += 1;
                if again > UDF_MAX_TRANSLATE_AGAIN {
                    return Err(einval("metadata partition maps on itself"));
                }
                continue;
            }
            _ => return Err(einval("vtop translation scheme unimplemented")),
        }
    }
}

/// The allocation type of a node: the low bits of its ICB tag's flags.
pub(crate) fn udf_addr_type(udf_node: &UdfNode) -> u16 {
    rd16(udf_node.dscr(), FE_ICBTAG + ICBTAG_FLAGS) & UDF_ICB_TAG_FLAGS_ALLOC_MASK
}

/// `udf_translate_file_extent`: `num_lb` logical blocks of a file from
/// `from` to the sectors they are in, `UDF_TRANS_ZERO` for blocks not
/// recorded, or only `UDF_TRANS_INTERN` for data in the node.
pub(crate) fn udf_translate_file_extent(
    ump: &UdfMount,
    udf_node: &UdfNode,
    from: u32,
    mut num_lb: u32,
    map: &mut Vec<u64>,
) -> Result<()> {
    map.clear();
    let lb_size = ump.lb_size();

    // Do the work.
    if udf_addr_type(udf_node) == UDF_ICB_INTERN_ALLOC {
        map.push(UDF_TRANS_INTERN);
        return Ok(());
    }

    // Find first overlapping extent.
    let mut foffset: u64 = 0;
    let mut slot = 0;
    loop {
        let Some(s_ad) = udf_get_adslot(udf_node, slot) else {
            return Err(einval("translate file extent failed: can't seek location"));
        };
        let flags = udf_ext_flags(s_ad.len);
        let len = udf_ext_len(s_ad.len);

        if flags == UDF_EXT_REDIRECT {
            slot += 1;
            continue;
        }

        let end_foffset = foffset + u64::from(len);

        if end_foffset > u64::from(from) * u64::from(lb_size) {
            break; // found
        }
        foffset = end_foffset;
        slot += 1;
    }
    // Found overlapping slot.
    let mut ext_offset = (u64::from(from) * u64::from(lb_size) - foffset) as u32;

    loop {
        let Some(s_ad) = udf_get_adslot(udf_node, slot) else {
            return Err(einval("translate file extent failed: past eof"));
        };

        let flags = udf_ext_flags(s_ad.len);
        let len = udf_ext_len(s_ad.len);

        let mut lb_num = s_ad.lb_num;
        let vpart_num = s_ad.part_num;

        let end_foffset = foffset + u64::from(len);

        // Process extent, don't forget to advance on ext_offset!
        lb_num = lb_num.wrapping_add(ext_offset.wrapping_add(lb_size - 1) / lb_size);
        let mut overlap = (len.wrapping_sub(ext_offset)).wrapping_add(lb_size - 1) / lb_size;
        ext_offset = 0;

        // Note that the loop is necessary for the extent that
        // udf_translate_vtop() returns doesn't have to span the whole
        // extent.
        overlap = overlap.min(num_lb);
        while overlap != 0 && flags != UDF_EXT_REDIRECT {
            match flags {
                UDF_EXT_FREE | UDF_EXT_ALLOCATED_BUT_NOT_USED => {
                    let mut translen = overlap;
                    while overlap != 0 && num_lb != 0 && translen != 0 {
                        map.push(UDF_TRANS_ZERO);
                        lb_num = lb_num.wrapping_add(1);
                        overlap -= 1;
                        num_lb -= 1;
                        translen -= 1;
                    }
                }
                UDF_EXT_ALLOCATED => {
                    let t_ad = LongAd {
                        len: 0,
                        lb_num,
                        part_num: vpart_num,
                    };
                    let (transsec32, mut translen) = udf_translate_vtop(ump, &t_ad)?;
                    // Not in NetBSD: an extent of no blocks (a block at the
                    // end of its partition) would loop for good.
                    if translen == 0 {
                        return Err(einval("block at the end of its partition"));
                    }
                    let mut transsec = u64::from(transsec32);
                    while overlap != 0 && num_lb != 0 && translen != 0 {
                        map.push(transsec);
                        lb_num = lb_num.wrapping_add(1);
                        transsec += 1;
                        overlap -= 1;
                        num_lb -= 1;
                        translen -= 1;
                    }
                }
                _ => return Err(einval("translate file extent failed: bad flags")),
            }
        }
        if num_lb == 0 {
            break;
        }

        if flags != UDF_EXT_REDIRECT {
            foffset = end_foffset;
        }
        slot += 1;
    }
    Ok(())
}

/// A short or long allocation descriptor at `at` of `blob`.
fn read_ad(blob: &[u8], at: i64, addr_type: u16, udf_node: &UdfNode) -> LongAd {
    // The C reads before the descriptors when there are none: the
    // node's own fields.
    let Ok(at) = usize::try_from(at) else {
        return LongAd::default();
    };
    if addr_type == UDF_ICB_SHORT_ALLOC {
        LongAd {
            len: rd32(blob, at),
            lb_num: rd32(blob, at + 4),
            part_num: udf_node.short_part,
        }
    } else {
        LongAd::at(blob, at)
    }
}

/// `udf_get_adslot`: the allocation descriptor `slot` of a node, through
/// its allocation extents, `None` past the last (eof).
///
/// For extended allocation descriptors, which NetBSD does not read, the C
/// leaves the descriptor it is given unchanged; here there is none.
pub(crate) fn udf_get_adslot(udf_node: &UdfNode, slot: u32) -> Option<LongAd> {
    let (dscr, dscr_size, l_ea, mut l_ad) = match (&udf_node.fe, &udf_node.efe) {
        (Some(fe), _) => (fe, UDF_FENTRY_SIZE, rd32(fe, FE_L_EA), rd32(fe, FE_L_AD)),
        (None, Some(efe)) => (
            efe,
            UDF_EXTFENTRY_SIZE,
            rd32(efe, EFE_L_EA),
            rd32(efe, EFE_L_AD),
        ),
        (None, None) => return None,
    };
    let mut blob: &[u8] = dscr;
    let mut data_pos = dscr_size as i64 + i64::from(l_ea);

    let addr_type = udf_addr_type(udf_node);

    // Just in case we're called on an intern, its EOF.
    if addr_type == UDF_ICB_INTERN_ALLOC {
        return None;
    }

    let adlen: u32 = match addr_type {
        UDF_ICB_SHORT_ALLOC => SHORT_AD_SIZE as u32,
        UDF_ICB_LONG_ALLOC => LONG_AD_SIZE as u32,
        _ => 0,
    };

    // If offset too big, we go to the allocation extensions.
    let mut offset = slot.wrapping_mul(adlen);
    let mut extnr: usize = 0;
    while offset >= l_ad {
        // Check if our last entry is a redirect.
        let l_icb = read_ad(
            blob,
            data_pos + i64::from(l_ad) - i64::from(adlen),
            addr_type,
            udf_node,
        );
        if udf_ext_flags(l_icb.len) != UDF_EXT_REDIRECT {
            l_ad = 0; // force EOF
            break;
        }

        // Advance to next extent.
        let Some(ext) = udf_node.ext.get(extnr) else {
            l_ad = 0; // force EOF
            break;
        };
        extnr += 1;
        offset -= l_ad;
        blob = ext;
        data_pos = AEE_DATA as i64;
        l_ad = rd32(ext, AEE_L_AD);
    }

    if offset >= l_ad || l_ad == 0 || adlen == 0 {
        return None;
    }

    // Get the element.
    Some(read_ad(
        blob,
        data_pos + i64::from(offset),
        addr_type,
        udf_node,
    ))
}
