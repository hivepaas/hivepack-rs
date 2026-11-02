//! Port of NetBSD's `ecma167-udf.h`: the structures UDF records, by the
//! offsets of their fields (the C structures are packed, little-endian),
//! and the constants that go with them.

/// `struct desc_tag` [3/7.2], 16 bytes.
pub(crate) const UDF_DESC_TAG_LENGTH: usize = 16;
pub(crate) const TAG_ID: usize = 0;
pub(crate) const TAG_CKSUM: usize = 4;
pub(crate) const TAG_DESC_CRC: usize = 8;
pub(crate) const TAG_DESC_CRC_LEN: usize = 10;

// Tag identifiers [3/7.2.1], [4/7.2.1].
pub(crate) const TAGID_PRI_VOL: u16 = 1;
pub(crate) const TAGID_ANCHOR: u16 = 2;
pub(crate) const TAGID_IMP_VOL: u16 = 4;
pub(crate) const TAGID_PARTITION: u16 = 5;
pub(crate) const TAGID_LOGVOL: u16 = 6;
pub(crate) const TAGID_UNALLOC_SPACE: u16 = 7;
pub(crate) const TAGID_TERM: u16 = 8;
pub(crate) const TAGID_LOGVOL_INTEGRITY: u16 = 9;
pub(crate) const TAGID_FSD: u16 = 256;
pub(crate) const TAGID_FID: u16 = 257;
pub(crate) const TAGID_ALLOCEXTENT: u16 = 258;
pub(crate) const TAGID_INDIRECTENTRY: u16 = 259;
pub(crate) const TAGID_ICB_TERM: u16 = 260;
pub(crate) const TAGID_FENTRY: u16 = 261;
pub(crate) const TAGID_EXTATTR_HDR: u16 = 262;
pub(crate) const TAGID_SPACE_BITMAP: u16 = 264;
pub(crate) const TAGID_EXTFENTRY: u16 = 266;
pub(crate) const TAGID_SPARING_TABLE: u16 = 0;

/// `struct extent_ad`: length, then location.
pub(crate) const EXTENT_AD_SIZE: usize = 8;

/// `struct long_ad`: length, `lb_addr` (block, partition), 6 bytes for the
/// implementation.
pub(crate) const LONG_AD_SIZE: usize = 16;
/// `struct short_ad`: length, block.
pub(crate) const SHORT_AD_SIZE: usize = 8;

// Extent flags, in the two high bits of an allocation descriptor's length.
pub(crate) const UDF_EXT_ALLOCATED: u32 = 0;
pub(crate) const UDF_EXT_ALLOCATED_BUT_NOT_USED: u32 = 1 << 30;
pub(crate) const UDF_EXT_FREE: u32 = 2 << 30;
pub(crate) const UDF_EXT_REDIRECT: u32 = 3 << 30;

/// `UDF_EXT_FLAGS`.
pub(crate) fn udf_ext_flags(len: u32) -> u32 {
    len & (3 << 30)
}

/// `UDF_EXT_LEN`.
pub(crate) fn udf_ext_len(len: u32) -> u32 {
    len & ((1 << 30) - 1)
}

/// `struct pathcomp`: type, length of the identifier, version, identifier.
pub(crate) const UDF_PATH_COMP_SIZE: usize = 4;
pub(crate) const UDF_PATH_COMP_ROOT: u8 = 1;
pub(crate) const UDF_PATH_COMP_MOUNTROOT: u8 = 2;
pub(crate) const UDF_PATH_COMP_PARENTDIR: u8 = 3;
pub(crate) const UDF_PATH_COMP_CURDIR: u8 = 4;
pub(crate) const UDF_PATH_COMP_NAME: u8 = 5;

/// `struct timestamp` [1/7.3], 12 bytes.
pub(crate) const UDF_TIMESTAMP_SIZE: usize = 12;

/// `struct regid`: flags, then the 23 bytes of its identifier.
pub(crate) const REGID_ID: usize = 1;
pub(crate) const UDF_REGID_ID_SIZE: usize = 23;

/// `struct icb_tag` [4/14.6], 20 bytes, at 16 in file entries.
pub(crate) const ICBTAG_STRAT_TYPE: usize = 4;
pub(crate) const ICBTAG_FILE_TYPE: usize = 11;
pub(crate) const ICBTAG_FLAGS: usize = 18;

pub(crate) const UDF_ICB_TAG_FLAGS_ALLOC_MASK: u16 = 0x03;
pub(crate) const UDF_ICB_SHORT_ALLOC: u16 = 0x00;
pub(crate) const UDF_ICB_LONG_ALLOC: u16 = 0x01;
pub(crate) const UDF_ICB_INTERN_ALLOC: u16 = 0x03;
pub(crate) const UDF_ICB_TAG_FLAGS_SETUID: u16 = 1 << 6;
pub(crate) const UDF_ICB_TAG_FLAGS_SETGID: u16 = 1 << 7;
pub(crate) const UDF_ICB_TAG_FLAGS_STICKY: u16 = 1 << 8;

pub(crate) const UDF_ICB_FILETYPE_UNKNOWN: u8 = 0;
pub(crate) const UDF_ICB_FILETYPE_DIRECTORY: u8 = 4;
pub(crate) const UDF_ICB_FILETYPE_RANDOMACCESS: u8 = 5;
pub(crate) const UDF_ICB_FILETYPE_BLOCKDEVICE: u8 = 6;
pub(crate) const UDF_ICB_FILETYPE_CHARDEVICE: u8 = 7;
pub(crate) const UDF_ICB_FILETYPE_FIFO: u8 = 9;
pub(crate) const UDF_ICB_FILETYPE_SOCKET: u8 = 10;
pub(crate) const UDF_ICB_FILETYPE_SYMLINK: u8 = 12;
pub(crate) const UDF_ICB_FILETYPE_STREAMDIR: u8 = 13;
pub(crate) const UDF_ICB_FILETYPE_VAT: u8 = 248;
pub(crate) const UDF_ICB_FILETYPE_REALTIME: u8 = 249;
pub(crate) const UDF_ICB_FILETYPE_META_MAIN: u8 = 250;
pub(crate) const UDF_ICB_FILETYPE_META_MIRROR: u8 = 251;

/// `struct anchor_vdp` [3/10.2]: the main and reserve VDS extents.
pub(crate) const AVDP_MAIN_VDS_EX: usize = 16;
pub(crate) const AVDP_RESERVE_VDS_EX: usize = 24;

/// `struct logvol_desc` [3/10.6].
pub(crate) const LVD_DESC_CHARSET: usize = 20;
pub(crate) const LVD_LB_SIZE: usize = 212;
pub(crate) const LVD_DOMAIN_ID: usize = 216;
pub(crate) const LVD_FSD_LOC: usize = 248;
pub(crate) const LVD_MT_L: usize = 264;
pub(crate) const LVD_N_PM: usize = 268;
pub(crate) const LVD_INTEGRITY_SEQ_LOC: usize = 432;
pub(crate) const LVD_MAPS: usize = 440;
/// `sizeof(struct logvol_desc)`, with its one byte of maps.
pub(crate) const LVD_SIZE: u32 = 441;

pub(crate) const UDF_INTEGRITY_CLOSED: u32 = 1;

/// Partition maps [3/10.7]: `part_map_1`, `part_map_2` and the UDF ones.
pub(crate) const PM_TYPE: usize = 0;
pub(crate) const PM_LEN: usize = 1;
pub(crate) const PM1_PART_NUM: usize = 4;
pub(crate) const PM2_PART_ID: usize = 4;
pub(crate) const PM2_PART_NUM: usize = 38;
pub(crate) const PMS_PACKET_LEN: usize = 40;
pub(crate) const PMS_N_ST: usize = 42;
pub(crate) const PMS_ST_LOC: usize = 48;
pub(crate) const PMM_META_FILE_LBN: usize = 40;
pub(crate) const PMM_META_MIRROR_FILE_LBN: usize = 44;
pub(crate) const PMM_META_BITMAP_FILE_LBN: usize = 48;

/// `struct part_desc` [3/10.5].
pub(crate) const PD_FLAGS: usize = 20;
pub(crate) const PD_PART_NUM: usize = 22;
pub(crate) const PD_START_LOC: usize = 188;
pub(crate) const PD_PART_LEN: usize = 192;
pub(crate) const UDF_PART_FLAG_ALLOCATED: u16 = 1;

/// `struct unalloc_sp_desc`: its number of extents, and its size without
/// them.
pub(crate) const USD_ALLOC_DESC_NUM: usize = 20;
pub(crate) const USD_SIZE: u32 = 32;

/// `struct logvol_int_desc` [3/10.10].
pub(crate) const LVID_INTEGRITY_TYPE: usize = 28;
pub(crate) const LVID_NUM_PART: usize = 72;
pub(crate) const LVID_L_IU: usize = 76;
pub(crate) const LVID_TABLES: usize = 80;
pub(crate) const LVID_SIZE: u32 = 84;

/// `struct space_bitmap_desc`.
pub(crate) const SBD_NUM_BYTES: usize = 20;
pub(crate) const SBD_SIZE: u32 = 25;

/// `struct udf_sparing_table`.
pub(crate) const SPT_RT_L: usize = 48;
pub(crate) const SPT_ENTRIES: usize = 56;
pub(crate) const SPT_SIZE: u32 = 64;

/// `struct fileset_desc` [4/14.1], 512 bytes.
pub(crate) const FSD_ROOTDIR_ICB: usize = 400;
pub(crate) const FSD_NEXT_EX: usize = 448;
pub(crate) const FSD_STREAMDIR_ICB: usize = 464;
pub(crate) const FSD_SIZE: u32 = 512;

/// `struct fileid_desc` [4/14.4].
pub(crate) const FID_FILE_CHAR: usize = 18;
pub(crate) const FID_L_FI: usize = 19;
pub(crate) const FID_ICB: usize = 20;
pub(crate) const FID_L_IU: usize = 36;
pub(crate) const FID_DATA: usize = 38;
pub(crate) const UDF_FID_SIZE: usize = 38;
pub(crate) const UDF_FILE_CHAR_VIS: u8 = 1 << 0;
pub(crate) const UDF_FILE_CHAR_DIR: u8 = 1 << 1;
pub(crate) const UDF_FILE_CHAR_DEL: u8 = 1 << 2;
pub(crate) const UDF_FILE_CHAR_PAR: u8 = 1 << 3;

/// `struct extattrhdr_desc` [4/14.10.1].
pub(crate) const EAHDR_IMPL_ATTR_LOC: usize = 16;
pub(crate) const EAHDR_APPL_ATTR_LOC: usize = 20;
pub(crate) const EAHDR_SIZE: u32 = 24;
pub(crate) const UDF_IMPL_ATTR_LOC_NOT_PRESENT: u32 = 0xffff_ffff;
pub(crate) const UDF_APPL_ATTR_LOC_NOT_PRESENT: u32 = 0xffff_ffff;

/// `struct extattr_entry`: type, subtype, length.
pub(crate) const EA_TYPE: usize = 0;
pub(crate) const EA_A_L: usize = 8;
pub(crate) const EA_ENTRY_SIZE: u32 = 12;
/// `struct impl_extattr_entry`: the implementation's name, and its data.
pub(crate) const IMPLEXT_IU_L: usize = 12;
pub(crate) const IMPLEXT_IMP_ID: usize = 16;
pub(crate) const IMPLEXT_DATA: usize = 48;
/// `struct filetimes_extattr_entry`.
pub(crate) const FT_EXISTENCE: usize = 16;
pub(crate) const FT_TIMES: usize = 20;
pub(crate) const UDF_FILETIMES_ATTR_NO: u32 = 5;
pub(crate) const UDF_FILETIMES_FILE_CREATION: u32 = 1;
/// `struct device_extattr_entry`.
pub(crate) const DEV_MAJOR: usize = 16;
pub(crate) const DEV_MINOR: usize = 20;
pub(crate) const UDF_DEVICESPEC_ATTR_NO: u32 = 12;

/// `struct file_entry` [4/14.9], 176 bytes and its data.
pub(crate) const FE_ICBTAG: usize = 16;
pub(crate) const FE_UID: usize = 36;
pub(crate) const FE_GID: usize = 40;
pub(crate) const FE_PERM: usize = 44;
pub(crate) const FE_LINK_CNT: usize = 48;
pub(crate) const FE_INF_LEN: usize = 56;
pub(crate) const FE_ATIME: usize = 72;
pub(crate) const FE_MTIME: usize = 84;
pub(crate) const FE_ATTRTIME: usize = 96;
pub(crate) const FE_UNIQUE_ID: usize = 160;
pub(crate) const FE_L_EA: usize = 168;
pub(crate) const FE_L_AD: usize = 172;
pub(crate) const UDF_FENTRY_SIZE: usize = 176;

/// `struct extfile_entry` [4/48.17], 216 bytes and its data.
pub(crate) const EFE_ATIME: usize = 80;
pub(crate) const EFE_MTIME: usize = 92;
pub(crate) const EFE_CTIME: usize = 104;
pub(crate) const EFE_ATTRTIME: usize = 116;
pub(crate) const EFE_UNIQUE_ID: usize = 200;
pub(crate) const EFE_L_EA: usize = 208;
pub(crate) const EFE_L_AD: usize = 212;
pub(crate) const UDF_EXTFENTRY_SIZE: usize = 216;

pub(crate) const UDF_FENTRY_PERM_USER_MASK: u32 = 0x07;
pub(crate) const UDF_FENTRY_PERM_GRP_MASK: u32 = 0xE0;
pub(crate) const UDF_FENTRY_PERM_OWNER_MASK: u32 = 0x1C00;

/// `struct indirect_entry`: its ICB, after the tag and ICB tag.
pub(crate) const INDE_INDIRECT_ICB: usize = 36;

/// `struct alloc_ext_entry`: its allocation descriptors' length and data.
pub(crate) const AEE_L_AD: usize = 20;
pub(crate) const AEE_DATA: usize = 24;

/// `struct udf_vat` (UDF 2.00), and `struct udf_oldvat_tail` (1.50).
pub(crate) const VAT_HEADER_LEN: usize = 0;
pub(crate) const VAT_SIZE: usize = 153;
pub(crate) const OLDVAT_TAIL_SIZE: usize = 36;

/// `sizeof(union dscrptr)`: its largest member, 512 bytes.
pub(crate) const DSCRPTR_SIZE: u32 = 512;

/// Little-endian 16 bits at `at`, zeros past the end.
pub(crate) fn rd16(b: &[u8], at: usize) -> u16 {
    let get = |i| b.get(at + i).copied().unwrap_or(0);
    u16::from_le_bytes([get(0), get(1)])
}

/// Little-endian 32 bits at `at`, zeros past the end.
pub(crate) fn rd32(b: &[u8], at: usize) -> u32 {
    let get = |i| b.get(at + i).copied().unwrap_or(0);
    u32::from_le_bytes([get(0), get(1), get(2), get(3)])
}

/// Little-endian 64 bits at `at`, zeros past the end.
pub(crate) fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from(rd32(b, at)) | u64::from(rd32(b, at + 4)) << 32
}

/// A byte at `at`, zero past the end.
pub(crate) fn rd8(b: &[u8], at: usize) -> u8 {
    b.get(at).copied().unwrap_or(0)
}

/// `struct long_ad`: an extent of a logical volume's partition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LongAd {
    /// The length, with the extent's flags in its two high bits.
    pub len: u32,
    /// The logical block in the partition.
    pub lb_num: u32,
    /// The logical partition: an index into the partition maps.
    pub part_num: u16,
}

impl LongAd {
    pub(crate) fn at(b: &[u8], at: usize) -> LongAd {
        LongAd {
            len: rd32(b, at),
            lb_num: rd32(b, at + 4),
            part_num: rd16(b, at + 8),
        }
    }
}
