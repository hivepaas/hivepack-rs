//! What a stream is, from its first bytes: a layer to take off (age, a
//! compressor, an RPM package's lead and headers, a Debian package's ar
//! archive around its data), a container (tar, ZIP, 7z, cpio, XAR, an ISO
//! 9660 image, a UDF volume, a SquashFS image, an AppImage), or plain
//! data.

/// A layer over the data: encryption or compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// age, binary or armored.
    Age,
    /// Zstandard: frames, skippable ones among them.
    Zstd,
    /// LZ4's frames, skippable ones among them, or its legacy format.
    Lz4,
    /// .xz.
    Xz,
    /// .lz (lzip).
    Lzip,
    /// .lzma (LZMA_Alone), which has no magic: told by its name only.
    Lzma,
    /// gzip.
    Gzip,
    /// bzip2.
    Bzip2,
    /// pbzx, the layer of macOS packages' payloads and of `.xip` files'
    /// content: xz streams, a block at a time.
    Pbzx,
    /// An RPM package: its lead and headers, around its payload, a cpio
    /// archive, compressed.
    Rpm,
    /// A Debian package (`.deb`, `.udeb`): an ar archive, `debian-binary`
    /// first, around its `data.tar`, a tar archive, compressed or not. What
    /// is under the layer is that `data.tar`, the files the package
    /// installs, as `dpkg-deb --fsys-tarfile` gives them; `hivepack::ar`
    /// reads the package's other members, `control.tar` among them.
    Deb,
}

/// What is under the layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Container {
    /// A tar archive.
    Tar,
    /// A ZIP archive, which is read by random access: in a layer, it must
    /// be taken out to a file first. Its file may be one volume of a split
    /// archive, told by its name when its bytes start anywhere: open it
    /// with `hivepack::zip::Volumes::open`, which finds the others.
    Zip,
    /// A 7z archive, which `hivepack::sevenz` reads by random access, its
    /// headers from its end: in a layer, it must be taken out to a file
    /// first.
    SevenZip,
    /// A RAR archive, which `hivepack::rar` reads, under UnRAR's license, and
    /// so is not a dependency here: only told, by its signature.
    Rar,
    /// A cpio archive, which `hivepack::cpio` reads in order: Linux's
    /// initramfs, an RPM package's payload, a macOS package's.
    Cpio,
    /// A XAR archive, which `hivepack::xar` reads in order: a macOS package
    /// (`.pkg`), a `.xip` file.
    Xar,
    /// An ISO 9660 image (`.iso`), which `hivepack::iso` reads in order, in
    /// a layer too (`.iso.xz`).
    Iso,
    /// A UDF volume (DVD, Blu-ray and Windows' images, `.iso` too), which
    /// `hivepack::udf` reads by random access: in a layer, it must be taken
    /// out to a file first. An image with ISO 9660 beside UDF (Windows' and
    /// most DVDs') is one, as the files are on its UDF side; `hivepack::iso`
    /// reads its ISO 9660 side.
    Udf,
    /// A type 2 AppImage: an ELF program, AppImage's runtime, with a
    /// SquashFS image after it, which `hivepack::appimage::open_squashfs`
    /// opens where the program ends, by random access: in a layer, it must
    /// be taken out to a file first.
    AppImageType2,
    /// A type 1 AppImage: an ISO 9660 image whose system area holds the
    /// program, which `hivepack::iso` reads from the start, as an ISO 9660
    /// image, in a layer too.
    AppImageType1,
    /// A SquashFS image (a snap package, `.sqfs`, `.squashfs`), which
    /// `hivepack::squashfs` reads by random access: in a layer, it must be
    /// taken out to a file first.
    Squashfs,
    /// A VHD disk image that grows (`.vhd`, QEMU's `vpc`), read by
    /// `hivepack::image::Vhd`. A fixed one keeps its footer only at the
    /// end, where a stream cannot reach: it is told by opening the file,
    /// not here.
    Vhd,
    /// A QCOW2 disk image (`.qcow2`), read by `hivepack::image::Qcow2`.
    Qcow2,
    /// A VHDX disk image (`.vhdx`, Hyper-V's and WSL2's), read by
    /// `hivepack::image::Vhdx`.
    Vhdx,
    /// A VMDK disk image (`.vmdk`, VMware's), read by
    /// `hivepack::image::Vmdk`: the sparse kind by its own signature, and a
    /// descriptor naming other files by its first line. A descriptor is
    /// only of use beside those files, so one under layers names nothing
    /// that can be reached.
    Vmdk,
    /// A raw disk image with a partition table on it (`.img`, `.bin`, a
    /// `dd` of a card or a stick), read by `hivepack::image::partitions`,
    /// whose partitions hold the file systems.
    PartitionedDisk,
    /// A FAT12, FAT16 or FAT32 file system with no table in front of it,
    /// read by `hivepack::fat`: an EFI system partition taken out on its
    /// own, a camera's card, a floppy image.
    Fat,
    /// An ext2, ext3 or ext4 file system with no table in front of it, read
    /// by `hivepack::ext`: a partition taken out on its own, and what
    /// WSL2's `ext4.vhdx` holds.
    Ext,
    /// An NTFS file system with no table in front of it, read by
    /// `hivepack::ntfs`: a Windows partition taken out on its own, and
    /// what a Windows `.vhdx` or a VM's disk holds. Told whether or not
    /// the crate was built with `ntfs`; reading it takes that feature.
    Ntfs,
    /// Data: one file, compressed or encrypted (`notes.txt.zst`).
    Data,
}

/// What [`detect`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detected {
    Layer(Layer),
    Container(Container),
}

/// How much of a stream [`detect`] looks at: a tar header block, or an
/// armored age file's 1 KiB of white space and its first line.
pub const HEAD_LEN: usize = 1024 + 34 + 512;

/// How much of a stream [`detect`] looks at to tell an ISO 9660 image, when
/// its first [`HEAD_LEN`] bytes are data: its system area and its first
/// volume descriptor.
pub const ISO_HEAD_LEN: usize = ISO_DESCRIPTORS + 2048;

/// How much of a stream [`detect`] looks at to tell a UDF volume, when its
/// first [`HEAD_LEN`] bytes are data or an ISO 9660 image: its system area
/// and 32 descriptors of the volume recognition sequence, room for ISO
/// 9660's before UDF's. With fewer bytes, an image with both is found as
/// ISO 9660.
pub const UDF_HEAD_LEN: usize = ISO_DESCRIPTORS + 32 * 2048;

/// Where an ISO 9660 image's volume descriptors start, after its 32 KiB
/// system area (which a bootable image fills with a boot sector, or a
/// partition table to be written to a USB stick).
const ISO_DESCRIPTORS: usize = 16 * 2048;

const AGE_INTRO: &[u8] = b"age-encryption.org/";
const AGE_ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];
const LZ4_MAGIC: &[u8] = &[0x04, 0x22, 0x4D, 0x18];
const LZ4_LEGACY_MAGIC: &[u8] = &[0x02, 0x21, 0x4C, 0x18];
/// The signatures of RAR 1.5 to 7 (`Rar!\x1a\x07`, then 0 or 1 for the format,
/// as `Archive::IsSignature` tells them) and RAR 1.4 (`RE~^`).
const RAR_MAGIC: &[u8] = b"Rar!\x1a\x07";
const RAR14_MAGIC: &[u8] = b"RE~^";

/// The disk images' signatures, each kept here so that telling one does not
/// take `hivepack::image`: `open` is built without it.
const VHD_MAGIC: &[u8] = b"conectix";
const QCOW2_MAGIC: &[u8] = b"QFI\xfb";
const VHDX_MAGIC: &[u8] = b"vhdxfile";
const VMDK_MAGIC: &[u8] = b"KDMV";
/// What a VMDK descriptor, which is text, begins with.
const VMDK_DESCRIPTOR: &[u8] = b"# Disk DescriptorFile";
/// A GUID partition table's header signature, in the second sector.
const GPT_SIGNATURE: &[u8] = b"EFI PART";
/// Where a master boot record's four entries are, and what one is.
const MBR_ENTRIES: usize = 446;
const MBR_ENTRY: usize = 16;
/// An ext file system's magic, little-endian, 56 bytes into the superblock
/// that is 1024 bytes into the disk.
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];
const EXT_SUPER: usize = 1024;

/// A 7z archive's signature (`hivepack::sevenz::SIGNATURE`, kept here so that
/// telling one does not take the decoder).
const SEVEN_ZIP_MAGIC: &[u8] = &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// Whether `head` starts a Debian package: an ar archive whose first
/// member is `debian-binary`, its name padded with spaces, or ending in
/// GNU's `/`, as dpkg reads it.
fn is_deb(head: &[u8]) -> bool {
    let Some(name) = head
        .strip_prefix(b"!<arch>\n")
        .and_then(|rest| rest.get(..16))
    else {
        return false;
    };
    let mut name = name;
    while let [rest @ .., b' '] = name {
        name = rest;
    }
    let name = name.strip_suffix(b"/").unwrap_or(name);
    name == b"debian-binary"
}

/// An ELF file's magic (`hivepack::appimage::ELF_MAGIC`).
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// SquashFS's magic, `hsqs` (`hivepack::squashfs::MAGIC`, kept here so
/// that telling one does not take the reader), as squashfuse and `file`
/// tell an image.
const SQUASHFS_MAGIC: &[u8] = b"hsqs";

/// Whether `head` starts with a skippable frame's magic, 0x184D2A50 to
/// 0x184D2A5F, little-endian: zstd's and LZ4's, which share them.
pub(crate) fn is_skippable(head: &[u8]) -> bool {
    head.len() >= 4 && head[0] & 0xF0 == 0x50 && head[1..4] == [0x2A, 0x4D, 0x18]
}

/// What comes after the skippable frames that start `head`, as far as it
/// goes: nothing if one goes on past its end.
fn past_skippable(head: &[u8]) -> &[u8] {
    let mut rest = head;
    while is_skippable(rest) {
        let Some(size) = rest.get(4..8) else {
            return &[];
        };
        let size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]) as usize;
        match rest.get(8 + size..) {
            Some(after) => rest = after,
            None => return &[],
        }
    }
    rest
}

/// Whether `head` is a tar header block: USTAR's or GNU's magic, or a
/// checksum that adds up, as V7 has nothing else.
fn is_tar(head: &[u8]) -> bool {
    let Some(block) = head.get(..512) else {
        return false;
    };
    if &block[257..262] == b"ustar" {
        return true;
    }
    let field = &block[148..156];
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .filter(|&c| c != b' ' && c != 0)
        .collect();
    if digits.is_empty() || !digits.iter().all(|c| (b'0'..=b'7').contains(c)) {
        return false;
    }
    let Ok(value) = i64::from_str_radix(std::str::from_utf8(&digits).unwrap_or("x"), 8) else {
        return false;
    };
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in block.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    // A block of zeros sums to 256 with its checksum field as spaces;
    // a value written for it is still not a header.
    value != 0 && (value == unsigned || value == signed) && block[..100].iter().any(|&c| c != 0)
}

/// Whether `head` starts with a XAR header as libarchive's bid tells one:
/// `xar!`, a header of 28 bytes, version 1, and a checksum it knows (none,
/// SHA-1, MD5, SHA-256 or SHA-512).
fn is_xar(head: &[u8]) -> bool {
    let Some(h) = head.get(..28) else {
        return false;
    };
    h.starts_with(b"xar!") && h[4..8] == [0, 28, 0, 1] && h[24..27] == [0, 0, 0] && h[27] <= 4
}

/// Whether `head` starts with a cpio header, as libarchive's bid tells
/// one, and whole: an ASCII header's digits all digits of its format, and
/// the binary format's two bytes of magic, which data can start with,
/// followed by a name of 1 to 1,024 bytes that ends where its length says.
fn is_cpio(head: &[u8]) -> bool {
    let digits = |len: usize, digit: fn(&u8) -> bool| {
        head.get(6..len)
            .is_some_and(|field| field.iter().all(digit))
    };
    let octal = |c: &u8| (b'0'..=b'7').contains(c);
    if head.starts_with(b"070707") {
        return digits(76, octal);
    }
    if head.starts_with(b"070701") || head.starts_with(b"070702") {
        return digits(110, u8::is_ascii_hexdigit);
    }
    if head.starts_with(b"070727") {
        // afio's large ASCII header: hexadecimal, but for the mode, with a
        // letter after some fields.
        return head.len() >= 116
            && [(30, b'm'), (85, b'n'), (98, b's'), (115, b':')]
                .iter()
                .all(|&(at, c)| head[at] == c)
            && [6..30, 31..85, 86..98, 99..115]
                .into_iter()
                .all(|field| head[field].iter().all(u8::is_ascii_hexdigit));
    }
    let Some(magic) = head.get(..2) else {
        return false;
    };
    let number: fn([u8; 2]) -> u16 = if magic == [0xC7, 0x71] {
        u16::from_le_bytes
    } else if magic == [0x71, 0xC7] {
        u16::from_be_bytes
    } else {
        return false;
    };
    let Some(size) = head.get(20..22) else {
        return false;
    };
    let size = usize::from(number([size[0], size[1]]));
    (1..=1024).contains(&size) && head.get(26 + size - 1).is_none_or(|&c| c == 0)
}

/// Whether `head` starts as an LZMA_Alone stream (`.lzma`), which has no
/// magic, does, as libarchive's bidder tells one: a properties byte LZMA
/// can have, and a dictionary size that the LZMA SDK's `lzma` or XZ Utils'
/// writes, or, with the usual properties and the size left unknown, one
/// that XZ Utils lowered in steps of 1 MiB for want of memory. Only an RPM
/// package's payload is told so, as it has no name: elsewhere `.lzma` is
/// told by its name.
pub(crate) fn is_lzma_alone(head: &[u8]) -> bool {
    let Some(h) = head.get(..14) else {
        return false;
    };
    if h[0] > (4 * 5 + 4) * 9 + 8 {
        return false;
    }
    let usual = (h[0] == 0x5D || h[0] == 0x5E) && h[5..13] == [0xFF; 8];
    let dictionary = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    (dictionary.is_power_of_two() && (1 << 12..=1 << 27).contains(&dictionary))
        || (usual && (0x30_0000..=0x3F0_0000).contains(&dictionary) && dictionary % (1 << 20) == 0)
}

/// Whether `head` has an ISO 9660 volume descriptor where the first one
/// is: a type (0 to 3, or 255 for the set's end), "CD001" and version 1,
/// as `file` and libarchive look for. An image with UDF beside ISO 9660
/// (Windows' and most DVDs') has it too; one with UDF alone does not.
fn is_iso(head: &[u8]) -> bool {
    let Some(vd) = head.get(ISO_DESCRIPTORS..ISO_DESCRIPTORS + 7) else {
        return false;
    };
    matches!(vd[0], 0..=3 | 255) && &vd[1..6] == b"CD001" && vd[6] == 1
}

/// Whether `head` has a UDF volume recognition sequence (ECMA-167 2/8.3):
/// from 32 KiB, descriptors of 2048 bytes (or of a block, when blocks are
/// larger, with nothing between them) of type 0 and version 1, among which
/// `BEA01`, then `NSR02` or `NSR03` before `TEA01`, as `file` and Linux
/// look for. ISO 9660's descriptors come first in an image with both.
fn is_udf(head: &[u8]) -> bool {
    let mut extended = false;
    for at in (ISO_DESCRIPTORS..head.len()).step_by(2048) {
        let Some(vsd) = head.get(at..at + 7) else {
            break;
        };
        if vsd[0] != 0 || vsd[6] != 1 {
            continue;
        }
        match &vsd[1..6] {
            b"BEA01" => extended = true,
            b"NSR02" | b"NSR03" if extended => return true,
            b"TEA01" => extended = false,
            _ => {}
        }
    }
    false
}

/// Whether `name` is that of a volume of a split ZIP archive, whose bytes,
/// but for the first volume's, start anywhere in the archive: `.z01`,
/// `.z02`, … and `.zip`, the last (Info-ZIP, PKZIP), `.zx01`, … and
/// `.zipx` (WinZip), and 7-Zip's `.zip.001`, ….
fn is_zip_volume_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    ext == "zip"
        || ext == "zipx"
        || ext
            .strip_prefix("zx")
            .is_some_and(|n| n.len() >= 2 && digits(n))
        || ext
            .strip_prefix('z')
            .is_some_and(|n| n.len() >= 2 && digits(n))
        || ext.len() >= 3 && digits(ext) && stem.ends_with(".zip")
}

/// Whether `name` is a `.lzma` file's: `.lzma`, or `.tlz`, the short name of
/// `.tar.lzma` that file managers give it. A `.tlz` that is lzip's, which some
/// give that name too, has lzip's magic and is told by it before its name.
fn is_lzma_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".lzma") || name.ends_with(".tlz")
}

/// Whether the disk checks may be made on `head`.
///
/// A head of exactly [`HEAD_LEN`] is the first of two, and a file longer
/// than it has more to come — the part where ISO 9660's and UDF's own
/// descriptors are, after a 32 KiB system area that holds anything, a
/// hybrid ISO's a protective master boot record to be written to a USB
/// stick. Telling a table from the first head would hide every one of
/// those images, because only [`Container::Data`] asks for the second
/// head. Any other length is everything there is to have: the whole of a
/// shorter file, or the second head itself.
fn enough_for_a_disk(head: &[u8]) -> bool {
    head.len() != HEAD_LEN
}

/// Whether `head` has a partition table on it: a GUID partition table's
/// header in the second sector, of either size a sector is, or a master
/// boot record whose entries are entries.
fn is_partitioned(head: &[u8]) -> bool {
    for sector in [512usize, 4096] {
        if head.get(sector..sector + GPT_SIGNATURE.len()) == Some(GPT_SIGNATURE) {
            return true;
        }
    }
    if head.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return false;
    }
    // The signature a record ends with is the signature a boot sector ends
    // with, and a file system begins with one: what tells them apart is
    // what is where the entries go. A FAT or NTFS boot sector has its code
    // and its own fields there, which fail these.
    let mut any = false;
    for i in 0..4 {
        let at = MBR_ENTRIES + i * MBR_ENTRY;
        let Some(entry) = head.get(at..at + MBR_ENTRY) else {
            return false;
        };
        // Bootable or not, and nothing else.
        if entry[0] != 0x00 && entry[0] != 0x80 {
            return false;
        }
        let kind = entry[4];
        let sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
        if kind == 0 && sectors == 0 {
            continue;
        }
        // A partition of a type but no sectors, or sectors but no type, is
        // what a tool leaves behind rather than what it writes.
        if kind == 0 || sectors == 0 {
            return false;
        }
        any = true;
    }
    any
}

/// Whether `head` begins a FAT file system. The rules are the reader's own
/// (`crates/hivepack/src/fat/boot.rs`), written again here because telling
/// one must not take the reader: `open` is built without `fat`. A test with
/// the feature on asserts that what the reader opens is told here
/// (`crates/hivepack/tests/open_open.rs`).
fn is_fat(head: &[u8]) -> bool {
    let Some(first) = head.get(..512) else {
        return false;
    };
    if first[510..512] != [0x55, 0xAA] || !matches!(first[0], 0xEB | 0xE9) {
        return false;
    }
    // exFAT keeps the same signature and the same jump, says its name
    // where the one that made the file system goes, and leaves every field
    // FAT's numbers are in zero. It is not read here.
    if &first[3..11] == b"EXFAT   " {
        return false;
    }
    let sector = u16::from_le_bytes([first[11], first[12]]);
    let per_cluster = first[13];
    let reserved = u16::from_le_bytes([first[14], first[15]]);
    let fats = first[16];
    let small_sectors = u16::from_le_bytes([first[19], first[20]]);
    let large_sectors = u32::from_le_bytes([first[32], first[33], first[34], first[35]]);
    let small_fat = u16::from_le_bytes([first[22], first[23]]);
    let large_fat = u32::from_le_bytes([first[36], first[37], first[38], first[39]]);
    matches!(sector, 512 | 1024 | 2048 | 4096)
        && per_cluster != 0
        && per_cluster.is_power_of_two()
        && per_cluster <= 128
        && reserved != 0
        && fats != 0
        && fats <= 4
        && (small_sectors != 0 || large_sectors != 0)
        && (small_fat != 0 || large_fat != 0)
}

/// Whether `head` begins an NTFS file system. The name is the reader's own
/// check (`crates/hivepack/src/ntfs/mod.rs`), written again here because
/// telling one must not take the reader: `open` is built without `ntfs`. A
/// test with the feature on asserts that what the reader opens is told
/// here (`crates/hivepack/tests/open_open.rs`).
///
/// The fields beside the name are the ones NTFS leaves zero where FAT
/// keeps its numbers, which is also why [`is_fat`] does not answer for an
/// NTFS boot sector: it wants a reserved count and a table, and NTFS has
/// neither. Everything told here the reader opens, since it asks for less
/// — the whole boot sector and the name.
fn is_ntfs(head: &[u8]) -> bool {
    let Some(first) = head.get(..512) else {
        return false;
    };
    if first[510..512] != [0x55, 0xAA] || !matches!(first[0], 0xEB | 0xE9) {
        return false;
    }
    if &first[3..11] != b"NTFS    " {
        return false;
    }
    let sector = u16::from_le_bytes([first[11], first[12]]);
    let per_cluster = first[13];
    let reserved = u16::from_le_bytes([first[14], first[15]]);
    let fats = first[16];
    let root_entries = u16::from_le_bytes([first[17], first[18]]);
    let small_sectors = u16::from_le_bytes([first[19], first[20]]);
    let table = u16::from_le_bytes([first[22], first[23]]);
    let sectors = u64::from_le_bytes(first[40..48].try_into().unwrap_or_default());
    let mft = u64::from_le_bytes(first[48..56].try_into().unwrap_or_default());
    matches!(sector, 512 | 1024 | 2048 | 4096)
        // Sectors in a cluster, a power of two; for the clusters above
        // 64 KiB that Windows 10 added, 2^-n sectors written as the two's
        // complement of n, which is 0xF4 and up.
        && ((per_cluster.is_power_of_two() && per_cluster <= 128) || per_cluster >= 0xF4)
        // Where FAT keeps its numbers, NTFS keeps nothing.
        && reserved == 0
        && fats == 0
        && root_entries == 0
        && small_sectors == 0
        && table == 0
        // And what NTFS keeps instead: how long the volume is, and where
        // the master file table begins. A volume of no sectors, or whose
        // table is at cluster 0, is not one.
        && sectors != 0
        && mft != 0
}

/// Whether `head` holds an ext superblock: its magic, and the two fields
/// every ext file system has had, which say sizes nothing else would.
fn is_ext(head: &[u8]) -> bool {
    let Some(sb) = head.get(EXT_SUPER..EXT_SUPER + 64) else {
        return false;
    };
    if sb[56..58] != EXT_MAGIC {
        return false;
    }
    // A block is 1 KiB shifted by this, and the format allows 0 to 6
    // (1 KiB to 64 KiB); a file system of no inodes and no blocks is not
    // one.
    let shift = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
    let inodes = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
    let blocks = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]);
    shift <= 6 && inodes != 0 && blocks != 0
}

/// What `head`, the first [`HEAD_LEN`] bytes of a stream (fewer if it is
/// shorter), or [`ISO_HEAD_LEN`] to tell an ISO 9660 image, or
/// [`UDF_HEAD_LEN`] to tell a UDF volume, is. `name`, the file's name if
/// the stream is the file's, tells `.lzma`, which has no magic, and the
/// volumes of a split ZIP archive after the first, which start anywhere in
/// it: read them with `hivepack::zip::Volumes::open`.
pub fn detect(head: &[u8], name: Option<&str>) -> Detected {
    let starts = |magic: &[u8]| head.starts_with(magic);
    if starts(AGE_INTRO) {
        return Detected::Layer(Layer::Age);
    }
    // An armored age file: its first line after white space.
    let text = head
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .map_or(&head[head.len()..], |i| &head[i..]);
    if head.len() - text.len() <= 1024 && text.starts_with(AGE_ARMOR) {
        return Detected::Layer(Layer::Age);
    }
    if starts(ZSTD_MAGIC) {
        return Detected::Layer(Layer::Zstd);
    }
    if starts(LZ4_MAGIC) || starts(LZ4_LEGACY_MAGIC) {
        return Detected::Layer(Layer::Lz4);
    }
    // Skippable frames, zstd's or LZ4's: the frame after them tells. zstd
    // when it is past what `head` holds.
    if is_skippable(head) {
        let next = past_skippable(head);
        if next.starts_with(LZ4_MAGIC) || next.starts_with(LZ4_LEGACY_MAGIC) {
            return Detected::Layer(Layer::Lz4);
        }
        return Detected::Layer(Layer::Zstd);
    }
    if starts(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Detected::Layer(Layer::Xz);
    }
    if starts(b"LZIP") {
        return Detected::Layer(Layer::Lzip);
    }
    if starts(b"pbzx") {
        return Detected::Layer(Layer::Pbzx);
    }
    if crate::cpio::rpm::bid(head) > 0 {
        return Detected::Layer(Layer::Rpm);
    }
    if is_deb(head) {
        return Detected::Layer(Layer::Deb);
    }
    if starts(&[0x1F, 0x8B]) {
        return Detected::Layer(Layer::Gzip);
    }
    if head.len() >= 4 && starts(b"BZh") && (b'1'..=b'9').contains(&head[3]) {
        return Detected::Layer(Layer::Bzip2);
    }
    // An AppImage: an ELF program with `AI` and its type at byte 8, in the
    // padding of e_ident, as AppImage's specification and `file` tell one.
    if starts(ELF_MAGIC) {
        match head.get(8..11) {
            Some(b"AI\x02") => return Detected::Container(Container::AppImageType2),
            Some(b"AI\x01") => return Detected::Container(Container::AppImageType1),
            _ => {}
        }
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return Detected::Container(Container::Zip);
    }
    if starts(SEVEN_ZIP_MAGIC) {
        return Detected::Container(Container::SevenZip);
    }
    if starts(RAR14_MAGIC) || starts(RAR_MAGIC) && matches!(head.get(6), Some(0 | 1)) {
        return Detected::Container(Container::Rar);
    }
    if starts(SQUASHFS_MAGIC) {
        return Detected::Container(Container::Squashfs);
    }
    if is_xar(head) {
        return Detected::Container(Container::Xar);
    }
    if is_cpio(head) {
        return Detected::Container(Container::Cpio);
    }
    if is_tar(head) {
        return Detected::Container(Container::Tar);
    }
    // After what starts the stream: an image's system area is anything.
    if is_udf(head) {
        return Detected::Container(Container::Udf);
    }
    if is_iso(head) {
        return Detected::Container(Container::Iso);
    }
    // The disk images, after the two whose system area may hold anything:
    // a hybrid ISO carries a protective master boot record in its own.
    if starts(QCOW2_MAGIC) {
        return Detected::Container(Container::Qcow2);
    }
    if starts(VHDX_MAGIC) {
        return Detected::Container(Container::Vhdx);
    }
    if starts(VMDK_MAGIC) || starts(VMDK_DESCRIPTOR) {
        return Detected::Container(Container::Vmdk);
    }
    if starts(VHD_MAGIC) {
        return Detected::Container(Container::Vhd);
    }
    // A table, or a file system with none in front of it, told only from a
    // head that has already said it is not an image.
    if enough_for_a_disk(head) {
        if is_partitioned(head) {
            return Detected::Container(Container::PartitionedDisk);
        }
        if is_fat(head) {
            return Detected::Container(Container::Fat);
        }
        if is_ntfs(head) {
            return Detected::Container(Container::Ntfs);
        }
        if is_ext(head) {
            return Detected::Container(Container::Ext);
        }
    }
    if name.is_some_and(is_lzma_name) {
        return Detected::Layer(Layer::Lzma);
    }
    if name.is_some_and(is_zip_volume_name) {
        return Detected::Container(Container::Zip);
    }
    Detected::Container(Container::Data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(head: &[u8]) -> Detected {
        detect(head, None)
    }

    /// A tar header block: `magic` at 257, the checksum summed as tar
    /// does, or `checksum` when it is given.
    fn tar_block(name: &[u8], magic: &[u8], checksum: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..name.len()].copy_from_slice(name);
        b[100..108].copy_from_slice(b"0000644\0");
        b[124..136].copy_from_slice(b"00000000005\0");
        b[257..257 + magic.len()].copy_from_slice(magic);
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
        let field = format!("{sum:06o}\0 ");
        b[148..156].copy_from_slice(checksum.unwrap_or(field.as_bytes()));
        b
    }

    #[test]
    fn cpio_by_its_headers() {
        let cpio = Detected::Container(Container::Cpio);
        let ascii = |magic: &[u8], len: usize, digit: u8| {
            let mut h = magic.to_vec();
            h.resize(len, digit);
            h
        };
        let mut afio = ascii(b"070727", 116, b'a');
        for (at, c) in [(30, b'm'), (85, b'n'), (98, b's'), (115, b':')] {
            afio[at] = c;
        }
        let binary = |magic: [u8; 2], size: [u8; 2], name: &[u8]| {
            let mut h = vec![0; 26];
            h[..2].copy_from_slice(&magic);
            h[20..22].copy_from_slice(&size);
            h.extend(name);
            h
        };
        for head in [
            ascii(b"070707", 76, b'7'),
            ascii(b"070701", 110, b'f'),
            ascii(b"070702", 110, b'A'),
            afio.clone(),
            binary([0xC7, 0x71], [2, 0], b"a\0"),
            binary([0x71, 0xC7], [0, 2], b"a\0"),
            // A name past what is looked at.
            binary([0xC7, 0x71], [0, 4], b""),
        ] {
            assert_eq!(layer(&head), cpio, "{head:?}");
        }
        // Near misses are data.
        let mut afio_off = afio;
        afio_off[30] = b'0';
        for head in [
            ascii(b"070707", 76, b'8'),
            ascii(b"070707", 75, b'0'),
            ascii(b"070701", 110, b'g'),
            ascii(b"070703", 110, b'0'),
            afio_off,
            binary([0xC7, 0x71], [0, 0], b""),
            binary([0xC7, 0x71], [2, 0], b"ab"),
            binary([0xC7, 0x71], [1, 4], b""),
            vec![0xC7, 0x71, 0],
        ] {
            assert_eq!(
                layer(&head),
                Detected::Container(Container::Data),
                "{head:?}"
            );
        }
    }

    #[test]
    fn xar_by_its_header() {
        let header = |size: u16, version: u16, checksum: u32| {
            let mut h = b"xar!".to_vec();
            h.extend(size.to_be_bytes());
            h.extend(version.to_be_bytes());
            h.extend([0; 16]);
            h.extend(checksum.to_be_bytes());
            h
        };
        for checksum in 0..=4 {
            assert_eq!(
                layer(&header(28, 1, checksum)),
                Detected::Container(Container::Xar)
            );
        }
        for head in [
            header(28, 1, 5),
            header(64, 1, 1),
            header(28, 2, 1),
            header(28, 1, 1)[..27].to_vec(),
        ] {
            assert_eq!(layer(&head), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn debian_packages_by_their_first_member() {
        for name in [&b"debian-binary   "[..], b"debian-binary/  "] {
            let head = [
                &b"!<arch>\n"[..],
                name,
                b"1700000000  0     0     100644  4         `\n2.0\n",
            ]
            .concat();
            assert_eq!(layer(&head), Detected::Layer(Layer::Deb));
        }
        // An ar archive whose first member is another, a static library's,
        // and one cut in its first name.
        for head in [
            &b"!<arch>\nhello.o/        "[..],
            b"!<arch>\ndebian-bin",
            b"!<arch>\ndebian-binaryx  ",
        ] {
            assert_eq!(layer(head), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn rpm_by_its_lead() {
        let lead = |version: u8, kind: u8| [0xED, 0xAB, 0xEE, 0xDB, version, 0, 0, kind, 0, 1];
        assert_eq!(layer(&lead(3, 0)), Detected::Layer(Layer::Rpm));
        assert_eq!(layer(&lead(4, 1)), Detected::Layer(Layer::Rpm));
        for head in [&lead(5, 0)[..], &lead(3, 2)[..], &lead(3, 0)[..7]] {
            assert_eq!(layer(head), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn lzma_alone_by_its_header() {
        let header = |props: u8, dictionary: u32, size: u64| {
            let mut h = vec![props];
            h.extend(dictionary.to_le_bytes());
            h.extend(size.to_le_bytes());
            h.push(0);
            h
        };
        let unknown = u64::MAX;
        // xz -6's, and the LZMA SDK's at its smallest and largest.
        assert!(is_lzma_alone(&header(0x5D, 8 << 20, unknown)));
        assert!(is_lzma_alone(&header(0, 1 << 12, 1000)));
        assert!(is_lzma_alone(&header(224, 1 << 27, 1000)));
        // xz lowered to 3 MiB, which only the usual header allows.
        assert!(is_lzma_alone(&header(0x5E, 3 << 20, unknown)));
        assert!(!is_lzma_alone(&header(0x5D, 3 << 20, 1000)));
        assert!(!is_lzma_alone(&header(0x40, 3 << 20, unknown)));
        assert!(!is_lzma_alone(&header(225, 8 << 20, unknown)));
        assert!(!is_lzma_alone(&header(0x5D, 1 << 28, unknown)));
        assert!(!is_lzma_alone(&header(0x5D, (8 << 20) + 1, unknown)));
        assert!(!is_lzma_alone(&header(0x5D, 8 << 20, unknown)[..13]));
    }

    #[test]
    fn layers_by_their_magic() {
        let cases: &[(&[u8], Layer)] = &[
            (b"age-encryption.org/v1\n-> X25519", Layer::Age),
            (&[0x28, 0xB5, 0x2F, 0xFD, 0x04], Layer::Zstd),
            (&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0], Layer::Zstd),
            (&[0x5F, 0x2A, 0x4D, 0x18, 0, 0, 0, 0], Layer::Zstd),
            (&[0x04, 0x22, 0x4D, 0x18, 0x64], Layer::Lz4),
            (&[0x02, 0x21, 0x4C, 0x18, 0x10], Layer::Lz4),
            (b"\xFD7zXZ\0\0\x04", Layer::Xz),
            (b"LZIP\x01\x14", Layer::Lzip),
            (&[0x1F, 0x8B, 0x08], Layer::Gzip),
            (b"BZh91AY&SY", Layer::Bzip2),
            (b"pbzx\0\0\0\0\x01\0\0\0", Layer::Pbzx),
        ];
        for &(head, want) in cases {
            assert_eq!(layer(head), Detected::Layer(want), "{head:?}");
        }
        // Near misses are data.
        for head in [
            &b"BZh0"[..],
            b"BZh",
            b"\xFD7zXZ",
            b"LZI",
            b"pbz",
            b"PBZX",
            b"\x1F",
            b"\x60\x2A\x4D\x18",
        ] {
            assert_eq!(
                layer(head),
                Detected::Container(Container::Data),
                "{head:?}"
            );
        }
    }

    #[test]
    fn skippable_frames_are_zstd_s_or_lz4_s() {
        let skip = |size: u32| {
            let mut frame = vec![0x53, 0x2A, 0x4D, 0x18];
            frame.extend(size.to_le_bytes());
            frame.extend(vec![9; size as usize]);
            frame
        };
        let mut head = [skip(3), skip(0), LZ4_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Lz4));
        head = [skip(10), LZ4_LEGACY_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Lz4));
        head = [skip(10), ZSTD_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Zstd));
        // What comes after is past the head, or nothing: zstd.
        head = [skip(HEAD_LEN as u32), LZ4_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head[..HEAD_LEN]), Detected::Layer(Layer::Zstd));
        for head in [&skip(4)[..], &skip(4)[..6], &[0x50, 0x2A, 0x4D, 0x18]] {
            assert_eq!(layer(head), Detected::Layer(Layer::Zstd));
        }
    }

    #[test]
    fn armored_age_after_white_space() {
        let mut head = b" \r\n\t".repeat(256);
        head.extend(AGE_ARMOR);
        head.extend(b"\nYWdl");
        assert_eq!(layer(&head), Detected::Layer(Layer::Age));
        // Past 1 KiB of it, age does not look further.
        head.insert(0, b' ');
        assert_eq!(layer(&head), Detected::Container(Container::Data));
        assert_eq!(
            layer(&AGE_ARMOR[..20]),
            Detected::Container(Container::Data)
        );
    }

    #[test]
    fn containers() {
        for head in [
            &b"PK\x03\x04\x14\0"[..],
            b"PK\x05\x06\0\0",
            b"PK\x07\x08PK\x03\x04",
        ] {
            assert_eq!(layer(head), Detected::Container(Container::Zip));
        }
        // USTAR and GNU tar by their magic, V7 by its checksum, signed or
        // not.
        let ustar = tar_block(b"a.txt", b"ustar\x0000", None);
        assert_eq!(layer(&ustar), Detected::Container(Container::Tar));
        let gnu = tar_block(b"a.txt", b"ustar  \0", None);
        assert_eq!(layer(&gnu), Detected::Container(Container::Tar));
        let v7 = tar_block(b"a.txt", b"", None);
        assert_eq!(layer(&v7), Detected::Container(Container::Tar));
        let mut high = tar_block("é.txt".as_bytes(), b"", None);
        let signed: i64 = high
            .iter()
            .enumerate()
            .map(|(i, &c)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    i64::from(c as i8)
                }
            })
            .sum();
        high[148..156].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
        assert_eq!(layer(&high), Detected::Container(Container::Tar));
        // A wrong checksum, no name, zeros, or less than a block: data.
        let wrong = tar_block(b"a.txt", b"", Some(b"0000001\0"));
        let unnamed = tar_block(b"", b"", None);
        for head in [&wrong[..], &unnamed, &[0; 512], &v7[..511], b""] {
            assert_eq!(layer(head), Detected::Container(Container::Data));
        }
    }

    /// A boot sector: the jump every one begins with, a BPB that holds
    /// together, and the signature at 510. `at` is where the kind's name
    /// goes, which nothing reads.
    fn boot_sector(sector: u16, per_cluster: u8, fat32: bool) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x3C;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"mkfs.fat");
        b[11..13].copy_from_slice(&sector.to_le_bytes());
        b[13] = per_cluster;
        b[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
        b[16] = 2; // two tables
        b[19..21].copy_from_slice(&0u16.to_le_bytes());
        b[32..36].copy_from_slice(&131072u32.to_le_bytes()); // sectors
        if fat32 {
            b[36..40].copy_from_slice(&1024u32.to_le_bytes()); // the table
        } else {
            b[17..19].copy_from_slice(&512u16.to_le_bytes()); // root entries
            b[22..24].copy_from_slice(&64u16.to_le_bytes()); // the table
        }
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// An NTFS boot sector, with the fields NTFS fills and the fields it
    /// leaves zero where FAT keeps its numbers.
    fn ntfs_boot_sector(sector: u16, per_cluster: u8) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x52;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"NTFS    ");
        b[11..13].copy_from_slice(&sector.to_le_bytes());
        b[13] = per_cluster;
        b[21] = 0xF8; // the media descriptor, as mkntfs writes it
        b[40..48].copy_from_slice(&131_071u64.to_le_bytes()); // sectors
        b[48..56].copy_from_slice(&4u64.to_le_bytes()); // $MFT's cluster
        b[56..64].copy_from_slice(&8191u64.to_le_bytes()); // $MFTMirr's
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// A master boot record: `kinds` are the types of its entries, each of
    /// 2048 sectors, the first bootable.
    fn mbr(kinds: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        for (i, &kind) in kinds.iter().enumerate().take(4) {
            let at = MBR_ENTRIES + i * MBR_ENTRY;
            b[at] = if i == 0 { 0x80 } else { 0x00 };
            b[at + 4] = kind;
            b[at + 8..at + 12].copy_from_slice(&(2048u32 * (i as u32 + 1)).to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&2048u32.to_le_bytes());
        }
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// An ext superblock, 1024 bytes into the disk.
    fn ext(blocks: u32, inodes: u32, shift: u32, magic: [u8; 2]) -> Vec<u8> {
        let mut b = vec![0u8; EXT_SUPER + 1024];
        let sb = &mut b[EXT_SUPER..];
        sb[0..4].copy_from_slice(&inodes.to_le_bytes());
        sb[4..8].copy_from_slice(&blocks.to_le_bytes());
        sb[24..28].copy_from_slice(&shift.to_le_bytes());
        sb[56..58].copy_from_slice(&magic);
        b
    }

    /// Long enough that it is not the first head of two.
    fn whole(mut head: Vec<u8>) -> Vec<u8> {
        if head.len() == HEAD_LEN {
            head.push(0);
        }
        head
    }

    #[test]
    fn the_disk_images_by_their_signatures() {
        for (magic, want) in [
            (&b"QFI\xfb\0\0\0\x03"[..], Container::Qcow2),
            (b"vhdxfile\0\0", Container::Vhdx),
            (b"KDMV\x03\0\0\0", Container::Vmdk),
            (b"# Disk DescriptorFile\nversion=1\n", Container::Vmdk),
            (b"conectix\0\0\0\x02", Container::Vhd),
        ] {
            assert_eq!(layer(magic), Detected::Container(want), "{magic:?}");
        }
    }

    #[test]
    fn a_table_is_told_from_its_entries_and_not_its_signature() {
        // A GUID partition table, in either sector size.
        for sector in [512usize, 4096] {
            let mut disk = vec![0u8; sector + 8];
            disk[sector..].copy_from_slice(b"EFI PART");
            assert_eq!(
                layer(&whole(disk)),
                Detected::Container(Container::PartitionedDisk)
            );
        }
        // A master boot record of one partition, and of four.
        for kinds in [&[0x83u8][..], &[0x83, 0x0C, 0x82, 0x07]] {
            assert_eq!(
                layer(&whole(mbr(kinds))),
                Detected::Container(Container::PartitionedDisk)
            );
        }
        // The signature alone is not a table: a boot sector ends with it
        // too. Four empty entries, an entry of a type but no sectors, and
        // one whose status is neither bootable nor not.
        let mut empty = vec![0u8; 512];
        empty[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mut no_sectors = mbr(&[0x83]);
        no_sectors[MBR_ENTRIES + 12..MBR_ENTRIES + 16].fill(0);
        let mut odd_status = mbr(&[0x83]);
        odd_status[MBR_ENTRIES] = 0x42;
        for head in [empty, no_sectors, odd_status] {
            assert_eq!(layer(&whole(head)), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn a_file_system_with_no_table_in_front_of_it_is_told() {
        // FAT16's shape and FAT32's, in each sector size.
        for sector in [512u16, 4096] {
            for fat32 in [false, true] {
                let head = whole(boot_sector(sector, 8, fat32));
                assert_eq!(layer(&head), Detected::Container(Container::Fat));
            }
        }
        // An ext file system, and the fields that say it is not one: the
        // magic, a block size the format has not got, and a file system of
        // no inodes.
        assert_eq!(
            layer(&whole(ext(1024, 256, 0, EXT_MAGIC))),
            Detected::Container(Container::Ext)
        );
        for head in [
            ext(1024, 256, 0, [0x53, 0xEE]),
            ext(1024, 256, 7, EXT_MAGIC),
            ext(1024, 0, 0, EXT_MAGIC),
            ext(0, 256, 0, EXT_MAGIC),
        ] {
            assert_eq!(layer(&whole(head)), Detected::Container(Container::Data));
        }
    }

    /// An NTFS boot sector is told as NTFS, and the fields that say it is
    /// not one. The clusters Windows 10 added, written as the two's
    /// complement of a power of two, are told as well.
    #[test]
    fn an_ntfs_file_system_with_no_table_in_front_of_it_is_told() {
        for sector in [512u16, 4096] {
            for per_cluster in [1u8, 8, 128, 0xF7] {
                let head = whole(ntfs_boot_sector(sector, per_cluster));
                assert_eq!(
                    layer(&head),
                    Detected::Container(Container::Ntfs),
                    "sector {sector}, {per_cluster} per cluster"
                );
            }
        }

        // The name, which is the whole of what the library underneath
        // checks and the only thing that tells NTFS from the other boot
        // sectors; a volume of no sectors; a master file table at cluster
        // 0; a sector size no disk has; and the fields FAT fills, which an
        // NTFS boot sector leaves zero.
        let mut other_name = ntfs_boot_sector(512, 8);
        other_name[3..11].copy_from_slice(b"EXFAT   ");
        let mut no_sectors = ntfs_boot_sector(512, 8);
        no_sectors[40..48].fill(0);
        let mut no_table = ntfs_boot_sector(512, 8);
        no_table[48..56].fill(0);
        let odd_sector = ntfs_boot_sector(777, 8);
        let mut reserved = ntfs_boot_sector(512, 8);
        reserved[14..16].copy_from_slice(&1u16.to_le_bytes());
        let mut two_tables = ntfs_boot_sector(512, 8);
        two_tables[16] = 2;
        let mut three_sectors = ntfs_boot_sector(512, 3);
        three_sectors[13] = 3;
        for head in [
            other_name,
            no_sectors,
            no_table,
            odd_sector,
            reserved,
            two_tables,
            three_sectors,
        ] {
            assert_eq!(layer(&whole(head)), Detected::Container(Container::Data));
        }
    }

    /// The two boot sectors do not answer for each other: FAT's rules
    /// refuse an NTFS one for having no reserved count and no table, and
    /// NTFS's refuse a FAT one for its name. Neither looks like a
    /// partition table, although all three end in the same two bytes.
    #[test]
    fn a_fat_boot_sector_and_an_ntfs_one_are_not_each_other() {
        let fat = boot_sector(512, 8, false);
        let ntfs = ntfs_boot_sector(512, 8);
        assert!(is_fat(&fat) && !is_ntfs(&fat));
        assert!(is_ntfs(&ntfs) && !is_fat(&ntfs));
        assert!(!is_partitioned(&fat) && !is_partitioned(&ntfs));
    }

    #[test]
    fn what_is_not_a_boot_sector_is_not_a_file_system() {
        // No jump, a sector size no disk has, no table, and exFAT, which
        // keeps FAT's signature and jump and is not read here.
        let mut no_jump = boot_sector(512, 1, false);
        no_jump[0] = 0x00;
        let odd_sector = boot_sector(777, 1, false);
        let mut no_fat = boot_sector(512, 1, false);
        no_fat[22..24].fill(0);
        let mut exfat = boot_sector(512, 1, false);
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        let mut three_clusters = boot_sector(512, 3, false);
        three_clusters[13] = 3;
        for head in [no_jump, odd_sector, no_fat, exfat, three_clusters] {
            assert_eq!(layer(&whole(head)), Detected::Container(Container::Data));
        }
    }

    /// The trap this order is for: an image that is both. A hybrid ISO
    /// carries a protective master boot record in its system area, to be
    /// written to a USB stick, and its files are on its ISO 9660 side.
    #[test]
    fn a_hybrid_image_is_the_image_and_not_the_table_in_front_of_it() {
        let mut image = mbr(&[0xEE]);
        image.resize(ISO_HEAD_LEN, 0);
        // The first descriptor, after the 32 KiB system area.
        image[ISO_DESCRIPTORS] = 1;
        image[ISO_DESCRIPTORS + 1..ISO_DESCRIPTORS + 6].copy_from_slice(b"CD001");
        image[ISO_DESCRIPTORS + 6] = 1;
        assert_eq!(layer(&image), Detected::Container(Container::Iso));
        // And the head that matters: the first one, which holds the record
        // and not the descriptor. It has to say data, or the second head
        // is never read and the image is lost behind its own boot sector.
        assert_eq!(
            layer(&image[..HEAD_LEN]),
            Detected::Container(Container::Data),
            "the first head of a hybrid image must ask for the second"
        );
    }

    /// And the trap in how the heads are read: a table told from the first
    /// of them would stop the second from ever being read, because only
    /// data asks for it. So a head of exactly HEAD_LEN says data, and the
    /// same bytes with one more say what they are.
    #[test]
    fn a_disk_waits_for_the_head_that_rules_an_image_out() {
        let mut first = mbr(&[0x83]);
        first.resize(HEAD_LEN, 0);
        assert_eq!(layer(&first), Detected::Container(Container::Data));
        first.push(0);
        assert_eq!(
            layer(&first),
            Detected::Container(Container::PartitionedDisk)
        );
    }

    #[test]
    fn appimages_by_their_elf_header() {
        let mut head = b"\x7fELF\x02\x01\x01\x00AI\x02".to_vec();
        head.resize(64, 0);
        assert_eq!(layer(&head), Detected::Container(Container::AppImageType2));
        head[10] = 1;
        assert_eq!(layer(&head), Detected::Container(Container::AppImageType1));
        // Another type, no AI, or no ELF magic: data.
        for (at, byte) in [(10, 3), (8, b'X'), (0, 0)] {
            let mut other = head.clone();
            other[at] = byte;
            assert_eq!(layer(&other), Detected::Container(Container::Data));
        }
        assert_eq!(layer(&head[..10]), Detected::Container(Container::Data));
    }

    #[test]
    fn squashfs_by_its_magic() {
        let mut head = b"hsqs".to_vec();
        head.extend_from_slice(&[0; 92]);
        assert_eq!(layer(&head), Detected::Container(Container::Squashfs));
        // Its magic in the other byte order (SquashFS 3 and older on
        // big-endian machines), and near misses, are data.
        for other in [&b"sqsh"[..], b"hsq", b"Hsqs", b"hsqt"] {
            assert_eq!(layer(other), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn iso_by_its_first_volume_descriptor() {
        let mut image = vec![0u8; ISO_HEAD_LEN];
        image[ISO_DESCRIPTORS..ISO_DESCRIPTORS + 7].copy_from_slice(b"\x01CD001\x01");
        assert_eq!(layer(&image), Detected::Container(Container::Iso));
        // A boot record first, or the set's end; a boot sector or a
        // partition table in the system area.
        for kind in [0, 2, 3, 255] {
            image[ISO_DESCRIPTORS] = kind;
            assert_eq!(layer(&image), Detected::Container(Container::Iso));
        }
        image[..2].copy_from_slice(&[0x33, 0xed]);
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(layer(&image), Detected::Container(Container::Iso));
        // What starts the stream comes first.
        image[..3].copy_from_slice(&[0x1F, 0x8B, 0x08]);
        assert_eq!(layer(&image), Detected::Layer(Layer::Gzip));
        image[..3].fill(0);
        // Another type, version or identifier (UDF alone has BEA01), or too
        // short (the first HEAD_LEN bytes alone): data.
        for (at, byte) in [(0, 4), (0, 254), (6, 2), (1, b'B')] {
            let mut other = image.clone();
            other[ISO_DESCRIPTORS + at] = byte;
            assert_eq!(layer(&other), Detected::Container(Container::Data));
        }
        for len in [ISO_DESCRIPTORS + 6, HEAD_LEN] {
            assert_eq!(layer(&image[..len]), Detected::Container(Container::Data));
        }
    }

    /// A UDF volume recognition sequence of `ids` from 32 KiB, a descriptor
    /// every `step` bytes, in an image of at least [`UDF_HEAD_LEN`].
    fn vrs(ids: &[&[u8]], step: usize) -> Vec<u8> {
        let mut image = vec![0u8; UDF_HEAD_LEN.max(ISO_DESCRIPTORS + ids.len() * step)];
        for (i, id) in ids.iter().enumerate() {
            let at = ISO_DESCRIPTORS + i * step;
            // ISO 9660's: a primary volume descriptor, and the set's end.
            image[at] = match *id {
                b"CD001" if i == 0 => 1,
                b"CD001" => 255,
                _ => 0,
            };
            image[at + 1..at + 6].copy_from_slice(id);
            image[at + 6] = 1;
        }
        image
    }

    #[test]
    fn udf_by_its_volume_recognition_sequence() {
        let udf = Detected::Container(Container::Udf);
        for ids in [
            &[&b"BEA01"[..], b"NSR02", b"TEA01"][..],
            &[b"BEA01", b"NSR03", b"TEA01"],
        ] {
            assert_eq!(layer(&vrs(ids, 2048)), udf);
            // Blocks of 4096 bytes.
            assert_eq!(layer(&vrs(ids, 4096)), udf);
        }
        // Beside ISO 9660, after its descriptors: UDF, but in its first
        // ISO_HEAD_LEN bytes.
        let bridge = vrs(&[b"CD001", b"CD001", b"BEA01", b"NSR02", b"TEA01"], 2048);
        assert_eq!(layer(&bridge), udf);
        assert_eq!(
            layer(&bridge[..ISO_HEAD_LEN]),
            Detected::Container(Container::Iso)
        );
        // NSR outside an extended area, none at all, or another version:
        // not UDF.
        for ids in [
            &[&b"NSR02"[..], b"BEA01", b"TEA01"][..],
            &[b"BEA01", b"TEA01", b"NSR03"],
            &[b"BEA01", b"TEA01"],
        ] {
            assert_eq!(layer(&vrs(ids, 2048)), Detected::Container(Container::Data));
        }
        let mut other = vrs(&[b"BEA01", b"NSR02"], 2048);
        other[ISO_DESCRIPTORS + 2048 + 6] = 2;
        assert_eq!(layer(&other), Detected::Container(Container::Data));
        // Past what is looked at.
        let far = vrs(&[b"BEA01", b"NSR02"], 2048 * 32);
        assert_eq!(
            layer(&far[..UDF_HEAD_LEN]),
            Detected::Container(Container::Data)
        );
    }

    #[test]
    fn rar_by_its_signature() {
        let rar = Detected::Container(Container::Rar);
        assert_eq!(layer(b"Rar!\x1a\x07\x00\xcf\x90"), rar);
        assert_eq!(layer(b"Rar!\x1a\x07\x01\x00"), rar);
        assert_eq!(layer(b"RE~^\x00\x00"), rar);
        // Cut short, a format to come, or a byte off: data.
        for head in [
            &b"Rar!\x1a\x07"[..],
            b"Rar!\x1a\x07\x05",
            b"Rar!\x1a\x08\x00",
            b"RE~",
        ] {
            assert_eq!(
                layer(head),
                Detected::Container(Container::Data),
                "{head:?}"
            );
        }
    }

    #[test]
    fn seven_zip_by_its_signature() {
        let seven = Detected::Container(Container::SevenZip);
        // The signature, its version (0.4) and its start header's CRC.
        assert_eq!(layer(b"7z\xBC\xAF\x27\x1C\x00\x04\x8d\x9b\xd5\x0f"), seven);
        assert_eq!(layer(b"7z\xBC\xAF\x27\x1C"), seven);
        // Cut short, or a byte off: data.
        for head in [
            &b"7z\xBC\xAF\x27"[..],
            b"7z\xBC\xAF\x27\x1D",
            b"7Z\xBC\xAF\x27\x1C",
        ] {
            assert_eq!(
                layer(head),
                Detected::Container(Container::Data),
                "{head:?}"
            );
        }
        // Not under a name: the signature tells.
        assert_eq!(detect(b"7z\xBC\xAF\x27\x1C", Some("x.lzma")), seven);
    }

    #[test]
    fn lzma_by_its_name_only() {
        let head = [0x5D, 0, 0, 0x10, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(layer(&head), Detected::Container(Container::Data));
        for name in ["notes.lzma", "BACKUP.TAR.LZMA"] {
            assert_eq!(detect(&head, Some(name)), Detected::Layer(Layer::Lzma));
        }
        // Magic bytes come first.
        assert_eq!(
            detect(b"\x1F\x8B\x08", Some("x.lzma")),
            Detected::Layer(Layer::Gzip)
        );
    }

    #[test]
    fn zip_volumes_by_their_names() {
        let middle = [0x98, 0x93, 0x8E, 0xEA, 0x7D, 0x32, 0x9D, 0xB0];
        assert_eq!(layer(&middle), Detected::Container(Container::Data));
        let zip = Detected::Container(Container::Zip);
        for name in [
            "a.zip",
            "A.ZIP",
            "a.z02",
            "a.Z99",
            "a.z100",
            "a.zipx",
            "a.zx01",
            "a.ZX12",
            "a.zip.002",
            "a.ZIP.0010",
        ] {
            assert_eq!(detect(&middle, Some(name)), zip, "{name}");
        }
        for name in [
            "a.z", "a.z1", "a.zx1", "a.zipper", "a.7z.002", "a.002", "zip", "a.tar",
        ] {
            assert_eq!(
                detect(&middle, Some(name)),
                Detected::Container(Container::Data),
                "{name}"
            );
        }
        // Magic bytes come first: a gzip file named .zip is gzip.
        assert_eq!(
            detect(b"\x1F\x8B\x08", Some("x.zip")),
            Detected::Layer(Layer::Gzip)
        );
    }
}
