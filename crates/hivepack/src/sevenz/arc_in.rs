//! Reading a 7z archive's headers: `7zArcIn.c`.
//!
//! Differs from the LZMA SDK: the structures are vectors, not pointers the
//! caller frees; every allocation counts against a memory limit
//! ([`Options::memory_limit`](crate::sevenz::Options)), past which the archive
//! fails to open with `SZ_ERROR_MEM`, where the SDK's would fail only
//! when the system refuses it the memory (a count of 2^31 files in a few
//! bytes of header asks for tens of GB).

use std::io::{Read, Seek, SeekFrom};

use crate::sevenz::aes7z::Decoding;
use crate::sevenz::dec;
use crate::sevenz::error::{Error, Result};

/// `k7zStartHeaderSize`.
pub const START_HEADER_SIZE: usize = 0x20;
/// `k7zSignatureSize`.
pub const SIGNATURE_SIZE: usize = 6;
/// `k7zSignature`: the first bytes of a 7z archive.
pub const SIGNATURE: [u8; SIGNATURE_SIZE] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

// EIdEnum.
const ID_END: u64 = 0;
const ID_HEADER: u64 = 1;
const ID_ARCHIVE_PROPERTIES: u64 = 2;
const ID_ADDITIONAL_STREAMS_INFO: u64 = 3;
const ID_MAIN_STREAMS_INFO: u64 = 4;
const ID_FILES_INFO: u64 = 5;
const ID_PACK_INFO: u64 = 6;
const ID_UNPACK_INFO: u64 = 7;
const ID_SUB_STREAMS_INFO: u64 = 8;
const ID_SIZE: u64 = 9;
const ID_CRC: u64 = 10;
const ID_FOLDER: u64 = 11;
const ID_CODERS_UNPACK_SIZE: u64 = 12;
const ID_NUM_UNPACK_STREAM: u64 = 13;
const ID_EMPTY_STREAM: u64 = 14;
const ID_EMPTY_FILE: u64 = 15;
const ID_NAME: u64 = 17;
const ID_CTIME: u64 = 18;
const ID_MTIME: u64 = 20;
const ID_WIN_ATTRIB: u64 = 21;
const ID_ENCODED_HEADER: u64 = 23;

/// `SZ_NUM_CODERS_IN_FOLDER_MAX`. Differs from the SDK, which stops at 4: its
/// fixed shapes need no more, and 7-Zip's graphs do (BCJ2 with AES takes 8).
/// The decoder's own checks still tell the SDK's shapes.
pub(crate) const NUM_CODERS_IN_FOLDER_MAX: usize = 16;
/// `SZ_NUM_BONDS_IN_FOLDER_MAX`.
pub(crate) const NUM_BONDS_IN_FOLDER_MAX: usize = NUM_CODERS_IN_FOLDER_MAX - 1;
/// `SZ_NUM_PACK_STREAMS_IN_FOLDER_MAX`.
pub(crate) const NUM_PACK_STREAMS_IN_FOLDER_MAX: usize = NUM_CODERS_IN_FOLDER_MAX;
/// `k_NumCodersStreams_in_Folder_MAX`.
const NUM_CODERS_STREAMS_IN_FOLDER_MAX: usize =
    NUM_BONDS_IN_FOLDER_MAX + NUM_PACK_STREAMS_IN_FOLDER_MAX;
/// `k_Scan_NumCoders_MAX`.
const SCAN_NUM_CODERS_MAX: u32 = 64;
/// `k_Scan_NumCodersStreams_in_Folder_MAX`.
const SCAN_NUM_CODERS_STREAMS_IN_FOLDER_MAX: u32 = 64;
/// `NUM_ADDITIONAL_STREAMS_MAX`.
const NUM_ADDITIONAL_STREAMS_MAX: u32 = 8;

/// `sizeof(size_t)`, in bytes.
const SIZE_T_BYTES: u32 = usize::BITS / 8;

/// What the vectors of an archive's description may take, in bytes.
pub(crate) struct Budget {
    left: u64,
    /// For an encoded header's folder.
    decoding: Decoding,
}

impl Budget {
    pub(crate) fn new(limit: u64, decoding: Decoding) -> Self {
        Budget {
            left: limit,
            decoding,
        }
    }

    /// `MY_ALLOC`: `n` items, `T::default()` each.
    pub(crate) fn alloc<T: Clone + Default>(&mut self, n: usize) -> Result<Vec<T>> {
        let bytes = (n as u64).saturating_mul(core::mem::size_of::<T>() as u64);
        if bytes > self.left {
            return Err(Error::Mem);
        }
        self.left -= bytes;
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Mem)?;
        v.resize(n, T::default());
        Ok(v)
    }

    /// `MY_ALLOC_AND_CPY`.
    pub(crate) fn copy(&mut self, from: &[u8]) -> Result<Vec<u8>> {
        let mut v = self.alloc::<u8>(0)?;
        let bytes = from.len() as u64;
        if bytes > self.left {
            return Err(Error::Mem);
        }
        self.left -= bytes;
        v.try_reserve_exact(from.len()).map_err(|_| Error::Mem)?;
        v.extend_from_slice(from);
        Ok(v)
    }
}

/// `SzBitArray_Check`: bit `i` of `bits`, from the most significant bit of
/// each byte.
pub(crate) fn bit_check(bits: &[u8], i: usize) -> bool {
    bits[i >> 3] & (0x80 >> (i & 7)) != 0
}

/// `CSzBitUi32s`: values, some defined.
#[derive(Clone, Debug, Default)]
pub(crate) struct BitUi32s {
    /// `Defs`: none when the vector was not read, or has no item.
    pub(crate) defs: Option<Vec<u8>>,
    pub(crate) vals: Vec<u32>,
}

impl BitUi32s {
    /// `SzBitWithVals_Check`.
    pub(crate) fn check(&self, i: usize) -> bool {
        self.defs.as_deref().is_some_and(|d| bit_check(d, i))
    }
}

/// `CSzBitUi64s`, with the NTFS times as they are, 100 ns since 1601.
#[derive(Clone, Debug, Default)]
pub(crate) struct BitUi64s {
    pub(crate) defs: Option<Vec<u8>>,
    pub(crate) vals: Vec<u64>,
}

impl BitUi64s {
    pub(crate) fn check(&self, i: usize) -> bool {
        self.defs.as_deref().is_some_and(|d| bit_check(d, i))
    }
}

/// `CSzData`: header bytes, read from the front.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sd<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> Sd<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Sd { data }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    /// `SZ_READ_BYTE_SD`.
    pub(crate) fn read_byte(&mut self) -> Result<u8> {
        let (&b, rest) = self.data.split_first().ok_or(Error::Archive)?;
        self.data = rest;
        Ok(b)
    }

    /// `SKIP_DATA`, `n` at most what is left.
    fn skip(&mut self, n: usize) {
        self.data = &self.data[n..];
    }

    /// `ReadNumber`: 7z's variable-length number, its first byte telling
    /// how many more follow.
    pub(crate) fn read_number(&mut self) -> Result<u64> {
        let first = u32::from(self.read_byte()?);
        if first & 0x80 == 0 {
            return Ok(u64::from(first));
        }
        let v = u32::from(self.read_byte()?);
        if first & 0x40 == 0 {
            return Ok(u64::from(((first & 0x3F) << 8) | v));
        }
        let m = u32::from(self.read_byte()?);
        let mut value = u64::from(v | (m << 8));
        let mut mask = 0x20u32;
        let mut i = 2 * 8;
        while i < 8 * 8 {
            if first & mask == 0 {
                let high_part = u64::from(first & (mask - 1));
                value |= high_part << i;
                return Ok(value);
            }
            mask >>= 1;
            let b = u64::from(self.read_byte()?);
            value |= b << i;
            i += 8;
        }
        Ok(value)
    }

    /// `SzReadNumber32`: a number that must fit a count.
    pub(crate) fn read_number32(&mut self) -> Result<u32> {
        let &first = self.data.first().ok_or(Error::Archive)?;
        if first & 0x80 == 0 {
            self.data = &self.data[1..];
            return Ok(u32::from(first));
        }
        let value64 = self.read_number()?;
        if value64 >= 0x8000_0000 - 1 {
            return Err(Error::Unsupported);
        }
        if value64 >= 1u64 << ((SIZE_T_BYTES - 1) * 8 + 4) {
            return Err(Error::Unsupported);
        }
        Ok(value64 as u32)
    }

    /// `ReadID`.
    fn read_id(&mut self) -> Result<u64> {
        self.read_number()
    }

    /// `SkipData`: a property's size, then its bytes.
    fn skip_data(&mut self) -> Result<()> {
        let size = self.read_number()?;
        if size > self.len() as u64 {
            return Err(Error::Archive);
        }
        self.skip(size as usize);
        Ok(())
    }

    /// `WaitId`: properties skipped up to `id`.
    fn wait_id(&mut self, id: u64) -> Result<()> {
        loop {
            let ty = self.read_id()?;
            if ty == id {
                return Ok(());
            }
            if ty == ID_END {
                return Err(Error::Archive);
            }
            self.skip_data()?;
        }
    }

    /// `ReadBitVector`: `num_items` bits, or all of them set.
    fn read_bit_vector(
        &mut self,
        num_items: usize,
        budget: &mut Budget,
    ) -> Result<Option<Vec<u8>>> {
        let num_bytes = num_items.div_ceil(8);
        let all_are_defined = self.read_byte()?;
        if num_bytes == 0 {
            return Ok(None);
        }
        if all_are_defined == 0 {
            if num_bytes > self.len() {
                return Err(Error::Archive);
            }
            let v = budget.copy(&self.data[..num_bytes])?;
            self.skip(num_bytes);
            return Ok(Some(v));
        }
        let mut v = budget.alloc::<u8>(num_bytes)?;
        v.fill(0xFF);
        let num_bits = num_items & 7;
        if num_bits != 0 {
            v[num_bytes - 1] = (0xff00u32 >> num_bits) as u8;
        }
        Ok(Some(v))
    }

    /// `ReadUi32s`: the defined values, 4 bytes each.
    fn read_ui32s(
        &mut self,
        num_items: usize,
        crcs: &mut BitUi32s,
        budget: &mut Budget,
    ) -> Result<()> {
        let mut vals = budget.alloc::<u32>(num_items)?;
        for (i, val) in vals.iter_mut().enumerate() {
            if crcs.defs.as_deref().is_some_and(|d| bit_check(d, i)) {
                let Some((word, rest)) = self.data.split_first_chunk::<4>() else {
                    crcs.vals = Vec::new();
                    return Err(Error::Archive);
                };
                *val = u32::from_le_bytes(*word);
                self.data = rest;
            }
        }
        crcs.vals = vals;
        Ok(())
    }

    /// `ReadBitUi32s`.
    fn read_bit_ui32s(
        &mut self,
        num_items: usize,
        crcs: &mut BitUi32s,
        budget: &mut Budget,
    ) -> Result<()> {
        if crcs.defs.is_some() {
            return Err(Error::Archive);
        }
        crcs.defs = self.read_bit_vector(num_items, budget)?;
        self.read_ui32s(num_items, crcs, budget)
    }

    /// `SkipBitUi32s`.
    fn skip_bit_ui32s(&mut self, num_items: u32) -> Result<()> {
        let all_are_defined = self.read_byte()?;
        let mut num_defined = num_items;
        if all_are_defined == 0 {
            let num_bytes = (num_items as usize).div_ceil(8);
            if num_bytes > self.len() {
                return Err(Error::Archive);
            }
            num_defined = count_defined_bits(self.data, num_items);
            self.skip(num_bytes);
        }
        if num_defined as usize > self.len() >> 2 {
            return Err(Error::Archive);
        }
        self.skip(num_defined as usize * 4);
        Ok(())
    }

    /// `SkipNumbers`.
    fn skip_numbers(&mut self, num: u32) -> Result<()> {
        for _ in 0..num {
            let &first = self.data.first().ok_or(Error::Archive)?;
            let mut first = u32::from(first);
            let mut i = 1;
            while first & 0x80 != 0 {
                first <<= 1;
                i += 1;
            }
            if self.len() < i {
                return Err(Error::Archive);
            }
            self.skip(i);
        }
        Ok(())
    }
}

/// `CountDefinedBits`.
fn count_defined_bits(bits: &[u8], num_items: u32) -> u32 {
    (0..num_items as usize)
        .filter(|&i| bit_check(bits, i))
        .count() as u32
}

/// `CSzCoderInfo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoderInfo {
    /// Where the coder's properties are in the folder's coder data.
    pub(crate) props_offset: usize,
    pub(crate) method_id: u32,
    pub(crate) num_streams: u8,
    pub(crate) props_size: u8,
}

/// `CSzBond`: an input stream of a coder, fed by another coder's output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bond {
    pub(crate) in_index: u32,
    pub(crate) out_index: u32,
}

/// `CSzFolder`: how a folder's coders are bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Folder {
    pub(crate) num_coders: u32,
    pub(crate) num_bonds: u32,
    pub(crate) num_pack_streams: u32,
    pub(crate) unpack_stream: u32,
    pub(crate) pack_streams: [u32; NUM_PACK_STREAMS_IN_FOLDER_MAX],
    pub(crate) bonds: [Bond; NUM_BONDS_IN_FOLDER_MAX],
    pub(crate) coders: [CoderInfo; NUM_CODERS_IN_FOLDER_MAX],
}

/// `SzGetNextFolderItem`: a folder's description, as the decoder takes it.
/// The props offsets are from the start of `sd`.
pub(crate) fn get_next_folder_item(sd: &mut Sd<'_>) -> Result<Folder> {
    let start = sd.data;
    let mut f = Folder::default();
    let num_coders = sd.read_number32()?;
    if num_coders == 0 || num_coders as usize > NUM_CODERS_IN_FOLDER_MAX {
        return Err(Error::Unsupported);
    }
    f.num_coders = num_coders;
    let mut num_in_streams = 0u32;

    for i in 0..num_coders as usize {
        let main_byte = sd.read_byte()?;
        if main_byte & 0xC0 != 0 {
            return Err(Error::Unsupported);
        }
        let id_size = usize::from(main_byte & 0xF);
        if id_size > 8 {
            return Err(Error::Unsupported);
        }
        if id_size > sd.len() {
            return Err(Error::Archive);
        }
        let id = sd.data[..id_size]
            .iter()
            .fold(0u64, |id, &b| (id << 8) | u64::from(b));
        sd.skip(id_size);
        if id > u64::from(u32::MAX) {
            return Err(Error::Unsupported);
        }
        let coder = &mut f.coders[i];
        coder.method_id = id as u32;
        coder.num_streams = 1;
        coder.props_offset = 0;
        coder.props_size = 0;

        if main_byte & 0x10 != 0 {
            let num_streams = sd.read_number32()?;
            if num_streams as usize > NUM_CODERS_STREAMS_IN_FOLDER_MAX {
                return Err(Error::Unsupported);
            }
            coder.num_streams = num_streams as u8;
            let num_out = sd.read_number32()?;
            if num_out != 1 {
                return Err(Error::Unsupported);
            }
        }

        num_in_streams += u32::from(coder.num_streams);
        if num_in_streams as usize > NUM_CODERS_STREAMS_IN_FOLDER_MAX {
            return Err(Error::Unsupported);
        }

        if main_byte & 0x20 != 0 {
            let props_size = sd.read_number32()?;
            if props_size as usize > sd.len() {
                return Err(Error::Archive);
            }
            if props_size >= 0x80 {
                return Err(Error::Unsupported);
            }
            coder.props_offset = start.len() - sd.len();
            coder.props_size = props_size as u8;
            sd.skip(props_size as usize);
        }
    }

    let mut stream_used = [false; NUM_CODERS_STREAMS_IN_FOLDER_MAX];
    let num_bonds = num_coders - 1;
    if num_in_streams < num_bonds {
        return Err(Error::Archive);
    }
    if num_bonds as usize > NUM_BONDS_IN_FOLDER_MAX {
        return Err(Error::Unsupported);
    }
    f.num_bonds = num_bonds;

    let num_pack_streams = num_in_streams - num_bonds;
    if num_pack_streams as usize > NUM_PACK_STREAMS_IN_FOLDER_MAX {
        return Err(Error::Unsupported);
    }
    f.num_pack_streams = num_pack_streams;

    if num_bonds != 0 {
        let mut coder_used = [false; NUM_CODERS_IN_FOLDER_MAX];
        for i in 0..num_bonds as usize {
            let in_index = sd.read_number32()?;
            if in_index >= num_in_streams || stream_used[in_index as usize] {
                return Err(Error::Archive);
            }
            stream_used[in_index as usize] = true;
            let out_index = sd.read_number32()?;
            if out_index >= num_coders || coder_used[out_index as usize] {
                return Err(Error::Archive);
            }
            coder_used[out_index as usize] = true;
            f.bonds[i] = Bond {
                in_index,
                out_index,
            };
        }
        let mut i = 0;
        while coder_used[i] {
            i += 1;
            if i == num_coders as usize {
                return Err(Error::Archive);
            }
        }
        f.unpack_stream = i as u32;
    }

    if num_pack_streams == 1 {
        let mut i = 0u32;
        loop {
            if i == num_in_streams {
                return Err(Error::Archive);
            }
            if !stream_used[i as usize] {
                break;
            }
            i += 1;
        }
        f.pack_streams[0] = i;
    } else {
        for i in 0..num_pack_streams as usize {
            let index = sd.read_number32()?;
            if index >= num_in_streams || stream_used[index as usize] {
                return Err(Error::Archive);
            }
            stream_used[index as usize] = true;
            f.pack_streams[i] = index;
        }
    }
    Ok(f)
}

/// `CSzAr`: the streams of an archive, its folders and their coders.
#[derive(Clone, Debug, Default)]
pub(crate) struct Ar {
    pub(crate) num_pack_streams: u32,
    pub(crate) num_folders: u32,
    /// `NumPackStreams + 1`.
    pub(crate) pack_positions: Vec<u64>,
    /// `NumFolders`.
    pub(crate) folder_crcs: BitUi32s,
    /// `NumFolders + 1`.
    pub(crate) fo_coders_offsets: Vec<usize>,
    /// `NumFolders + 1`.
    pub(crate) fo_start_pack_stream_index: Vec<u32>,
    /// `NumFolders + 1`.
    pub(crate) fo_to_coder_unpack_sizes: Vec<u32>,
    /// `NumFolders`.
    pub(crate) fo_to_main_unpack_size_index: Vec<u8>,
    /// For all coders in all folders.
    pub(crate) coder_unpack_sizes: Vec<u64>,
    pub(crate) coders_data: Vec<u8>,
    pub(crate) range_limit: u64,
}

impl Ar {
    /// `SzAr_GetFolderUnpackSize`.
    pub(crate) fn folder_unpack_size(&self, folder_index: usize) -> u64 {
        self.coder_unpack_sizes[self.fo_to_coder_unpack_sizes[folder_index] as usize
            + usize::from(self.fo_to_main_unpack_size_index[folder_index])]
    }

    /// `ReadPackInfo`.
    fn read_pack_info(&mut self, sd: &mut Sd<'_>, budget: &mut Budget) -> Result<()> {
        self.num_pack_streams = sd.read_number32()?;
        sd.wait_id(ID_SIZE)?;
        let num = self.num_pack_streams as usize + 1;
        let mut pack_positions = budget.alloc::<u64>(num)?;
        let mut sum = 0u64;
        for (i, pos) in pack_positions.iter_mut().enumerate() {
            *pos = sum;
            if i + 1 == num {
                break;
            }
            let pack_size = match sd.read_number() {
                Ok(size) => size,
                Err(e) => {
                    self.pack_positions = Vec::new();
                    return Err(e);
                }
            };
            sum = sum.wrapping_add(pack_size);
            if sum < pack_size {
                return Err(Error::Archive);
            }
        }
        self.pack_positions = pack_positions;
        loop {
            let ty = sd.read_id()?;
            if ty == ID_END {
                return Ok(());
            }
            if ty == ID_CRC {
                // The CRCs of packed streams are unused now.
                sd.skip_bit_ui32s(self.num_pack_streams)?;
                continue;
            }
            sd.skip_data()?;
        }
    }

    /// `ReadUnpackInfo`: the folders, their coders, the coders' unpack
    /// sizes and the folders' CRCs.
    fn read_unpack_info(
        &mut self,
        sd2: &mut Sd<'_>,
        num_folders_max: u32,
        temp_bufs: &[Vec<u8>],
        budget: &mut Budget,
    ) -> Result<()> {
        sd2.wait_id(ID_FOLDER)?;
        let num_folders = sd2.read_number32()?;
        if num_folders > num_folders_max {
            return Err(Error::Unsupported);
        }
        self.num_folders = num_folders;

        let external = sd2.read_byte()?;
        if external == 0 {
            self.read_folders(sd2, budget)?;
        } else {
            let index = sd2.read_number32()?;
            if index as usize >= temp_bufs.len() {
                return Err(Error::Archive);
            }
            let mut sd = Sd::new(&temp_bufs[index as usize]);
            self.read_folders(&mut sd, budget)?;
            if sd.len() != 0 {
                return Err(Error::Archive);
            }
        }
        let n = num_folders as usize;
        let mut sd = *sd2;

        sd.wait_id(ID_CODERS_UNPACK_SIZE)?;
        let mut sizes = budget.alloc::<u64>(self.fo_to_coder_unpack_sizes[n] as usize)?;
        for size in sizes.iter_mut() {
            *size = sd.read_number()?;
        }
        self.coder_unpack_sizes = sizes;

        loop {
            let ty = sd.read_id()?;
            if ty == ID_END {
                break;
            }
            if ty == ID_CRC {
                sd.read_bit_ui32s(n, &mut self.folder_crcs, budget)?;
                continue;
            }
            sd.skip_data()?;
        }
        *sd2 = sd;
        Ok(())
    }

    /// The folders' part of `ReadUnpackInfo`, from `sd`: the header, or the
    /// additional stream that holds them.
    fn read_folders(&mut self, sd: &mut Sd<'_>, budget: &mut Budget) -> Result<()> {
        let n = self.num_folders as usize;
        self.fo_coders_offsets = budget.alloc::<usize>(n + 1)?;
        self.fo_start_pack_stream_index = budget.alloc::<u32>(n + 1)?;
        self.fo_to_coder_unpack_sizes = budget.alloc::<u32>(n + 1)?;
        self.fo_to_main_unpack_size_index = budget.alloc::<u8>(n)?;

        let start_buf = sd.data;
        let mut pack_stream_index = 0u32;
        let mut num_coders_out_streams = 0u32;

        for fo in 0..n {
            self.fo_coders_offsets[fo] = start_buf.len() - sd.len();
            let num_coders = sd.read_number32()?;
            if num_coders == 0 || num_coders > SCAN_NUM_CODERS_MAX {
                return Err(Error::Unsupported);
            }
            let mut num_in_streams = 0u32;
            for _ in 0..num_coders {
                let main_byte = sd.read_byte()?;
                if main_byte & 0xC0 != 0 {
                    return Err(Error::Unsupported);
                }
                let id_size = usize::from(main_byte & 0xF);
                if id_size > 8 {
                    return Err(Error::Unsupported);
                }
                if id_size > sd.len() {
                    return Err(Error::Archive);
                }
                sd.skip(id_size);
                let mut coder_in_streams = 1;
                if main_byte & 0x10 != 0 {
                    coder_in_streams = sd.read_number32()?;
                    let coder_out_streams = sd.read_number32()?;
                    if coder_in_streams > SCAN_NUM_CODERS_STREAMS_IN_FOLDER_MAX
                        || coder_out_streams != 1
                    {
                        return Err(Error::Unsupported);
                    }
                }
                num_in_streams += coder_in_streams;
                if main_byte & 0x20 != 0 {
                    let props_size = sd.read_number32()?;
                    if props_size as usize > sd.len() {
                        return Err(Error::Archive);
                    }
                    sd.skip(props_size as usize);
                }
            }

            let mut index_of_main_stream = 0u32;
            let mut num_pack_streams = 1u32;
            if num_coders != 1 || num_in_streams != 1 {
                let num_bonds = num_coders - 1;
                if num_in_streams < num_bonds {
                    return Err(Error::Archive);
                }
                if num_in_streams > SCAN_NUM_CODERS_STREAMS_IN_FOLDER_MAX {
                    return Err(Error::Unsupported);
                }
                let mut stream_used = [false; SCAN_NUM_CODERS_STREAMS_IN_FOLDER_MAX as usize];
                let mut coder_used = [false; SCAN_NUM_CODERS_MAX as usize];
                for _ in 0..num_bonds {
                    let index = sd.read_number32()?;
                    if index >= num_in_streams || stream_used[index as usize] {
                        return Err(Error::Archive);
                    }
                    stream_used[index as usize] = true;
                    let index = sd.read_number32()?;
                    if index >= num_coders || coder_used[index as usize] {
                        return Err(Error::Archive);
                    }
                    coder_used[index as usize] = true;
                }
                num_pack_streams = num_in_streams - num_bonds;
                if num_pack_streams != 1 {
                    for _ in 0..num_pack_streams {
                        let index = sd.read_number32()?;
                        if index >= num_in_streams || stream_used[index as usize] {
                            return Err(Error::Archive);
                        }
                        stream_used[index as usize] = true;
                    }
                }
                let mut i = 0u32;
                while coder_used[i as usize] {
                    i += 1;
                    if i == num_coders {
                        return Err(Error::Archive);
                    }
                }
                index_of_main_stream = i;
            }

            self.fo_start_pack_stream_index[fo] = pack_stream_index;
            self.fo_to_coder_unpack_sizes[fo] = num_coders_out_streams;
            self.fo_to_main_unpack_size_index[fo] = index_of_main_stream as u8;
            num_coders_out_streams = num_coders_out_streams.wrapping_add(num_coders);
            if num_coders_out_streams < num_coders {
                return Err(Error::Unsupported);
            }
            if num_pack_streams > self.num_pack_streams.wrapping_sub(pack_stream_index) {
                return Err(Error::Archive);
            }
            pack_stream_index += num_pack_streams;
        }

        let limit = 1u64 << (usize::BITS - 4);
        if u64::from(num_coders_out_streams) >= limit {
            return Err(Error::Unsupported);
        }
        self.fo_to_coder_unpack_sizes[n] = num_coders_out_streams;
        self.fo_start_pack_stream_index[n] = pack_stream_index;
        let data_size = start_buf.len() - sd.len();
        self.fo_coders_offsets[n] = data_size;
        self.coders_data = budget.copy(&start_buf[..data_size])?;
        Ok(())
    }
}

/// `CSubStreamInfo`: where the files' sizes and CRCs are in the header.
#[derive(Clone, Copy, Default)]
struct SubStreamInfo<'a> {
    num_total_sub_streams: u32,
    num_sub_digests: u32,
    sd_num_sub_streams: Option<Sd<'a>>,
    sd_sizes: Option<Sd<'a>>,
    sd_crcs: Option<Sd<'a>>,
}

/// `ReadSubStreamsInfo`.
fn read_sub_streams_info<'a>(p: &Ar, sd: &mut Sd<'a>, ssi: &mut SubStreamInfo<'a>) -> Result<()> {
    let num_folders = p.num_folders;
    let mut num_unpack_streams = num_folders;
    let mut num_sub_digests = num_folders;
    let mut num_unpack_sizes_in_data = 0u32;
    let mut ty;

    loop {
        ty = sd.read_id()?;
        if ty == ID_NUM_UNPACK_STREAM {
            if ssi.sd_num_sub_streams.is_some() {
                return Err(Error::Unsupported);
            }
            let start = sd.data;
            num_unpack_streams = 0;
            num_sub_digests = 0;
            for i in 0..num_folders as usize {
                let num_streams = sd.read_number32()?;
                num_unpack_streams = num_unpack_streams.wrapping_add(num_streams);
                if num_unpack_streams < num_streams {
                    return Err(Error::Unsupported);
                }
                if num_streams != 0 {
                    num_unpack_sizes_in_data += num_streams - 1;
                }
                if num_streams != 1 || !p.folder_crcs.check(i) {
                    num_sub_digests = num_sub_digests.wrapping_add(num_streams);
                }
            }
            ssi.sd_num_sub_streams = Some(Sd::new(&start[..start.len() - sd.len()]));
            continue;
        }
        if ty == ID_CRC || ty == ID_SIZE || ty == ID_END {
            break;
        }
        sd.skip_data()?;
    }

    if ssi.sd_num_sub_streams.is_none()
        && let Some(defs) = p.folder_crcs.defs.as_deref()
    {
        num_sub_digests = num_folders - count_defined_bits(defs, num_folders);
    }

    ssi.num_total_sub_streams = num_unpack_streams;
    ssi.num_sub_digests = num_sub_digests;

    if ty == ID_SIZE {
        let start = sd.data;
        sd.skip_numbers(num_unpack_sizes_in_data)?;
        ssi.sd_sizes = Some(Sd::new(&start[..start.len() - sd.len()]));
        ty = sd.read_id()?;
    }

    loop {
        if ty == ID_END {
            return Ok(());
        }
        if ty == ID_CRC {
            if ssi.sd_crcs.is_some() {
                return Err(Error::Unsupported);
            }
            let start = sd.data;
            sd.skip_bit_ui32s(num_sub_digests)?;
            ssi.sd_crcs = Some(Sd::new(&start[..start.len() - sd.len()]));
        } else {
            sd.skip_data()?;
        }
        ty = sd.read_id()?;
    }
}

/// `SzReadStreamsInfo`. Returns the offset of the packed streams.
fn read_streams_info<'a>(
    p: &mut Ar,
    sd: &mut Sd<'a>,
    num_folders_max: u32,
    temp_bufs: &[Vec<u8>],
    ssi: &mut SubStreamInfo<'a>,
    budget: &mut Budget,
) -> Result<u64> {
    ssi.sd_sizes = None;
    ssi.sd_crcs = None;
    ssi.sd_num_sub_streams = None;

    let mut data_offset = 0;
    let mut ty = sd.read_id()?;
    if ty == ID_PACK_INFO {
        data_offset = sd.read_number()?;
        if data_offset > p.range_limit {
            return Err(Error::Archive);
        }
        p.read_pack_info(sd, budget)?;
        if p.pack_positions[p.num_pack_streams as usize] > p.range_limit - data_offset {
            return Err(Error::Archive);
        }
        ty = sd.read_id()?;
    }
    if ty == ID_UNPACK_INFO {
        p.read_unpack_info(sd, num_folders_max, temp_bufs, budget)?;
        ty = sd.read_id()?;
    }
    if ty == ID_SUB_STREAMS_INFO {
        read_sub_streams_info(p, sd, ssi)?;
        ty = sd.read_id()?;
    } else {
        ssi.num_total_sub_streams = p.num_folders;
    }
    if ty == ID_END {
        Ok(data_offset)
    } else {
        Err(Error::Unsupported)
    }
}

/// `SzReadAndDecodePackedStreams`: the folders of an encoded header, or of
/// additional streams, decoded into buffers.
fn read_and_decode_packed_streams<R: Read + Seek>(
    in_stream: &mut R,
    sd: &mut Sd<'_>,
    num_folders_max: u32,
    base_offset: u64,
    p: &mut Ar,
    budget: &mut Budget,
) -> Result<Vec<Vec<u8>>> {
    let mut ssi = SubStreamInfo::default();
    let data_start_pos = read_streams_info(p, sd, num_folders_max, &[], &mut ssi, budget)?;
    let data_start_pos = data_start_pos.wrapping_add(base_offset);
    if p.num_folders == 0 {
        return Err(Error::Archive);
    }
    let mut bufs = Vec::new();
    for fo in 0..p.num_folders as usize {
        let unpack_size = p.folder_unpack_size(fo);
        if unpack_size > usize::MAX as u64 {
            return Err(Error::Mem);
        }
        bufs.push(budget.alloc::<u8>(unpack_size as usize)?);
    }
    for (fo, buf) in bufs.iter_mut().enumerate() {
        seek_to(in_stream, data_start_pos)?;
        dec::decode_folder(p, fo, in_stream, data_start_pos, &mut budget.decoding, buf)?;
    }
    Ok(bufs)
}

/// `LookInStream_SeekTo`.
pub(crate) fn seek_to<R: Seek>(in_stream: &mut R, pos: u64) -> Result<()> {
    in_stream
        .seek(SeekFrom::Start(pos))
        .map(|_| ())
        .map_err(|_| Error::Read)
}

/// `SzReadFileNames`: the offsets of the names, in UTF-16 units, each name
/// ending with a 0.
fn read_file_names(data: &[u8], num_files: u32, offsets: &mut [usize]) -> Result<()> {
    offsets[0] = 0;
    if num_files == 0 {
        return if data.is_empty() {
            Ok(())
        } else {
            Err(Error::Archive)
        };
    }
    let size = data.len();
    if size < 2 {
        return Err(Error::Archive);
    }
    if data[size - 2] != 0 || data[size - 1] != 0 {
        return Err(Error::Archive);
    }
    let mut p = 0;
    for offset in offsets.iter_mut().skip(1).take(num_files as usize) {
        if p >= size {
            return Err(Error::Archive);
        }
        while data[p] != 0 || data[p + 1] != 0 {
            p += 2;
        }
        p += 2;
        *offset = p >> 1;
    }
    if p == size {
        Ok(())
    } else {
        Err(Error::Archive)
    }
}

/// `ReadTime`.
fn read_time(
    p: &mut BitUi64s,
    num: usize,
    sd2: &mut Sd<'_>,
    temp_bufs: &[Vec<u8>],
    budget: &mut Budget,
) -> Result<()> {
    if p.defs.is_some() {
        return Err(Error::Archive);
    }
    p.defs = sd2.read_bit_vector(num, budget)?;
    let external = sd2.read_byte()?;
    let mut data = if external == 0 {
        *sd2
    } else {
        let index = sd2.read_number32()?;
        if index as usize >= temp_bufs.len() || sd2.len() != 0 {
            return Err(Error::Archive);
        }
        Sd::new(&temp_bufs[index as usize])
    };
    let mut vals = budget.alloc::<u64>(num)?;
    for (i, val) in vals.iter_mut().enumerate() {
        if p.defs.as_deref().is_some_and(|d| bit_check(d, i)) {
            let Some((word, rest)) = data.data.split_first_chunk::<8>() else {
                return Err(Error::Archive);
            };
            *val = u64::from_le_bytes(*word);
            data.data = rest;
        }
    }
    p.vals = vals;
    if data.len() != 0 {
        return Err(Error::Archive);
    }
    Ok(())
}

/// `CSzArEx`: an archive's description, its streams and its files.
#[derive(Clone, Debug, Default)]
pub(crate) struct ArEx {
    pub(crate) db: Ar,
    pub(crate) start_pos_after_header: u64,
    pub(crate) data_pos: u64,
    pub(crate) num_files: u32,
    /// `NumFiles + 1`.
    pub(crate) unpack_positions: Vec<u64>,
    pub(crate) is_dirs: Vec<u8>,
    pub(crate) crcs: BitUi32s,
    pub(crate) attribs: BitUi32s,
    pub(crate) mtime: BitUi64s,
    pub(crate) ctime: BitUi64s,
    /// `NumFolders + 1`.
    pub(crate) folder_to_file: Vec<u32>,
    /// `NumFiles`; `u32::MAX` for a file without data.
    pub(crate) file_to_folder: Vec<u32>,
    /// In UTF-16 units; none without names.
    pub(crate) file_name_offsets: Option<Vec<usize>>,
    /// UTF-16LE.
    pub(crate) file_names: Vec<u8>,
}

impl ArEx {
    /// `SzArEx_IsDir`.
    pub(crate) fn is_dir(&self, i: usize) -> bool {
        bit_check(&self.is_dirs, i)
    }

    /// `SzArEx_GetFileSize`.
    pub(crate) fn file_size(&self, i: usize) -> u64 {
        self.unpack_positions[i + 1] - self.unpack_positions[i]
    }

    /// `SzArEx_GetFileNameUtf16`, without the terminating 0 (none for an
    /// archive without names).
    pub(crate) fn file_name_utf16(&self, i: usize) -> Vec<u16> {
        let Some(offsets) = self.file_name_offsets.as_deref() else {
            return Vec::new();
        };
        let (start, end) = (offsets[i], offsets[i + 1] - 1);
        self.file_names[start * 2..end * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect()
    }

    /// `SzReadHeader2`.
    fn read_header2<R: Read + Seek>(
        &mut self,
        sd: &mut Sd<'_>,
        in_stream: &mut R,
        temp_bufs: &mut Vec<Vec<u8>>,
        budget: &mut Budget,
    ) -> Result<()> {
        let mut ssi = SubStreamInfo::default();
        let mut ty = sd.read_id()?;

        if ty == ID_ARCHIVE_PROPERTIES {
            loop {
                let ty2 = sd.read_id()?;
                if ty2 == ID_END {
                    break;
                }
                sd.skip_data()?;
            }
            ty = sd.read_id()?;
        }

        if ty == ID_ADDITIONAL_STREAMS_INFO {
            let mut temp_ar = Ar {
                range_limit: self.db.range_limit,
                ..Ar::default()
            };
            *temp_bufs = read_and_decode_packed_streams(
                in_stream,
                sd,
                NUM_ADDITIONAL_STREAMS_MAX,
                self.start_pos_after_header,
                &mut temp_ar,
                budget,
            )?;
            ty = sd.read_id()?;
        }

        if ty == ID_MAIN_STREAMS_INFO {
            const NUM_FOLDERS_MAX: u32 = 1 << 30;
            self.data_pos = read_streams_info(
                &mut self.db,
                sd,
                NUM_FOLDERS_MAX,
                temp_bufs,
                &mut ssi,
                budget,
            )?
            .wrapping_add(self.start_pos_after_header);
            ty = sd.read_id()?;
        }

        if ty == ID_END {
            return Ok(());
        }
        if ty != ID_FILES_INFO {
            return Err(Error::Archive);
        }

        let num_files = sd.read_number32()?;
        self.num_files = num_files;
        let nf = num_files as usize;
        let mut num_empty_streams = 0u32;
        let mut empty_streams: Option<&[u8]> = None;
        let mut empty_files: Option<&[u8]> = None;

        loop {
            let ty = sd.read_id()?;
            if ty == ID_END {
                break;
            }
            let size = sd.read_number()?;
            if size > sd.len() as u64 {
                return Err(Error::Archive);
            }
            let mut sd_switch = Sd::new(&sd.data[..size as usize]);
            sd.skip(size as usize);
            if ty >= 64 {
                continue;
            }
            match ty {
                ID_EMPTY_STREAM => {
                    if empty_streams.is_some() || empty_files.is_some() {
                        return Err(Error::Archive);
                    }
                    if nf.div_ceil(8) != sd_switch.len() {
                        return Err(Error::Archive);
                    }
                    empty_streams = Some(sd_switch.data);
                    num_empty_streams = count_defined_bits(sd_switch.data, num_files);
                }
                ID_EMPTY_FILE => {
                    if empty_files.is_some() {
                        return Err(Error::Archive);
                    }
                    if (num_empty_streams as usize).div_ceil(8) != sd_switch.len() {
                        return Err(Error::Archive);
                    }
                    empty_files = Some(sd_switch.data);
                }
                ID_NAME => {
                    if self.file_name_offsets.is_some() {
                        return Err(Error::Archive);
                    }
                    let external = sd_switch.read_byte()?;
                    let names_data = if external == 0 {
                        sd_switch.data
                    } else {
                        let index = sd_switch.read_number32()?;
                        if index as usize >= temp_bufs.len() || sd_switch.len() != 0 {
                            return Err(Error::Archive);
                        }
                        &temp_bufs[index as usize][..]
                    };
                    if names_data.len() & 1 != 0 {
                        return Err(Error::Archive);
                    }
                    let mut offsets = budget.alloc::<usize>(nf + 1)?;
                    self.file_names = budget.copy(names_data)?;
                    let res = read_file_names(&self.file_names, num_files, &mut offsets);
                    self.file_name_offsets = Some(offsets);
                    res?;
                }
                ID_WIN_ATTRIB => {
                    if self.attribs.defs.is_some() {
                        return Err(Error::Archive);
                    }
                    self.attribs.defs = sd_switch.read_bit_vector(nf, budget)?;
                    let external = sd_switch.read_byte()?;
                    if external != 0 {
                        let index = sd_switch.read_number32()?;
                        if index as usize >= temp_bufs.len() || sd_switch.len() != 0 {
                            return Err(Error::Archive);
                        }
                        sd_switch = Sd::new(&temp_bufs[index as usize]);
                    }
                    sd_switch.read_ui32s(nf, &mut self.attribs, budget)?;
                    if sd_switch.len() != 0 {
                        return Err(Error::Archive);
                    }
                }
                ID_MTIME => read_time(&mut self.mtime, nf, &mut sd_switch, temp_bufs, budget)?,
                ID_CTIME => read_time(&mut self.ctime, nf, &mut sd_switch, temp_bufs, budget)?,
                _ => {}
            }
        }

        if num_files.wrapping_sub(num_empty_streams) != ssi.num_total_sub_streams {
            return Err(Error::Archive);
        }

        loop {
            let ty = sd.read_id()?;
            if ty == ID_END {
                break;
            }
            sd.skip_data()?;
        }

        self.read_files(empty_streams, empty_files, &mut ssi, budget)
    }

    /// The end of `SzReadHeader2`: each file's place in the folders, its
    /// size and CRC.
    fn read_files(
        &mut self,
        empty_streams: Option<&[u8]>,
        empty_files: Option<&[u8]>,
        ssi: &mut SubStreamInfo<'_>,
        budget: &mut Budget,
    ) -> Result<()> {
        let num_files = self.num_files as usize;
        let num_folders = self.db.num_folders as usize;
        let mut empty_file_index = 0usize;
        let mut folder_index = 0usize;
        let mut rem_sub_streams = 0u32;
        let mut num_sub_streams = 0u32;
        let mut unpack_pos = 0u64;
        let mut digests_defs: Option<&[u8]> = None;
        let mut digests_vals: Option<&[u8]> = None;
        let mut digest_index = 0usize;

        self.folder_to_file = budget.alloc::<u32>(num_folders + 1)?;
        self.file_to_folder = budget.alloc::<u32>(num_files)?;
        self.unpack_positions = budget.alloc::<u64>(num_files + 1)?;
        self.is_dirs = budget.alloc::<u8>(num_files.div_ceil(8))?;
        // SzBitUi32s_Alloc.
        if num_files != 0 {
            self.crcs.defs = Some(budget.alloc::<u8>(num_files.div_ceil(8))?);
        }
        self.crcs.vals = budget.alloc::<u32>(num_files)?;

        if let Some(mut crcs) = ssi.sd_crcs
            && crcs.len() != 0
        {
            let all_digests_defined = crcs.read_byte()?;
            if all_digests_defined != 0 {
                digests_vals = Some(crcs.data);
            } else {
                let num_bytes = (ssi.num_sub_digests as usize).div_ceil(8);
                digests_defs = Some(crcs.data);
                digests_vals = Some(&crcs.data[num_bytes.min(crcs.len())..]);
            }
        }

        let in_empty = |i: usize| empty_streams.is_some_and(|e| bit_check(e, i));
        let mut is_dir_mask = 0u8;
        let mut crc_mask = 0u8;
        let mut mask = 0x80u8;
        let mut i = 0usize;
        while i < num_files {
            if mask == 0 {
                let byte_index = (i - 1) >> 3;
                self.is_dirs[byte_index] = is_dir_mask;
                if let Some(defs) = self.crcs.defs.as_mut() {
                    defs[byte_index] = crc_mask;
                }
                is_dir_mask = 0;
                crc_mask = 0;
                mask = 0x80;
            }

            self.unpack_positions[i] = unpack_pos;
            self.crcs.vals[i] = 0;

            if in_empty(i) {
                if let Some(empty_files) = empty_files {
                    if !bit_check(empty_files, empty_file_index) {
                        is_dir_mask |= mask;
                    }
                    empty_file_index += 1;
                } else {
                    is_dir_mask |= mask;
                }
                if rem_sub_streams == 0 {
                    self.file_to_folder[i] = u32::MAX;
                    i += 1;
                    mask >>= 1;
                    continue;
                }
            }

            if rem_sub_streams == 0 {
                loop {
                    if folder_index >= num_folders {
                        return Err(Error::Archive);
                    }
                    self.folder_to_file[folder_index] = i as u32;
                    num_sub_streams = 1;
                    if let Some(sd) = ssi.sd_num_sub_streams.as_mut() {
                        num_sub_streams = sd.read_number32()?;
                    }
                    rem_sub_streams = num_sub_streams;
                    if num_sub_streams != 0 {
                        break;
                    }
                    let folder_unpack_size = self.db.folder_unpack_size(folder_index);
                    unpack_pos = unpack_pos.wrapping_add(folder_unpack_size);
                    if unpack_pos < folder_unpack_size {
                        return Err(Error::Archive);
                    }
                    folder_index += 1;
                }
            }

            self.file_to_folder[i] = folder_index as u32;

            if in_empty(i) {
                i += 1;
                mask >>= 1;
                continue;
            }

            rem_sub_streams -= 1;
            if rem_sub_streams == 0 {
                let folder_unpack_size = self.db.folder_unpack_size(folder_index);
                let start_folder_unpack_pos =
                    self.unpack_positions[self.folder_to_file[folder_index] as usize];
                if folder_unpack_size < unpack_pos.wrapping_sub(start_folder_unpack_pos) {
                    return Err(Error::Archive);
                }
                unpack_pos = start_folder_unpack_pos.wrapping_add(folder_unpack_size);
                if unpack_pos < folder_unpack_size {
                    return Err(Error::Archive);
                }
                if num_sub_streams == 1 && self.db.folder_crcs.check(folder_index) {
                    self.crcs.vals[i] = self.db.folder_crcs.vals[folder_index];
                    crc_mask |= mask;
                }
                folder_index += 1;
            } else {
                let sizes = ssi.sd_sizes.as_mut().ok_or(Error::Archive)?;
                let v = sizes.read_number()?;
                unpack_pos = unpack_pos.wrapping_add(v);
                if unpack_pos < v {
                    return Err(Error::Archive);
                }
            }
            if crc_mask & mask == 0
                && let Some(vals) = digests_vals
            {
                if digests_defs.is_none_or(|d| bit_check(d, digest_index)) {
                    let (word, rest) = vals.split_first_chunk::<4>().ok_or(Error::Archive)?;
                    self.crcs.vals[i] = u32::from_le_bytes(*word);
                    digests_vals = Some(rest);
                    crc_mask |= mask;
                }
                digest_index += 1;
            }
            i += 1;
            mask >>= 1;
        }

        if mask != 0x80 {
            let byte_index = (i - 1) >> 3;
            self.is_dirs[byte_index] = is_dir_mask;
            if let Some(defs) = self.crcs.defs.as_mut() {
                defs[byte_index] = crc_mask;
            }
        }

        self.unpack_positions[i] = unpack_pos;

        if rem_sub_streams != 0 {
            return Err(Error::Archive);
        }

        loop {
            self.folder_to_file[folder_index] = i as u32;
            if folder_index >= num_folders {
                break;
            }
            let sd = ssi.sd_num_sub_streams.as_mut().ok_or(Error::Archive)?;
            num_sub_streams = sd.read_number32()?;
            if num_sub_streams != 0 {
                return Err(Error::Archive);
            }
            folder_index += 1;
        }

        if ssi.sd_num_sub_streams.is_some_and(|sd| sd.len() != 0) {
            return Err(Error::Archive);
        }
        Ok(())
    }

    /// `SzReadHeader`.
    fn read_header<R: Read + Seek>(
        &mut self,
        sd: &mut Sd<'_>,
        in_stream: &mut R,
        budget: &mut Budget,
    ) -> Result<()> {
        let mut temp_bufs = Vec::new();
        self.read_header2(sd, in_stream, &mut temp_bufs, budget)?;
        if sd.len() != 0 {
            return Err(Error::Archive);
        }
        Ok(())
    }

    /// `SzArEx_Open2`.
    fn open2<R: Read + Seek>(&mut self, in_stream: &mut R, budget: &mut Budget) -> Result<()> {
        let mut header = [0u8; START_HEADER_SIZE];
        read_exact(in_stream, &mut header, Error::NoArchive)?;
        let start_pos_after_header = in_stream.stream_position().map_err(|_| Error::Read)?;
        self.start_pos_after_header = start_pos_after_header;
        if header[..SIGNATURE_SIZE] != SIGNATURE {
            return Err(Error::NoArchive);
        }
        // k7zMajorVersion.
        if header[6] != 0 {
            return Err(Error::Unsupported);
        }
        let le32 = |at: usize| {
            u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        let le64 = |at: usize| u64::from(le32(at)) | (u64::from(le32(at + 4)) << 32);
        if crate::sevenz::crc(&header[12..32]) != le32(8) {
            return Err(Error::Crc);
        }

        let next_header_offset = le64(12);
        let next_header_size = le64(20);
        let next_header_crc = le32(28);

        self.db.range_limit = next_header_offset;
        if next_header_offset >= 1 << 62 || next_header_size >= 1 << 48 {
            return Err(Error::NoArchive);
        }
        if next_header_size > usize::MAX as u64 {
            return Err(Error::Mem);
        }
        if next_header_size == 0 {
            if next_header_offset != 0 || next_header_crc != 0 {
                return Err(Error::NoArchive);
            }
            return Ok(());
        }
        let end = in_stream.seek(SeekFrom::End(0)).map_err(|_| Error::Read)?;
        if end.wrapping_sub(start_pos_after_header) < next_header_offset + next_header_size {
            return Err(Error::InputEof);
        }
        seek_to(in_stream, start_pos_after_header + next_header_offset)?;

        let mut buf = budget.alloc::<u8>(next_header_size as usize)?;
        read_exact(in_stream, &mut buf, Error::InputEof)?;

        if crate::sevenz::crc(&buf) != next_header_crc {
            return Err(Error::Archive);
        }
        let mut sd = Sd::new(&buf);
        let mut ty = sd.read_id()?;
        let decoded;
        if ty == ID_ENCODED_HEADER {
            let mut temp_ar = Ar {
                range_limit: self.db.range_limit,
                ..Ar::default()
            };
            let mut bufs = read_and_decode_packed_streams(
                in_stream,
                &mut sd,
                1,
                self.start_pos_after_header,
                &mut temp_ar,
                budget,
            )?;
            decoded = bufs.swap_remove(0);
            sd = Sd::new(&decoded);
            ty = sd.read_id()?;
        }
        if ty == ID_HEADER {
            self.read_header(&mut sd, in_stream, budget)
        } else {
            Err(Error::Unsupported)
        }
    }
}

/// `LookInStream_Read2`: all of `buf`, or `eof` if the archive ends first.
pub(crate) fn read_exact<R: Read>(in_stream: &mut R, buf: &mut [u8], eof: Error) -> Result<()> {
    let mut at = 0;
    while at < buf.len() {
        match in_stream.read(&mut buf[at..]) {
            Ok(0) => return Err(eof),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Read),
        }
    }
    Ok(())
}

/// `SzArEx_Open`.
pub(crate) fn open<R: Read + Seek>(
    in_stream: &mut R,
    memory_limit: u64,
    decoding: Decoding,
) -> Result<(ArEx, Decoding)> {
    let mut p = ArEx::default();
    let mut budget = Budget::new(memory_limit, decoding);
    p.open2(in_stream, &mut budget)?;
    Ok((p, budget.decoding))
}
