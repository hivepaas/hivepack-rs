//! Where an AppImage's program ends: `appimage_get_elf_size` of the type 2
//! runtime's `runtime.c`, with `read_elf32` and `read_elf64`. The runtime
//! mounts the SquashFS image that starts there.

use std::io::{self, Read, Seek, SeekFrom};

use super::Error;

/// `EI_NIDENT`: the bytes of `e_ident`.
pub const EI_NIDENT: usize = 16;
/// `EI_CLASS`: where `e_ident` says 32 or 64 bits.
const EI_CLASS: usize = 4;
/// `EI_DATA`: where `e_ident` says the byte order.
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

/// `sizeof(Elf32_Ehdr)` and `sizeof(Elf64_Ehdr)`.
const EHDR32_SIZE: usize = 52;
const EHDR64_SIZE: usize = 64;
/// `sizeof(Elf32_Shdr)` and `sizeof(Elf64_Shdr)`.
const SHDR32_SIZE: usize = 40;
const SHDR64_SIZE: usize = 64;

/// The file's byte order, as `e_ident[EI_DATA]` gives it: the runtime's
/// `file16_to_cpu`, `file32_to_cpu` and `file64_to_cpu` read the file's
/// numbers in it.
#[derive(Clone, Copy)]
struct Order {
    big: bool,
}

impl Order {
    fn u16(self, b: &[u8], at: usize) -> u16 {
        let v = [b[at], b[at + 1]];
        if self.big {
            u16::from_be_bytes(v)
        } else {
            u16::from_le_bytes(v)
        }
    }

    fn u32(self, b: &[u8], at: usize) -> u32 {
        let v = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if self.big {
            u32::from_be_bytes(v)
        } else {
            u32::from_le_bytes(v)
        }
    }

    fn u64(self, b: &[u8], at: usize) -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[at..at + 8]);
        if self.big {
            u64::from_be_bytes(v)
        } else {
            u64::from_le_bytes(v)
        }
    }
}

/// `fread` of `buf.len()` bytes at `pos`: whether all were read.
fn read_at<R: Read + Seek>(r: &mut R, pos: u64, buf: &mut [u8]) -> Result<bool, Error> {
    r.seek(SeekFrom::Start(pos))?;
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return Ok(false),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(true)
}

/// The end of the section header table (`sht_end`), and where the last
/// section header is (`last_shdr_offset`).
///
/// Differs from the runtime: the arithmetic is checked. The runtime's is
/// `off_t`'s, where an `e_shnum` of 0 puts the last section header one
/// entry before the table, and offsets past 2^63 wrap.
fn table(shoff: u64, shentsize: u16, shnum: u16) -> Result<(u64, u64), Error> {
    if shnum == 0 {
        return Err(Error::Elf("no section headers"));
    }
    let entsize = u64::from(shentsize);
    let last = shoff
        .checked_add(entsize * u64::from(shnum - 1))
        .ok_or(Error::Elf("section headers past the largest offset"))?;
    let end = shoff
        .checked_add(entsize * u64::from(shnum))
        .ok_or(Error::Elf("section headers past the largest offset"))?;
    Ok((end, last))
}

/// `read_elf32`: the end of a 32-bit ELF file, the end of its section
/// header table or of its last section, whichever is later.
///
/// Differs from the runtime: the last section's offset and size are read
/// as the 32-bit numbers they are; the runtime swaps them as 64-bit ones
/// (`file64_to_cpu`), which, for a file of the other byte order than the
/// machine's, puts them past 2^32.
fn read_elf32<R: Read + Seek>(r: &mut R, order: Order) -> Result<u64, Error> {
    let mut ehdr32 = [0u8; EHDR32_SIZE];
    if !read_at(r, 0, &mut ehdr32)? {
        return Err(Error::Elf("Read of ELF header failed"));
    }
    let e_shoff = u64::from(order.u32(&ehdr32, 32));
    let e_shentsize = order.u16(&ehdr32, 46);
    let e_shnum = order.u16(&ehdr32, 48);

    let (sht_end, last_shdr_offset) = table(e_shoff, e_shentsize, e_shnum)?;
    let mut shdr32 = [0u8; SHDR32_SIZE];
    if !read_at(r, last_shdr_offset, &mut shdr32)? {
        return Err(Error::Elf("Read of ELF section header failed"));
    }
    // ELF ends either with the table of section headers (SHT) or with a
    // section.
    let last_section_end = u64::from(order.u32(&shdr32, 16)) + u64::from(order.u32(&shdr32, 20));
    Ok(sht_end.max(last_section_end))
}

/// `read_elf64`: the end of a 64-bit ELF file, the end of its section
/// header table or of its last section, whichever is later.
fn read_elf64<R: Read + Seek>(r: &mut R, order: Order) -> Result<u64, Error> {
    let mut ehdr64 = [0u8; EHDR64_SIZE];
    if !read_at(r, 0, &mut ehdr64)? {
        return Err(Error::Elf("Read of ELF header failed"));
    }
    let e_shoff = order.u64(&ehdr64, 40);
    let e_shentsize = order.u16(&ehdr64, 58);
    let e_shnum = order.u16(&ehdr64, 60);

    let (sht_end, last_shdr_offset) = table(e_shoff, e_shentsize, e_shnum)?;
    let mut shdr64 = [0u8; SHDR64_SIZE];
    if !read_at(r, last_shdr_offset, &mut shdr64)? {
        return Err(Error::Elf("Read of ELF section header failed"));
    }
    // ELF ends either with the table of section headers (SHT) or with a
    // section.
    let last_section_end = order
        .u64(&shdr64, 24)
        .checked_add(order.u64(&shdr64, 32))
        .ok_or(Error::Elf("a section past the largest offset"))?;
    Ok(sht_end.max(last_section_end))
}

/// `appimage_get_elf_size`: where the ELF program at the start of `r` ends,
/// by its header and its last section header.
pub fn appimage_get_elf_size<R: Read + Seek>(r: &mut R) -> Result<u64, Error> {
    let mut e_ident = [0u8; EI_NIDENT];
    if !read_at(r, 0, &mut e_ident)? {
        return Err(Error::Elf("Read of e_ident failed"));
    }
    let order = match e_ident[EI_DATA] {
        ELFDATA2LSB => Order { big: false },
        ELFDATA2MSB => Order { big: true },
        _ => return Err(Error::Elf("Unknown ELF data order")),
    };
    match e_ident[EI_CLASS] {
        ELFCLASS32 => read_elf32(r, order),
        ELFCLASS64 => read_elf64(r, order),
        _ => Err(Error::Elf("Unknown ELF class")),
    }
}
