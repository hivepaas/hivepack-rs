// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! A header's bytes, read from the archive and taken apart: UnRAR's
//! `RawRead` (rawread.cpp). Reads past what was read give zeroes, as in
//! UnRAR, never a panic.

use std::io;

use crate::deflate::crc32;

use crate::rar::archive::Archive;
use crate::rar::crypt::CryptData;
use crate::rar::source::ReadAt;

/// The bytes of one header, and how far they are taken apart.
#[derive(Debug, Default)]
pub(crate) struct RawRead {
    data: Vec<u8>,
    /// How many of `data` were read: the rest is room a short read left.
    data_size: usize,
    read_pos: usize,
    /// What the header's bytes are encrypted with, if they are.
    crypt: Option<CryptData>,
}

impl RawRead {
    pub(crate) fn new() -> RawRead {
        RawRead::default()
    }

    /// `RawRead::SetCrypt`.
    pub(crate) fn set_crypt(&mut self, crypt: CryptData) {
        self.crypt = Some(crypt);
    }

    /// Reads `size` more bytes from `src`: the number read, fewer at the
    /// end of the archive. Encrypted, whole blocks are read, and what they
    /// hold past `size` is there for the next read.
    pub(crate) fn read<R: ReadAt>(
        &mut self,
        src: &mut Archive<R>,
        size: usize,
    ) -> io::Result<usize> {
        if let Some(crypt) = &mut self.crypt {
            let full_size = self.data.len();
            let data_left = full_size - self.data_size;
            if size <= data_left {
                self.data_size += size;
                return Ok(size);
            }
            let size_to_read = size - data_left;
            let aligned = size_to_read + (size_to_read.wrapping_neg() & 15);
            self.data.resize(full_size + aligned, 0);
            let read = src.read(&mut self.data[full_size..])?;
            crypt.decrypt_block(&mut self.data[full_size..], aligned);
            if read != 0 {
                self.data_size += size;
            }
            return Ok(read);
        }
        if size == 0 {
            return Ok(0);
        }
        self.data.resize(self.data.len() + size, 0);
        let read = src.read(&mut self.data[self.data_size..self.data_size + size])?;
        self.data_size += read;
        Ok(read)
    }

    /// Takes `bytes` as read: UnRAR's `RawRead::Read(byte*, size_t)`.
    pub(crate) fn read_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.data.resize(self.data.len() + bytes.len(), 0);
        self.data[self.data_size..self.data_size + bytes.len()].copy_from_slice(bytes);
        self.data_size += bytes.len();
    }

    pub(crate) fn get1(&mut self) -> u8 {
        if self.read_pos < self.data_size {
            self.read_pos += 1;
            self.data[self.read_pos - 1]
        } else {
            0
        }
    }

    pub(crate) fn get2(&mut self) -> u16 {
        if self.read_pos + 1 < self.data_size {
            let value =
                u16::from_le_bytes([self.data[self.read_pos], self.data[self.read_pos + 1]]);
            self.read_pos += 2;
            value
        } else {
            0
        }
    }

    pub(crate) fn get4(&mut self) -> u32 {
        if self.read_pos + 3 < self.data_size {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.data[self.read_pos..self.read_pos + 4]);
            self.read_pos += 4;
            u32::from_le_bytes(bytes)
        } else {
            0
        }
    }

    pub(crate) fn get8(&mut self) -> u64 {
        let low = self.get4();
        let high = self.get4();
        (u64::from(high) << 32) | u64::from(low)
    }

    /// A variable length integer, seven bits a byte, or 0 if it runs past
    /// what was read.
    pub(crate) fn get_v(&mut self) -> u64 {
        let mut result: u64 = 0;
        let mut shift = 0;
        while self.read_pos < self.data_size && shift < 64 {
            let byte = self.data[self.read_pos];
            self.read_pos += 1;
            result = result.wrapping_add(u64::from(byte & 0x7f) << shift);
            if byte & 0x80 == 0 {
                return result;
            }
            shift += 7;
        }
        0
    }

    /// How many bytes the variable length integer at `pos` takes, or 0 if
    /// it runs past what was read.
    pub(crate) fn get_v_size(&self, pos: usize) -> usize {
        (pos..self.data_size)
            .find(|&i| self.data[i] & 0x80 == 0)
            .map_or(0, |i| i - pos + 1)
    }

    /// Copies `field.len()` bytes, zeroes past what was read: how many were
    /// there.
    pub(crate) fn get_b(&mut self, field: &mut [u8]) -> usize {
        let copy = self
            .data_size
            .saturating_sub(self.read_pos)
            .min(field.len());
        field[..copy].copy_from_slice(&self.data[self.read_pos..self.read_pos + copy]);
        field[copy..].fill(0);
        self.read_pos += copy;
        copy
    }

    /// RAR 1.5 to 4.x's header CRC: the low 16 bits of the CRC-32 of the
    /// header after its CRC field, all of it or what was taken apart.
    pub(crate) fn get_crc15(&self, processed_only: bool) -> u32 {
        if self.data_size <= 2 {
            return 0;
        }
        let end = if processed_only {
            self.read_pos
        } else {
            self.data_size
        };
        crc32(0, self.data.get(2..end).unwrap_or(&[])) & 0xffff
    }

    /// RAR 5's header CRC: the CRC-32 of the header after its CRC field.
    pub(crate) fn get_crc50(&self) -> u32 {
        if self.data_size <= 4 {
            return 0xffff_ffff;
        }
        crc32(0, &self.data[4..self.data_size])
    }

    pub(crate) fn size(&self) -> usize {
        self.data_size
    }

    pub(crate) fn data_left(&self) -> usize {
        self.data_size.saturating_sub(self.read_pos)
    }

    pub(crate) fn get_pos(&self) -> usize {
        self.read_pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.read_pos = pos;
    }
}
