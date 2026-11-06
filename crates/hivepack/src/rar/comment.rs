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

//! An archive's comment: UnRAR's `Archive::GetComment` (arccmt.cpp) and
//! `ReadSubData` (arcread.cpp).

use crate::rar::archive::Archive;
use crate::rar::crypt::{CryptData, set_crypt_keys};
use crate::rar::error::{Error, ExitCode};
use crate::rar::extract::{DataIo, unstore_file};
use crate::rar::hash::DataHash;
use crate::rar::headers::*;
use crate::rar::name::{char_to_wide, utf_to_wide};
use crate::rar::source::ReadAt;
use crate::rar::unpack::Unpack;

/// `MAXCMTSIZE`.
const MAX_CMT_SIZE: usize = 0x40000;
/// `VER_UNPACK`.
const VER_UNPACK: u32 = 29;
/// `VER_UNPACK7`.
const VER_UNPACK7: u32 = 70;

/// A C string's bytes.
fn up_to_zero(data: &[u8]) -> &[u8] {
    data.iter()
        .position(|&b| b == 0)
        .map_or(data, |end| &data[..end])
}

impl<R: ReadAt> Archive<R> {
    /// `Archive::GetComment`: the archive's comment, in the characters names
    /// have, if it has one and it is not broken. The position stays, and the
    /// last header read is another, so this is for before the first entry,
    /// where UnRAR does it.
    ///
    /// # Errors
    ///
    /// [`Error::NoMemory`] for a comment's dictionary, [`Error::MissingPassword`]
    /// where its headers need one, and [`Error::Io`].
    pub fn get_comment(&mut self) -> Result<Option<WideString>, Error> {
        if !self.main_comment {
            return Ok(None);
        }
        let save_pos = self.tell_pos();
        let comment = self.do_get_comment();
        self.seek(save_pos);
        comment
    }

    /// `Archive::DoGetComment`.
    fn do_get_comment(&mut self) -> Result<Option<WideString>, Error> {
        let mut cmt_length;
        if self.format == Format::Rar14 {
            self.seek(self.sfx_size + SIZEOF_MAINHEAD14 as u64);
            cmt_length = u32::from(self.next_byte()?);
            cmt_length += u32::from(self.next_byte()?) << 8;
        } else {
            if !self.main_head.comment_in_header {
                self.seek(self.start_pos());
                if self.search_sub_block(SUBHEAD_TYPE_CMT)? != 0 {
                    return self.read_comment_data();
                }
                return Ok(None);
            }
            // Old style (RAR 2.9): embedded into the main header.
            self.seek(self.sfx_size + (SIZEOF_MARKHEAD3 + SIZEOF_MAINHEAD3) as u64);
            if self.read_header()? == 0 || self.cur_header_type != HEAD3_CMT {
                return Ok(None);
            }
            if self.broken_header || (self.comm_head.base.head_size as usize) < SIZEOF_COMMHEAD {
                return Ok(None);
            }
            cmt_length = self.comm_head.base.head_size - SIZEOF_COMMHEAD as u32;
        }

        let comment = if self.format == Format::Rar14 && self.main_head.pack_comment
            || self.format != Format::Rar14 && self.comm_head.method != 0x30
        {
            let mut decrypt = None;
            let mut unp_ver = u32::from(self.comm_head.unp_ver);
            let unp_cmt_length;
            if self.format == Format::Rar14 {
                let mut length = u32::from(self.next_byte()?);
                length += u32::from(self.next_byte()?) << 8;
                unp_cmt_length = length;
                if cmt_length < 2 {
                    return Ok(None);
                }
                cmt_length -= 2;
                decrypt = Some(CryptData::cmt13());
                unp_ver = 15;
            } else {
                if !(15..=VER_UNPACK).contains(&unp_ver) || self.comm_head.method > 0x35 {
                    return Ok(None);
                }
                unp_cmt_length = u32::from(self.comm_head.unp_size);
            }
            let mut hash = DataHash::new(HashType::Crc32);
            // `GetUnpackedData`: what was written the last time.
            let mut last = Vec::new();
            let mut written = 0;
            let mut unpack = Unpack::new();
            unpack.init(0x10000, false)?;
            unpack.set_dest_size(i64::from(unp_cmt_length));
            let mut out = |data: &[u8]| {
                last.clear();
                last.extend_from_slice(data);
                Ok(())
            };
            let mut io = DataIo {
                arc: &mut *self,
                packed_left: i64::from(cmt_length),
                hash: &mut hash,
                out: &mut out,
                skip_unp_crc: false,
                cur_unp_write: &mut written,
                decrypt,
                unp_volume: false,
                next_volume_missing: false,
                ahead: None,
            };
            unpack.do_unpack(unp_ver, false, &mut io)?;
            if self.format != Format::Rar14
                && hash.result().crc32 & 0xffff != u32::from(self.comm_head.comm_crc)
            {
                return Ok(None);
            }
            if !last.is_empty() && last.len() <= MAX_CMT_SIZE {
                char_to_wide(up_to_zero(&last))
            } else {
                WideString::new()
            }
        } else {
            if cmt_length == 0 || cmt_length as usize > MAX_CMT_SIZE {
                return Ok(None);
            }
            let mut cmt_raw = vec![0; cmt_length as usize];
            let read = self.read(&mut cmt_raw)?;
            cmt_raw.truncate(read);
            if self.format != Format::Rar14 {
                let mut hash = DataHash::new(HashType::Crc32);
                hash.update(&cmt_raw);
                if u32::from(self.comm_head.comm_crc) != hash.result().crc32 & 0xffff {
                    return Ok(None);
                }
            }
            char_to_wide(up_to_zero(&cmt_raw))
        };
        Ok((!comment.is_empty()).then_some(comment))
    }

    /// `Archive::ReadCommentData`.
    fn read_comment_data(&mut self) -> Result<Option<WideString>, Error> {
        let Some(mut cmt_raw) = self.read_sub_data()? else {
            return Ok(None);
        };
        cmt_raw.push(0);
        Ok(Some(if self.format == Format::Rar50 {
            utf_to_wide(up_to_zero(&cmt_raw))
        } else if self.sub_head.file_attr & SUBHEAD_FLAGS_CMT_UNICODE != 0 {
            // `RawToWide`, which keeps the zero it stops at.
            let mut wide = WideString::new();
            for pair in cmt_raw.as_chunks::<2>().0 {
                let c = u32::from(pair[0]) + (u32::from(pair[1]) << 8);
                wide.push(c);
                if c == 0 {
                    break;
                }
            }
            wide
        } else {
            char_to_wide(up_to_zero(&cmt_raw))
        }))
    }

    /// `Archive::ReadSubData`, into memory: nothing if it cannot be read.
    fn read_sub_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.broken_header {
            self.set_error_code(ExitCode::Crc);
            return Ok(None);
        }
        let max_ver = if self.format == Format::Rar50 {
            VER_UNPACK7
        } else {
            VER_UNPACK
        };
        if self.sub_head.method > 5 || self.sub_head.unp_ver > max_ver {
            return Ok(None);
        }
        if self.sub_head.pack_size == 0 && !self.sub_head.split_after {
            return Ok(Some(Vec::new()));
        }

        let mut unpack = Unpack::new();
        unpack.init(self.sub_head.win_size, false)?;

        // No more than this, read to memory.
        if self.sub_head.unp_size < 0 || self.sub_head.unp_size > 0x100_0000 {
            return Ok(None);
        }
        let mut data = vec![0; self.sub_head.unp_size as usize];

        let mut decrypt = None;
        let mut hash_key = None;
        if self.sub_head.encrypted {
            if !self.password.is_set() {
                return Ok(None);
            }
            let keys = set_crypt_keys(
                self.sub_head.crypt_method,
                &self.password,
                &mut self.kdf_cache,
                self.sub_head.salt_set.then_some(&self.sub_head.salt[..]),
                &self.sub_head.init_v,
                self.sub_head.lg2_count,
            );
            if let Some((crypt, checks)) = keys {
                decrypt = Some(crypt);
                hash_key = Some(checks.hash_key);
            }
        }

        let mut hash = DataHash::new(self.sub_head.file_hash.kind);
        let (method, unp_ver, unp_size, pack_size, split_after) = (
            self.sub_head.method,
            self.sub_head.unp_ver,
            self.sub_head.unp_size,
            self.sub_head.pack_size,
            self.sub_head.split_after,
        );
        unpack.set_dest_size(unp_size);
        {
            // `UnpWrite` to memory: a piece that does not fit is left out.
            let mut at = 0;
            let mut out = |piece: &[u8]| {
                if piece.len() <= data.len() - at {
                    data[at..at + piece.len()].copy_from_slice(piece);
                    at += piece.len();
                }
                Ok(())
            };
            let mut written = 0;
            let mut io = DataIo {
                arc: &mut *self,
                packed_left: pack_size,
                hash: &mut hash,
                out: &mut out,
                skip_unp_crc: false,
                cur_unp_write: &mut written,
                decrypt,
                unp_volume: split_after,
                next_volume_missing: false,
                ahead: None,
            };
            if method == 0 {
                unstore_file(&mut io, unp_size as u64)?;
            } else {
                unpack.do_unpack(unp_ver, false, &mut io)?;
            }
        }

        let key = hash_key.filter(|_| self.sub_head.use_hash_key);
        let valid = match &key {
            Some(key) => hash.matches_keyed(&self.sub_head.file_hash, key),
            None => hash.matches(&self.sub_head.file_hash),
        };
        if !valid {
            self.set_error_code(ExitCode::Crc);
            return Ok(None);
        }
        Ok(Some(data))
    }
}
