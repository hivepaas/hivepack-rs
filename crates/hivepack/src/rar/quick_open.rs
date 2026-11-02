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

//! A RAR 5 archive's QuickOpen record: UnRAR's `QuickOpen` (qopen.cpp).
//!
//! The record holds copies of headers, with where they belong, and while it
//! is loaded every read of the archive at such a place gets the copy and not
//! what is there. The file's own position goes its own way meanwhile, and
//! both are kept, as what happens when the record fails depends on them.

use crate::rar::archive::Archive;
use crate::rar::crypt::{CryptData, set_crypt_keys};
use crate::rar::error::{Error, ExitCode};
use crate::rar::headers::*;
use crate::rar::raw::RawRead;
use crate::rar::source::{Cursor, ReadAt};

/// `CRYPT_BLOCK_MASK`.
const CRYPT_BLOCK_MASK: usize = CRYPT_BLOCK_SIZE - 1;
/// `MaxBufSize`.
const MAX_BUF_SIZE: usize = 0x10000;
/// `MAX_HEADER_SIZE_RAR5`.
const MAX_HEADER_SIZE_RAR5: u64 = 0x20_0000;

/// `QuickOpen`, for reading. Only `loaded` starts it again: the rest stays as
/// it was until the record is loaded.
#[derive(Default)]
pub(crate) struct QuickOpen {
    pub(crate) loaded: bool,
    buf: Vec<u8>,
    /// Nothing until keys are set, which decrypts nothing, as `CRYPT_NONE`.
    crypt: Option<CryptData>,
    qo_header_pos: u64,
    raw_data_start: u64,
    raw_data_size: u64,
    raw_data_pos: u64,
    read_buf_size: usize,
    read_buf_pos: usize,
    last_read_header: Vec<u8>,
    last_read_header_pos: u64,
    pub(crate) seek_pos: u64,
    /// `seek_pos` is not where the file is.
    unsync_seek_pos: bool,
}

impl<R: ReadAt> Archive<R> {
    /// `QuickOpen::Load` the first time: finds the record at `block_pos`.
    /// Reading its header here cannot start another, and what it leaves in
    /// the headers stays, as in UnRAR.
    pub(crate) fn qopen_load(&mut self, block_pos: u64) -> Result<(), Error> {
        let save_pos = self.tell();
        self.qopen.seek_pos = save_pos;
        self.qopen.unsync_seek_pos = false;
        // Too far for `lseek`, which `File::Seek` takes as a fatal error.
        if block_pos > i64::MAX as u64 {
            self.set_error_code(ExitCode::Fatal);
            return Err(Error::BadSeek {
                exit_code: self.exit_code(),
            });
        }
        self.seek(block_pos);
        self.prohibit_qopen = true;
        let read_size = self.read_header()?;
        self.prohibit_qopen = false;

        if read_size == 0
            || self.cur_header_type != HEAD_SERVICE
            || !self.sub_head.is_named(SUBHEAD_TYPE_QOPEN)
        {
            self.seek(save_pos);
            return Ok(());
        }
        self.qopen.qo_header_pos = self.cur_block_pos as u64;
        self.qopen.raw_data_start = self.tell();
        self.qopen.raw_data_size = self.sub_head.unp_size as u64;
        self.seek(save_pos);
        self.qopen.loaded = true;
        self.qopen_start();
        Ok(())
    }

    /// The rest of `QuickOpen::Load`, also for going back to the record's
    /// start. The service header it goes by is the last one read, which need
    /// no longer be the record's.
    fn qopen_start(&mut self) {
        if self.sub_head.encrypted {
            if !self.password.is_set() {
                self.qopen.loaded = false;
                return;
            }
            // Keys that cannot be made leave those there were.
            let keys = set_crypt_keys(
                CryptMethod::Rar50,
                &self.password,
                &mut self.kdf_cache,
                Some(&self.sub_head.salt[..]),
                &self.sub_head.init_v,
                self.sub_head.lg2_count,
            );
            if let Some((crypt, checks)) = keys {
                self.qopen.crypt = Some(crypt);
                self.sub_head.psw_check = checks.psw_check;
            }
        }
        let q = &mut self.qopen;
        q.raw_data_pos = 0;
        q.read_buf_size = 0;
        q.read_buf_pos = 0;
        q.last_read_header.clear();
        q.last_read_header_pos = 0;
        if q.buf.is_empty() {
            q.buf = vec![0; MAX_BUF_SIZE];
        }
        self.qopen_read_buffer();
    }

    /// `QuickOpen::Read`, with `Archive::Read`'s `File::Read` for when it
    /// says false: nothing, then.
    pub(crate) fn qopen_read(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        if !self.qopen.loaded {
            return Ok(None);
        }
        // Find the next suitable copy.
        while self
            .qopen
            .last_read_header_pos
            .wrapping_add(self.qopen.last_read_header.len() as u64)
            <= self.qopen.seek_pos
        {
            if !self.qopen_read_next() {
                break;
            }
        }
        let q = &mut self.qopen;
        if !q.loaded {
            // Something went wrong: the file must be where it should be.
            if q.unsync_seek_pos {
                self.pos = q.seek_pos;
            }
            return Ok(None);
        }

        let size = buf.len() as u64;
        let last_end = q
            .last_read_header_pos
            .wrapping_add(q.last_read_header.len() as u64);
        if q.seek_pos >= q.last_read_header_pos && q.seek_pos.wrapping_add(size) <= last_end {
            let at = (q.seek_pos - q.last_read_header_pos) as usize;
            buf.copy_from_slice(&q.last_read_header[at..at + buf.len()]);
            q.seek_pos = q.seek_pos.wrapping_add(size);
            q.unsync_seek_pos = true;
            return Ok(Some(buf.len()));
        }
        if q.unsync_seek_pos {
            self.pos = q.seek_pos;
            q.unsync_seek_pos = false;
        }
        let read = Cursor {
            src: &self.src,
            pos: &mut self.pos,
        }
        .read(buf)?;
        self.qopen.seek_pos = self.qopen.seek_pos.wrapping_add(read as u64);
        Ok(Some(read))
    }

    /// `QuickOpen::Seek` with `SEEK_SET`, when the record is loaded. Going
    /// back before the copy at hand reads the record from its start.
    pub(crate) fn qopen_seek(&mut self, offset: u64) {
        if offset < self.qopen.seek_pos && offset < self.qopen.last_read_header_pos {
            self.qopen_start();
        }
        self.qopen.seek_pos = offset;
        self.qopen.unsync_seek_pos = true;
    }

    /// `QuickOpen::Seek` with `SEEK_END`, when the record is loaded.
    pub(crate) fn qopen_seek_end(&mut self, length: u64) {
        self.pos = length;
        self.qopen.seek_pos = length;
        self.qopen.unsync_seek_pos = false;
    }

    /// `QuickOpen::ReadBuffer`. A read that fails gives nothing, there.
    fn qopen_read_buffer(&mut self) -> usize {
        let save_pos = self.tell();
        let encrypted = self.sub_head.encrypted;
        let q = &mut self.qopen;
        self.pos = q.raw_data_start.wrapping_add(q.raw_data_pos);
        let room = (MAX_BUF_SIZE - q.read_buf_size) as u64;
        let mut size_to_read = q.raw_data_size.wrapping_sub(q.raw_data_pos).min(room) as usize;
        if encrypted {
            size_to_read &= !CRYPT_BLOCK_MASK;
        }
        let mut read = 0;
        if size_to_read != 0 {
            let start = q.read_buf_size;
            read = Cursor {
                src: &self.src,
                pos: &mut self.pos,
            }
            .read(&mut q.buf[start..start + size_to_read])
            .unwrap_or(0);
            if read != 0 {
                if encrypted && let Some(crypt) = &mut q.crypt {
                    let whole = read & !CRYPT_BLOCK_MASK;
                    crypt.decrypt_block(&mut q.buf[start..start + whole], whole);
                }
                q.raw_data_pos += read as u64;
                q.read_buf_size += read;
            }
        }
        self.seek(save_pos);
        read
    }

    /// `QuickOpen::ReadRaw`: a block of the record, whether its CRC is right.
    fn qopen_read_raw(&mut self, raw: &mut RawRead) -> bool {
        if MAX_BUF_SIZE - self.qopen.read_buf_pos < 0x100 {
            // Near the end of the buffer: enough for the CRC and the size.
            let q = &mut self.qopen;
            let data_left = q.read_buf_size - q.read_buf_pos;
            q.buf.copy_within(q.read_buf_pos..q.read_buf_size, 0);
            q.read_buf_pos = 0;
            q.read_buf_size = data_left;
            self.qopen_read_buffer();
        }
        const FIRST_READ_SIZE: usize = 7;
        let q = &mut self.qopen;
        if q.read_buf_pos + FIRST_READ_SIZE > q.read_buf_size {
            return false;
        }
        raw.read_bytes(&q.buf[q.read_buf_pos..q.read_buf_pos + FIRST_READ_SIZE]);
        q.read_buf_pos += FIRST_READ_SIZE;

        let saved_crc = raw.get4();
        let size_bytes = raw.get_v_size(4);
        let block_size = raw.get_v();
        // UnRAR keeps this in `int`.
        let mut size_to_read =
            (block_size as i32).wrapping_sub((FIRST_READ_SIZE - size_bytes - 4) as i32);
        if size_to_read < 0 || size_bytes == 0 || block_size == 0 {
            q.loaded = false;
            return false;
        }

        // What is left of the block may cross the end of the buffer.
        while size_to_read > 0 {
            let q = &mut self.qopen;
            let data_left = q.read_buf_size - q.read_buf_pos;
            let cur_size = data_left.min(size_to_read as usize);
            raw.read_bytes(&q.buf[q.read_buf_pos..q.read_buf_pos + cur_size]);
            q.read_buf_pos += cur_size;
            size_to_read -= cur_size as i32;
            if size_to_read > 0 {
                q.read_buf_pos = 0;
                q.read_buf_size = 0;
                if self.qopen_read_buffer() == 0 {
                    return false;
                }
            }
        }
        saved_crc == raw.get_crc50()
    }

    /// `QuickOpen::ReadNext`: the next copy of a header.
    fn qopen_read_next(&mut self) -> bool {
        let mut raw = RawRead::new();
        if !self.qopen_read_raw(&mut raw) {
            return false;
        }
        let _flags = raw.get_v();
        let offset = raw.get_v();
        let header_size = raw.get_v();
        if header_size > MAX_HEADER_SIZE_RAR5 {
            return false;
        }
        let q = &mut self.qopen;
        q.last_read_header.resize(header_size as usize, 0);
        raw.get_b(&mut q.last_read_header);
        // Where it belongs, counted back from the record's header.
        q.last_read_header_pos = q.qo_header_pos.wrapping_sub(offset);
        true
    }
}
