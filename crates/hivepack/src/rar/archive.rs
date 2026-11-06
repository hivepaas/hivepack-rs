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

//! An archive and its headers, read in order: UnRAR's `Archive`
//! (archive.cpp, arcread.cpp).

use std::io;

use crate::crypto::Sha256;

use crate::rar::crypt::{KdfCache, Password, set_crypt_keys};
use crate::rar::error::{Error, ExitCode};
use crate::rar::headers::*;
use crate::rar::name::next_volume_name;
use crate::rar::name::{
    arc_char_to_wide, char_to_wide, convert_file_header, decode_encoded, utf_to_wide,
};
use crate::rar::quick_open::QuickOpen;
use crate::rar::raw::RawRead;
use crate::rar::source::{Cursor, ReadAt};
use crate::rar::time::RarTime;

/// `SafeAdd`: `a + b`, or `fallback` if either is negative or the sum
/// overflows.
fn safe_add(a: i64, b: i64, fallback: i64) -> i64 {
    if a >= 0 && b >= 0 && a <= i64::MAX - b {
        a + b
    } else {
        fallback
    }
}

/// How a next volume is got, by its name.
type OpenVolume<R> = Box<dyn FnMut(&str) -> Option<R>>;

/// A RAR archive being read, header by header, as UnRAR's `Archive` reads
/// it: [`open`](Archive::open) finds the signature and the main header,
/// then [`read_header`](Archive::read_header) reads the next header and
/// [`seek_to_next`](Archive::seek_to_next) moves past its data.
pub struct Archive<R> {
    pub(crate) src: R,
    /// Where the file is: `File::Tell`, which `tell` is unless a QuickOpen
    /// record is loaded.
    pub(crate) pos: u64,

    pub format: Format,
    pub solid: bool,
    pub volume: bool,
    pub main_comment: bool,
    pub locked: bool,
    pub signed: bool,
    pub first_volume: bool,
    pub new_numbering: bool,
    pub protected: bool,
    pub encrypted: bool,
    pub failed_header_decryption: bool,
    pub broken_header: bool,
    /// Where the archive starts, after a self-extracting module.
    pub sfx_size: u64,
    pub cur_block_pos: i64,
    pub next_block_pos: i64,
    pub cur_header_type: u32,
    pub vol_number: u32,
    pub recovery_percent: i32,

    pub mark_head: MarkHeader,
    pub short_block: BaseBlock,
    pub main_head: MainHeader,
    pub file_head: FileHeader,
    pub sub_head: FileHeader,
    pub end_arc_head: EndArcHeader,
    pub crypt_head: CryptHeader,
    pub comm_head: CommentHeader,
    pub protect_head: ProtectHeader,
    pub sub_block_head: SubBlockHeader,

    /// Archives with encrypted headers are opened without asking for the
    /// password, as UnRAR's library opens them without a callback.
    silent_open: bool,
    exit_code: ExitCode,
    /// `Cmd->Password`.
    pub(crate) password: Password,
    /// `FileName`, and how to get what is called something else: without it,
    /// no next volume can be found.
    name: String,
    open_volume: Option<OpenVolume<R>>,
    /// Where the derivations of keys are kept, for the headers and the data.
    pub(crate) kdf_cache: KdfCache,
    pub(crate) qopen: QuickOpen,
    pub(crate) prohibit_qopen: bool,
}

impl<R: ReadAt> Archive<R> {
    /// Opens an archive: finds its signature, at the start or after a
    /// self-extracting module, and reads up to its main header (`Open`,
    /// then `IsArchive`). `enable_broken` reads on past a broken main
    /// header, as UnRAR's `IsArchive(true)` does.
    pub fn open(src: R, enable_broken: bool) -> Result<Archive<R>, Error> {
        Archive::open_with(src, enable_broken, None)
    }

    /// [`Archive::open`] for an archive that may be encrypted. A password of
    /// nothing is no password, as for UnRAR. Only the first 127 characters
    /// count, as RAR itself takes no more.
    pub fn open_with_password(
        src: R,
        enable_broken: bool,
        password: &str,
    ) -> Result<Archive<R>, Error> {
        Archive::open_with(src, enable_broken, Some(password))
    }

    /// [`Archive::open_with_password`] for a volume of many, called `name`. A
    /// next volume's name comes from it as UnRAR makes it, the path included,
    /// and `open` is asked for it: nothing, if there is none.
    pub fn open_volumes(
        src: R,
        name: &str,
        open: impl FnMut(&str) -> Option<R> + 'static,
        enable_broken: bool,
        password: &str,
    ) -> Result<Archive<R>, Error> {
        Archive::open_with_volumes(
            src,
            enable_broken,
            Some(password),
            name.to_string(),
            Some(Box::new(open)),
        )
    }

    fn open_with(src: R, enable_broken: bool, password: Option<&str>) -> Result<Archive<R>, Error> {
        Archive::open_with_volumes(src, enable_broken, password, String::new(), None)
    }

    fn open_with_volumes(
        src: R,
        enable_broken: bool,
        password: Option<&str>,
        name: String,
        open_volume: Option<OpenVolume<R>>,
    ) -> Result<Archive<R>, Error> {
        let mut archive = Archive {
            src,
            pos: 0,
            format: Format::None,
            solid: false,
            volume: false,
            main_comment: false,
            locked: false,
            signed: false,
            first_volume: false,
            new_numbering: false,
            protected: false,
            encrypted: false,
            failed_header_decryption: false,
            broken_header: false,
            sfx_size: 0,
            cur_block_pos: 0,
            next_block_pos: 0,
            cur_header_type: HEAD_UNKNOWN,
            vol_number: 0,
            recovery_percent: -1,
            mark_head: MarkHeader::default(),
            short_block: BaseBlock::default(),
            main_head: MainHeader::default(),
            file_head: FileHeader::default(),
            sub_head: FileHeader::default(),
            end_arc_head: EndArcHeader::default(),
            crypt_head: CryptHeader::default(),
            comm_head: CommentHeader::default(),
            protect_head: ProtectHeader::default(),
            sub_block_head: SubBlockHeader::default(),
            silent_open: false,
            exit_code: ExitCode::Success,
            password: Password::new(password.unwrap_or_default()),
            name,
            open_volume,
            kdf_cache: KdfCache::default(),
            qopen: QuickOpen::default(),
            prohibit_qopen: false,
        };
        if archive.is_archive(enable_broken)? {
            Ok(archive)
        } else {
            Err(Error::NotRar {
                exit_code: archive.exit_code,
            })
        }
    }

    /// What UnRAR's `ErrHandler` would say so far.
    pub fn exit_code(&self) -> ExitCode {
        self.exit_code
    }

    /// Where the next read starts: `Tell`.
    pub fn position(&self) -> u64 {
        self.tell()
    }

    /// `Archive::Read`.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(read) = self.qopen_read(buf)? {
            return Ok(read);
        }
        Cursor {
            src: &self.src,
            pos: &mut self.pos,
        }
        .read(buf)
    }

    /// `Archive::Seek`.
    pub(crate) fn seek(&mut self, pos: u64) {
        if self.qopen.loaded {
            self.qopen_seek(pos);
        } else {
            self.pos = pos;
        }
    }

    /// Reads at `pos` in the archive's file, wherever its own position is,
    /// as much of `buf` as there is: data is never a QuickOpen record's copy.
    pub(crate) fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut pos = pos;
        Cursor {
            src: &self.src,
            pos: &mut pos,
        }
        .read(buf)
    }

    /// `Archive::Tell`.
    pub(crate) fn tell(&self) -> u64 {
        if self.qopen.loaded {
            self.qopen.seek_pos
        } else {
            self.pos
        }
    }

    /// `File::FileLength`, by way of `Seek` and `Tell`: with a QuickOpen
    /// record loaded, going back can read it again from its start.
    fn file_length(&mut self) -> io::Result<u64> {
        let save_pos = self.tell();
        let length = self.src.size()?;
        if self.qopen.loaded {
            self.qopen_seek_end(length);
        } else {
            self.pos = length;
        }
        self.seek(save_pos);
        Ok(length)
    }

    /// `IsSignature`: which format the bytes start with.
    fn is_signature(d: &[u8]) -> Format {
        let mut kind = Format::None;
        if d.first() == Some(&0x52) {
            if d.len() >= 4 && d[1] == 0x45 && d[2] == 0x7e && d[3] == 0x5e {
                kind = Format::Rar14;
            } else if d.len() >= 7 && d[1..6] == [0x61, 0x72, 0x21, 0x1a, 0x07] {
                kind = match d[6] {
                    0 => Format::Rar15,
                    1 => Format::Rar50,
                    2..=4 => Format::Future,
                    _ => Format::None,
                };
            }
        }
        kind
    }

    fn is_archive(&mut self, enable_broken: bool) -> Result<bool, Error> {
        self.encrypted = false;
        self.broken_header = false;

        let mut mark = [0u8; SIZEOF_MARKHEAD3];
        if self.read(&mut mark)? != SIZEOF_MARKHEAD3 {
            return Ok(false);
        }
        self.mark_head.mark[..SIZEOF_MARKHEAD3].copy_from_slice(&mark);
        self.sfx_size = 0;

        let kind = Self::is_signature(&mark);
        if kind != Format::None {
            self.format = kind;
            if self.format == Format::Rar14 {
                let at = self.tell() - SIZEOF_MARKHEAD3 as u64;
                self.seek(at);
            }
        } else {
            // A self-extracting module: the signature within its first
            // 4 MB, the buffers overlapping by 16 bytes.
            const BUF_SIZE: u64 = 0x40000;
            const OVERLAP: u64 = 16;
            let mut buffer = vec![0u8; BUF_SIZE as usize];
            let mut buf_pos: u64 = 0;
            loop {
                self.seek(buf_pos);
                let size_to_read = BUF_SIZE.min(MAXSFXSIZE.saturating_sub(buf_pos)) as usize;
                let read_size = self.read(&mut buffer[..size_to_read])?;
                for i in 0..read_size {
                    if buffer[i] != 0x52 {
                        continue;
                    }
                    let kind = Self::is_signature(&buffer[i..read_size]);
                    if kind == Format::None {
                        continue;
                    }
                    self.format = kind;
                    // RAR 1.4 self-extracting modules had `RSFX` at 28.
                    if kind == Format::Rar14
                        && buf_pos == 0
                        && read_size > 31
                        && buffer[28..32] != *b"RSFX"
                    {
                        continue;
                    }
                    self.sfx_size = buf_pos + i as u64;
                    break;
                }
                if self.sfx_size > 0 || read_size != buffer.len() {
                    break;
                }
                buf_pos += read_size as u64 - OVERLAP;
            }
            if self.sfx_size == 0 {
                return Ok(false);
            }
            self.seek(self.sfx_size);
            if matches!(self.format, Format::Rar15 | Format::Rar50) {
                let mut mark = [0u8; SIZEOF_MARKHEAD3];
                self.read(&mut mark)?;
                self.mark_head.mark[..SIZEOF_MARKHEAD3].copy_from_slice(&mark);
            }
        }
        if self.format == Format::Future {
            return Ok(false);
        }
        if self.format == Format::Rar50 {
            let mut last = [0u8; 1];
            if self.read(&mut last)? != 1 || last[0] != 0 {
                return Ok(false);
            }
            self.mark_head.mark[SIZEOF_MARKHEAD3] = 0;
            self.mark_head.head_size = SIZEOF_MARKHEAD5 as u32;
        } else {
            self.mark_head.head_size = SIZEOF_MARKHEAD3 as u32;
        }

        // UnRAR's library, without a callback to ask for a password.
        self.silent_open = true;

        let mut headers_left;
        let mut start_found = false;
        loop {
            headers_left = self.read_header()? != 0;
            if !headers_left {
                break;
            }
            self.seek_to_next();
            let kind = self.cur_header_type;
            start_found = kind == HEAD_MAIN || self.silent_open && kind == HEAD_CRYPT;
            if start_found {
                break;
            }
        }

        if self.failed_header_decryption && !enable_broken {
            return Ok(false);
        }
        if (self.broken_header || !start_found) && !enable_broken {
            return Ok(false);
        }

        self.main_comment = self.main_head.comment_in_header;

        // RAR 2.x volumes do not say they are the first: scan to the first
        // file header to know, and for the comment flag.
        if headers_left && (!self.silent_open || !self.encrypted) {
            let save_pos = self.tell();
            let save_cur = self.cur_block_pos;
            let save_next = self.next_block_pos;
            let save_type = self.cur_header_type;
            while self.read_header()? != 0 {
                let kind = self.cur_header_type;
                if kind == HEAD_SERVICE {
                    self.first_volume = self.volume && !self.sub_head.split_before;
                } else if kind == HEAD_FILE {
                    self.first_volume = self.volume && !self.file_head.split_before;
                    break;
                } else if kind == HEAD_ENDARC {
                    break;
                }
                self.seek_to_next();
            }
            self.cur_block_pos = save_cur;
            self.next_block_pos = save_next;
            self.cur_header_type = save_type;
            self.seek(save_pos);
        }
        Ok(true)
    }

    /// Moves to the header after the current one and its data.
    pub fn seek_to_next(&mut self) {
        // Positions are never negative: SafeAdd makes overflows 0.
        self.seek(self.next_block_pos.max(0) as u64);
    }

    /// `FullHeaderSize`: a header's size with its encryption fields.
    fn full_header_size(&self, size: usize) -> u32 {
        let mut size = size;
        if self.encrypted {
            size = size.div_ceil(CRYPT_BLOCK_SIZE) * CRYPT_BLOCK_SIZE;
            size += if self.format == Format::Rar50 {
                SIZE_INITV
            } else {
                SIZE_SALT30
            };
        }
        size as u32
    }

    pub(crate) fn set_error_code(&mut self, code: ExitCode) {
        self.exit_code = self.exit_code.set(code);
    }

    fn broken_header_msg(&mut self) {
        self.broken_header = true;
        self.set_error_code(ExitCode::Crc);
    }

    fn unexp_end_arc_msg(&mut self) -> io::Result<()> {
        let arc_size = self.file_length()? as i64;
        if self.cur_block_pos != arc_size || self.next_block_pos != arc_size {
            self.set_error_code(ExitCode::Warning);
        }
        Ok(())
    }

    /// Reads the header at the current position: its size, or 0 at the end
    /// or for a header that cannot be read. `Archive::ReadHeader`.
    pub fn read_header(&mut self) -> Result<usize, Error> {
        if self.failed_header_decryption {
            return Ok(0);
        }
        self.cur_block_pos = self.tell() as i64;
        let mut read_size = match self.format {
            Format::Rar14 => self.read_header14()?,
            Format::Rar15 => self.read_header15()?,
            Format::Rar50 => self.read_header50()?,
            Format::None | Format::Future => 0,
        };
        if !self.sanitize_header() || read_size > 0 && self.next_block_pos <= self.cur_block_pos {
            self.broken_header_msg();
            read_size = 0;
        }
        if read_size == 0 {
            self.cur_header_type = HEAD_UNKNOWN;
        }
        Ok(read_size)
    }

    /// `Archive::SearchBlock`.
    fn search_block(&mut self, header_type: u32) -> Result<usize, Error> {
        loop {
            let size = self.read_header()?;
            if size == 0 || (header_type != HEAD_ENDARC && self.cur_header_type == HEAD_ENDARC) {
                return Ok(0);
            }
            if self.cur_header_type == header_type {
                return Ok(size);
            }
            self.seek_to_next();
        }
    }

    /// `Archive::SearchSubBlock`.
    pub(crate) fn search_sub_block(&mut self, kind: &str) -> Result<usize, Error> {
        loop {
            let size = self.read_header()?;
            if size == 0 || self.cur_header_type == HEAD_ENDARC {
                return Ok(0);
            }
            if self.cur_header_type == HEAD_SERVICE && self.sub_head.is_named(kind) {
                return Ok(size);
            }
            self.seek_to_next();
        }
    }

    /// `Archive::GetStartPos`.
    pub(crate) fn start_pos(&self) -> u64 {
        let mut pos = self.sfx_size + u64::from(self.mark_head.head_size);
        if self.format == Format::Rar15 {
            pos += u64::from(self.main_head.base.head_size);
        } else {
            pos += u64::from(self.crypt_head.base.head_size)
                + u64::from(self.full_header_size(self.main_head.base.head_size as usize));
        }
        pos
    }

    /// `File::Tell`, in the crate.
    pub(crate) fn tell_pos(&self) -> u64 {
        self.tell()
    }

    /// `File::GetByte`, in the crate.
    pub(crate) fn next_byte(&mut self) -> io::Result<u8> {
        self.get_byte()
    }

    /// `MergeArchive`: goes on to the next volume, nothing if there is none,
    /// and otherwise where the data goes on: `DataIO->UnpVolume`, and
    /// `SetPackedSizeToRead`. The hash of the packed data is left out, which
    /// UnRAR only says something about.
    pub(crate) fn merge_archive(&mut self) -> Result<Option<(bool, u64)>, Error> {
        let header_type = self.cur_header_type;
        let is_service = header_type == HEAD_SERVICE;
        let is_part = header_type == HEAD_FILE || is_service;
        let split_after = if is_service {
            self.sub_head.split_after
        } else {
            self.file_head.split_after
        };
        let split_header = is_part && split_after;
        let prev_vol_encrypted = self.encrypted;
        let pos_before_close = self.tell();
        // `Archive::Open`, whether or not there is anything to open.
        self.qopen.loaded = false;

        let mut next_name = next_volume_name(&self.name, !self.new_numbering);
        let mut opened = self.open_volume.as_mut().and_then(|open| open(&next_name));
        if opened.is_none() {
            // New style volumes renamed to the old style.
            let alt_name = next_volume_name(&self.name, true);
            opened = self.open_volume.as_mut().and_then(|open| open(&alt_name));
            if opened.is_some() {
                next_name = alt_name;
            }
        }
        let Some(src) = opened else {
            self.set_error_code(ExitCode::Open);
            self.seek(pos_before_close);
            return Ok(None);
        };
        self.src = src;
        self.name = next_name;
        self.seek(0);

        // `CheckArc`, and `ErrHandler.Exit`, which sets the code first.
        if !self.is_archive(true)? || self.encrypted != prev_vol_encrypted {
            self.set_error_code(ExitCode::BadArchive);
            return Err(Error::BadVolume {
                exit_code: self.exit_code,
            });
        }

        if split_header {
            self.search_block(header_type)?;
        } else {
            self.read_header()?;
        }
        if self.cur_header_type == HEAD_FILE {
            self.seek((self.next_block_pos - self.file_head.pack_size) as u64);
        }
        if header_type == HEAD_ENDARC {
            return Ok(Some((false, 0)));
        }
        let hd = if is_service {
            &self.sub_head
        } else {
            &self.file_head
        };
        Ok(Some((hd.split_after, hd.pack_size as u64)))
    }

    fn sanitize_header(&mut self) -> bool {
        if self.cur_header_type == HEAD_FILE || self.cur_header_type == HEAD_SERVICE {
            let file_block = self.cur_header_type == HEAD_FILE;
            let hd = if file_block {
                &mut self.file_head
            } else {
                &mut self.sub_head
            };
            if hd.pack_size < 0 || hd.unp_size < 0 {
                hd.pack_size = 0;
                hd.unp_size = 0;
                self.broken_header_msg();
                return false;
            }
        }
        true
    }

    /// The password the headers need: without one the reading stops, as
    /// UnRAR's library stops without a callback that gives one.
    fn request_arc_password(&mut self) -> Result<(), Error> {
        if self.password.is_set() {
            return Ok(());
        }
        // `ErrHandler.Exit(RARX_USERBREAK)`, which sets the code first.
        self.set_error_code(ExitCode::UserBreak);
        Err(Error::MissingPassword {
            exit_code: self.exit_code,
        })
    }

    fn read_header15(&mut self) -> Result<usize, Error> {
        let mut raw = RawRead::new();
        let decrypt =
            self.encrypted && self.cur_block_pos > (self.sfx_size + SIZEOF_MARKHEAD3 as u64) as i64;
        if decrypt {
            self.request_arc_password()?;
            let mut salt = [0u8; SIZE_SALT30];
            if self.read(&mut salt)? != SIZE_SALT30 {
                self.unexp_end_arc_msg()?;
                return Ok(0);
            }
            let keys = set_crypt_keys(
                CryptMethod::Rar30,
                &self.password,
                &mut self.kdf_cache,
                Some(&salt),
                &[0; SIZE_INITV],
                0,
            );
            if let Some((crypt, _)) = keys {
                raw.set_crypt(crypt);
            }
        }

        raw.read(self, SIZEOF_SHORTBLOCKHEAD)?;
        if raw.size() == 0 {
            self.unexp_end_arc_msg()?;
            return Ok(0);
        }

        let mut short = BaseBlock {
            head_crc: u32::from(raw.get2()),
            ..BaseBlock::default()
        };
        let header_type = u32::from(raw.get1());
        short.flags = u32::from(raw.get2());
        short.skip_if_unknown = short.flags & SKIP_IF_UNKNOWN != 0;
        short.head_size = u32::from(raw.get2());
        short.header_type = header_type;
        if (short.head_size as usize) < SIZEOF_SHORTBLOCKHEAD {
            self.short_block = short;
            self.broken_header_msg();
            return Ok(0);
        }
        // RAR 1.5's header types common with RAR 5 as RAR 5's.
        short.header_type = match short.header_type {
            HEAD3_MAIN => HEAD_MAIN,
            HEAD3_FILE => HEAD_FILE,
            HEAD3_SERVICE => HEAD_SERVICE,
            HEAD3_ENDARC => HEAD_ENDARC,
            other => other,
        };
        self.cur_header_type = short.header_type;
        self.short_block = short;

        if short.header_type == HEAD3_CMT {
            // An old comment header inside a main or file header: only its
            // fixed part.
            raw.read(self, SIZEOF_COMMHEAD - SIZEOF_SHORTBLOCKHEAD)?;
        } else if short.header_type == HEAD_MAIN && short.flags & MHD_COMMENT != 0 {
            raw.read(self, SIZEOF_MAINHEAD3 - SIZEOF_SHORTBLOCKHEAD)?;
        } else {
            raw.read(self, short.head_size as usize - SIZEOF_SHORTBLOCKHEAD)?;
        }

        self.next_block_pos =
            self.cur_block_pos + i64::from(self.full_header_size(short.head_size as usize));

        match short.header_type {
            HEAD_MAIN => {
                self.main_head = MainHeader {
                    base: short,
                    ..MainHeader::default()
                };
                self.main_head.high_pos_av = raw.get2();
                self.main_head.pos_av = raw.get4();
                let flags = self.main_head.base.flags;
                self.volume = flags & MHD_VOLUME != 0;
                self.solid = flags & MHD_SOLID != 0;
                self.locked = flags & MHD_LOCK != 0;
                self.protected = flags & MHD_PROTECT != 0;
                self.encrypted = flags & MHD_PASSWORD != 0;
                self.signed = self.main_head.pos_av != 0 || self.main_head.high_pos_av != 0;
                self.main_head.comment_in_header = flags & MHD_COMMENT != 0;
                self.first_volume = flags & MHD_FIRSTVOLUME != 0;
                self.new_numbering = flags & MHD_NEWNUMBERING != 0;
            }
            HEAD_FILE | HEAD_SERVICE => {
                let file_block = short.header_type == HEAD_FILE;
                self.read_file_header15(&mut raw, short, file_block, decrypt);
            }
            HEAD_ENDARC => {
                let end = &mut self.end_arc_head;
                end.base = short;
                end.next_volume = end.base.flags & EARC_NEXT_VOLUME != 0;
                end.data_crc = end.base.flags & EARC_DATACRC != 0;
                end.rev_space = end.base.flags & EARC_REVSPACE != 0;
                end.store_vol_number = end.base.flags & EARC_VOLNUMBER != 0;
                if end.data_crc {
                    end.arc_data_crc = raw.get4();
                }
                if end.store_vol_number {
                    end.vol_number = u32::from(raw.get2());
                    self.vol_number = end.vol_number;
                }
            }
            HEAD3_CMT => {
                let comm = &mut self.comm_head;
                comm.base = short;
                comm.unp_size = raw.get2();
                comm.unp_ver = raw.get1();
                comm.method = raw.get1();
                comm.comm_crc = raw.get2();
            }
            HEAD3_PROTECT => {
                let protect = &mut self.protect_head;
                protect.base = short;
                protect.data_size = raw.get4();
                protect.version = raw.get1();
                protect.rec_sectors = raw.get2();
                protect.total_blocks = raw.get4();
                raw.get_b(&mut protect.mark);
                self.next_block_pos += i64::from(protect.data_size);
            }
            HEAD3_OLDSERVICE => {
                let sub = &mut self.sub_block_head;
                sub.base = short;
                sub.data_size = raw.get4();
                self.next_block_pos += i64::from(sub.data_size);
                sub.sub_type = raw.get2();
                sub.level = raw.get1();
                match sub.sub_type {
                    NTACL_HEAD => {
                        sub.unp_size = raw.get4();
                        sub.unp_ver = raw.get1();
                        sub.method = raw.get1();
                        sub.crc = raw.get4();
                    }
                    STREAM_HEAD => {
                        sub.unp_size = raw.get4();
                        sub.unp_ver = raw.get1();
                        sub.method = raw.get1();
                        sub.crc = raw.get4();
                        let name_size = usize::from(raw.get2()).min(260);
                        sub.stream_name = vec![0; name_size];
                        raw.get_b(&mut sub.stream_name);
                    }
                    _ => {}
                }
            }
            _ => {
                if short.flags & LONG_BLOCK != 0 {
                    self.next_block_pos += i64::from(raw.get4());
                }
            }
        }

        let header_crc = raw.get_crc15(false);
        // The old authenticity header and the old Unix owners header do
        // not have their CRC as others.
        if self.short_block.head_crc != header_crc
            && self.short_block.header_type != HEAD3_SIGN
            && self.short_block.header_type != HEAD3_AV
            && (self.short_block.header_type != HEAD3_OLDSERVICE
                || self.sub_block_head.sub_type != UO_HEAD)
        {
            let mut recovered = false;
            if self.short_block.header_type == HEAD_ENDARC && self.end_arc_head.rev_space {
                // A recovered volume's last 7 bytes can be zeroes.
                let length = self.tell();
                self.seek(length.wrapping_sub(7));
                recovered = true;
                for _ in 0..7 {
                    if self.get_byte()? != 0 {
                        recovered = false;
                    }
                }
            }
            if !recovered {
                self.broken_header = true;
                self.set_error_code(ExitCode::Crc);
                if decrypt {
                    self.failed_header_decryption = true;
                    return Ok(0);
                }
            }
        }
        Ok(raw.size())
    }

    /// `File::GetByte`: a byte, 0 at the end.
    fn get_byte(&mut self) -> io::Result<u8> {
        let mut byte = [0u8; 1];
        self.read(&mut byte)?;
        Ok(byte[0])
    }

    fn read_file_header15(
        &mut self,
        raw: &mut RawRead,
        short: BaseBlock,
        file_block: bool,
        decrypt: bool,
    ) {
        let format = self.format;
        let hd = if file_block {
            &mut self.file_head
        } else {
            &mut self.sub_head
        };
        hd.reset();
        hd.base = short;

        let flags = hd.base.flags;
        hd.split_before = flags & LHD_SPLIT_BEFORE != 0;
        hd.split_after = flags & LHD_SPLIT_AFTER != 0;
        hd.encrypted = flags & LHD_PASSWORD != 0;
        hd.salt_set = flags & LHD_SALT != 0;
        // RAR before 2.0 does not set it in file headers.
        hd.solid = file_block && flags & LHD_SOLID != 0;
        hd.sub_block = !file_block && flags & LHD_SOLID != 0;
        hd.dir = flags & LHD_WINDOWMASK == LHD_DIRECTORY;
        hd.win_size = if hd.dir {
            0
        } else {
            0x10000u64 << ((flags & LHD_WINDOWMASK) >> 5)
        };
        hd.comment_in_header = flags & LHD_COMMENT != 0;
        hd.version = flags & LHD_VERSION != 0;

        hd.data_size = raw.get4();
        let low_unp_size = raw.get4();
        hd.host_os = raw.get1();
        hd.file_hash.kind = HashType::Crc32;
        hd.file_hash.crc32 = raw.get4();
        let file_time = raw.get4();
        hd.unp_ver = u32::from(raw.get1());
        hd.method = raw.get1().wrapping_sub(0x30);
        let name_size = usize::from(raw.get2());
        hd.file_attr = raw.get4();

        // RAR 1.5 did not mark directories by the dictionary size.
        if hd.unp_ver < 20 && hd.file_attr & 0x10 != 0 {
            hd.dir = true;
        }

        hd.crypt_method = CryptMethod::None;
        if hd.encrypted {
            hd.crypt_method = match hd.unp_ver {
                13 => CryptMethod::Rar13,
                15 => CryptMethod::Rar15,
                20 | 26 => CryptMethod::Rar20,
                _ => CryptMethod::Rar30,
            };
        }

        hd.hs_type = HostSystem::Unknown;
        if hd.host_os == HOST_UNIX || hd.host_os == HOST_BEOS {
            hd.hs_type = HostSystem::Unix;
        } else if hd.host_os < HOST_MAX {
            hd.hs_type = HostSystem::Windows;
        }

        hd.redir_type = Redirection::None;
        // A RAR 4 Unix symbolic link.
        if hd.host_os == HOST_UNIX && hd.file_attr & 0xf000 == 0xa000 {
            hd.redir_type = Redirection::UnixSymlink;
            hd.redir_name.clear();
        }

        hd.inherited = !file_block && hd.file_attr & SUBHEAD_FLAGS_INHERITED != 0;
        hd.large_file = flags & LHD_LARGE != 0;

        let (high_pack_size, high_unp_size);
        if hd.large_file {
            high_pack_size = raw.get4();
            high_unp_size = raw.get4();
            hd.unknown_unp_size = low_unp_size == 0xffff_ffff && high_unp_size == 0xffff_ffff;
        } else {
            high_pack_size = 0;
            high_unp_size = 0;
            // No size: unpacked until the end marker of the data.
            hd.unknown_unp_size = low_unp_size == 0xffff_ffff;
        }
        hd.pack_size = ((u64::from(high_pack_size) << 32) | u64::from(hd.data_size)) as i64;
        hd.unp_size = ((u64::from(high_unp_size) << 32) | u64::from(low_unp_size)) as i64;
        if hd.unknown_unp_size {
            hd.unp_size = INT64NDF;
        }

        let read_name_size = name_size.min(MAXPATHSIZE);
        let mut file_name = vec![0u8; read_name_size];
        raw.get_b(&mut file_name);

        if file_block {
            hd.file_name.clear();
            if flags & LHD_UNICODE != 0 {
                let length = file_name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(file_name.len())
                    + 1;
                if read_name_size > length {
                    decode_encoded(&file_name, &file_name[length..], &mut hd.file_name);
                }
            }
            if hd.file_name.is_empty() {
                hd.file_name = arc_char_to_wide(&file_name);
            }
            convert_file_header(&mut hd.file_name, format, hd.hs_type);
        } else {
            hd.file_name = char_to_wide(&file_name);
            // Optional data after the name and before the salt.
            let mut data_size =
                hd.base.head_size as i64 - name_size as i64 - SIZEOF_FILEHEAD3 as i64;
            if flags & LHD_SALT != 0 {
                data_size -= SIZE_SALT30 as i64;
            }
            if data_size > 0 {
                hd.sub_data = vec![0; data_size as usize];
                raw.get_b(&mut hd.sub_data);
            }
        }
        let is_comment = !file_block && hd.is_named(SUBHEAD_TYPE_CMT);

        if flags & LHD_SALT != 0 {
            let mut salt = [0u8; SIZE_SALT30];
            raw.get_b(&mut salt);
            hd.salt[..SIZE_SALT30].copy_from_slice(&salt);
        }
        hd.mtime.set_dos(file_time);
        let pack_size = hd.pack_size;
        let comment_in_header = hd.comment_in_header;
        let head_crc = hd.base.head_crc;

        if is_comment {
            self.main_comment = true;
        }

        if flags & LHD_EXTTIME != 0 {
            let time_flags = raw.get2();
            // UnRAR sets the file header's times here, for a service
            // header too.
            for i in 0..3u32 {
                let rmode = u32::from(time_flags) >> ((3 - i) * 4);
                if rmode & 8 == 0 {
                    continue;
                }
                let time = match i {
                    0 => &mut self.file_head.mtime,
                    1 => &mut self.file_head.ctime,
                    _ => &mut self.file_head.atime,
                };
                if i != 0 {
                    let dos = raw.get4();
                    time.set_dos(dos);
                }
                let mut local = time.get_local();
                if rmode & 4 != 0 {
                    local.second += 1;
                }
                local.reminder = 0;
                let count = rmode & 3;
                for j in 0..count {
                    let byte = raw.get1();
                    local.reminder |= u32::from(byte) << ((j + 3 - count) * 8);
                }
                // From RAR's 100 ns to nanoseconds.
                local.reminder = local.reminder.wrapping_mul(100);
                time.set_local(&local);
            }
        }
        // 0 on overflow, which ReadHeader takes for a broken header.
        self.next_block_pos = safe_add(self.next_block_pos, pack_size, 0);

        let header_crc = raw.get_crc15(comment_in_header);
        if head_crc != header_crc {
            self.broken_header = true;
            self.set_error_code(ExitCode::Warning);
        }
        let _ = decrypt;
    }

    fn read_header50(&mut self) -> Result<usize, Error> {
        let mut raw = RawRead::new();
        let decrypt =
            self.encrypted && self.cur_block_pos > (self.sfx_size + SIZEOF_MARKHEAD5 as u64) as i64;
        if decrypt {
            let mut init_v = [0u8; SIZE_INITV];
            if self.read(&mut init_v)? != SIZE_INITV {
                self.unexp_end_arc_msg()?;
                return Ok(0);
            }
            self.request_arc_password()?;
            let keys = set_crypt_keys(
                CryptMethod::Rar50,
                &self.password,
                &mut self.kdf_cache,
                Some(&self.crypt_head.salt),
                &init_v,
                self.crypt_head.lg2_count,
            );
            if let Some((crypt, checks)) = keys {
                // A damaged header cannot be relied on for the check value.
                if self.crypt_head.use_psw_check
                    && !self.broken_header
                    && checks.psw_check != self.crypt_head.psw_check
                {
                    self.failed_header_decryption = true;
                    self.set_error_code(ExitCode::BadPassword);
                    return Ok(0);
                }
                raw.set_crypt(crypt);
            }
        }

        // The CRC, then up to 3 bytes of size: a header is 2 MB at most.
        const FIRST_READ_SIZE: usize = 7;
        if raw.read(self, FIRST_READ_SIZE)? < FIRST_READ_SIZE {
            self.unexp_end_arc_msg()?;
            return Ok(0);
        }

        let mut short = BaseBlock {
            head_crc: raw.get4(),
            ..BaseBlock::default()
        };
        let size_bytes = raw.get_v_size(4);
        let block_size = raw.get_v();
        if block_size == 0 || size_bytes == 0 {
            self.broken_header_msg();
            return Ok(0);
        }

        // UnRAR keeps these in `int` and `uint`.
        let size_to_read =
            (block_size as i32).wrapping_sub((FIRST_READ_SIZE - size_bytes - 4) as i32);
        let header_size = (4 + size_bytes as u32).wrapping_add(block_size as u32);
        if size_to_read < 0 || (header_size as usize) < SIZEOF_SHORTBLOCKHEAD5 {
            self.broken_header_msg();
            return Ok(0);
        }

        raw.read(self, size_to_read as usize)?;
        if raw.size() < header_size as usize {
            self.unexp_end_arc_msg()?;
            return Ok(0);
        }

        let header_crc = raw.get_crc50();
        // UnRAR casts the vint to HEADER_TYPE, an `int`, so to its low 32
        // bits, signed, then takes the smaller of it and HEAD_UNKNOWN: a
        // value with its top bit set stays as it is.
        let header_type = raw.get_v() as u32;
        short.header_type = if (header_type as i32) < HEAD_UNKNOWN as i32 {
            header_type
        } else {
            HEAD_UNKNOWN
        };
        short.flags = raw.get_v() as u32;
        short.skip_if_unknown = short.flags & HFL_SKIPIFUNKNOWN != 0;
        short.head_size = header_size;
        self.cur_header_type = short.header_type;
        self.short_block = short;

        let bad_crc = short.head_crc != header_crc;
        if bad_crc {
            self.broken_header_msg();
            if decrypt {
                self.failed_header_decryption = true;
                return Ok(0);
            }
        }

        let mut extra_size: u64 = 0;
        if short.flags & HFL_EXTRA != 0 {
            extra_size = raw.get_v();
            if extra_size >= u64::from(short.head_size) {
                self.broken_header_msg();
                return Ok(0);
            }
        }

        let mut data_size: u64 = 0;
        if short.flags & HFL_DATA != 0 {
            data_size = raw.get_v();
        }

        self.next_block_pos =
            self.cur_block_pos + i64::from(self.full_header_size(short.head_size as usize));
        self.next_block_pos = safe_add(self.next_block_pos, data_size as i64, 0);

        match short.header_type {
            HEAD_CRYPT => {
                let crypt = &mut self.crypt_head;
                crypt.base = short;
                let crypt_version = raw.get_v() as u32;
                if crypt_version > CRYPT_VERSION {
                    self.failed_header_decryption = true;
                    self.set_error_code(ExitCode::Fatal);
                    return Ok(0);
                }
                let enc_flags = raw.get_v() as u32;
                crypt.use_psw_check = enc_flags & CHFL_CRYPT_PSWCHECK != 0;
                crypt.lg2_count = u32::from(raw.get1());
                if crypt.lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
                    self.failed_header_decryption = true;
                    self.set_error_code(ExitCode::Fatal);
                    return Ok(0);
                }
                raw.get_b(&mut crypt.salt);
                if crypt.use_psw_check {
                    raw.get_b(&mut crypt.psw_check);
                    let mut csum = [0u8; SIZE_PSWCHECK_CSUM];
                    raw.get_b(&mut csum);
                    crypt.use_psw_check = psw_check_valid(&crypt.psw_check, &csum);
                }
                self.encrypted = true;
            }
            HEAD_MAIN => {
                self.main_head = MainHeader {
                    base: short,
                    ..MainHeader::default()
                };
                let arc_flags = raw.get_v() as u32;
                self.volume = arc_flags & MHFL_VOLUME != 0;
                self.solid = arc_flags & MHFL_SOLID != 0;
                self.locked = arc_flags & MHFL_LOCK != 0;
                self.protected = arc_flags & MHFL_PROTECT != 0;
                self.signed = false;
                self.new_numbering = true;
                self.vol_number = if arc_flags & MHFL_VOLNUMBER != 0 {
                    raw.get_v() as u32
                } else {
                    0
                };
                self.first_volume = self.volume && self.vol_number == 0;
                if extra_size != 0 {
                    self.process_extra50(&mut raw, extra_size as usize, short.header_type);
                }
                if !self.prohibit_qopen && self.main_head.locator && self.main_head.qopen_offset > 0
                {
                    // Reading the record moves through the archive: what
                    // called this goes on from the same blocks.
                    let save_cur = self.cur_block_pos;
                    let save_next = self.next_block_pos;
                    let save_type = self.cur_header_type;
                    self.qopen.loaded = false;
                    self.qopen_load(self.main_head.qopen_offset)?;
                    self.cur_block_pos = save_cur;
                    self.next_block_pos = save_next;
                    self.cur_header_type = save_type;
                }
            }
            HEAD_FILE | HEAD_SERVICE => {
                let file_block = short.header_type == HEAD_FILE;
                self.read_file_header50(&mut raw, short, file_block, data_size, extra_size);
            }
            HEAD_ENDARC => {
                let end = &mut self.end_arc_head;
                end.base = short;
                let arc_flags = raw.get_v() as u32;
                end.next_volume = arc_flags & EHFL_NEXTVOLUME != 0;
                end.store_vol_number = false;
                end.data_crc = false;
                end.rev_space = false;
            }
            _ => {}
        }
        Ok(raw.size())
    }

    fn read_file_header50(
        &mut self,
        raw: &mut RawRead,
        short: BaseBlock,
        file_block: bool,
        data_size: u64,
        extra_size: u64,
    ) {
        let format = self.format;
        let hd = if file_block {
            &mut self.file_head
        } else {
            &mut self.sub_head
        };
        hd.reset();
        hd.base = short;
        hd.large_file = true;

        hd.pack_size = data_size as i64;
        hd.file_flags = raw.get_v() as u32;
        hd.unp_size = raw.get_v() as i64;
        hd.unknown_unp_size = hd.file_flags & FHFL_UNPUNKNOWN != 0;
        if hd.unknown_unp_size {
            hd.unp_size = INT64NDF;
        }
        hd.max_size = hd.pack_size.max(hd.unp_size);
        hd.file_attr = raw.get_v() as u32;
        if hd.file_flags & FHFL_UTIME != 0 {
            let unix = raw.get4();
            hd.mtime.set_unix(i64::from(unix));
        }

        hd.file_hash.kind = HashType::None;
        if hd.file_flags & FHFL_CRC32 != 0 {
            hd.file_hash.kind = HashType::Crc32;
            hd.file_hash.crc32 = raw.get4();
        }

        hd.redir_type = Redirection::None;

        let comp_info = raw.get_v() as u32;
        hd.method = ((comp_info >> 7) & 7) as u8;
        // Plus 50, apart from RAR 1.5's algorithms.
        let unp_ver = comp_info & 0x3f;
        hd.unp_ver = match unp_ver {
            0 => VER_PACK5,
            1 => VER_PACK7,
            _ => VER_UNKNOWN,
        };

        hd.host_os = raw.get_v() as u8;
        // On x86-64, as the oracle runs: a 64-bit size_t.
        let name_size = raw.get_v();
        hd.inherited = short.flags & HFL_INHERITED != 0;

        hd.hs_type = HostSystem::Unknown;
        if hd.host_os == HOST5_UNIX {
            hd.hs_type = HostSystem::Unix;
        } else if hd.host_os == HOST5_WINDOWS {
            hd.hs_type = HostSystem::Windows;
        }

        hd.split_before = hd.base.flags & HFL_SPLITBEFORE != 0;
        hd.split_after = hd.base.flags & HFL_SPLITAFTER != 0;
        hd.sub_block = hd.base.flags & HFL_CHILD != 0;
        hd.solid = file_block && comp_info & FCI_SOLID != 0;
        hd.dir = hd.file_flags & FHFL_DIRECTORY != 0;
        if hd.dir || unp_ver > 1 {
            hd.win_size = 0;
        } else {
            let mask = if unp_ver == 0 { 0x0f } else { 0x1f };
            hd.win_size = 0x20000u64.wrapping_shl((comp_info >> 10) & mask);
            if unp_ver == 1 {
                hd.win_size += hd.win_size / 32 * u64::from((comp_info >> 15) & 0x1f);
                // A RAR 7 header with RAR 5's algorithm.
                if comp_info & FCI_RAR5_COMPAT != 0 {
                    hd.unp_ver = VER_PACK5;
                }
                if hd.win_size > UNPACK_MAX_DICT {
                    hd.unp_ver = VER_UNKNOWN;
                }
            }
        }

        let read_name_size = name_size.min(MAXPATHSIZE as u64) as usize;
        let mut file_name = vec![0u8; read_name_size];
        raw.get_b(&mut file_name);
        hd.file_name = utf_to_wide(&file_name);

        // Before the names are converted: extra records can change them.
        if extra_size != 0 {
            self.process_extra50(raw, extra_size as usize, short.header_type);
        }

        let hd = if file_block {
            &mut self.file_head
        } else {
            &mut self.sub_head
        };
        if file_block {
            convert_file_header(&mut hd.file_name, format, hd.hs_type);
        }
        if !file_block && hd.is_named(SUBHEAD_TYPE_CMT) {
            self.main_comment = true;
        }
        let hd = if file_block {
            &self.file_head
        } else {
            &self.sub_head
        };
        // RAR 5's recovery percent, a byte up to RAR 6.02, then a vint.
        if !file_block && hd.is_named(SUBHEAD_TYPE_RR) && !hd.sub_data.is_empty() {
            let mut percent = RawRead::new();
            percent.read_bytes(&hd.sub_data);
            self.recovery_percent = percent.get_v() as i32;
        }
    }

    fn process_extra50(&mut self, raw: &mut RawRead, extra_size: usize, header_type: u32) {
        // The extra area is the end of the header.
        let Some(extra_start) = raw.size().checked_sub(extra_size) else {
            return;
        };
        if extra_start < raw.get_pos() {
            return;
        }
        raw.set_pos(extra_start);
        let cur_block_pos = self.cur_block_pos;
        while raw.data_left() >= 2 {
            let field_size = raw.get_v() as i64;
            if field_size <= 0 || raw.data_left() == 0 || field_size > raw.data_left() as i64 {
                break;
            }
            let next_pos = raw.get_pos() + field_size as usize;
            let field_type = raw.get_v();
            // Without its size and type.
            let field_size = next_pos as i64 - raw.get_pos() as i64;
            if field_size < 0 {
                break;
            }

            if header_type == HEAD_MAIN {
                let hd = &mut self.main_head;
                match field_type {
                    MHEXTRA_LOCATOR => {
                        hd.locator = true;
                        let flags = raw.get_v() as u32;
                        if flags & MHEXTRA_LOCATOR_QLIST != 0 {
                            let offset = raw.get_v();
                            if offset != 0 {
                                hd.qopen_offset = offset.wrapping_add(cur_block_pos as u64);
                            }
                        }
                        if flags & MHEXTRA_LOCATOR_RR != 0 {
                            let offset = raw.get_v();
                            if offset != 0 {
                                hd.rr_offset = offset.wrapping_add(cur_block_pos as u64);
                            }
                        }
                    }
                    MHEXTRA_METADATA => {
                        let flags = raw.get_v() as u32;
                        if flags & MHEXTRA_METADATA_NAME != 0 {
                            let name_size = raw.get_v();
                            if name_size > 0 && name_size < MAXPATHSIZE as u64 {
                                let mut name = vec![0u8; name_size as usize];
                                raw.get_b(&mut name);
                                // A name that did not fit starts with 0.
                                if name[0] != 0 {
                                    hd.orig_name = utf_to_wide(&name);
                                }
                            }
                        }
                        if flags & MHEXTRA_METADATA_CTIME != 0 {
                            if flags & MHEXTRA_METADATA_UNIXTIME != 0 {
                                if flags & MHEXTRA_METADATA_UNIX_NS != 0 {
                                    let ns = raw.get8();
                                    hd.orig_time.set_unix_ns(ns);
                                } else {
                                    let unix = raw.get4();
                                    hd.orig_time.set_unix(i64::from(unix));
                                }
                            } else {
                                let win = raw.get8();
                                hd.orig_time.set_win(win);
                            }
                        }
                    }
                    _ => {}
                }
            }

            if header_type == HEAD_FILE || header_type == HEAD_SERVICE {
                let hd = if header_type == HEAD_FILE {
                    &mut self.file_head
                } else {
                    &mut self.sub_head
                };
                match field_type {
                    FHEXTRA_CRYPT => {
                        let enc_version = raw.get_v() as u32;
                        if enc_version > CRYPT_VERSION {
                            hd.crypt_method = CryptMethod::Unknown;
                            self.exit_code = self.exit_code.set(ExitCode::Fatal);
                        } else {
                            let flags = raw.get_v() as u32;
                            hd.lg2_count = u32::from(raw.get1());
                            if hd.lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
                                hd.crypt_method = CryptMethod::Unknown;
                                self.exit_code = self.exit_code.set(ExitCode::Fatal);
                            } else {
                                hd.use_psw_check = flags & FHEXTRA_CRYPT_PSWCHECK != 0;
                                hd.use_hash_key = flags & FHEXTRA_CRYPT_HASHMAC != 0;
                                raw.get_b(&mut hd.salt);
                                raw.get_b(&mut hd.init_v);
                                if hd.use_psw_check {
                                    raw.get_b(&mut hd.psw_check);
                                    let mut csum = [0u8; SIZE_PSWCHECK_CSUM];
                                    raw.get_b(&mut csum);
                                    hd.use_psw_check = psw_check_valid(&hd.psw_check, &csum);
                                    // RAR 5.21 and earlier wrote zeroes in
                                    // service headers.
                                    if header_type == HEAD_SERVICE
                                        && hd.psw_check == [0; SIZE_PSWCHECK]
                                    {
                                        hd.use_psw_check = false;
                                    }
                                }
                                hd.salt_set = true;
                                hd.crypt_method = CryptMethod::Rar50;
                                hd.encrypted = true;
                            }
                        }
                    }
                    FHEXTRA_HASH => {
                        let kind = raw.get_v() as u32;
                        if kind == FHEXTRA_HASH_BLAKE2 {
                            hd.file_hash.kind = HashType::Blake2;
                            raw.get_b(&mut hd.file_hash.digest);
                        }
                    }
                    FHEXTRA_HTIME => {
                        if field_size >= 5 {
                            let flags = raw.get_v() as u8;
                            let unix_time = flags & FHEXTRA_HTIME_UNIXTIME != 0;
                            let set = |raw: &mut RawRead, time: &mut RarTime| {
                                if unix_time {
                                    let unix = raw.get4();
                                    time.set_unix(i64::from(unix));
                                } else {
                                    let win = raw.get8();
                                    time.set_win(win);
                                }
                            };
                            if flags & FHEXTRA_HTIME_MTIME != 0 {
                                set(raw, &mut hd.mtime);
                            }
                            if flags & FHEXTRA_HTIME_CTIME != 0 {
                                set(raw, &mut hd.ctime);
                            }
                            if flags & FHEXTRA_HTIME_ATIME != 0 {
                                set(raw, &mut hd.atime);
                            }
                            if unix_time && flags & FHEXTRA_HTIME_UNIX_NS != 0 {
                                for (bit, time) in [
                                    (FHEXTRA_HTIME_MTIME, &mut hd.mtime),
                                    (FHEXTRA_HTIME_CTIME, &mut hd.ctime),
                                    (FHEXTRA_HTIME_ATIME, &mut hd.atime),
                                ] {
                                    if flags & bit != 0 {
                                        let ns = raw.get4() & 0x3fff_ffff;
                                        if ns < 1_000_000_000 {
                                            time.adjust(i64::from(ns));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    FHEXTRA_VERSION => {
                        if field_size >= 1 {
                            raw.get_v();
                            let version = raw.get_v() as u32;
                            if version != 0 {
                                hd.version = true;
                                hd.file_name.push(u32::from(b';'));
                                hd.file_name
                                    .extend(version.to_string().chars().map(u32::from));
                            }
                        }
                    }
                    FHEXTRA_REDIR => {
                        let redir_type = raw.get_v();
                        let flags = raw.get_v() as u32;
                        let name_size = raw.get_v();
                        if name_size > 0 && name_size < MAXPATHSIZE as u64 {
                            let mut name = vec![0u8; name_size as usize];
                            hd.redir_type = Redirection::of(redir_type);
                            hd.dir_target = flags & FHEXTRA_REDIR_DIR != 0;
                            raw.get_b(&mut name);
                            hd.redir_name = utf_to_wide(&name);
                        }
                    }
                    FHEXTRA_UOWNER => {
                        let flags = raw.get_v() as u32;
                        hd.unix_owner_numeric = flags & FHEXTRA_UOWNER_NUMUID != 0;
                        hd.unix_group_numeric = flags & FHEXTRA_UOWNER_NUMGID != 0;
                        hd.unix_owner_name.clear();
                        hd.unix_group_name.clear();
                        // Names of 255 bytes at most, as C strings.
                        let get_name = |raw: &mut RawRead| {
                            let length = raw.get_v().min(255) as usize;
                            let mut name = vec![0u8; length];
                            raw.get_b(&mut name);
                            name.truncate(name.iter().position(|&b| b == 0).unwrap_or(name.len()));
                            name
                        };
                        if flags & FHEXTRA_UOWNER_UNAME != 0 {
                            hd.unix_owner_name = get_name(raw);
                        }
                        if flags & FHEXTRA_UOWNER_GNAME != 0 {
                            hd.unix_group_name = get_name(raw);
                        }
                        if hd.unix_owner_numeric {
                            hd.unix_owner_id = raw.get_v() as u32;
                        }
                        if hd.unix_group_numeric {
                            hd.unix_group_id = raw.get_v() as u32;
                        }
                        hd.unix_owner_set = true;
                    }
                    FHEXTRA_SUBDATA => {
                        // RAR 5.21 and earlier wrote this field 1 byte
                        // short, and always last in a service header.
                        let mut size = field_size;
                        if header_type == HEAD_SERVICE && raw.size() as i64 - next_pos as i64 == 1 {
                            size += 1;
                        }
                        hd.sub_data = vec![0; size as usize];
                        raw.get_b(&mut hd.sub_data);
                    }
                    _ => {}
                }
            }
            raw.set_pos(next_pos);
        }
    }

    fn read_header14(&mut self) -> Result<usize, Error> {
        let mut raw = RawRead::new();
        if self.cur_block_pos <= self.sfx_size as i64 {
            raw.read(self, SIZEOF_MAINHEAD14)?;
            self.main_head = MainHeader::default();
            let mut mark = [0u8; 4];
            raw.get_b(&mut mark);
            let head_size = raw.get2();
            if head_size < 7 {
                return Ok(0);
            }
            let flags = u32::from(raw.get1());
            self.next_block_pos = self.cur_block_pos + i64::from(head_size);
            self.cur_header_type = HEAD_MAIN;
            self.volume = flags & MHD_VOLUME != 0;
            self.solid = flags & MHD_SOLID != 0;
            self.locked = flags & MHD_LOCK != 0;
            self.main_head.comment_in_header = flags & MHD_COMMENT != 0;
            self.main_head.pack_comment = flags & MHD_PACK_COMMENT != 0;
        } else {
            raw.read(self, SIZEOF_FILEHEAD14)?;
            let hd = &mut self.file_head;
            hd.reset();
            hd.base.header_type = HEAD_FILE;
            hd.data_size = raw.get4();
            hd.unp_size = i64::from(raw.get4());
            hd.file_hash.kind = HashType::Rar14;
            hd.file_hash.crc32 = u32::from(raw.get2());
            hd.base.head_size = u32::from(raw.get2());
            if hd.base.head_size < 21 {
                return Ok(0);
            }
            let file_time = raw.get4();
            hd.file_attr = u32::from(raw.get1());
            hd.base.flags = u32::from(raw.get1()) | LONG_BLOCK;
            hd.unp_ver = if raw.get1() == 2 { 13 } else { 10 };
            let name_size = usize::from(raw.get1());
            hd.method = raw.get1();

            let flags = hd.base.flags;
            hd.split_before = flags & LHD_SPLIT_BEFORE != 0;
            hd.split_after = flags & LHD_SPLIT_AFTER != 0;
            hd.encrypted = flags & LHD_PASSWORD != 0;
            hd.crypt_method = if hd.encrypted {
                CryptMethod::Rar13
            } else {
                CryptMethod::None
            };
            hd.pack_size = i64::from(hd.data_size);
            hd.win_size = 0x10000;
            hd.dir = hd.file_attr & 0x10 != 0;
            hd.host_os = HOST_MSDOS;
            hd.hs_type = HostSystem::Windows;
            hd.mtime.set_dos(file_time);

            raw.read(self, name_size)?;
            let hd = &mut self.file_head;
            let mut file_name = vec![0u8; name_size];
            raw.get_b(&mut file_name);
            hd.file_name = char_to_wide(&file_name);
            convert_file_header(&mut hd.file_name, Format::Rar14, hd.hs_type);

            if raw.size() != 0 {
                self.next_block_pos =
                    self.cur_block_pos + i64::from(hd.base.head_size) + hd.pack_size;
            }
            self.cur_header_type = HEAD_FILE;
        }
        Ok(if self.next_block_pos > self.cur_block_pos {
            raw.size()
        } else {
            0
        })
    }
}

/// Whether a password check value is what its 4-byte checksum, the start
/// of its SHA-256, says.
fn psw_check_valid(psw_check: &[u8; SIZE_PSWCHECK], csum: &[u8; SIZE_PSWCHECK_CSUM]) -> bool {
    let mut sha = Sha256::new();
    sha.update(psw_check);
    sha.out()[..SIZE_PSWCHECK_CSUM] == csum[..]
}
