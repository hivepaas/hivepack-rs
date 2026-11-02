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
//! Going through an archive's entries: UnRAR's `CmdExtract` (extract.cpp)
//! and the reading and writing of `ComprDataIO` (rdwrfn.cpp), as they are
//! when testing an archive: each entry's data is read, given to a callback
//! and checked against its hash, and nothing is created.

use std::io;

use crate::rar::archive::Archive;
use crate::rar::crypt::{CryptData, set_crypt_keys};
use crate::rar::error::{Error, ExitCode};
use crate::rar::hash::DataHash;
use crate::rar::headers::{CryptMethod, Format, HEAD_ENDARC, HEAD_FILE, Redirection};
use crate::rar::name::convert_path;
use crate::rar::source::ReadAt;
use crate::rar::unpack::{UnpIo, Unpack};

/// A size at a time. `File::CopyBufferSize`'s is larger, which makes no
/// difference to what comes out.
const COPY_BUFFER_SIZE: usize = 64 << 10;

/// `VER_UNPACK`.
const VER_UNPACK: u32 = 29;
/// `VER_UNPACK7`.
const VER_UNPACK7: u32 = 70;

/// `ComprDataIO`, for an entry that is whole in this volume.
pub(crate) struct DataIo<'a, 'o, R: ReadAt> {
    pub(crate) arc: &'a mut Archive<R>,
    /// `UnpPackedLeft`: below 0 only in the case `unp_read` tells of.
    pub(crate) packed_left: i64,
    pub(crate) hash: &'a mut DataHash,
    pub(crate) out: &'a mut Output<'o>,
    pub(crate) skip_unp_crc: bool,
    pub(crate) cur_unp_write: &'a mut u64,
    pub(crate) decrypt: Option<CryptData>,
    /// `UnpVolume`: the data goes on in the next volume.
    pub(crate) unp_volume: bool,
    /// `NextVolumeMissing`.
    pub(crate) next_volume_missing: bool,
}

impl<R: ReadAt> UnpIo for DataIo<'_, '_, R> {
    fn unp_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        let decrypting = self.decrypt.is_some();
        // Whole blocks: what reads here always asks for more than one.
        let mut count = if decrypting {
            buf.len() & !15
        } else {
            buf.len()
        };
        let (mut read, mut total) = (0, 0);
        while count > 0 {
            let mut to_read = (count as i64).min(self.packed_left).max(0) as usize;
            if to_read > 0 {
                if self.unp_volume && decrypting && count as i64 > self.packed_left {
                    // Aligned blocks for decrypting: the next volume is only
                    // asked for over the last few bytes, when what can be had
                    // from this one has been had.
                    let new_total = total + to_read;
                    let new_to_read = to_read.wrapping_sub(new_total & 15);
                    if new_to_read as i32 > 0 {
                        to_read = new_to_read;
                    }
                }
                read = self.arc.read(&mut buf[total..total + to_read])?;
            }
            // With nothing to read this is what was read the last time, as in
            // UnRAR, when a next volume has no data after an unaligned read.
            // UnRAR then goes on to read without end into its buffer, with the
            // size below 0: `to_read` of nothing above, here.
            total = (total + read).min(buf.len());
            count = count.saturating_sub(read);
            self.packed_left -= read as i64;

            // Not asked for if this volume gave something, unless decrypting
            // has an incomplete block.
            if self.unp_volume
                && self.packed_left == 0
                && (read == 0 || decrypting && total & 15 != 0)
            {
                match self.arc.merge_archive()? {
                    Some((unp_volume, packed_size)) => {
                        self.unp_volume = unp_volume;
                        self.packed_left = packed_size as i64;
                    }
                    None => {
                        self.next_volume_missing = true;
                        return Ok(None);
                    }
                }
            } else {
                break;
            }
        }
        if let Some(decrypt) = &mut self.decrypt {
            decrypt.decrypt_block(buf, total);
        }
        Ok(Some(total))
    }

    fn unp_write(&mut self, data: &[u8]) -> Result<(), Error> {
        (self.out)(data)?;
        *self.cur_unp_write += data.len() as u64;
        if !self.skip_unp_crc {
            self.hash.update(data);
        }
        Ok(())
    }
}

/// `MAXPATHSIZE`: the longest target of a RAR 4 link.
const MAX_PATH_SIZE: i64 = 0x10000;

/// Where an entry's data goes.
pub type Output<'a> = dyn FnMut(&[u8]) -> io::Result<()> + 'a;

/// `CmdExtract`: what lasts from one entry to the next, and what became of
/// the last entry.
#[derive(Debug)]
pub struct Extract {
    /// The largest dictionary an entry may ask for, stored or not: over it
    /// the extraction stops, as `CheckWinLimit` stops it when nobody allows
    /// more. By default what UnRAR allows, 4 GiB.
    pub win_size_limit: u64,
    /// Goes through the entries without decompressing or giving out any data:
    /// what is read and what is passed over are as when reading it, as what
    /// follows a directory's header or a split entry's end depends on that, so
    /// that a caller sees the entries a reading will see. Data is not checked.
    pub headers_only: bool,
    /// Reads the target of a RAR 4 Unix link, which is kept as its data, into
    /// [`link_target`](Extract::link_target), and checks it: `ExtractUnixLink30`.
    /// Otherwise links are as when testing, which passes over it.
    pub link_targets: bool,
    /// The last entry's target, with [`link_targets`](Extract::link_targets).
    pub link_target: Vec<u8>,
    /// Whether that target is too long to be one or is cut short.
    pub bad_link_target: bool,
    /// How many bytes of the last entry were given out: `CurUnpWrite`.
    pub cur_unp_write: u64,
    /// Whether the last entry's data was skipped over, as the data before a
    /// wanted entry of a solid archive is. The data is still given out, as
    /// UnRAR's library gives it out, and has not been checked.
    pub skip_solid: bool,
    /// Whether the last entry's hash was checked and failed.
    pub broken_file: bool,
    /// Whether the last entry was encrypted and there was no password: the
    /// going through stops there, as `ERAR_MISSING_PASSWORD` stops it.
    pub missing_password: bool,
    /// Whether RAR 5's check says the password is not the last entry's: its
    /// data is not read, unless a solid stream needs it to go on.
    pub bad_password: bool,
    /// Whether the last entry goes on from a volume before the first one seen:
    /// `ERAR_BAD_DATA`, with the exit code [`ExitCode::Open`].
    pub needs_previous_volume: bool,
    /// Whether a next volume was wanted and is not there: `ERAR_EOPEN`, with
    /// the exit code [`ExitCode::Open`].
    pub missing_volume: bool,
    /// Whether the last entry's dictionary is over `win_size_limit`.
    pub dictionary_too_large: bool,
    /// Whether the last entry is of a version or an encryption not known.
    pub unknown_format: bool,
    /// `Unp`: made when first needed, and it lasts for a solid archive's sake.
    unp: Option<Box<Unpack>>,
    /// `FileCount`: the entries gone through that were to be read.
    file_count: u32,
    /// `DataIO.UnpVolume`.
    unp_volume: bool,
    /// `FirstFile`: nothing was gone through yet.
    gone_through: bool,
}

impl Default for Extract {
    fn default() -> Extract {
        Extract {
            win_size_limit: 0x1_0000_0000,
            headers_only: false,
            link_targets: false,
            link_target: Vec::new(),
            bad_link_target: false,
            cur_unp_write: 0,
            skip_solid: false,
            broken_file: false,
            missing_password: false,
            bad_password: false,
            needs_previous_volume: false,
            missing_volume: false,
            dictionary_too_large: false,
            unknown_format: false,
            unp: None,
            file_count: 0,
            unp_volume: false,
            gone_through: false,
        }
    }
}

impl Extract {
    /// Nothing done yet.
    pub fn new() -> Extract {
        Extract::default()
    }

    /// `CmdExtract::ExtractCurrentFile` when testing: what to do with the
    /// header [`Archive::read_header`] just read, whose result is
    /// `header_size`. Whether to go on with the next header.
    ///
    /// A file's data goes to `out`, in pieces; a directory, a link or
    /// anything else has none. A hash that fails sets the exit code to
    /// [`ExitCode::Crc`] and the reading goes on, as UnRAR's does.
    ///
    /// # Errors
    ///
    /// [`Error::NoMemory`] when a dictionary cannot be had: it stops
    /// everything, as `bad_alloc` does in UnRAR.
    /// [`Error::Io`] when the archive cannot be read or `out` fails.
    pub fn current_file<R: ReadAt>(
        &mut self,
        arc: &mut Archive<R>,
        header_size: usize,
        out: &mut Output<'_>,
    ) -> Result<bool, Error> {
        self.cur_unp_write = 0;
        self.skip_solid = false;
        self.broken_file = false;
        self.missing_password = false;
        self.bad_password = false;
        self.needs_previous_volume = false;
        self.missing_volume = false;
        self.dictionary_too_large = false;
        self.unknown_format = false;
        self.link_target.clear();
        self.bad_link_target = false;
        if header_size == 0 {
            if !self.unp_volume {
                return Ok(false);
            }
            // An old volume without an end of archive record, whose last file
            // is not split.
            match arc.merge_archive()? {
                Some((unp_volume, _)) => self.unp_volume = unp_volume,
                None => {
                    self.missing_volume = true;
                    arc.set_error_code(ExitCode::Warning);
                    return Ok(false);
                }
            }
        }
        let header_type = arc.cur_header_type;
        if header_type != HEAD_FILE {
            if header_type == HEAD_ENDARC {
                if !arc.end_arc_head.next_volume {
                    return Ok(false);
                }
                match arc.merge_archive()? {
                    Some((unp_volume, _)) => self.unp_volume = unp_volume,
                    None => {
                        self.missing_volume = true;
                        arc.set_error_code(ExitCode::Warning);
                        return Ok(false);
                    }
                }
                arc.seek(arc.cur_block_pos as u64);
                return Ok(true);
            }
            arc.seek_to_next();
            return Ok(true);
        }

        let head = &arc.file_head;
        let named = !convert_path(&head.file_name).is_empty();
        let (redir_type, dir, split_before) = (head.redir_type, head.dir, head.split_before);
        self.unp_volume = head.split_after;

        // `Arc.Seek(Arc.NextBlockPos-Arc.FileHead.PackSize,SEEK_SET)`: the end
        // of the header, as the next position is the header's end plus the
        // pack size, or reading the header would have failed. So this always
        // moves forward from the header's start.
        arc.seek((arc.next_block_pos - arc.file_head.pack_size) as u64);

        // The first file going on from a volume that is not here.
        let mut matched = true;
        if !self.gone_through && split_before {
            self.needs_previous_volume = true;
            arc.set_error_code(ExitCode::Open);
            matched = false;
        }
        self.gone_through = true;
        if !matched && !arc.solid {
            arc.seek_to_next();
            return Ok(true);
        }

        // `CheckUnpVer`: stored data does not care about the version. A kind
        // of encryption UnRAR does not know stops even a stored entry, whether
        // or not the entry says it is encrypted.
        let unp_ver = arc.file_head.unp_ver;
        let wrong_ver = arc.file_head.method != 0
            && if arc.format == Format::Rar50 {
                unp_ver > VER_UNPACK7
            } else {
                !(13..=VER_UNPACK).contains(&unp_ver)
            };
        if wrong_ver || arc.file_head.crypt_method == CryptMethod::Unknown {
            self.unknown_format = true;
            arc.set_error_code(ExitCode::Fatal);
            arc.seek_to_next();
            return Ok(!arc.solid);
        }

        // Also excludes names of nothing, like "/" or "../".
        let mut extr_file = matched && named && !split_before;

        let mut decrypt = None;
        let mut hash_key = None;
        if arc.file_head.encrypted {
            if !arc.password.is_set() {
                self.missing_password = true;
                return Ok(false);
            }
            let keys = set_crypt_keys(
                arc.file_head.crypt_method,
                &arc.password,
                &mut arc.kdf_cache,
                arc.file_head.salt_set.then_some(&arc.file_head.salt[..]),
                &arc.file_head.init_v,
                arc.file_head.lg2_count,
            );
            if let Some((crypt, checks)) = keys {
                // A damaged header cannot be relied on for the check value.
                if arc.file_head.use_psw_check
                    && !arc.broken_header
                    && arc.file_head.psw_check != checks.psw_check
                {
                    self.bad_password = true;
                    arc.set_error_code(ExitCode::BadPassword);
                    extr_file = false;
                }
                decrypt = Some(crypt);
                hash_key = Some(checks.hash_key);
            }
        }

        let link_entry = redir_type != Redirection::None;
        if !link_entry || redir_type == Redirection::FileCopy {
            if dir {
                // No seek: what follows a directory's header is read as the
                // next header, whatever its pack size says.
                return Ok(true);
            }
            if extr_file && !self.check_win_limit(arc) {
                return Ok(false);
            }
        }
        if !extr_file && arc.solid {
            self.skip_solid = true;
            extr_file = true;
            if !self.check_win_limit(arc) {
                return Ok(false);
            }
        }
        if !extr_file {
            // Not solid here: solid has just set it.
            arc.seek_to_next();
            return Ok(true);
        }

        self.file_count = self.file_count.wrapping_add(1);

        let mut hash = DataHash::new(arc.file_head.file_hash.kind);
        let mut show_checksum = true;
        let mut next_volume_missing = false;
        if link_entry {
            // Nothing to read for any of them when testing. A kind nobody
            // knows has no checksum to speak of, and RAR 4's links keep
            // their target as data, checked only when extracting.
            if redir_type == Redirection::Unknown || arc.format == Format::Rar15 {
                show_checksum = false;
            }
            if self.link_targets && arc.format == Format::Rar15 {
                let size = arc.file_head.pack_size;
                if size > MAX_PATH_SIZE {
                    self.bad_link_target = true;
                } else {
                    let mut target = vec![0; size as usize];
                    let mut io = DataIo {
                        arc: &mut *arc,
                        packed_left: size,
                        hash: &mut hash,
                        out,
                        skip_unp_crc: self.skip_solid,
                        cur_unp_write: &mut self.cur_unp_write,
                        decrypt,
                        unp_volume: false,
                        next_volume_missing: false,
                    };
                    let read = io.unp_read(&mut target)?.unwrap_or(0);
                    if read == target.len() {
                        // The hash goes up to a zero, and so does the target.
                        let end = target.iter().position(|&b| b == 0).unwrap_or(read);
                        target.truncate(end);
                        hash.update(&target);
                        show_checksum = true;
                        self.link_target = target;
                    } else {
                        self.bad_link_target = true;
                    }
                }
            }
        } else if self.headers_only {
            arc.seek_to_next();
            return Ok(true);
        } else if split_before {
            // What this entry goes on from is not here: nothing to read.
        } else if arc.file_head.method == 0 {
            let packed_left = arc.file_head.pack_size;
            let dest_left = arc.file_head.unp_size as u64;
            let mut io = DataIo {
                arc: &mut *arc,
                packed_left,
                hash: &mut hash,
                out,
                skip_unp_crc: self.skip_solid,
                cur_unp_write: &mut self.cur_unp_write,
                decrypt,
                unp_volume: self.unp_volume,
                next_volume_missing: false,
            };
            unstore_file(&mut io, dest_left)?;
            self.unp_volume = io.unp_volume;
            next_volume_missing = io.next_volume_missing;
        } else {
            let unp = self.unp.get_or_insert_with(|| Box::new(Unpack::new()));
            unp.init(arc.file_head.win_size, arc.file_head.solid)?;
            unp.set_dest_size(arc.file_head.unp_size);
            // RAR 1.3 to 1.5 archives do not set a solid flag per file.
            let (method, solid) = if arc.format != Format::Rar50 && arc.file_head.unp_ver <= 15 {
                (15, self.file_count > 1 && arc.solid)
            } else {
                (arc.file_head.unp_ver, arc.file_head.solid)
            };
            let packed_left = arc.file_head.pack_size;
            let mut io = DataIo {
                arc: &mut *arc,
                packed_left,
                hash: &mut hash,
                out,
                skip_unp_crc: self.skip_solid,
                cur_unp_write: &mut self.cur_unp_write,
                decrypt,
                unp_volume: self.unp_volume,
                next_volume_missing: false,
            };
            unp.do_unpack(method, solid, &mut io)?;
            self.unp_volume = io.unp_volume;
            next_volume_missing = io.next_volume_missing;
        }
        arc.seek_to_next();

        let key = hash_key.filter(|_| arc.file_head.use_hash_key);
        // An entry still going on has a hash of its packed data, if any.
        let valid = !arc.file_head.split_after
            && match &key {
                Some(key) => hash.matches_keyed(&arc.file_head.file_hash, key),
                None => hash.matches(&arc.file_head.file_hash),
            };
        if !self.skip_solid && show_checksum && !valid {
            self.broken_file = true;
            arc.set_error_code(ExitCode::Crc);
        }
        self.missing_volume = next_volume_missing;
        Ok(!next_volume_missing)
    }

    /// `CmdExtract::CheckWinLimit`, where nobody allows more.
    fn check_win_limit<R: ReadAt>(&mut self, arc: &mut Archive<R>) -> bool {
        // `Cmd->WinSize`, the default of the -md switch, is smaller.
        if arc.file_head.win_size <= self.win_size_limit {
            return true;
        }
        self.dictionary_too_large = true;
        arc.set_error_code(ExitCode::Fatal);
        arc.seek_to_next();
        false
    }
}

/// `CmdExtract::UnstoreFile`: up to the pack size is read, and up to the
/// unpacked size written. Neither is negative: the header's reading sees to it.
pub(crate) fn unstore_file<R: ReadAt>(
    io: &mut DataIo<'_, '_, R>,
    mut dest_left: u64,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        let read = io.unp_read(&mut buffer)?.unwrap_or(0);
        if read == 0 {
            return Ok(());
        }
        let write = (read as u64).min(dest_left) as usize;
        if write > 0 {
            io.unp_write(&buffer[..write])?;
            dest_left -= write as u64;
        }
    }
}
