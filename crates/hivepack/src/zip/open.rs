//! Opening an archive: port of `zip_open.c`, with `zip_new.c`.
//!
//! As in libzip, the functions that look for the central directory take
//! the error as an out-parameter: an end of central directory record that
//! turns out unusable may set it, and the search then goes on, so the error
//! reported is the last one set.

use crate::deflate::{Library, crc32};

use crate::threads::Threads;
use crate::zip::buffer::Buffer;
use crate::zip::dirent::{Dirent, check_consistency};
use crate::zip::error::{
    Detail, Error, ErrorCode, Result, add_index_to_detail, make_detail_with_index,
};
use crate::zip::extra_field::EFBIG;
use crate::zip::hash::Names;
use crate::zip::random::RandomSource;
use crate::zip::source::{ReadAt, Source, Whence, stat};
use crate::zip::string::{ZipString, string_equal, string_get, string_length};
use crate::zip::zip::{ArchiveFlags, Flags, OpenFlags};
use crate::zip::zipint::Password;
use crate::zip::zipint::{
    CDBUFSIZE, CDENTRYSIZE, CENTRAL_MAGIC, Cdir, EOCD_MAGIC, EOCD64_MAGIC, EOCD64LEN,
    EOCD64LOC_MAGIC, EOCD64LOCLEN, EOCDLEN, Entry, GPBF_DATA_DESCRIPTOR, LENTRYSIZE, LOCAL_MAGIC,
    MAGIC_LEN, TORRENTZIP_CRC_LENGTH, TORRENTZIP_SIGNATURE, TORRENTZIP_SIGNATURE_LENGTH,
};

/// An open archive: `struct zip`. It can be cloned, with its changes, when
/// its source can.
#[derive(Clone)]
pub struct Archive<R> {
    /// data source for archive
    pub(crate) src: Source<R>,
    /// flags passed to zip_open
    pub(crate) open_flags: OpenFlags,
    /// archive global flags
    pub(crate) flags: ArchiveFlags,
    /// changed archive global flags
    pub(crate) ch_flags: ArchiveFlags,
    /// archive comment
    pub(crate) comment_orig: Option<ZipString>,
    /// changed archive comment
    pub(crate) comment_changes: Option<ZipString>,
    /// whether archive comment was changed
    pub(crate) comment_changed: bool,
    /// entries
    pub(crate) entry: Vec<Entry>,
    /// hash table for name lookup
    pub(crate) names: Names,
    /// password used when no other supplied
    pub(crate) default_password: Option<Password>,
    /// where encrypting takes its random bytes from, if not the system
    pub(crate) random: Option<RandomSource>,
    /// how many threads compress new data when the archive is written: not
    /// in libzip
    pub(crate) threads: Threads,
    /// whether new data is deflated in blocks, as pigz does: not in libzip
    pub(crate) deflate_blocks: bool,
    /// whose compressor deflates new data: not in libzip
    pub(crate) deflate_library: Library,
}

/// What `_zip_read_eocd64` found.
enum CdirStatus {
    Ok,
    Invalid,
    NotFound,
}

/// What `_zip_read_cdir` decided: `false`, go on looking for an earlier end
/// of central directory record, or `true`, stop, with the directory or,
/// if it is unusable, `None` and the error set.
enum Search {
    Continue,
    Stop(Option<Cdir>),
}

impl<R: ReadAt> Archive<R> {
    /// Opens the archive in `src`: port of `zip_open_from_source` and
    /// `_zip_open`. With [`OpenFlags::CHECKCONS`], every local header is
    /// compared with the central directory, and more is checked. Unless
    /// [`OpenFlags::RDONLY`] is given, the archive can be changed, and
    /// [`Archive::close_to`] writes it. A source that is not there, whose
    /// length fails with `ENOENT`, is refused with `ZIP_ER_NOENT`, or with
    /// [`OpenFlags::CREATE`] taken as an empty archive.
    ///
    /// Differs from libzip: the source is only read, as the archive is
    /// written elsewhere.
    pub fn open(src: R, flags: OpenFlags) -> Result<Archive<R>> {
        if flags.contains(OpenFlags::RDONLY | OpenFlags::TRUNCATE) {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        // _zip_file_exists
        let len = match stat(&src) {
            Ok(len) => len,
            Err(e) if e.code() == ErrorCode::Read && e.system() == ENOENT => {
                if !flags.intersects(OpenFlags::CREATE) {
                    return Err(Error::new(ErrorCode::NoEntry, 0));
                }
                return Ok(Archive::allocate_new(Source::with_size(src, 0), flags));
            }
            Err(e) => return Err(e),
        };

        if flags.intersects(OpenFlags::EXCL) {
            return Err(Error::new(ErrorCode::Exists, 0));
        }

        let src = Source::with_size(src, len);
        if flags.intersects(OpenFlags::TRUNCATE) {
            return Ok(Archive::allocate_new(src, flags));
        }
        // ZIP_CREATE gets ignored if file exists and not ZIP_EXCL, just
        // like open()
        Archive::open_source(src, flags)
    }

    /// Port of `_zip_open`.
    fn open_source(src: Source<R>, flags: OpenFlags) -> Result<Archive<R>> {
        let len = src.size();
        let mut za = Archive::allocate_new(src, flags);

        // treat empty files as empty archives
        if len == 0 && za.src.accept_empty() {
            return Ok(za);
        }

        za.src.start_read_ahead();
        let found = za.find_central_dir(len);
        za.src.stop_read_ahead();
        let cdir = match found {
            Ok(cdir) => cdir,
            Err(e) => {
                // not a zip - find out if it's truncated
                if e.code() == ErrorCode::NoZip && za.is_truncated_zip() {
                    return Err(Error::new(ErrorCode::TruncatedZip, 0));
                }
                return Err(e);
            }
        };

        let is_torrentzip = za.check_torrentzip(&cdir);
        let Cdir { entry, comment, .. } = cdir;
        za.entry = entry;
        if is_torrentzip {
            // Torrentzip uses the archive comment to detect changes by tools
            // that are not torrentzip aware.
            za.flags = za.flags | ArchiveFlags::IS_TORRENTZIP;
        } else {
            za.comment_orig = comment;
        }

        za.names.reserve_capacity(za.entry.len());

        for (idx, entry) in za.entry.iter().enumerate() {
            let name = string_get(
                entry.orig.as_ref().and_then(|de| de.filename.as_ref()),
                Flags::NONE,
            );
            if let Err(e) = za.names.add(name, idx as u64, Flags::UNCHANGED)
                && (e.code() != ErrorCode::Exists || flags.intersects(OpenFlags::CHECKCONS))
            {
                return Err(e);
            }
        }

        za.ch_flags = za.flags;
        Ok(za)
    }

    /// Port of `_zip_allocate_new` and `_zip_new`.
    fn allocate_new(src: Source<R>, flags: OpenFlags) -> Archive<R> {
        let mut za = Archive {
            src,
            open_flags: flags,
            flags: ArchiveFlags(0),
            ch_flags: ArchiveFlags(0),
            comment_orig: None,
            comment_changes: None,
            comment_changed: false,
            entry: Vec::new(),
            names: Names::default(),
            default_password: None,
            random: None,
            threads: Threads::One,
            deflate_blocks: false,
            deflate_library: Library::Zlib,
        };
        if flags.intersects(OpenFlags::RDONLY) {
            za.flags = za.flags | ArchiveFlags::RDONLY;
            za.ch_flags = za.ch_flags | ArchiveFlags::RDONLY;
        }
        za
    }

    /// Whether the source starts with a local header, as a truncated
    /// archive would: port of `_is_truncated_zip`.
    fn is_truncated_zip(&mut self) -> bool {
        let mut data = [0; 4];
        if self.src.seek(0, Whence::Set).is_err() {
            return false;
        }
        matches!(self.src.read(&mut data), Ok(4)) && &data == LOCAL_MAGIC
    }

    /// The central directory: the first end of central directory record,
    /// looking backwards from the end through the last 64 KiB, that leads
    /// to one. Port of `_zip_find_central_dir`.
    fn find_central_dir(&mut self, len: u64) -> Result<Cdir> {
        if len < EOCDLEN {
            return Err(Error::new(ErrorCode::NoZip, 0));
        }

        let buflen = len.min(CDBUFSIZE);
        self.src.seek(-(buflen as i64), Whence::End)?;
        let buf_offset = self.src.tell();

        let mut buffer = Buffer::from_source(&mut self.src, buflen)?;

        if buflen >= CDBUFSIZE {
            // EOCD64 locator is before EOCD, so leave place for it
            buffer.set_offset(EOCD64LOCLEN);
        }
        let mut error = Error::new(ErrorCode::NoZip, 0);

        let mut cdir = None;
        let mut found = None;
        while let Some(at) = find_eocd(buffer.data(), found) {
            found = Some(at);
            buffer.set_offset(at as u64);
            if let Search::Stop(cd) = self.read_cdir(&mut buffer, buf_offset, &mut error) {
                cdir = cd;
                if let Some(cd) = cdir.as_mut()
                    && self.open_flags.intersects(OpenFlags::CHECKCONS)
                    && self.checkcons(cd, &mut error).is_none()
                {
                    cdir = None;
                }
                break;
            }
        }

        cdir.ok_or(error)
    }

    /// Reads the end of central directory record at `buffer`'s position,
    /// then the central directory it points to: port of `_zip_read_cdir`.
    fn read_cdir(&mut self, buffer: &mut Buffer<'_>, buf_offset: u64, error: &mut Error) -> Search {
        let eocd_offset = buffer.offset();
        let checkcons = self.open_flags.intersects(OpenFlags::CHECKCONS);
        let volumes = self.src.volume_starts();

        let Some(mut cd) = read_eocd(buffer, buf_offset, error) else {
            return Search::Continue;
        };

        let mut eocd64_found = false;
        if eocd_offset >= EOCD64LOCLEN {
            let at = (eocd_offset - EOCD64LOCLEN) as usize;
            if &buffer.data()[at..at + 4] == EOCD64LOC_MAGIC {
                eocd64_found = true;
                buffer.set_offset(eocd_offset - EOCD64LOCLEN);
                match read_eocd64(
                    &mut cd,
                    &mut self.src,
                    buffer,
                    buf_offset,
                    self.open_flags,
                    volumes.as_deref(),
                    error,
                ) {
                    CdirStatus::Ok => {}
                    CdirStatus::Invalid => return Search::Stop(None),
                    CdirStatus::NotFound => return Search::Continue,
                }
            }
        }

        // Not in libzip: the archive is on the volumes the source joins,
        // its last disk on the last of them, and its central directory is
        // where its disk says.
        let split = volumes.as_deref().filter(|starts| {
            (cd.eocd_disk != 0 || cd.this_disk != 0) && cd.this_disk as usize + 1 == starts.len()
        });
        if let Some(starts) = split {
            if cd.eocd_disk > cd.this_disk {
                *error = Error::incons(Detail::CdirInvalid);
                return Search::Stop(None);
            }
            if cd.disk_entries > cd.num_entries {
                *error = Error::incons(Detail::CdirWrongEntriesCount);
                return Search::Stop(None);
            }
            match starts[cd.eocd_disk as usize].checked_add(cd.offset) {
                Some(offset) => cd.offset = offset,
                None => {
                    *error = Error::new(ErrorCode::Seek, EFBIG);
                    return Search::Stop(None);
                }
            }
        } else if volumes.is_some() && (cd.eocd_disk != 0 || cd.this_disk != 0) {
            // An archive on more disks than the volumes, or fewer.
            *error = Error::new(ErrorCode::MultiDisk, 0);
            return Search::Stop(None);
        } else if (cd.eocd_disk != 0 || cd.this_disk != 0)
            && !eocd64_found
            && cd.eocd_disk != cd.this_disk
        {
            // If the central directory doesn't start on this disk, we can't
            // check that offset is valid. Check as much as we can instead.
            if cd.this_disk < cd.eocd_disk {
                // Disks before the start of the central directory don't
                // contain an EOCD.
                return Search::Continue;
            }
            if cd.size <= cd.eocd_offset {
                // The complete central directory would fit on this disk.
                return Search::Continue;
            }
        }
        if !eocd64_found {
            if cd.this_disk == 0
                && cd.eocd_disk == 0
                && cd.eocd_offset == 0
                && cd.offset == 0
                && cd.num_entries == 0
            {
                // An empty archive doesn't contain central directory
                // entries.
            } else if !check_magic(cd.offset, buffer, buf_offset, &mut self.src, CENTRAL_MAGIC) {
                return Search::Continue;
            }
        }

        // We accept this EOCD as valid and won't search for an earlier one
        // if it is unusable.

        if !check_eocd(&cd, self.open_flags, split.is_some(), error) {
            return Search::Stop(None);
        }

        buffer.set_offset(eocd_offset + 20);
        let mut comment_len = buffer.get_16();

        if cd.offset + cd.size > buf_offset + eocd_offset {
            // cdir spans past EOCD record
            *error = Error::incons(Detail::CdirOverlapsEocd);
            return Search::Stop(None);
        }

        if comment_len > 0 || checkcons {
            buffer.set_offset(eocd_offset + EOCDLEN);
            let tail_len = buffer.left();

            if tail_len != u64::from(comment_len) {
                if checkcons {
                    *error = Error::incons(Detail::CommentLengthInvalid);
                    return Search::Stop(None);
                }
                if tail_len < u64::from(comment_len) {
                    comment_len = tail_len as u16;
                }
            }

            if comment_len > 0 {
                let raw = buffer.get(u64::from(comment_len)).unwrap_or(&[]);
                match ZipString::new(raw, Flags::ENC_GUESS) {
                    Ok(comment) => cd.comment = comment,
                    Err(e) => {
                        *error = e;
                        return Search::Stop(None);
                    }
                }
            }
        }

        let mut cd_data = None;
        if cd.offset >= buf_offset {
            // if buffer already read in, use it
            buffer.set_offset(cd.offset - buf_offset);
            match buffer.get(cd.size) {
                Some(data) => cd_data = Some(data.to_vec()),
                None => {
                    *error = Error::incons(Detail::CdirLengthInvalid);
                    return Search::Stop(None);
                }
            }
        } else {
            if let Err(e) = self.src.seek(cd.offset as i64, Whence::Set) {
                *error = e;
                return Search::Stop(None);
            }

            // possible consistency check: cd->offset =
            // len-(cd->size+cd->comment_len+EOCDLEN) ?
            if self.src.tell() != cd.offset {
                *error = Error::new(ErrorCode::NoZip, 0);
                return Search::Stop(None);
            }
        }
        let mut cd_buffer = cd_data.as_deref().map(Buffer::new);

        let num_entries = cd.num_entries;
        if let Err(e) = cdir_grow(&mut cd, num_entries) {
            *error = e;
            return Search::Stop(None);
        }
        let mut left = cd.size;
        let mut i = 0;
        while left > 0 {
            let mut grown = false;

            if i == cd.entry.len() {
                // InfoZIP has a hack to avoid using Zip64: it stores
                // nentries % 0x10000. This hack isn't applicable if we're
                // using Zip64, or if there is no central directory entry
                // following.
                if cd.is_zip64 || left < CDENTRYSIZE {
                    break;
                }
                if let Err(e) = cdir_grow(&mut cd, 0x10000) {
                    *error = e;
                    return Search::Stop(None);
                }
                grown = true;
            }

            match Dirent::read(
                &mut self.src,
                cd_buffer.as_mut(),
                false,
                cd.is_zip64,
                0,
                checkcons,
                error,
            ) {
                Some((dirent, entry_size)) => {
                    cd.entry[i].orig = Some(dirent);
                    i += 1;
                    left = left.wrapping_sub(entry_size);
                }
                None => {
                    if error.code() == ErrorCode::Incons {
                        *error = Error::new(
                            ErrorCode::Incons,
                            add_index_to_detail(error.system(), i as u64),
                        );
                    } else if grown && error.code() == ErrorCode::NoZip {
                        *error = Error::incons_at(Detail::CdirEntryInvalid, i as u64);
                    }
                    return Search::Stop(None);
                }
            }
        }

        // If we didn't fill all we grew, cd->num_entries was wrong.
        if i != cd.entry.len() || left > 0 {
            *error = Error::incons(Detail::CdirWrongEntriesCount);
            return Search::Stop(None);
        }

        // Not in libzip: each local header is on the disk its entry says,
        // at an offset from the disk's start, which becomes one from the
        // start of the first; the entry is then as on a single disk.
        if let Some(starts) = split {
            for (i, entry) in cd.entry.iter_mut().enumerate() {
                let Some(de) = entry.orig.as_mut() else {
                    continue;
                };
                let Some(&start) = starts.get(de.disk_number as usize) else {
                    *error = Error::incons_at(Detail::CdirInvalid, i as u64);
                    return Search::Stop(None);
                };
                let Some(offset) = start.checked_add(de.offset) else {
                    *error = Error::new(ErrorCode::Seek, EFBIG);
                    return Search::Stop(None);
                };
                de.offset = offset;
                de.disk_number = 0;
            }
        }

        if checkcons {
            let ok = match &cd_buffer {
                Some(cd_buffer) => cd_buffer.eof(),
                None => self.src.tell() == cd.offset + cd.size,
            };
            if !ok {
                *error = Error::incons(Detail::CdirLengthInvalid);
                return Search::Stop(None);
            }
        }

        Search::Stop(Some(cd))
    }

    /// Compares each central directory entry with its local header, and
    /// checks that the entries lie before the central directory. Returns the
    /// span of the entries, or `None` with `error` set. Port of
    /// `_zip_checkcons`.
    fn checkcons(&mut self, cd: &mut Cdir, error: &mut Error) -> Option<i64> {
        let (mut min, mut max) = match cd.entry.first().and_then(|e| e.orig.as_ref()) {
            Some(first) => (first.offset, first.offset),
            None => (0, 0),
        };

        // Currently we use the presence of a Zip64 End of Central Directory
        // do decide if the archive is Zip64 and use that to decide the size
        // of data descriptors in local headers. This is not guaranteed to be
        // correct. We could also assume Zip64 format if any of the central
        // directory entries has a Zip64 extra field.
        //
        // Since we only read local headers when checking consistency, this
        // is not a problem for normal use, but only when checking
        // consistency for archives using data descriptors.

        for i in 0..cd.entry.len() {
            let Some(orig) = cd.entry[i].orig.as_mut() else {
                *error = Error::new(ErrorCode::Internal, 0);
                return None;
            };
            if orig.offset < min {
                min = orig.offset;
            }
            if min > cd.offset {
                *error = Error::new(ErrorCode::NoZip, 0);
                return None;
            }

            let tail_length = u64::from(string_length(orig.filename.as_ref())) + LENTRYSIZE;
            let Some(j) = orig
                .comp_size
                .checked_add(tail_length)
                .and_then(|_| (orig.offset + tail_length).checked_add(orig.comp_size))
            else {
                *error = Error::new(ErrorCode::NoZip, 0);
                return None;
            };

            if j > max {
                max = j;
            }
            if max > cd.offset {
                *error = Error::new(ErrorCode::NoZip, 0);
                return None;
            }

            if let Err(e) = self.src.seek(orig.offset as i64, Whence::Set) {
                *error = e;
                return None;
            }

            let Some((temp, _)) = Dirent::read(
                &mut self.src,
                None,
                true,
                cd.is_zip64,
                orig.comp_size,
                true,
                error,
            ) else {
                if error.code() == ErrorCode::Incons {
                    *error = Error::new(
                        ErrorCode::Incons,
                        add_index_to_detail(error.system(), i as u64),
                    );
                }
                return None;
            };

            if !headercomp(orig, &temp) {
                *error = Error::incons_at(Detail::EntryHeaderMismatch, i as u64);
                return None;
            }

            // The local fields are read now, none if there are none.
            let local = temp.extra_fields.local.into_inner().unwrap_or_default();
            orig.extra_fields.local = std::sync::OnceLock::from(local);

            if let Some(detail) = check_consistency(orig) {
                *error = Error::new(ErrorCode::Incons, make_detail_with_index(detail, i as u64));
                return None;
            }
        }

        Some(i64::try_from(max - min).unwrap_or(i64::MAX))
    }

    /// Whether the archive comment is a valid torrentzip signature, with
    /// the CRC-32 of the central directory: port of `zip_check_torrentzip`,
    /// which sets `ZIP_AFL_IS_TORRENTZIP`.
    fn check_torrentzip(&mut self, cdir: &Cdir) -> bool {
        let Some(comment) = cdir.comment.as_ref() else {
            return false;
        };
        let raw = comment.raw();
        if raw.len() != TORRENTZIP_SIGNATURE_LENGTH + TORRENTZIP_CRC_LENGTH
            || !raw.starts_with(TORRENTZIP_SIGNATURE)
        {
            return false;
        }

        let buf = &raw[TORRENTZIP_SIGNATURE_LENGTH..];
        let mut crc_should: u32 = 0;
        for pair in buf.chunks(2) {
            let (Some(high), Some(low)) = (decode_hex(pair[0]), decode_hex(pair[1])) else {
                return false;
            };
            crc_should = (crc_should << 8) + (high << 4) + low;
        }

        // The central directory read through a window of the source, and
        // its CRC-32 checked, as libzip does with a window and a CRC source.
        if i64::try_from(cdir.offset).is_err()
            || self.src.seek(cdir.offset as i64, Whence::Set).is_err()
        {
            return false;
        }
        let mut crc = 0;
        let mut left = cdir.size;
        let mut buffer = [0; 512];
        while left > 0 {
            let want = left.min(buffer.len() as u64) as usize;
            match self.src.read(&mut buffer[..want]) {
                Ok(n) if n > 0 => {
                    crc = crc32(crc, &buffer[..n]);
                    left -= n as u64;
                }
                _ => return false,
            }
        }
        // TODO in libzip: if check consistency, check cdir entries for
        // valid values
        crc == crc_should
    }
}

/// `ENOENT`.
const ENOENT: i32 = 2;

/// `decode_hex`: an upper-case hexadecimal digit.
fn decode_hex(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'A'..=b'F' => Some(u32::from(c - b'A' + 10)),
        _ => None,
    }
}

/// Grows the entries by `additional_entries` empty ones: port of
/// `_zip_cdir_grow`, failing with `ZIP_ER_MEMORY` as `zip_realloc` does.
fn cdir_grow(cd: &mut Cdir, additional_entries: u64) -> Result<()> {
    let Ok(additional) = usize::try_from(additional_entries) else {
        return Err(Error::new(ErrorCode::Memory, 0));
    };
    if cd.entry.try_reserve_exact(additional).is_err() {
        return Err(Error::new(ErrorCode::Memory, 0));
    }
    cd.entry
        .resize_with(cd.entry.len() + additional, Entry::default);
    Ok(())
}

/// Whether `magic` is at `offset` in the file, looked for in `buffer`
/// (which starts at `buffer_offset`) if it is there, else in `src`: port of
/// `check_magic`.
fn check_magic<R: ReadAt + ?Sized>(
    offset: u64,
    buffer: &mut Buffer<'_>,
    buffer_offset: u64,
    src: &mut Source<R>,
    magic: &[u8; 4],
) -> bool {
    if buffer_offset <= offset {
        if !buffer.set_offset(offset - buffer_offset) {
            return false;
        }
        return buffer.get(MAGIC_LEN) == Some(&magic[..]);
    }
    let mut data = [0; 4];
    if src.seek(offset as i64, Whence::Set).is_err() || !matches!(src.read(&mut data), Ok(4)) {
        return false;
    }
    &data == magic
}

/// The position of the last end of central directory signature in `data`
/// before `last`, or the last of all: port of `find_eocd`.
fn find_eocd(data: &[u8], last: Option<usize>) -> Option<usize> {
    let start = match last {
        None => data.len().checked_sub(MAGIC_LEN as usize)?,
        Some(0) => return None,
        Some(last) => last - 1,
    };
    (0..=start).rev().find(|&p| &data[p..p + 4] == EOCD_MAGIC)
}

/// The end of central directory record at `buffer`'s position: port of
/// `_zip_read_eocd`.
fn read_eocd(buffer: &mut Buffer<'_>, buf_offset: u64, error: &mut Error) -> Option<Cdir> {
    if buffer.left() < EOCDLEN {
        *error = Error::incons(Detail::EocdLengthInvalid);
        return None;
    }

    let eocd_offset = buf_offset + buffer.offset();
    // This function is only called where EOCD magic was found, so no need
    // to check that here.
    buffer.skip(MAGIC_LEN);
    let this_disk = u32::from(buffer.get_16());
    let eocd_disk = u32::from(buffer.get_16());
    // number of cdir-entries on this disk
    let disk_entries = u64::from(buffer.get_16());
    // number of cdir-entries
    let num_entries = u64::from(buffer.get_16());
    let size = u64::from(buffer.get_32());
    let offset = u64::from(buffer.get_32());

    Some(Cdir {
        entry: Vec::new(),
        this_disk,
        eocd_disk,
        disk_entries,
        num_entries,
        size,
        offset,
        eocd_offset,
        comment: None,
        is_zip64: false,
    })
}

/// Port of `check_eocd`. Differs from libzip: the archive may be on
/// several disks if it is `split` (read from the volumes it is on).
fn check_eocd(cd: &Cdir, flags: OpenFlags, split: bool, error: &mut Error) -> bool {
    if !split && (cd.disk_entries != cd.num_entries || cd.this_disk != 0 || cd.eocd_disk != 0) {
        *error = Error::new(ErrorCode::MultiDisk, 0);
        return false;
    }

    let Some(end) = cd.offset.checked_add(cd.size) else {
        *error = Error::new(ErrorCode::Seek, EFBIG);
        return false;
    };

    if flags.intersects(OpenFlags::CHECKCONS) && end != cd.eocd_offset {
        *error = Error::incons(Detail::CdirOverlapsEocd);
        return false;
    }

    true
}

/// The Zip64 end of central directory record, through the locator at
/// `buffer`'s position: port of `_zip_read_eocd64`. Differs from libzip:
/// the archive may be on as many disks as there are `volumes`, where each
/// starts, and the record on any of them.
fn read_eocd64<R: ReadAt + ?Sized>(
    cdir: &mut Cdir,
    src: &mut Source<R>,
    buffer: &mut Buffer<'_>,
    buf_offset: u64,
    flags: OpenFlags,
    volumes: Option<&[u64]>,
    error: &mut Error,
) -> CdirStatus {
    // The offset of the end of the buffer is less than ZIP_UINT64_MAX, so
    // this can't overflow.
    let eocdloc_offset = buf_offset + buffer.offset();

    buffer.get(4); // magic already verified

    let eocd_disk = buffer.get_32();
    let mut eocd_offset = buffer.get_64();
    let num_disks = buffer.get_32();

    // Not in libzip: on the disk the locator says, of the volumes.
    let split = volumes.filter(|starts| num_disks != 1 && num_disks as usize == starts.len());
    if let Some(starts) = split {
        match starts
            .get(eocd_disk as usize)
            .and_then(|start| start.checked_add(eocd_offset))
        {
            Some(offset) => eocd_offset = offset,
            None => return CdirStatus::NotFound,
        }
    }
    if num_disks != 1 && volumes.is_some() && split.is_none() {
        // An archive on more disks than the volumes, or fewer.
        *error = Error::new(ErrorCode::MultiDisk, 0);
        return CdirStatus::Invalid;
    }

    if !check_magic(eocd_offset, buffer, buf_offset, src, EOCD64_MAGIC) {
        return CdirStatus::NotFound;
    }

    if num_disks != 1 && split.is_none() {
        *error = Error::new(ErrorCode::MultiDisk, 0);
        return CdirStatus::Invalid;
    }

    // valid seek value for start of EOCD
    if eocd_offset > i64::MAX as u64 {
        *error = Error::new(ErrorCode::Seek, EFBIG);
        return CdirStatus::Invalid;
    }

    // does EOCD fit before EOCD locator?
    if eocd_offset + EOCD64LEN > eocdloc_offset {
        *error = Error::incons(Detail::Eocd64OverlapsEocd);
        return CdirStatus::Invalid;
    }

    // make sure current position of buffer is beginning of EOCD
    let mut own;
    let eocd: &mut Buffer<'_> =
        if eocd_offset >= buf_offset && eocd_offset + EOCD64LEN <= buf_offset + buffer.size() {
            buffer.set_offset(eocd_offset - buf_offset);
            buffer
        } else {
            if let Err(e) = src.seek(eocd_offset as i64, Whence::Set) {
                *error = e;
                return CdirStatus::Invalid;
            }
            match Buffer::from_source(src, EOCD64LEN) {
                Ok(b) => {
                    own = b;
                    &mut own
                }
                Err(e) => {
                    *error = e;
                    return CdirStatus::Invalid;
                }
            }
        };

    if eocd.get(4) != Some(&EOCD64_MAGIC[..]) {
        *error = Error::incons(Detail::Eocd64WrongMagic);
        return CdirStatus::Invalid;
    }

    // size of EOCD
    let size = eocd.get_64();

    // Is there a hole between EOCD and EOCD locator, or do they overlap?
    // Also check for overflow.
    if flags.intersects(OpenFlags::CHECKCONS)
        && size.checked_add(eocd_offset + 12) != Some(eocdloc_offset)
    {
        *error = Error::incons(Detail::Eocd64OverlapsEocd);
        return CdirStatus::Invalid;
    }

    eocd.get(4); // skip version made by/needed

    let this_disk = eocd.get_32();
    if eocd.get_32() != eocd_disk {
        *error = Error::incons(Detail::Eocd64LocatorMismatch);
        return CdirStatus::Invalid;
    }

    let i = eocd.get_64();
    let nentry = eocd.get_64();

    if nentry != i && split.is_none() {
        *error = Error::new(ErrorCode::MultiDisk, 0);
        return CdirStatus::Invalid;
    }

    let size = eocd.get_64();
    let offset = eocd.get_64();

    // did we read past the end of the buffer?
    if !eocd.ok() {
        *error = Error::new(ErrorCode::Internal, 0);
        return CdirStatus::Invalid;
    }

    if offset > i64::MAX as u64 || offset.checked_add(size).is_none() {
        *error = Error::new(ErrorCode::Seek, EFBIG);
        return CdirStatus::Invalid;
    }

    if nentry > size / CDENTRYSIZE {
        *error = Error::incons(Detail::CdirInvalid);
        return CdirStatus::Invalid;
    }

    if (cdir.size != 0xffff_ffff && cdir.size != size)
        || (cdir.offset != 0xffff_ffff && cdir.offset != offset)
        || (cdir.num_entries != 0xffff && cdir.num_entries != nentry)
        || (cdir.disk_entries != 0xffff && cdir.disk_entries != i)
        || (cdir.this_disk != 0xffff && cdir.this_disk != this_disk)
        || (cdir.eocd_disk != 0xffff && cdir.eocd_disk != eocd_disk)
    {
        *error = Error::incons(Detail::Eocd64Mismatch);
        return CdirStatus::Invalid;
    }

    cdir.is_zip64 = true;
    cdir.size = size;
    cdir.offset = offset;
    cdir.disk_entries = i;
    cdir.num_entries = nentry;
    cdir.this_disk = this_disk;
    cdir.eocd_disk = eocd_disk;
    cdir.eocd_offset = eocd_offset;

    CdirStatus::Ok
}

/// Whether a central directory entry and its local header agree: port of
/// `_zip_headercomp`.
fn headercomp(central: &Dirent, local: &Dirent) -> bool {
    // Some zip-files have different values in local and global headers for
    // the bitflags; libzip does not compare them.
    if central.version_needed < local.version_needed
        || central.comp_method != local.comp_method
        || central.last_mod.time != local.last_mod.time
        || central.last_mod.date != local.last_mod.date
        || !string_equal(central.filename.as_ref(), local.filename.as_ref())
    {
        return false;
    }

    if central.crc != local.crc
        || central.comp_size != local.comp_size
        || central.uncomp_size != local.uncomp_size
    {
        // InfoZip stores valid values in local header even when data
        // descriptor is used. This is in violation of the appnote. macOS
        // Archive sets the compressed size even when data descriptor is
        // used (but not the others), also in violation of the appnote.

        // if data descriptor is not used, the values must match
        if local.bitflags & GPBF_DATA_DESCRIPTOR == 0 {
            return false;
        }
        // when using a data descriptor, the local header value must be zero
        // or match
        if (local.crc != 0 && central.crc != local.crc)
            || (local.comp_size != 0 && central.comp_size != local.comp_size)
            || (local.uncomp_size != 0 && central.uncomp_size != local.uncomp_size)
        {
            return false;
        }
    }

    true
}
