//! Central and local headers: port of `zip_dirent.c`.
//!
//! `read` keeps libzip's error out-parameter: on some failures (a data
//! descriptor that cannot be reached), libzip returns without setting the
//! error, so what the caller reports is what the error held before, and the
//! port reports the same.

use std::io::{Seek, Write};
use std::sync::OnceLock;

use crate::deflate::crc32;

use crate::zip::buffer::Buffer;
use crate::zip::error::{Detail, Error, ErrorCode};
use crate::zip::extra_field::{
    EFBIG, ExtraField, ExtraFields, ef_parse, ef_remove_internal, ef_size, ef_write,
};
use crate::zip::io_util::{read, read_data, read_string};
use crate::zip::source::{ReadAt, Source, Whence};
use crate::zip::source_data::{
    FileAttributes, GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK, file_attributes,
};
use crate::zip::source_write::Output;
use crate::zip::string::{ZipString, guess_encoding, string_crc32, string_equal, string_length};
use crate::zip::zip::{Flags, cm, em, opsys};
use crate::zip::zipint::Password;
use crate::zip::zipint::{
    CDENTRYSIZE, CENTRAL_MAGIC, CM_WINZIP_AES, DATADES_MAGIC, EF_BOTH, EF_CENTRAL, EF_LOCAL,
    EF_UTF_8_COMMENT, EF_UTF_8_NAME, EF_WINZIP_AES, EF_WINZIP_AES_SIZE, EF_ZIP64, EFZIP64SIZE,
    EOCD_MAGIC, EOCD64_MAGIC, EOCD64LEN, EOCD64LOC_MAGIC, EOCD64LOCLEN, EOCDLEN,
    EXT_ATTRIB_DEFAULT, Encoding, FL_DATA_FOLLOWS, FL_FORCE_ZIP64, GPBF_DATA_DESCRIPTOR,
    GPBF_ENCODING_UTF_8, GPBF_ENCRYPTED, GPBF_STRONG_ENCRYPTION, LENTRYSIZE, LOCAL_MAGIC,
    MAGIC_LEN, MAX_DATA_DESCRIPTOR_LENGTH, TORRENTZIP_COMPRESSION_FLAGS, TORRENTZIP_CRC_LENGTH,
    TORRENTZIP_SIGNATURE, TORRENTZIP_SIGNATURE_LENGTH, changed,
};

/// `zip_dostime_t`: a time as MS-DOS keeps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DosTime {
    pub time: u16,
    pub date: u16,
}

/// `ZIP_CM_DEFAULT`: better of deflate or store.
pub(crate) const CM_DEFAULT: i32 = -1;

/// `zip_dirent_t`: a central directory entry or local header, as read, or
/// an entry's changes.
///
/// Differs from libzip: a dirent of changes owns its strings and extra
/// fields, where libzip shares those it has not changed with the original
/// (`cloned`), and whether the local extra fields were read is whether
/// [`ExtraFields::local`] is set (`local_extra_fields_read`).
#[derive(Clone, Debug)]
pub(crate) struct Dirent {
    /// which fields are changed, in a dirent of changes (`ZIP_DIRENT_*`)
    pub changed: u32,
    /// if CRC is valid (sometimes not for encrypted archives)
    pub crc_valid: bool,
    /// (c) version of creator
    pub version_madeby: u16,
    /// (cl) version needed to extract
    pub version_needed: u16,
    /// (cl) general purpose bit flag
    pub bitflags: u16,
    /// (cl) compression method used (uint16 and ZIP_CM_DEFAULT (-1))
    pub comp_method: i32,
    /// (cl) time of last modification
    pub last_mod: DosTime,
    /// (cl) CRC-32 of uncompressed data
    pub crc: u32,
    /// (cl) size of compressed data
    pub comp_size: u64,
    /// (cl) size of uncompressed data
    pub uncomp_size: u64,
    /// (cl) file name
    pub filename: Option<ZipString>,
    /// (cl) extra fields, parsed
    pub extra_fields: ExtraFields,
    /// (c) file comment
    pub comment: Option<ZipString>,
    /// (c) disk number start
    pub disk_number: u32,
    /// (c) internal file attributes
    pub int_attrib: u16,
    /// (c) external file attributes
    pub ext_attrib: u32,
    /// (c) offset of local header
    pub offset: u64,
    /// encryption method, computed from other fields
    pub encryption_method: u16,
    /// file specific encryption password
    pub password: Option<Password>,
    /// level of compression to use (never valid in orig)
    pub compression_level: u32,
    /// cached last_mod in Unix time format, if valid
    pub last_mod_mtime: Option<i64>,
}

impl Default for Dirent {
    /// Port of `_zip_dirent_init`.
    fn default() -> Dirent {
        Dirent {
            changed: 0,
            crc_valid: true,
            version_madeby: 63 | (u16::from(opsys::DEFAULT) << 8),
            version_needed: 10, // 1.0
            bitflags: 0,
            comp_method: CM_DEFAULT,
            last_mod: DosTime::default(),
            crc: 0,
            comp_size: 0,
            uncomp_size: 0,
            filename: None,
            extra_fields: ExtraFields::default(),
            comment: None,
            disk_number: 0,
            int_attrib: 0,
            ext_attrib: EXT_ATTRIB_DEFAULT,
            offset: 0,
            encryption_method: em::NONE,
            password: None,
            compression_level: 0,
            last_mod_mtime: None,
        }
    }
}

impl Dirent {
    /// Reads a central directory entry, or with `local` a local header,
    /// from `buffer` if there is one, else from `src` at its position.
    /// Returns the entry and the bytes it took, or `None` with `error` set
    /// (or, where libzip leaves it, as it was). Port of `_zip_dirent_read`.
    // The fields are read in the order of the header, as in libzip.
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn read<R: ReadAt + ?Sized>(
        src: &mut Source<R>,
        mut buffer: Option<&mut Buffer<'_>>,
        local: bool,
        is_zip64: bool,
        central_compressed_size: u64,
        check_consistency: bool,
        error: &mut Error,
    ) -> Option<(Box<Dirent>, u64)> {
        let size = if local { LENTRYSIZE } else { CDENTRYSIZE };

        // On the stack, and below for what is short: this is done for each
        // entry of the central directory.
        let mut fixed_bytes = [0; CDENTRYSIZE as usize];
        let head = match buffer.as_deref_mut() {
            Some(buffer) => {
                if buffer.left() < size {
                    *error = Error::new(ErrorCode::NoZip, 0);
                    return None;
                }
                read_fixed(buffer, local)
            }
            None => {
                let bytes = &mut fixed_bytes[..size as usize];
                if let Err(e) = read(src, bytes) {
                    *error = e;
                    return None;
                }
                read_fixed(&mut Buffer::new(bytes), local)
            }
        };
        let (mut zde, filename_len, ef_len, comment_len) = match head {
            Ok(head) => head,
            Err(e) => {
                *error = e;
                return None;
            }
        };

        zde.encryption_method = if zde.bitflags & GPBF_ENCRYPTED != 0 {
            if zde.bitflags & GPBF_STRONG_ENCRYPTION != 0 {
                em::UNKNOWN
            } else {
                em::TRAD_PKWARE
            }
        } else {
            em::NONE
        };

        let variable_size = u64::from(filename_len) + u64::from(ef_len) + u64::from(comment_len);

        let lengths = (filename_len, ef_len, comment_len);
        let zde = match buffer {
            Some(buffer) => {
                if buffer.left() < variable_size {
                    *error = Error::incons(Detail::VariableSizeOverflow);
                    return None;
                }
                read_variable(
                    zde,
                    buffer,
                    src,
                    lengths,
                    local,
                    is_zip64,
                    central_compressed_size,
                    check_consistency,
                    error,
                )?
            }
            None => {
                let mut short_bytes = [0; 1024];
                let mut long_bytes;
                let bytes = if variable_size as usize <= short_bytes.len() {
                    &mut short_bytes[..variable_size as usize]
                } else {
                    long_bytes = vec![0; variable_size as usize];
                    &mut long_bytes[..]
                };
                if let Err(e) = read(src, bytes) {
                    *error = e;
                    return None;
                }
                read_variable(
                    zde,
                    &mut Buffer::new(bytes),
                    src,
                    lengths,
                    local,
                    is_zip64,
                    central_compressed_size,
                    check_consistency,
                    error,
                )?
            }
        };
        Some((zde, size + variable_size))
    }
}

/// The fixed part of a directory entry, and the lengths of what follows it: the
/// file name, the extra fields and the comment.
fn read_fixed(fixed: &mut Buffer<'_>, local: bool) -> Result<(Box<Dirent>, u16, u16, u16), Error> {
    let magic: &[u8; 4] = if local { LOCAL_MAGIC } else { CENTRAL_MAGIC };
    if fixed.get(4) != Some(&magic[..]) {
        return Err(Error::new(ErrorCode::NoZip, 0));
    }

    // convert buffercontents to zip_dirent
    let mut zde = Box::<Dirent>::default();
    zde.version_madeby = if local { 0 } else { fixed.get_16() };
    zde.version_needed = fixed.get_16();
    zde.bitflags = fixed.get_16();
    zde.comp_method = i32::from(fixed.get_16());

    zde.last_mod.time = fixed.get_16();
    zde.last_mod.date = fixed.get_16();

    zde.crc = fixed.get_32();
    zde.comp_size = u64::from(fixed.get_32());
    zde.uncomp_size = u64::from(fixed.get_32());

    let filename_len = fixed.get_16();
    let ef_len = fixed.get_16();

    let comment_len;
    if local {
        comment_len = 0;
        zde.disk_number = 0;
        zde.int_attrib = 0;
        zde.ext_attrib = 0;
        zde.offset = 0;
    } else {
        comment_len = fixed.get_16();
        zde.disk_number = u32::from(fixed.get_16());
        zde.int_attrib = fixed.get_16();
        zde.ext_attrib = fixed.get_32();
        zde.offset = u64::from(fixed.get_32());
    }

    if !fixed.ok() {
        return Err(Error::new(ErrorCode::Internal, 0));
    }

    Ok((zde, filename_len, ef_len, comment_len))
}

/// Whether the data descriptor `dd` is at, past its signature, has 4-byte
/// sizes: its compressed size, so read, is `central_compressed_size`, and
/// what follows is the next local header, the central directory, or the
/// archive extra data record before it.
fn narrow_data_descriptor(dd: &Buffer<'_>, central_compressed_size: u64) -> bool {
    let at = dd.offset() as usize;
    let Some(rest) = dd.data().get(at..) else {
        return false;
    };
    let Some(comp_size) = rest.get(4..8) else {
        return false;
    };
    u64::from(u32::from_le_bytes([
        comp_size[0],
        comp_size[1],
        comp_size[2],
        comp_size[3],
    ])) == central_compressed_size
        && matches!(
            rest.get(12..16),
            Some(b"PK\x03\x04" | b"PK\x01\x02" | b"PK\x06\x08")
        )
}

/// The file name, the extra fields and the comment of a directory entry, what
/// they say, and the data descriptor of a local one.
#[allow(clippy::too_many_arguments)]
fn read_variable<R: ReadAt + ?Sized>(
    mut zde: Box<Dirent>,
    variable: &mut Buffer<'_>,
    src: &mut Source<R>,
    (filename_len, ef_len, comment_len): (u16, u16, u16),
    local: bool,
    is_zip64: bool,
    central_compressed_size: u64,
    check_consistency: bool,
    error: &mut Error,
) -> Option<Box<Dirent>> {
    if filename_len > 0 {
        match read_string(Some(&mut *variable), src, filename_len) {
            Ok(name) => zde.filename = name,
            Err(e) => {
                *error = if e.code() == ErrorCode::Eof {
                    Error::incons(Detail::VariableSizeOverflow)
                } else {
                    e
                };
                return None;
            }
        }
        if zde.bitflags & GPBF_ENCODING_UTF_8 != 0
            && let Some(name) = zde.filename.as_mut()
            && name.guess_encoding(Encoding::Utf8Known) == Encoding::Error
        {
            *error = Error::incons(Detail::InvalidUtf8InFilename);
            return None;
        }
    }

    if ef_len > 0 {
        let ef = match read_data(Some(&mut *variable), src, usize::from(ef_len)) {
            Ok(ef) => ef,
            Err(e) => {
                *error = e;
                return None;
            }
        };
        match ef_parse(&ef) {
            Ok(fields) if local => zde.extra_fields.local = OnceLock::from(fields),
            Ok(fields) => zde.extra_fields.central = fields,
            Err(e) => {
                *error = e;
                return None;
            }
        }
    }

    if comment_len > 0 {
        match read_string(Some(&mut *variable), src, comment_len) {
            Ok(comment) => zde.comment = comment,
            Err(e) => {
                *error = e;
                return None;
            }
        }
        if zde.bitflags & GPBF_ENCODING_UTF_8 != 0
            && let Some(comment) = zde.comment.as_mut()
            && comment.guess_encoding(Encoding::Utf8Known) == Encoding::Error
        {
            *error = Error::incons(Detail::InvalidUtf8InComment);
            return None;
        }
    }

    let filename = zde.filename.take();
    let had_filename = filename.is_some();
    match process_ef_utf_8(&zde, EF_UTF_8_NAME, filename, check_consistency) {
        Some(name) => zde.filename = name,
        None if had_filename => {
            *error = Error::incons(Detail::Utf8FilenameMismatch);
            return None;
        }
        None => {}
    }

    // Check for a NUL byte in the final name; the Info-ZIP Unicode Path
    // extra field can replace zde->filename above, so this must run
    // after that.
    if check_consistency
        && zde
            .filename
            .as_ref()
            .is_some_and(|name| name.raw().contains(&0))
    {
        *error = Error::incons(Detail::NulInFilename);
        return None;
    }

    if !local {
        let comment = zde.comment.take();
        let had_comment = comment.is_some();
        match process_ef_utf_8(&zde, EF_UTF_8_COMMENT, comment, check_consistency) {
            Some(comment) => zde.comment = comment,
            None if had_comment => {
                *error = Error::incons(Detail::Utf8CommentMismatch);
                return None;
            }
            None => {}
        }
    }

    // Zip64

    if zde.uncomp_size == u64::from(u32::MAX)
        || zde.comp_size == u64::from(u32::MAX)
        || zde.offset == u64::from(u32::MAX)
    {
        let flags = if local { EF_LOCAL } else { EF_CENTRAL };
        match zde.extra_fields.get_by_id(EF_ZIP64, 0, flags) {
            Ok(ef) => {
                let ef = ef.to_vec();
                if let Err(e) = process_ef_zip64(&mut zde, &ef, local) {
                    *error = e;
                    return None;
                }
            }
            Err(e) => {
                *error = e;
                if is_zip64 {
                    *error = Error::incons(Detail::MissingZip64Ef);
                    return None;
                }
            }
        }
    }

    if !variable.ok() {
        *error = Error::new(ErrorCode::Internal, 0);
        return None;
    }

    if local && zde.bitflags & GPBF_DATA_DESCRIPTOR != 0 {
        // libzip returns here without setting the error when the seek
        // fails; so does the port.
        if src
            .seek(central_compressed_size as i64, Whence::Cur)
            .is_err()
        {
            return None;
        }
        let mut dd = match Buffer::from_source(src, MAX_DATA_DESCRIPTOR_LENGTH) {
            Ok(dd) => dd,
            Err(e) => {
                *error = e;
                return None;
            }
        };
        if dd.peek(MAGIC_LEN) == Some(&DATADES_MAGIC[..]) {
            dd.skip(MAGIC_LEN);
        }
        // Differs from libzip, which takes a data descriptor's sizes as 8
        // bytes each in every archive with a Zip64 end of central directory. The appnote has them
        // so only for an entry in Zip64 format, and writers (Info-ZIP's zip,
        // libarchive, and so File Roller) give 4-byte ones to the entries
        // that need no more, in an archive Zip64 for its count of entries
        // alone: read as 8 bytes, those sizes are wrong, and the archive was
        // refused. They are 4 bytes when that much is the compressed size the
        // central directory says and a header follows.
        let wide = is_zip64 && !narrow_data_descriptor(&dd, central_compressed_size);
        let df_crc = dd.get_32();
        let df_comp_size = if wide {
            dd.get_64()
        } else {
            u64::from(dd.get_32())
        };
        let df_uncomp_size = if wide {
            dd.get_64()
        } else {
            u64::from(dd.get_32())
        };

        if !dd.ok() {
            *error = Error::new(ErrorCode::Internal, 0);
            return None;
        }

        // According to the appnote, it should be 0, but some
        // implementations write the actual value.
        if (zde.crc != 0 && zde.crc != df_crc)
            || (zde.comp_size != 0 && zde.comp_size != df_comp_size)
            || (zde.uncomp_size != 0 && zde.uncomp_size != df_uncomp_size)
        {
            *error = Error::incons(Detail::DataDescriptorMismatch);
            return None;
        }
        zde.crc = df_crc;
        zde.comp_size = df_comp_size;
        zde.uncomp_size = df_uncomp_size;
    }

    // zip_source_seek / zip_source_tell don't support values >
    // ZIP_INT64_MAX
    if zde.offset > i64::MAX as u64 {
        *error = Error::new(ErrorCode::Seek, EFBIG);
        return None;
    }

    if let Err(e) = process_winzip_aes(&mut zde) {
        *error = e;
        return None;
    }

    if local {
        if let Some(efp) = zde.extra_fields.local.get_mut() {
            ef_remove_internal(efp);
        }
    } else {
        ef_remove_internal(&mut zde.extra_fields.central);
    }

    Some(zde)
}

/// Takes the sizes, offset and disk number the header leaves to the Zip64
/// extra field `ef`: port of `zip_dirent_process_ef_zip64`.
fn process_ef_zip64(zde: &mut Dirent, ef: &[u8], local: bool) -> Result<(), Error> {
    let mut ef_buffer = Buffer::new(ef);
    let got_len = ef.len();

    if zde.uncomp_size == u64::from(u32::MAX) {
        zde.uncomp_size = ef_buffer.get_64();
    } else if local {
        // From appnote.txt: This entry in the Local header MUST include
        // BOTH original and compressed file size fields.
        ef_buffer.skip(8); // error is caught by _zip_buffer_eof() call
    }
    if zde.comp_size == u64::from(u32::MAX) {
        zde.comp_size = ef_buffer.get_64();
    } else if local {
        ef_buffer.skip(8); // error is caught by _zip_buffer_eof() call
    }
    if !local {
        if zde.offset == u64::from(u32::MAX) {
            zde.offset = ef_buffer.get_64();
        }
        if zde.disk_number == u32::from(u16::MAX) {
            zde.disk_number = ef_buffer.get_32();
        }
    }

    if !ef_buffer.eof() {
        // accept additional fields if values match
        let mut ok = true;
        match got_len {
            28 | 24 => {
                if got_len == 28 {
                    ef_buffer.set_offset(24);
                    if zde.disk_number != ef_buffer.get_32() {
                        ok = false;
                    }
                }
                ef_buffer.set_offset(0);
                if zde.uncomp_size != ef_buffer.get_64()
                    || zde.comp_size != ef_buffer.get_64()
                    || zde.offset != ef_buffer.get_64()
                {
                    ok = false;
                }
            }
            _ => ok = false,
        }
        if !ok {
            return Err(Error::incons(Detail::InvalidZip64Ef));
        }
    }
    Ok(())
}

/// The name or comment from the Info-ZIP Unicode Path or Comment extra
/// field `id`, if it has one whose CRC is that of `str`; `str` otherwise.
/// `None` where libzip returns `NULL`: with `check_consistency`, a field
/// in ASCII that differs from `str`, and when `str` is absent and nothing
/// replaces it. Port of `_zip_dirent_process_ef_utf_8`.
fn process_ef_utf_8(
    de: &Dirent,
    id: u16,
    str: Option<ZipString>,
    check_consistency: bool,
) -> Option<Option<ZipString>> {
    let Ok(ef) = de.extra_fields.get_by_id(id, 0, EF_BOTH) else {
        return keep(str);
    };
    if ef.len() < 5 || ef[0] != 1 {
        return keep(str);
    }

    let mut buffer = Buffer::new(ef);
    buffer.get_8();
    let ef_crc = buffer.get_32();

    if string_crc32(str.as_ref()) == ef_crc {
        let len = buffer.left();
        let raw = buffer.get(len).unwrap_or(&[]);
        if let Ok(Some(ef_str)) = ZipString::new(raw, Flags::ENC_UTF_8) {
            if check_consistency && !string_equal(str.as_ref(), Some(&ef_str)) && ef_str.is_ascii()
            {
                return None;
            }
            return Some(Some(ef_str));
        }
    }

    keep(str)
}

/// `return str;` of `_zip_dirent_process_ef_utf_8`, which is `NULL` when
/// `str` is.
fn keep(str: Option<ZipString>) -> Option<Option<ZipString>> {
    str.map(Some)
}

/// The encryption method and real compression method of a WinZip AES
/// entry, from its extra field: port of `_zip_dirent_process_winzip_aes`.
fn process_winzip_aes(de: &mut Dirent) -> Result<(), Error> {
    if de.comp_method != i32::from(CM_WINZIP_AES) {
        return Ok(());
    }

    let Ok(ef) = de.extra_fields.get_by_id(EF_WINZIP_AES, 0, EF_BOTH) else {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    };
    if ef.len() < 7 {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    }
    let ef_len = ef.len();
    let mut buffer = Buffer::new(ef);

    // version
    let crc_valid = match buffer.get_16() {
        1 => true,
        2 => false,
        _ => return Err(Error::new(ErrorCode::EncrNotSupp, 0)),
    };

    // vendor
    if buffer.get(2) != Some(b"AE") {
        return Err(Error::new(ErrorCode::EncrNotSupp, 0));
    }

    // mode
    let enc_method = match buffer.get_8() {
        1 => em::AES_128,
        2 => em::AES_192,
        3 => em::AES_256,
        _ => return Err(Error::new(ErrorCode::EncrNotSupp, 0)),
    };

    if ef_len != 7 {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    }

    let comp_method = buffer.get_16();
    de.crc_valid = crc_valid;
    de.encryption_method = enc_method;
    de.comp_method = i32::from(comp_method);
    Ok(())
}

/// The length of the header at `src`'s position, read from its length
/// fields: port of `_zip_dirent_size`.
pub(crate) fn dirent_size<R: ReadAt + ?Sized>(
    src: &mut Source<R>,
    local: bool,
) -> Result<u32, Error> {
    let mut size = if local { LENTRYSIZE } else { CDENTRYSIZE } as u32;

    // Central header has fixed fields after size pointers.
    let want = if local { LENTRYSIZE } else { 34 };
    let mut buffer = Buffer::from_source(src, want)?;
    if buffer.left() != want {
        return Err(Error::incons(Detail::CdirEntryInvalid));
    }

    let magic: &[u8; 4] = if local { LOCAL_MAGIC } else { CENTRAL_MAGIC };
    if buffer.peek(4) != Some(&magic[..]) {
        return Err(Error::incons(Detail::CdirEntryInvalid));
    }

    // Skip to size pointers.
    buffer.skip(if local { 26 } else { 28 });

    for _ in 0..if local { 2 } else { 3 } {
        size += u32::from(buffer.get_16());
    }

    Ok(size)
}

/// Seconds since 1970 of a DOS time, taken as UTC: port of `_zip_d2u_time`.
///
/// Differs from libzip, which calls `mktime` and so takes the time in the
/// machine's time zone: the two agree where it is UTC. Out-of-range fields
/// carry over into the next as `mktime` carries them (month 0 is December
/// of the year before).
pub(crate) fn d2u_time(dtime: DosTime) -> i64 {
    let year = i64::from((dtime.date >> 9) & 127) + 1980;
    let mon = i64::from((dtime.date >> 5) & 15) - 1;
    let mday = i64::from(dtime.date & 31);

    let hour = i64::from((dtime.time >> 11) & 31);
    let min = i64::from((dtime.time >> 5) & 63);
    let sec = i64::from((dtime.time << 1) & 62);

    let year = year + mon.div_euclid(12);
    let mon = mon.rem_euclid(12);
    let days = days_from_civil(year, mon + 1, 1) + mday - 1;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The stored sizes of a stored entry, which must differ by the length of
/// its encryption header: port of `zip_dirent_check_consistency`.
pub(crate) fn check_consistency(dirent: &Dirent) -> Option<Detail> {
    if dirent.comp_method == 0 {
        let header_size = match dirent.encryption_method {
            em::NONE => 0,
            em::TRAD_PKWARE => 12,
            em::AES_128 => 20,
            em::AES_192 => 24,
            em::AES_256 => 28,
            _ => return None,
        };
        match dirent.uncomp_size.checked_add(header_size) {
            Some(size) if size == dirent.comp_size => {}
            _ => return Some(Detail::StoredSizeMismatch),
        }
    }
    None
}

impl<R: ReadAt> crate::zip::open::Archive<R> {
    /// The entry `idx` with its changes, or as read with
    /// [`Flags::UNCHANGED`]: port of `_zip_get_dirent`.
    pub(crate) fn get_dirent(&self, idx: u64, flags: Flags) -> Result<&Dirent, Error> {
        let Some(entry) = self.entry.get(usize::try_from(idx).unwrap_or(usize::MAX)) else {
            return Err(Error::new(ErrorCode::Inval, 0));
        };
        match entry.changes.as_deref() {
            Some(changes) if !flags.intersects(Flags::UNCHANGED) => Ok(changes),
            _ => {
                let Some(orig) = entry.orig.as_deref() else {
                    return Err(Error::new(ErrorCode::Inval, 0));
                };
                if entry.deleted && !flags.intersects(Flags::UNCHANGED) {
                    return Err(Error::new(ErrorCode::Deleted, 0));
                }
                Ok(orig)
            }
        }
    }
}

impl Dirent {
    /// A dirent to keep the changes of an entry in, a copy of `sde` (the
    /// entry as read) or, for none, a new one: port of `_zip_dirent_clone`.
    pub(crate) fn clone_changes(sde: Option<&Dirent>) -> Dirent {
        let mut tde = sde.cloned().unwrap_or_default();
        tde.changed = 0;
        tde
    }

    /// Takes the fields that are not changed from `de_orig`, the entry as
    /// read; with `replacing_data`, the compression and encryption methods
    /// are those for new data instead. Port of `_zip_dirent_merge`.
    pub(crate) fn merge(&mut self, de_orig: &Dirent, replacing_data: bool) {
        if self.changed & changed::ATTRIBUTES == 0 {
            self.ext_attrib = de_orig.ext_attrib;
            self.int_attrib = de_orig.int_attrib;
        }
        if self.changed & changed::COMMENT == 0 {
            self.comment.clone_from(&de_orig.comment);
        }
        if self.changed & changed::COMP_METHOD == 0 {
            if replacing_data {
                self.comp_method = CM_DEFAULT;
                self.compression_level = 0;
            } else {
                self.comp_method = de_orig.comp_method;
                self.compression_level = de_orig.compression_level;
            }
        }
        if self.changed & changed::ENCRYPTION_METHOD == 0 {
            if replacing_data {
                self.encryption_method = em::NONE;
            } else {
                self.encryption_method = de_orig.encryption_method;
            }
        }
        if self.changed & changed::EXTRA_FIELD == 0 {
            self.extra_fields.clone_from(&de_orig.extra_fields);
        }
        if self.changed & changed::FILENAME == 0 {
            self.filename.clone_from(&de_orig.filename);
        }
        if self.changed & changed::LAST_MOD == 0 {
            self.last_mod = de_orig.last_mod;
        }
        if self.changed & changed::PASSWORD == 0 {
            self.password.clone_from(&de_orig.password);
        }
    }

    /// Whether the sizes, or in the central directory the offset, need the
    /// Zip64 extra field: port of `_zip_dirent_needs_zip64`.
    pub(crate) fn needs_zip64(&self, flags: Flags) -> bool {
        self.uncomp_size >= u64::from(u32::MAX)
            || self.comp_size >= u64::from(u32::MAX)
            || (flags.intersects(Flags::CENTRAL) && self.offset >= u64::from(u32::MAX))
    }

    /// Takes what a source says about the file: the general purpose bits
    /// it may set, ASCII, the external attributes and host system unless
    /// they were set, and the version needed for the method, encryption
    /// and sizes; whether that changed the entry. Port of
    /// `_zip_dirent_apply_attributes`.
    pub(crate) fn apply_attributes(
        &mut self,
        attributes: &FileAttributes,
        force_zip64: bool,
    ) -> bool {
        let mut has_changed = false;

        if attributes.valid & file_attributes::GENERAL_PURPOSE_BIT_FLAGS != 0 {
            let mask = attributes.general_purpose_bit_mask & GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK;
            let bitflags = (self.bitflags & !mask) | (attributes.general_purpose_bit_flags & mask);
            if self.bitflags != bitflags {
                self.bitflags = bitflags;
                has_changed = true;
            }
        }
        if attributes.valid & file_attributes::ASCII != 0 {
            let int_attrib = (self.int_attrib & !1) | u16::from(attributes.ascii);
            if self.int_attrib != int_attrib {
                self.int_attrib = int_attrib;
                has_changed = true;
            }
        }
        // manually set attributes are preferred over attributes provided by
        // source
        if self.changed & changed::ATTRIBUTES == 0
            && attributes.valid & file_attributes::EXTERNAL_FILE_ATTRIBUTES != 0
            && self.ext_attrib != attributes.external_file_attributes
        {
            self.ext_attrib = attributes.external_file_attributes;
            has_changed = true;
        }

        let is_dir = self
            .filename
            .as_ref()
            .is_some_and(|name| name.raw().last() == Some(&b'/'));
        let mut version_needed: u16 = if self.comp_method == i32::from(cm::LZMA) {
            63
        } else if matches!(
            self.encryption_method,
            em::AES_128 | em::AES_192 | em::AES_256
        ) {
            51
        } else if self.comp_method == i32::from(cm::BZIP2) {
            46
        } else if force_zip64 || self.needs_zip64(Flags::NONE) {
            45
        } else if self.comp_method == i32::from(cm::DEFLATE)
            || self.encryption_method == em::TRAD_PKWARE
            || is_dir
        {
            20
        } else {
            10
        };

        if attributes.valid & file_attributes::VERSION_NEEDED != 0 {
            version_needed = version_needed.max(u16::from(attributes.version_needed));
        }

        if self.version_needed != version_needed {
            self.version_needed = version_needed;
            has_changed = true;
        }

        let mut version_madeby = 63 | (self.version_madeby & 0xff00);
        if self.changed & changed::ATTRIBUTES == 0
            && attributes.valid & file_attributes::HOST_SYSTEM != 0
        {
            version_madeby = (version_madeby & 0xff) | (u16::from(attributes.host_system) << 8);
        }
        if self.version_madeby != version_madeby {
            self.version_madeby = version_madeby;
            has_changed = true;
        }

        has_changed
    }

    /// Sets what torrentzip has the same in every entry: port of
    /// `zip_dirent_torrentzip_normalize`.
    pub(crate) fn torrentzip_normalize(&mut self) {
        self.version_madeby = 0;
        self.version_needed = 20; // 2.0
        self.bitflags = 2; // maximum compression
        self.comp_method = i32::from(cm::DEFLATE);
        self.compression_level = TORRENTZIP_COMPRESSION_FLAGS;
        self.disk_number = 0;
        self.int_attrib = 0;
        self.ext_attrib = 0;

        // last_mod, extra_fields, and comment are normalized in
        // zip_dirent_write() directly
    }

    /// The modification time in seconds since 1970, from the cache:
    /// `zip_dirent_get_last_mod_mtime`. Differs from libzip: the time
    /// computed is not kept, as it depends only on `last_mod`.
    pub(crate) fn get_last_mod_mtime(&self) -> i64 {
        self.last_mod_mtime
            .unwrap_or_else(|| d2u_time(self.last_mod))
    }

    /// The version of WinZip's AES it is written with, if it has that: AE-2 has no CRC.
    pub(crate) fn winzip_aes_version(&self) -> u16 {
        match self.encryption_method {
            // TODO in libzip: WinZip also uses AE-2 for bzip compressed
            // files and maybe others?
            em::AES_128 | em::AES_192 | em::AES_256 if self.uncomp_size < 20 => 2,
            em::AES_128 | em::AES_192 | em::AES_256 => 1,
            _ => 0,
        }
    }

    /// Writes the entry as a local header ([`Flags::LOCAL`]) or a central
    /// directory entry ([`Flags::CENTRAL`]), and whether it has the Zip64
    /// extra field; with [`FL_FORCE_ZIP64`], a local header has it in any
    /// case. With `want_torrentzip`, as torrentzip has it: no time, extra
    /// fields or comment. The UTF-8 flag and the Info-ZIP UTF-8 extra
    /// fields are set from the encodings of the name and comment. With
    /// [`FL_DATA_FOLLOWS`], a local header has no CRC or sizes: its data descriptor
    /// has them. Port of `_zip_dirent_write`.
    pub(crate) fn write<W: Write + Seek>(
        &mut self,
        out: &mut Output<W>,
        flags: Flags,
        want_torrentzip: bool,
    ) -> Result<bool, Error> {
        let local = flags.intersects(Flags::LOCAL);
        // The extra fields written before the entry's own, in order.
        let mut ef: Vec<ExtraField> = Vec::new();

        let name_enc = guess_encoding(self.filename.as_mut(), Encoding::Unknown);
        let com_enc = guess_encoding(self.comment.as_mut(), Encoding::Unknown);

        if (name_enc == Encoding::Utf8Known && com_enc == Encoding::Ascii)
            || (name_enc == Encoding::Ascii && com_enc == Encoding::Utf8Known)
            || (name_enc == Encoding::Utf8Known && com_enc == Encoding::Utf8Known)
        {
            self.bitflags |= GPBF_ENCODING_UTF_8;
        } else {
            self.bitflags &= !GPBF_ENCODING_UTF_8;
            if name_enc == Encoding::Utf8Known
                && let Some(filename) = &self.filename
            {
                ef.push(ef_utf8(EF_UTF_8_NAME, filename)?);
            }
            if !local
                && com_enc == Encoding::Utf8Known
                && let Some(comment) = &self.comment
            {
                ef.insert(0, ef_utf8(EF_UTF_8_COMMENT, comment)?);
            }
        }

        if self.encryption_method == em::NONE {
            self.bitflags &= !GPBF_ENCRYPTED;
        } else {
            self.bitflags |= GPBF_ENCRYPTED;
        }

        let is_really_zip64 = self.needs_zip64(flags);
        let is_zip64 = (local && flags.intersects(FL_FORCE_ZIP64)) || is_really_zip64;
        let data_follows = local && flags.intersects(FL_DATA_FOLLOWS);
        let winzip_aes_version = self.winzip_aes_version();

        // Differs from libzip, whose archive does not read back otherwise:
        // a size or offset of exactly 0xffffffff, which the header has as
        // 0xffffffff, has its value in the Zip64 extra field too (libzip
        // adds it only when it is larger), and so does the disk number
        // when the header has it as 0xffff, which tells a reader of the
        // field to look for it there.
        if is_zip64 {
            let mut ef_buffer = Buffer::with_size(EFZIP64SIZE);
            let max = u64::from(u32::MAX);
            if local {
                if flags.intersects(FL_FORCE_ZIP64)
                    || self.comp_size >= max
                    || self.uncomp_size >= max
                {
                    ef_buffer.put_64(if data_follows { 0 } else { self.uncomp_size });
                    ef_buffer.put_64(if data_follows { 0 } else { self.comp_size });
                }
            } else {
                if self.uncomp_size >= max {
                    ef_buffer.put_64(self.uncomp_size);
                }
                if self.comp_size >= max {
                    ef_buffer.put_64(self.comp_size);
                }
                if self.offset >= max {
                    ef_buffer.put_64(self.offset);
                }
                if self.disk_number as u16 == u16::MAX {
                    ef_buffer.put_32(self.disk_number);
                }
            }
            if !ef_buffer.ok() {
                return Err(Error::new(ErrorCode::Internal, 0));
            }
            let len = ef_buffer.offset() as usize;
            ef.insert(
                0,
                ExtraField {
                    id: EF_ZIP64,
                    data: ef_buffer.data()[..len].to_vec(),
                },
            );
        }

        if winzip_aes_version > 0 {
            let mut ef_buffer = Buffer::with_size(EF_WINZIP_AES_SIZE);
            ef_buffer.put_16(winzip_aes_version);
            ef_buffer.put(b"AE");
            ef_buffer.put_8((self.encryption_method & 0xff) as u8);
            ef_buffer.put_16(self.comp_method as u16);
            if !ef_buffer.ok() {
                return Err(Error::new(ErrorCode::Internal, 0));
            }
            ef.insert(
                0,
                ExtraField {
                    id: EF_WINZIP_AES,
                    data: ef_buffer.data().to_vec(),
                },
            );
        }

        let mut buffer = Buffer::with_size(CDENTRYSIZE as usize);

        buffer.put(if local { LOCAL_MAGIC } else { CENTRAL_MAGIC });

        if !local {
            buffer.put_16(self.version_madeby);
        }
        buffer.put_16(
            self.version_needed
                .max(if is_really_zip64 || (data_follows && is_zip64) {
                    45
                } else {
                    0
                }),
        );
        buffer.put_16(self.bitflags);
        if winzip_aes_version > 0 {
            buffer.put_16(CM_WINZIP_AES);
        } else {
            buffer.put_16(cm_actual(self.comp_method));
        }

        let dostime = if want_torrentzip {
            DosTime {
                time: 0xbc00,
                date: 0x2198,
            }
        } else {
            self.last_mod
        };
        buffer.put_16(dostime.time);
        buffer.put_16(dostime.date);

        if winzip_aes_version == 2 || data_follows {
            buffer.put_32(0);
        } else {
            buffer.put_32(self.crc);
        }

        let max = u64::from(u32::MAX);
        if data_follows && !is_zip64 {
            buffer.put_32(0);
            buffer.put_32(0);
        } else if local && (data_follows || self.comp_size >= max || self.uncomp_size >= max) {
            // In local headers, if a ZIP64 EF is written, it MUST contain
            // both compressed and uncompressed sizes (even if one of the
            // two is smaller than 0xFFFFFFFF); on the other hand, those
            // may only appear when the corresponding standard entry is
            // 0xFFFFFFFF. (appnote.txt 4.5.3)
            buffer.put_32(u32::MAX);
            buffer.put_32(u32::MAX);
        } else {
            buffer.put_32(self.comp_size.min(max) as u32);
            buffer.put_32(self.uncomp_size.min(max) as u32);
        }

        buffer.put_16(string_length(self.filename.as_ref()));

        let own_ef: &[ExtraField] = if local {
            self.extra_fields.local.get().map_or(&[], Vec::as_slice)
        } else {
            &self.extra_fields.central
        };
        let ef_len = ef_size(&ef);
        let de_ef_len = if want_torrentzip {
            Some(0)
        } else {
            ef_size(own_ef)
        };
        let total = match (ef_len, de_ef_len) {
            (Some(a), Some(b)) if u32::from(a) + u32::from(b) <= 0xffff => a + b,
            _ => return Err(Error::new(ErrorCode::EfTooLarge, 0)),
        };
        buffer.put_16(total);

        if !local {
            buffer.put_16(if want_torrentzip {
                0
            } else {
                string_length(self.comment.as_ref())
            });
            buffer.put_16(self.disk_number as u16);
            buffer.put_16(self.int_attrib);
            buffer.put_32(self.ext_attrib);
            buffer.put_32(self.offset.min(max) as u32);
        }

        if !buffer.ok() {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        let len = buffer.offset() as usize;
        out.write(&buffer.data()[..len])?;

        if let Some(filename) = &self.filename {
            out.write(filename.raw())?;
        }

        ef_write(out, &ef)?;
        if !want_torrentzip {
            ef_write(out, own_ef)?;
        }

        if !local
            && !want_torrentzip
            && let Some(comment) = &self.comment
        {
            out.write(comment.raw())?;
        }

        Ok(is_zip64)
    }
}

/// Info-ZIP's extra field `id` for the UTF-8 name or comment `str`: version
/// 1, the CRC-32 of the string and the string. Port of `_zip_ef_utf8`.
fn ef_utf8(id: u16, str: &ZipString) -> Result<ExtraField, Error> {
    let raw = str.raw();
    if raw.len() + 5 > 0xffff {
        // TODO in libzip: better error code?
        return Err(Error::new(ErrorCode::Inval, 0));
    }
    let mut buffer = Buffer::with_size(raw.len() + 5);
    buffer.put_8(1);
    buffer.put_32(string_crc32(Some(str)));
    buffer.put(raw);
    if !buffer.ok() {
        return Err(Error::new(ErrorCode::Internal, 0));
    }
    let len = buffer.offset() as usize;
    Ok(ExtraField {
        id,
        data: buffer.data()[..len].to_vec(),
    })
}

/// `ZIP_CM_ACTUAL`: deflate for the default method.
pub(crate) fn cm_actual(method: i32) -> u16 {
    if method == CM_DEFAULT {
        cm::DEFLATE
    } else {
        method as u16
    }
}

/// `EOVERFLOW`, which `localtime_r` sets for a year past what an `int`
/// holds: the platform's value (in the Windows C runtime's `errno.h`
/// there).
const EOVERFLOW: i32 = if cfg!(windows) {
    132
} else if cfg!(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)) {
    84
} else if cfg!(any(target_os = "solaris", target_os = "illumos")) {
    79
} else {
    75
};

/// A time in seconds since 1970 as MS-DOS keeps it, taken as UTC: port of
/// `_zip_u2d_time`. Years before 1980 are taken as 1980, with the same
/// day, and years past 2107 wrap around in the 7 bits of the year, as in
/// libzip. A year that does not fit in an `int` fails with `ZIP_ER_INVAL`
/// and the platform's `EOVERFLOW`, as `localtime_r` refuses it.
///
/// Differs from libzip, which calls `localtime_r` and so takes the time in
/// the machine's time zone: the two agree where it is UTC.
pub(crate) fn u2d_time(intime: i64) -> Result<DosTime, Error> {
    let days = intime.div_euclid(86400);
    let secs = intime.rem_euclid(86400);
    let (year, month, mday) = civil_from_days(days);
    let tm_year = year - 1900;
    if i32::try_from(tm_year).is_err() {
        return Err(Error::new(ErrorCode::Inval, EOVERFLOW));
    }
    let tm_year = tm_year.max(80);

    let (hour, min, sec) = (secs / 3600, secs / 60 % 60, secs % 60);
    Ok(DosTime {
        date: (((tm_year + 1900 - 1980) << 9) + (month << 5) + mday) as u16,
        time: ((hour << 11) + (min << 5) + (sec >> 1)) as u16,
    })
}

/// The year, month (1 to 12) and day of a count of days since 1970-01-01
/// in the proleptic Gregorian calendar (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

impl<R: ReadAt> crate::zip::open::Archive<R> {
    /// Writes the central directory of the entries `filelist`, by index,
    /// and the end of central directory records, with the archive comment,
    /// and gives the size of the directory: port of `_zip_cdir_write`.
    pub(crate) fn cdir_write<W: Write + Seek>(
        &mut self,
        filelist: &[usize],
        out: &mut Output<W>,
    ) -> Result<u64, Error> {
        let want_torrentzip = self.want_torrentzip();
        let offset = out.tell_write()?;

        if want_torrentzip {
            out.write_crc = Some(crc32(0, &[]));
        }

        for &i in filelist {
            let entry = &mut self.entry[i];
            let de = match (entry.changes.as_deref_mut(), entry.orig.as_deref_mut()) {
                (Some(changes), _) => changes,
                (None, Some(orig)) => orig,
                (None, None) => {
                    out.write_crc = None;
                    return Err(Error::new(ErrorCode::Internal, 0));
                }
            };
            if let Err(e) = de.write(out, Flags::CENTRAL, want_torrentzip) {
                out.write_crc = None;
                return Err(e);
            }
        }

        let cdir_crc = out.write_crc.take().unwrap_or(0);

        let size = out.tell_write()? - offset;
        let survivors = filelist.len() as u64;

        let mut buffer = Buffer::with_size((EOCDLEN + EOCD64LEN + EOCD64LOCLEN) as usize);

        let max16 = u64::from(u16::MAX);
        let max32 = u64::from(u32::MAX);
        if survivors > max16 || offset > max32 || size > max32 {
            buffer.put(EOCD64_MAGIC);
            buffer.put_64(EOCD64LEN - 12);
            buffer.put_16(45);
            buffer.put_16(45);
            buffer.put_32(0);
            buffer.put_32(0);
            buffer.put_64(survivors);
            buffer.put_64(survivors);
            buffer.put_64(size);
            buffer.put_64(offset);
            buffer.put(EOCD64LOC_MAGIC);
            buffer.put_32(0);
            buffer.put_64(offset + size);
            buffer.put_32(1);
        }

        buffer.put(EOCD_MAGIC);
        buffer.put_32(0);
        buffer.put_16(survivors.min(max16) as u16);
        buffer.put_16(survivors.min(max16) as u16);
        buffer.put_32(size.min(max32) as u32);
        buffer.put_32(offset.min(max32) as u32);

        let comment = if self.comment_changed {
            self.comment_changes.as_ref()
        } else {
            self.comment_orig.as_ref()
        };

        if want_torrentzip {
            buffer.put_16((TORRENTZIP_SIGNATURE_LENGTH + TORRENTZIP_CRC_LENGTH) as u16);
        } else {
            buffer.put_16(string_length(comment));
        }

        if !buffer.ok() {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        let len = buffer.offset() as usize;
        out.write(&buffer.data()[..len])?;

        if want_torrentzip {
            let mut torrentzip_comment = TORRENTZIP_SIGNATURE.to_vec();
            torrentzip_comment.extend_from_slice(format!("{cdir_crc:08X}").as_bytes());
            out.write(&torrentzip_comment)?;
        } else if let Some(comment) = comment {
            out.write(comment.raw())?;
        }

        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_dos_times_as_mktime_in_utc() {
        // 2026-10-29 12:34:56
        let t = DosTime {
            date: ((2026 - 1980) << 9) | (10 << 5) | 29,
            time: (12 << 11) | (34 << 5) | 28,
        };
        assert_eq!(d2u_time(t), 1_793_277_296);
        // 1980-00-00 00:00:00 is 1979-11-30.
        assert_eq!(d2u_time(DosTime::default()), 312_768_000);
    }
}
