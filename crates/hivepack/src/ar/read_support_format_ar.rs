//! libarchive's ar reader (`archive_read_support_format_ar.c`): the global
//! header, the 60-byte headers, the GNU/SVR4 and BSD variants and their long
//! names, and the data with its padding to an even offset.

use std::io::Read;

use crate::ar::entry::{AE_IFMT, AE_IFREG, Header, c_string};
use crate::ar::error::Error;
use crate::ar::read::Input;

/// `AR_name_offset`, `AR_name_size` and the other fields of a header.
const AR_NAME_OFFSET: usize = 0;
const AR_NAME_SIZE: usize = 16;
const AR_DATE_OFFSET: usize = 16;
const AR_DATE_SIZE: usize = 12;
const AR_UID_OFFSET: usize = 28;
const AR_UID_SIZE: usize = 6;
const AR_GID_OFFSET: usize = 34;
const AR_GID_SIZE: usize = 6;
const AR_MODE_OFFSET: usize = 40;
const AR_MODE_SIZE: usize = 8;
const AR_SIZE_OFFSET: usize = 48;
const AR_SIZE_SIZE: usize = 10;
const AR_FMAG_OFFSET: usize = 58;

/// The size of a header.
const HEADER_SIZE: usize = 60;

/// The global header every ar archive starts with.
const MAGIC: &[u8; 8] = b"!<arch>\n";

/// The variant of ar, as libarchive guesses it from the names
/// (`ARCHIVE_FORMAT_AR`, `_AR_GNU` and `_AR_BSD`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// Not told yet: no name has said (`ARCHIVE_FORMAT_AR`, "ar").
    Ar,
    /// GNU and SVR4's: names end in `/`, long names are in a filename table
    /// (`ARCHIVE_FORMAT_AR_GNU`, "ar (GNU/SVR4)").
    Gnu,
    /// BSD's: long names come before the data, `#1/<length>`
    /// (`ARCHIVE_FORMAT_AR_BSD`, "ar (BSD)").
    Bsd,
}

impl Format {
    /// libarchive's code for the format, as `archive_format` gives it.
    pub fn code(self) -> i32 {
        match self {
            Format::Ar => 0x70000,
            Format::Gnu => 0x70001,
            Format::Bsd => 0x70002,
        }
    }

    /// libarchive's name for it, as `archive_format_name` gives it.
    pub fn name(self) -> &'static str {
        match self {
            Format::Ar => "ar",
            Format::Gnu => "ar (GNU/SVR4)",
            Format::Bsd => "ar (BSD)",
        }
    }
}

/// `archive_read_format_ar_bid`: 64 for an archive that starts with
/// `!<arch>\n`, the only check; -1 for anything else, `head` too short among
/// them.
pub fn bid(head: &[u8]) -> i32 {
    if head.starts_with(MAGIC) { 64 } else { -1 }
}

/// What [`Ar::read_header`] found.
pub(crate) enum Next {
    Entry(Header),
    Eof,
}

/// `struct ar`: where the reader is in the current entry, and the GNU
/// filename table.
#[derive(Debug, Default)]
pub(crate) struct Ar {
    entry_bytes_remaining: i64,
    /// What `read_data` gave and has not consumed yet: always 0 here, as
    /// the data is copied out and consumed at once.
    entry_bytes_unconsumed: i64,
    entry_offset: i64,
    entry_padding: i64,
    strtab: Option<Vec<u8>>,
    read_global_header: bool,
    /// `a->archive.archive_format`; `None` before the global header.
    pub(crate) format: Option<Format>,
}

/// `ar_atol8` and `ar_atol10`: the number in `base` at `offset` in the
/// header `h`, `count` characters long: spaces and tabs first, then
/// digits, until one that is not; `u64::MAX` on overflow.
///
/// The C walks a pointer, and counts down `char_cnt` as it goes. Its first
/// loop counts down once more when a field of spaces is followed by another
/// space, which wraps the count around; but the pointer is then on that
/// space, where the digits stop at once, so a field of spaces is 0, as
/// here. Fifteen digits, the most a field has, cannot overflow.
fn ar_atol(h: &[u8], offset: usize, count: usize, base: u64) -> u64 {
    let mut p = offset;
    let mut char_cnt = count;
    // while ((*p == ' ' || *p == '\t') && char_cnt-- > 0) p++;
    while matches!(h[p], b' ' | b'\t') {
        let more = char_cnt > 0;
        char_cnt = char_cnt.wrapping_sub(1);
        if !more {
            break;
        }
        p += 1;
    }
    let mut l: u64 = 0;
    // digit = *p - '0'; while (*p >= '0' && digit < base && char_cnt-- > 0)
    let mut digit = u64::from(h[p].wrapping_sub(b'0'));
    while h[p] >= b'0' && digit < base {
        let more = char_cnt > 0;
        char_cnt = char_cnt.wrapping_sub(1);
        if !more {
            break;
        }
        match l.checked_mul(base).and_then(|l| l.checked_add(digit)) {
            Some(next) => l = next,
            None => {
                // Truncate on overflow.
                l = u64::MAX;
                break;
            }
        }
        p += 1;
        digit = u64::from(h[p].wrapping_sub(b'0'));
    }
    l
}

impl Ar {
    /// `archive_read_format_ar_bid`, at the start of the input.
    pub(crate) fn bid<R: Read>(&mut self, input: &mut Input<R>) -> Result<i32, Error> {
        Ok(match input.ahead(MAGIC.len())? {
            Some(h) => bid(h),
            None => -1,
        })
    }

    /// `archive_read_format_ar_read_header`: the next entry, past the
    /// symbol table and the GNU filename table, or the end.
    pub(crate) fn read_header<R: Read>(&mut self, input: &mut Input<R>) -> Result<Next, Error> {
        if !self.read_global_header {
            // We are at the beginning of the archive now, so the global
            // header is consumed first.
            input.consume(MAGIC.len() as u64)?;
            self.read_global_header = true;
            self.format = Some(Format::Ar);
        }
        loop {
            // The header of the next entry: a broken one is the end.
            let Some(ahead) = input.ahead(HEADER_SIZE)? else {
                return Ok(Next::Eof);
            };
            let mut h = [0u8; HEADER_SIZE];
            h.copy_from_slice(&ahead[..HEADER_SIZE]);
            let mut unconsumed = HEADER_SIZE as i64;
            let found = self.ar_read_header(input, &h, &mut unconsumed);
            // libarchive does not look at what this returns: after the
            // symbol table's data skipped from the header's start, the
            // archive may end in what is left of it, and then no header
            // follows (the end). The message it sets stays, and is the
            // one given when the skip failed too.
            if unconsumed != 0 {
                match input.consume(unconsumed as u64) {
                    Err(e @ Error::Truncated { .. }) if found.is_err() => return Err(e),
                    Err(Error::Truncated { .. }) => {}
                    result => result?,
                }
            }
            // An entry with no name (the symbol table, the filename
            // table) is passed over.
            if let Some(entry) = found? {
                return Ok(Next::Entry(entry));
            }
        }
    }

    /// `_ar_read_header`: the entry of the header `h`, or `None` for one
    /// that is not a file (`archive_entry_pathname` NULL). `unconsumed` is
    /// what of the header is still to be consumed.
    fn ar_read_header<R: Read>(
        &mut self,
        input: &mut Input<R>,
        h: &[u8; HEADER_SIZE],
        unconsumed: &mut i64,
    ) -> Result<Option<Header>, Error> {
        // Verify the magic signature on the file header.
        if &h[AR_FMAG_OFFSET..AR_FMAG_OFFSET + 2] != b"`\n" {
            return Err(Error::HeaderSignature);
        }
        // strncpy(filename, h + AR_name_offset, AR_name_size): the name up
        // to its first NUL, the rest of the buffer NULs.
        let mut filename = [0u8; AR_NAME_SIZE + 1];
        let name = c_string(&h[AR_NAME_OFFSET..AR_NAME_OFFSET + AR_NAME_SIZE]);
        filename[..name.len()].copy_from_slice(name);

        // Guess the format variant from the name, until it is known.
        if self.format == Some(Format::Ar) {
            // The biggest clue is a '/': GNU starts special names with one
            // and ends the others with one, so anything with a '/' is GNU,
            // but for BSD's long names.
            if filename.starts_with(b"#1/") {
                self.format = Some(Format::Bsd);
            } else if c_string(&filename).contains(&b'/') {
                self.format = Some(Format::Gnu);
            } else if filename.starts_with(b"__.SYMDEF") {
                self.format = Some(Format::Bsd);
            }
        }

        // Trailing spaces off the name: GNU and BSD both pad with them.
        let mut p = AR_NAME_SIZE as isize - 1;
        while p >= 0 && filename[p as usize] == b' ' {
            filename[p as usize] = 0;
            p -= 1;
        }
        // The trailing slash off, unless the name starts with one (GNU's
        // special names).
        if filename[0] != b'/' && p > 0 && filename[p as usize] == b'/' {
            filename[p as usize] = 0;
        }
        if p < 0 {
            return Err(Error::EmptyFilename);
        }

        // The time, owner, mode and size, before any read ahead.
        let mut entry = self.ar_parse_common_header(h);
        let name = c_string(&filename);

        // "/" is the ranlib index, linker information: passed over.
        if name == b"/" {
            // Its data is skipped from where the header starts, the
            // header left unconsumed: so libarchive counts it.
            self.skip(input)?;
            return Ok(None);
        }

        // "//" is the GNU filename table, which later names refer to.
        if name == b"//" {
            let entry_size = entry.size as i64;
            if entry_size == 0 || entry_size > 1024 * 1024 * 1024 {
                return Err(Error::FilenameTableSize);
            }
            let strtab_size = entry_size as usize;
            if self.strtab.is_some() {
                return Err(Error::TwoFilenameTables);
            }
            if *unconsumed != 0 {
                input.consume(*unconsumed as u64)?;
                *unconsumed = 0;
            }
            let Some(b) = input.ahead(strtab_size)? else {
                // libarchive sets no message.
                return Err(Error::Unspecified);
            };
            self.strtab = Some(b[..strtab_size].to_vec());
            self.skip(input)?;
            self.ar_parse_gnu_filename_table()?;
            return Ok(None);
        }

        // A GNU long name: "/<number>", an offset in the filename table.
        if filename[0] == b'/' && filename[1].is_ascii_digit() {
            let number = ar_atol(h, AR_NAME_OFFSET + 1, AR_NAME_SIZE - 1, 10);
            let strtab = match &self.strtab {
                Some(strtab) if number < strtab.len() as u64 => strtab,
                _ => return Err(Error::LongFilename),
            };
            entry.path = c_string(&strtab[number as usize..]).to_vec();
            return Ok(Some(entry));
        }

        // A BSD long name: "#1/<length>", the name before the data.
        if filename.starts_with(b"#1/") {
            let number = ar_atol(h, AR_NAME_OFFSET + 3, AR_NAME_SIZE - 3, 10);
            // At most 1 MiB, and no more than the entry.
            if number > usize::MAX as u64 - 1
                || number > 1024 * 1024
                || number > self.entry_bytes_remaining as u64
            {
                return Err(Error::BadSize);
            }
            let bsd_name_length = number as usize;
            self.entry_bytes_remaining -= bsd_name_length as i64;
            entry.size = self.entry_bytes_remaining as u64;
            if *unconsumed != 0 {
                input.consume(*unconsumed as u64)?;
                *unconsumed = 0;
            }
            let Some(b) = input.ahead(bsd_name_length)? else {
                return Err(Error::TruncatedName);
            };
            entry.path = c_string(&b[..bsd_name_length]).to_vec();
            input.consume(bsd_name_length as u64)?;
            return Ok(Some(entry));
        }

        // A standard entry, its name trimmed as far as is known.
        entry.path = name.to_vec();
        Ok(Some(entry))
    }

    /// `ar_parse_common_header`: the time, owner, group, mode and size, and
    /// where the data starts.
    fn ar_parse_common_header(&mut self, h: &[u8; HEADER_SIZE]) -> Header {
        let mod_time = ar_atol(h, AR_DATE_OFFSET, AR_DATE_SIZE, 10) as i64;
        let uid = ar_atol(h, AR_UID_OFFSET, AR_UID_SIZE, 10) as u32;
        let gid = ar_atol(h, AR_GID_OFFSET, AR_GID_SIZE, 10) as u32;
        let mode = ar_atol(h, AR_MODE_OFFSET, AR_MODE_SIZE, 8) as u32;
        // archive_entry_set_filetype(entry, AE_IFREG).
        let mode = (mode & !AE_IFMT) | AE_IFREG;
        let n = ar_atol(h, AR_SIZE_OFFSET, AR_SIZE_SIZE, 10) as i64;
        self.entry_offset = 0;
        self.entry_padding = n % 2;
        self.entry_bytes_remaining = n;
        Header {
            path: Vec::new(),
            mode,
            uid,
            gid,
            size: n as u64,
            mod_time,
        }
    }

    /// `archive_read_format_ar_read_data`: the next of the entry's data,
    /// into `buf`; 0 at its end, where its padding is consumed.
    pub(crate) fn read_data<R: Read>(
        &mut self,
        input: &mut Input<R>,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        if self.entry_bytes_unconsumed != 0 {
            input.consume(self.entry_bytes_unconsumed as u64)?;
            self.entry_bytes_unconsumed = 0;
        }
        if self.entry_bytes_remaining > 0 {
            let available = match input.ahead(1)? {
                Some(b) => b,
                None => return Err(Error::TruncatedData),
            };
            let n = (available.len() as u64)
                .min(self.entry_bytes_remaining as u64)
                .min(buf.len() as u64) as usize;
            buf[..n].copy_from_slice(&available[..n]);
            input.consume(n as u64)?;
            self.entry_offset += n as i64;
            self.entry_bytes_remaining -= n as i64;
            Ok(n)
        } else {
            input.consume(self.entry_padding as u64)?;
            self.entry_padding = 0;
            Ok(0)
        }
    }

    /// `archive_read_format_ar_skip`: what is left of the entry's data, and
    /// its padding, from where the input is. `archive_read_data_skip` calls
    /// it between entries.
    pub(crate) fn skip<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        input.consume(
            (self.entry_bytes_remaining + self.entry_padding + self.entry_bytes_unconsumed) as u64,
        )?;
        self.entry_bytes_remaining = 0;
        self.entry_bytes_unconsumed = 0;
        self.entry_padding = 0;
        Ok(())
    }

    /// `ar_parse_gnu_filename_table`: the names split at their `/\n`, which
    /// become NULs, backslashes made slashes.
    fn ar_parse_gnu_filename_table(&mut self) -> Result<(), Error> {
        let Some(strtab) = self.strtab.as_mut() else {
            return Ok(());
        };
        let size = strtab.len();
        let mut p = 0;
        while p < size - 1 {
            // Normalize backslash, even before separator check.
            if strtab[p] == b'\\' {
                strtab[p] = b'/';
            }
            if strtab[p] == b'/' && strtab[p + 1] == b'\n' {
                strtab[p] = 0;
                p += 1;
                strtab[p] = 0;
            }
            p += 1;
        }
        // GNU ar pads the table to an even size with '\n' or '`'; Windows'
        // archives with NULs.
        if p != size && !matches!(strtab[p], b'\n' | b'`' | 0) {
            self.strtab = None;
            return Err(Error::StringTable);
        }
        // Enforce zero termination.
        strtab[size - 1] = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(fields: &str) -> [u8; HEADER_SIZE] {
        let mut h = [b' '; HEADER_SIZE];
        h[..fields.len()].copy_from_slice(fields.as_bytes());
        h[AR_FMAG_OFFSET..].copy_from_slice(b"`\n");
        h
    }

    #[test]
    fn numbers_stop_at_their_field_or_the_first_other_character() {
        let h = header("a.o/            1700000000  1000  100   100644  1234      ");
        assert_eq!(ar_atol(&h, AR_DATE_OFFSET, AR_DATE_SIZE, 10), 1_700_000_000);
        assert_eq!(ar_atol(&h, AR_UID_OFFSET, AR_UID_SIZE, 10), 1000);
        assert_eq!(ar_atol(&h, AR_MODE_OFFSET, AR_MODE_SIZE, 8), 0o100644);
        assert_eq!(ar_atol(&h, AR_SIZE_OFFSET, AR_SIZE_SIZE, 10), 1234);
        // An 8 is not octal.
        let h = header("a.o/            0           0     0     1789    0         ");
        assert_eq!(ar_atol(&h, AR_MODE_OFFSET, AR_MODE_SIZE, 8), 0o17);
    }

    #[test]
    fn a_field_of_spaces_is_zero() {
        // Followed by a space, the count wraps around, but the space stops
        // the digits.
        let h = header("a.o/                          42    7     644     0         ");
        assert_eq!(ar_atol(&h, AR_DATE_OFFSET, AR_DATE_SIZE, 10), 0);
        // Followed by a digit, the count is spent.
        let h = header("a.o/                        4242    7     644     0         ");
        assert_eq!(ar_atol(&h, AR_DATE_OFFSET, AR_DATE_SIZE, 10), 0);
        assert_eq!(ar_atol(&h, AR_UID_OFFSET, AR_UID_SIZE, 10), 4242);
    }

    #[test]
    fn a_field_of_digits_is_read_whole() {
        let mut h = header("");
        h[..58].fill(b'9');
        assert_eq!(ar_atol(&h, 1, AR_NAME_SIZE - 1, 10), 999_999_999_999_999);
        assert_eq!(ar_atol(&h, AR_SIZE_OFFSET, AR_SIZE_SIZE, 10), 9_999_999_999);
    }

    #[test]
    fn the_bid_is_the_global_header() {
        assert_eq!(bid(b"!<arch>\ndebian-binary"), 64);
        assert_eq!(bid(b"!<arch>"), -1);
        assert_eq!(bid(b"!<thin>\n"), -1);
    }
}
