//! Writing an archive: port of `writer.go`.
//!
//! Differs from Go: `Flush` is [`Writer::finish_entry`], as `io::Write::flush`
//! has to work in the middle of an entry; `close` flushes the output too; an
//! error that comes with the last bytes written comes after them, at the next
//! call. Not ported: `AddFS`, and what Go's writer has commented out or does
//! not reach, sparse files.

use std::io::{self, Write};

use crate::common::{
    BLOCK_SIZE, Error, Format, Header, HeaderView, MAX_SPECIAL_FILE_SIZE, NAME_SIZE, Records,
    TYPE_GNU_LONG_LINK, TYPE_GNU_LONG_NAME, TYPE_X_GLOBAL_HEADER, TYPE_X_HEADER, allowed_formats,
    block_padding, is_header_only_type,
};
use crate::format::{Block, field, get_mut, set_format};
use crate::strconv::{Formatter, append_pax_record, split_ustar_path, to_ascii};

/// A block of zeros: `zeroBlock`.
const ZERO_BLOCK: Block = [0; BLOCK_SIZE];

/// `stringFormatter` and `numberFormatter`.
type FormatString = fn(&mut Formatter, &mut [u8], &[u8]);
type FormatNumber = fn(&mut Formatter, &mut [u8], i64);

/// Writes a tar archive in order: [`Writer::write_header`] begins an entry,
/// `io::Write` takes its data, and [`Writer::close`] ends the archive. Go's
/// `Writer`.
///
/// Without `close` the archive has no end, and data still in `W`'s buffers is
/// its own to flush. An error from the output stays: every later call returns
/// it. Headers that cannot be written and writes past an entry's size fail
/// alone.
pub struct Writer<W> {
    w: W,
    /// What is left to write of the entry, and the padding after it.
    nb: i64,
    pad: i64,
    err: Option<Error>,
}

impl<W: Write> Writer<W> {
    /// `NewWriter`.
    pub fn new(w: W) -> Writer<W> {
        Writer {
            w,
            nb: 0,
            pad: 0,
            err: None,
        }
    }

    /// `Flush`: writes the padding of an entry whose data is all written.
    /// Not needed: the next `write_header` or `close` does it.
    pub fn finish_entry(&mut self) -> Result<(), Error> {
        if let Some(e) = &self.err {
            return Err(e.again());
        }
        if self.nb > 0 {
            return Err(Error::MissedWriting(self.nb));
        }
        if let Err(e) = self.w.write_all(&ZERO_BLOCK[..self.pad as usize]) {
            return Err(self.stick(Error::from(e)));
        }
        self.pad = 0;
        Ok(())
    }

    /// `WriteHeader`: begins an entry, of which `header.size` bytes of data
    /// may then be written (none for links, folders, devices and FIFOs). The
    /// entry before must have all its data.
    ///
    /// Without `header.format`, the modification time is rounded to a second
    /// and the other two left out, and the first of USTAR, PAX and GNU that can
    /// hold the header is used. A header that none can hold, or not the one it
    /// names, is an [`Error::CannotEncode`], and the archive goes on without it.
    pub fn write_header(&mut self, header: &Header) -> Result<(), Error> {
        self.finish_entry()?;
        let h = HeaderView::new(header);
        let (allowed, pax_hdrs) = allowed_formats(&h)?; // Not kept.
        let written = if allowed.has(Format::USTAR) {
            self.write_ustar_header(h)
        } else if allowed.has(Format::PAX) {
            self.write_pax_header(h, &pax_hdrs)
        } else {
            self.write_gnu_header(h)
        };
        written.map_err(|e| self.stick(e))
    }

    /// `writeUSTARHeader`.
    fn write_ustar_header(&mut self, mut h: HeaderView<'_>) -> Result<(), Error> {
        // The name in two fields, if it takes both.
        let mut prefix: &[u8] = b"";
        if let Some((p, suffix)) = split_ustar_path(h.name) {
            (prefix, h.name) = (p, suffix);
        }
        let mut f = Formatter::default();
        let mut blk = template_v7_plus(
            &h,
            &mut f,
            Formatter::format_string,
            Formatter::format_octal,
        );
        f.format_string(get_mut(&mut blk, field::USTAR_PREFIX), prefix);
        set_format(&mut blk, Format::USTAR);
        if f.err {
            return Err(Error::FieldTooLong); // The header was checked: not expected.
        }
        self.write_raw_header(&blk, h.size, h.typeflag)
    }

    /// `writePAXHeader`.
    fn write_pax_header(&mut self, h: HeaderView<'_>, pax_hdrs: &Records) -> Result<(), Error> {
        let is_global = h.typeflag == TYPE_X_GLOBAL_HEADER;
        if !pax_hdrs.is_empty() || is_global {
            // In key order, which a BTreeMap has.
            let mut data = Vec::new();
            for (k, v) in pax_hdrs {
                if !append_pax_record(&mut data, k, v) {
                    return Err(Error::Header);
                }
            }
            let (name, flag) = if is_global {
                let name = if h.name.is_empty() {
                    b"GlobalHead.0.0".to_vec()
                } else {
                    h.name.to_vec()
                };
                (name, TYPE_X_GLOBAL_HEADER)
            } else {
                let (dir, file) = split_path(h.name);
                (join_path(dir, b"PaxHeaders.0", file), TYPE_X_HEADER)
            };
            if data.len() > MAX_SPECIAL_FILE_SIZE {
                return Err(Error::FieldTooLong);
            }
            self.write_raw_file(&name, &data, flag, Format::PAX)?;
            if is_global {
                return Ok(());
            }
        }

        // What does not fit is in the records: the formatter's errors are expected.
        let mut f = Formatter::default();
        let mut blk = template_v7_plus(
            &h,
            &mut f,
            |f, b, s| f.format_string(b, &to_ascii(s)),
            Formatter::format_octal,
        );
        set_format(&mut blk, Format::PAX);
        self.write_raw_header(&blk, h.size, h.typeflag)
    }

    /// `writeGNUHeader`.
    fn write_gnu_header(&mut self, h: HeaderView<'_>) -> Result<(), Error> {
        const LONG_NAME: &[u8] = b"././@LongLink";
        // Files of their own for what is longer than its field.
        if h.name.len() > NAME_SIZE {
            let data = [h.name, b"\0"].concat();
            self.write_raw_file(LONG_NAME, &data, TYPE_GNU_LONG_NAME, Format::GNU)?;
        }
        if h.linkname.len() > NAME_SIZE {
            let data = [h.linkname, b"\0"].concat();
            self.write_raw_file(LONG_NAME, &data, TYPE_GNU_LONG_LINK, Format::GNU)?;
        }

        // The long names are cut off in the fields: the formatter's errors are
        // expected.
        let mut f = Formatter::default();
        let mut blk = template_v7_plus(
            &h,
            &mut f,
            Formatter::format_string,
            Formatter::format_numeric,
        );
        if let Some(t) = h.access_time {
            f.format_numeric(get_mut(&mut blk, field::GNU_ACCESS_TIME), t.secs);
        }
        if let Some(t) = h.change_time {
            f.format_numeric(get_mut(&mut blk, field::GNU_CHANGE_TIME), t.secs);
        }
        set_format(&mut blk, Format::GNU);
        self.write_raw_header(&blk, h.size, h.typeflag)
    }

    /// `writeRawFile`: a file with little but a name, a type and its data, as
    /// BSD and GNU tar write them.
    fn write_raw_file(
        &mut self,
        name: &[u8],
        data: &[u8],
        flag: u8,
        format: Format,
    ) -> Result<(), Error> {
        // The name is only the best that can be done.
        let name = to_ascii(name);
        let mut end = name.len().min(NAME_SIZE);
        while end > 0 && name[end - 1] == b'/' {
            end -= 1;
        }

        let mut blk = ZERO_BLOCK;
        let mut f = Formatter::default();
        get_mut(&mut blk, field::TYPE_FLAG)[0] = flag;
        f.format_string(get_mut(&mut blk, field::NAME), &name[..end]);
        f.format_octal(get_mut(&mut blk, field::MODE), 0);
        f.format_octal(get_mut(&mut blk, field::UID), 0);
        f.format_octal(get_mut(&mut blk, field::GID), 0);
        f.format_octal(get_mut(&mut blk, field::SIZE), data.len() as i64);
        f.format_octal(get_mut(&mut blk, field::MOD_TIME), 0);
        set_format(&mut blk, format);
        if f.err {
            return Err(Error::FieldTooLong); // Only for 8 GiB of data.
        }

        self.write_raw_header(&blk, data.len() as i64, flag)?;
        self.w.write_all(data)?;
        self.nb = 0;
        Ok(())
    }

    /// `writeRawHeader`: writes the block, and makes ready for the entry's data.
    fn write_raw_header(&mut self, blk: &Block, size: i64, flag: u8) -> Result<(), Error> {
        self.finish_entry()?;
        self.w.write_all(blk)?;
        let size = if is_header_only_type(flag) { 0 } else { size };
        self.nb = size;
        self.pad = block_padding(size);
        Ok(())
    }

    /// `Close`: the padding of the last entry and the two zero blocks that end
    /// the archive, then the output flushed. Every call after it fails with
    /// [`Error::WriteAfterClose`], but another `close`, which does nothing.
    /// The output is not closed.
    pub fn close(&mut self) -> Result<(), Error> {
        match &self.err {
            Some(Error::WriteAfterClose) => return Ok(()),
            Some(e) => return Err(e.again()),
            None => {}
        }
        let mut result = self.finish_entry();
        for _ in 0..2 {
            if result.is_ok() {
                result = self.w.write_all(&ZERO_BLOCK).map_err(Error::from);
            }
        }
        if result.is_ok() {
            result = self.w.flush().map_err(Error::from);
        }
        self.err = Some(Error::WriteAfterClose);
        result
    }

    /// Keeps `error`, and returns it to give back.
    fn stick(&mut self, error: Error) -> Error {
        let copy = error.again();
        self.err = Some(error);
        copy
    }

    /// The output.
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    /// The output. What is written to it around the writer's back ends up in
    /// the archive.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.w
    }

    /// The output, whatever has been written.
    pub fn into_inner(self) -> W {
        self.w
    }
}

/// `Writer.Write`: the data of the entry begun, up to its size. What is past
/// the size is not written: the write stops there, and the next one, as
/// `write_all`'s, fails with [`Error::WriteTooLong`].
impl<W: Write> Write for Writer<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if let Some(e) = &self.err {
            return Err(e.again().into());
        }
        if b.is_empty() {
            return Ok(0);
        }
        if self.nb == 0 {
            return Err(Error::WriteTooLong.into());
        }
        let room = usize::try_from(self.nb).unwrap_or(usize::MAX);
        let b = &b[..b.len().min(room)];
        loop {
            match self.w.write(b) {
                Ok(n) => {
                    self.nb -= n as i64;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.stick(Error::from(e)).into()),
            }
        }
    }

    /// The output's `flush`, which can come in the middle of an entry; the
    /// padding is [`Writer::finish_entry`]'s.
    fn flush(&mut self) -> io::Result<()> {
        match &self.err {
            None | Some(Error::WriteAfterClose) => self.w.flush(),
            Some(e) => Err(e.again().into()),
        }
    }
}

/// `templateV7Plus`: a block with the fields of V7, and those USTAR, PAX and
/// GNU share, written by the formatters given.
fn template_v7_plus(
    h: &HeaderView<'_>,
    f: &mut Formatter,
    fmt_str: FormatString,
    fmt_num: FormatNumber,
) -> Block {
    let mut blk = ZERO_BLOCK;
    get_mut(&mut blk, field::TYPE_FLAG)[0] = h.typeflag;
    fmt_str(f, get_mut(&mut blk, field::NAME), h.name);
    fmt_str(f, get_mut(&mut blk, field::LINK_NAME), h.linkname);
    fmt_num(f, get_mut(&mut blk, field::MODE), h.mode);
    fmt_num(f, get_mut(&mut blk, field::UID), h.uid);
    fmt_num(f, get_mut(&mut blk, field::GID), h.gid);
    fmt_num(f, get_mut(&mut blk, field::SIZE), h.size);
    let mod_time = h.mod_time.map_or(0, |t| t.secs);
    fmt_num(f, get_mut(&mut blk, field::MOD_TIME), mod_time);
    fmt_str(f, get_mut(&mut blk, field::USER_NAME), h.uname);
    fmt_str(f, get_mut(&mut blk, field::GROUP_NAME), h.gname);
    fmt_num(f, get_mut(&mut blk, field::DEV_MAJOR), h.devmajor);
    fmt_num(f, get_mut(&mut blk, field::DEV_MINOR), h.devminor);
    blk
}

/// Go's `path.Split`: up to the last slash, and after it.
fn split_path(name: &[u8]) -> (&[u8], &[u8]) {
    let at = name.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
    name.split_at(at)
}

/// Go's `path.Join` of three elements, the middle one not empty: joined by
/// slashes and made as short as `path.Clean` makes it, by reading alone.
fn join_path(dir: &[u8], middle: &[u8], file: &[u8]) -> Vec<u8> {
    let rooted = dir.first() == Some(&b'/');
    let mut parts: Vec<&[u8]> = Vec::new();
    let all = dir
        .split(|&c| c == b'/')
        .chain([middle])
        .chain(file.split(|&c| c == b'/'));
    for part in all {
        match part {
            b"" | b"." => {}
            b".." => match parts.last() {
                Some(&last) if last != b".." => {
                    parts.pop();
                }
                None if rooted => {}
                _ => parts.push(part),
            },
            _ => parts.push(part),
        }
    }
    let mut out = Vec::new();
    if rooted {
        out.push(b'/');
    }
    out.extend_from_slice(&parts.join(&b'/'));
    if out.is_empty() {
        out.push(b'.');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // What Go's path.Join gives for these, with "m" in the middle.
    #[test]
    fn join_path_cleans_as_go() {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"", b"f", b"m/f"),
            (b"a/", b"f", b"a/m/f"),
            (b"a//b/", b"f", b"a/b/m/f"),
            (b"/", b"f", b"/m/f"),
            (b"//a/", b"f", b"/a/m/f"),
            (b"./", b"f", b"m/f"),
            (b"a/./", b"f", b"a/m/f"),
            (b"../", b"f", b"../m/f"),
            (b"../../a/", b"f", b"../../a/m/f"),
            (b"a/../", b"f", b"m/f"),
            (b"a/b/../../", b"f", b"m/f"),
            (b"a/../../", b"f", b"../m/f"),
            (b"/../", b"f", b"/m/f"),
            (b"/a/../../", b"f", b"/m/f"),
            (b"a/", b"", b"a/m"),
            (b"", b"..", b"."),
        ];
        for &(dir, file, want) in cases {
            assert_eq!(join_path(dir, b"m", file), want, "{dir:x?}, {file:x?}");
        }
    }
}
