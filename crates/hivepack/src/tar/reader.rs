//! Reading an archive: port of `reader.go`.
//!
//! Inside, reads keep Go's shape: a count and perhaps an error, `io.EOF`
//! among them, which can come with the last bytes. [`Reader`] gives the
//! entries through [`Reader::next`] and their data through `io::Read`.
//!
//! Differs from Go: no `Seek` to skip data (the input is only `Read`); no
//! `GODEBUG=tarinsecurepath`, as checking names is hivepack::extract's job.

use std::io::{self, Read, Seek, SeekFrom};

use crate::tar::common::{
    BLOCK_SIZE, Error, Format, Header, MAX_SPARSE_FILE_ENTRIES, MAX_SPECIAL_FILE_SIZE, Records,
    SparseEntry, TYPE_DIR, TYPE_GNU_LONG_LINK, TYPE_GNU_LONG_NAME, TYPE_GNU_SPARSE, TYPE_REG,
    TYPE_REG_A, TYPE_X_GLOBAL_HEADER, TYPE_X_HEADER, Time, block_padding, invert_sparse_entries,
    is_header_only_type, validate_sparse_entries,
};
use crate::tar::format::{Block, SparseArray, field, get, get_format};
use crate::tar::strconv::{Parser, is_ascii, parse_int, parse_pax_record, parse_pax_time};

/// What a Go read returns besides its count: `io.EOF`, or an error.
#[derive(Debug)]
enum GoErr {
    Eof,
    Err(Error),
}

impl From<Error> for GoErr {
    fn from(e: Error) -> GoErr {
        GoErr::Err(e)
    }
}

/// A count, and what came with it.
type GoRead = (usize, Option<GoErr>);

/// An `io.Reader` as Go has it.
trait GoReader {
    fn go_read(&mut self, b: &mut [u8]) -> GoRead;
}

/// The archive's input, as an `io.Reader`.
struct Raw<'a, R>(&'a mut R);

impl<R: Read> GoReader for Raw<'_, R> {
    fn go_read(&mut self, b: &mut [u8]) -> GoRead {
        if b.is_empty() {
            return (0, None);
        }
        loop {
            match self.0.read(b) {
                Ok(0) => return (0, Some(GoErr::Eof)),
                Ok(n) => return (n, None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return (0, Some(GoErr::Err(Error::from(e)))),
            }
        }
    }
}

/// `zeroReader`.
struct ZeroReader;

impl GoReader for ZeroReader {
    fn go_read(&mut self, b: &mut [u8]) -> GoRead {
        b.fill(0);
        (b.len(), None)
    }
}

/// `tryReadFull`: `b` filled, or `io.EOF` (or another error) when the
/// input ends first.
fn try_read_full(r: &mut impl GoReader, b: &mut [u8]) -> GoRead {
    let mut n = 0;
    let mut err = None;
    while b.len() > n && err.is_none() {
        let (nn, e) = r.go_read(&mut b[n..]);
        n += nn;
        err = e;
    }
    if b.len() == n && matches!(err, Some(GoErr::Eof)) {
        err = None;
    }
    (n, err)
}

/// `mustReadFull`: as [`try_read_full`], `io.EOF` turned into
/// `io.ErrUnexpectedEOF`.
fn must_read_full(r: &mut impl GoReader, b: &mut [u8]) -> GoRead {
    let (n, err) = try_read_full(r, b);
    match err {
        Some(GoErr::Eof) => (n, Some(GoErr::Err(Error::UnexpectedEof))),
        err => (n, err),
    }
}

/// `io.ReadFull`: `io.EOF` only if nothing was read,
/// `io.ErrUnexpectedEOF` if some was.
fn read_full(r: &mut impl GoReader, b: &mut [u8]) -> Result<(), GoErr> {
    let (n, err) = try_read_full(r, b);
    match err {
        None => Ok(()),
        Some(GoErr::Eof) if n == 0 => Err(GoErr::Eof),
        Some(GoErr::Eof) => Err(GoErr::Err(Error::UnexpectedEof)),
        Some(e) => Err(e),
    }
}

/// `regFileReader`: what is left of an entry's data in the archive.
#[derive(Clone, Copy, Debug)]
struct RegFileReader {
    nb: i64,
}

/// `regFileReader.Read`, from `r`.
fn reg_read<R: Read>(r: &mut R, fr: &mut RegFileReader, b: &mut [u8]) -> GoRead {
    let len = b.len().min(usize::try_from(fr.nb).unwrap_or(usize::MAX));
    let b = &mut b[..len];
    let (mut n, mut err) = (0, None);
    if !b.is_empty() {
        (n, err) = Raw(r).go_read(b);
        fr.nb -= n as i64;
    }
    match err {
        Some(GoErr::Eof) if fr.nb > 0 => (n, Some(GoErr::Err(Error::UnexpectedEof))),
        None if fr.nb == 0 => (n, Some(GoErr::Eof)),
        err => (n, err),
    }
}

/// The entry's data in the archive, as an `io.Reader`: `regFileReader`.
struct Reg<'a, R> {
    r: &'a mut R,
    fr: &'a mut RegFileReader,
}

impl<R: Read> GoReader for Reg<'_, R> {
    fn go_read(&mut self, b: &mut [u8]) -> GoRead {
        reg_read(self.r, self.fr, b)
    }
}

/// `sparseFileReader`: a sparse file's data, its holes read as zeros.
#[derive(Clone, Debug)]
struct SparseFileReader {
    fr: RegFileReader,
    /// The holes, normalised; the last always stays.
    sp: Vec<SparseEntry>,
    at: usize,
    pos: i64,
}

impl SparseFileReader {
    /// `logicalRemaining`.
    fn logical_remaining(&self) -> i64 {
        self.sp[self.sp.len() - 1].end_offset() - self.pos
    }
}

/// `sparseFileReader.Read`.
fn sparse_read<R: Read>(r: &mut R, sr: &mut SparseFileReader, b: &mut [u8]) -> GoRead {
    let finished = b.len() as i64 >= sr.logical_remaining();
    let len = if finished {
        sr.logical_remaining().max(0) as usize
    } else {
        b.len()
    };
    let b0 = &mut b[..len];
    let mut done = 0;
    let mut err = None;
    let end_pos = sr.pos + len as i64;
    while end_pos > sr.pos && err.is_none() {
        let b = &mut b0[done..];
        let hole = sr.sp[sr.at];
        let (hole_start, hole_end) = (hole.offset, hole.end_offset());
        let nf;
        if sr.pos < hole_start {
            // In a data fragment.
            let take = (b.len() as i64).min(hole_start - sr.pos) as usize;
            (nf, err) = try_read_full(&mut Reg { r, fr: &mut sr.fr }, &mut b[..take]);
        } else {
            // In a hole.
            let take = (b.len() as i64).min(hole_end - sr.pos) as usize;
            (nf, err) = try_read_full(&mut ZeroReader, &mut b[..take]);
        }
        done += nf;
        sr.pos += nf as i64;
        if sr.pos >= hole_end && sr.at + 1 < sr.sp.len() {
            sr.at += 1; // The last fragment always stays.
        }
    }

    let n = done;
    match err {
        Some(GoErr::Eof) => (n, Some(GoErr::Err(Error::MissData))), // Less data than the map.
        Some(e) => (n, Some(e)),
        None if sr.logical_remaining() == 0 && sr.fr.nb > 0 => {
            (n, Some(GoErr::Err(Error::UnrefData))) // More data than the map.
        }
        None if finished => (n, Some(GoErr::Eof)),
        None => (n, None),
    }
}

/// `fileReader`: the current entry's data.
#[derive(Clone, Debug)]
enum FileReader {
    Reg(RegFileReader),
    Sparse(SparseFileReader),
}

impl FileReader {
    /// `physicalRemaining`: what is left of it in the archive.
    fn physical_remaining(&self) -> i64 {
        match self {
            FileReader::Reg(fr) => fr.nb,
            FileReader::Sparse(sr) => sr.fr.nb,
        }
    }
}

/// What stopped the reader: the end of the archive, or an error, returned
/// again by every later call.
#[derive(Debug)]
enum Stop {
    End,
    Error(Error),
}

/// A tar archive, read in order: Go's `Reader`. [`Reader::next`] gives the
/// next entry's header, and `io::Read` its data; data not read is skipped
/// by the next call to `next`.
///
/// An entry's data ends with `Ok(0)`. A failure is an `io::Error` that
/// holds an [`Error`], which `Error::from` takes back out; once a read or
/// `next` fails, every later call fails the same way.
#[derive(Debug)]
pub struct Reader<R> {
    r: R,
    /// Padding after the current entry's data.
    pad: i64,
    curr: FileReader,
    blk: Box<Block>,
    err: Option<Stop>,
    /// Moves the input on, from where it is, and gives where it is then, if
    /// it can: `Reader::seekable`.
    seek: Option<fn(&mut R, i64) -> io::Result<u64>>,
}

impl<R: Read + Seek> Reader<R> {
    /// `NewReader`, on an input that seeks past the data of entries not read:
    /// a file, whose data the next call to [`Reader::next`] then does not read,
    /// so that going through a large archive takes a moment.
    ///
    /// Differs from Go, which finds out that its input can seek by asking it:
    /// Rust cannot, so this is apart from [`Reader::new`]. An input that says it
    /// can and fails is read through, as Go does. An archive cut short in data
    /// that is skipped is found at the last byte of that data, as Go finds it.
    pub fn seekable(r: R) -> Reader<R> {
        let mut reader = Reader::new(r);
        reader.seek = Some(|r, n| r.seek(SeekFrom::Current(n)));
        reader
    }
}

impl<R: Read> Reader<R> {
    /// `NewReader`.
    pub fn new(r: R) -> Reader<R> {
        Reader {
            r,
            pad: 0,
            curr: FileReader::Reg(RegFileReader { nb: 0 }),
            blk: Box::new([0; BLOCK_SIZE]),
            err: None,
            seek: None,
        }
    }

    /// Whether the entry [`Reader::next`] gave last is sparse, its holes read as
    /// zeros.
    pub fn is_sparse(&self) -> bool {
        matches!(self.curr, FileReader::Sparse(_))
    }

    /// The input, as far as it was read.
    pub fn into_inner(self) -> R {
        self.r
    }

    /// `Next`: the next entry's header, or `None` at the end of the
    /// archive. What is left of the current entry's data is skipped.
    ///
    /// Not an `Iterator`: the entry's data is read from the reader itself,
    /// until the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        match &self.err {
            Some(Stop::End) => return Ok(None),
            Some(Stop::Error(e)) => return Err(e.again()),
            None => {}
        }
        match self.next_inner() {
            Ok(hdr) => Ok(Some(hdr)),
            Err(GoErr::Eof) => {
                self.err = Some(Stop::End);
                Ok(None)
            }
            Err(GoErr::Err(e)) => {
                self.err = Some(Stop::Error(e.again()));
                Err(e)
            }
        }
    }

    /// `next`.
    fn next_inner(&mut self) -> Result<Header, GoErr> {
        let mut pax_hdrs: Option<Records> = None;
        let mut gnu_long_name = Vec::new();
        let mut gnu_long_link = Vec::new();

        // Meta entries (PAX records, GNU long names) describe the entry
        // that follows them; this goes through them to a real entry.
        let mut format = Format::USTAR.union(Format::PAX).union(Format::GNU);
        loop {
            // The rest of the current entry's data, and its padding.
            self.discard(self.curr.physical_remaining())?;
            let pad = self.pad as usize;
            let (_, err) = try_read_full(&mut Raw(&mut self.r), &mut self.blk[..pad]);
            if let Some(e) = err {
                return Err(e);
            }
            self.pad = 0;

            let (mut hdr, raw_hdr) = self.read_header()?;
            self.handle_regular_file(&hdr)?;
            format.may_only_be(hdr.format);

            match hdr.typeflag {
                TYPE_X_HEADER | TYPE_X_GLOBAL_HEADER => {
                    format.may_only_be(Format::PAX);
                    let records = self.parse_pax()?;
                    if hdr.typeflag == TYPE_X_GLOBAL_HEADER {
                        // Go ignores what merging returns here.
                        let _ = merge_pax(&mut hdr, Some(records));
                        return Ok(Header {
                            name: hdr.name,
                            typeflag: hdr.typeflag,
                            xattrs: hdr.xattrs,
                            pax_records: hdr.pax_records,
                            format,
                            ..Header::default()
                        });
                    }
                    pax_hdrs = Some(records);
                    continue; // For the next header.
                }
                TYPE_GNU_LONG_NAME | TYPE_GNU_LONG_LINK => {
                    format.may_only_be(Format::GNU);
                    let realname = self.read_special_file()?;
                    let p = Parser::default();
                    if hdr.typeflag == TYPE_GNU_LONG_NAME {
                        gnu_long_name = p.parse_string(&realname);
                    } else {
                        gnu_long_link = p.parse_string(&realname);
                    }
                    continue; // For the next header.
                }
                _ => {
                    // The old GNU sparse format is a regular file with more
                    // to it, handled here.
                    merge_pax(&mut hdr, pax_hdrs.take())?;
                    if !gnu_long_name.is_empty() {
                        hdr.name = std::mem::take(&mut gnu_long_name);
                    }
                    if !gnu_long_link.is_empty() {
                        hdr.linkname = std::mem::take(&mut gnu_long_link);
                    }
                    if hdr.typeflag == TYPE_REG_A {
                        // Old archives mark directories with a trailing
                        // slash.
                        hdr.typeflag = if hdr.name.ends_with(b"/") {
                            TYPE_DIR
                        } else {
                            TYPE_REG
                        };
                    }

                    // PAX records may have changed the size.
                    self.handle_regular_file(&hdr)?;
                    // The sparse formats read from the data section, which
                    // the call above sets up.
                    self.handle_sparse_file(&mut hdr, &raw_hdr)?;

                    // The last guess at the format.
                    if format.has(Format::USTAR) && format.has(Format::PAX) {
                        format.may_only_be(Format::USTAR);
                    }
                    hdr.format = format;
                    return Ok(hdr);
                }
            }
        }
    }

    /// `handleRegularFile`: the reader and padding for the entry's data,
    /// none for the types that have none.
    fn handle_regular_file(&mut self, hdr: &Header) -> Result<(), GoErr> {
        let nb = if is_header_only_type(hdr.typeflag) {
            0
        } else {
            hdr.size
        };
        if nb < 0 {
            return Err(Error::Header.into());
        }
        self.pad = block_padding(nb);
        self.curr = FileReader::Reg(RegFileReader { nb });
        Ok(())
    }

    /// `handleSparseFile`: a sparse reader over the data, if the entry is
    /// sparse in any of GNU's formats.
    fn handle_sparse_file(&mut self, hdr: &mut Header, raw_hdr: &Block) -> Result<(), GoErr> {
        let spd = if hdr.typeflag == TYPE_GNU_SPARSE {
            self.read_old_gnu_sparse_map(hdr, raw_hdr)?
        } else {
            self.read_gnu_sparse_pax_headers(hdr)?
        };
        // Not sparse without a map; a map may be empty.
        if let Some(spd) = spd {
            if is_header_only_type(hdr.typeflag) || !validate_sparse_entries(&spd, hdr.size) {
                return Err(Error::Header.into());
            }
            let sph = invert_sparse_entries(&spd, hdr.size);
            let fr = match self.curr {
                FileReader::Reg(fr) => fr,
                FileReader::Sparse(ref sr) => sr.fr,
            };
            self.curr = FileReader::Sparse(SparseFileReader {
                fr,
                sp: sph,
                at: 0,
                pos: 0,
            });
        }
        Ok(())
    }

    /// The current entry's data, as an `io.Reader`, to read meta entries
    /// and sparse maps from.
    fn reg(&mut self) -> Reg<'_, R> {
        let fr = match &mut self.curr {
            FileReader::Reg(fr) => fr,
            FileReader::Sparse(sr) => &mut sr.fr,
        };
        Reg { r: &mut self.r, fr }
    }

    /// `readGNUSparsePAXHeaders`: the sparse map of PAX's GNU formats (0.0
    /// and 0.1 in the records, 1.0 at the start of the data), if any.
    fn read_gnu_sparse_pax_headers(
        &mut self,
        hdr: &mut Header,
    ) -> Result<Option<Vec<SparseEntry>>, GoErr> {
        let rec = |k: &[u8]| hdr.pax_records.get(k).map_or(&b""[..], |v| &v[..]);
        let (major, minor) = (rec(b"GNU.sparse.major"), rec(b"GNU.sparse.minor"));
        let is1x0 = if major == b"0" && (minor == b"0" || minor == b"1") {
            false
        } else if major == b"1" && minor == b"0" {
            true
        } else if !major.is_empty() || !minor.is_empty() {
            return Ok(None); // An unknown version.
        } else if !rec(b"GNU.sparse.map").is_empty() {
            false // 0.0 and 0.1 had no version records: a guess.
        } else {
            return Ok(None); // Not sparse.
        };
        hdr.format.may_only_be(Format::PAX);

        let name = rec(b"GNU.sparse.name").to_vec();
        let mut size = rec(b"GNU.sparse.size").to_vec();
        if size.is_empty() {
            size = rec(b"GNU.sparse.realsize").to_vec();
        }
        if !name.is_empty() {
            hdr.name = name;
        }
        if !size.is_empty() {
            hdr.size = parse_int(&size).ok_or(GoErr::Err(Error::Header))?;
        }

        if is1x0 {
            return read_gnu_sparse_map_1x0(&mut self.reg()).map(Some);
        }
        read_gnu_sparse_map_0x1(&hdr.pax_records).map(Some)
    }

    /// `parsePAX`: the records of a PAX header; GNU's sparse format 0.0,
    /// whose repeated `offset` and `numbytes` records are not PAX, is
    /// turned into 0.1's `map`.
    fn parse_pax(&mut self) -> Result<Records, GoErr> {
        let buf = self.read_special_file()?;
        let mut sbuf = &buf[..];
        let mut sparse_map: Vec<&[u8]> = Vec::new();
        let mut pax_hdrs = Records::new();
        while !sbuf.is_empty() {
            let (key, value, residual) = parse_pax_record(sbuf).ok_or(GoErr::Err(Error::Header))?;
            sbuf = residual;
            match key {
                b"GNU.sparse.offset" | b"GNU.sparse.numbytes" => {
                    // In order, and without commas.
                    if (sparse_map.len().is_multiple_of(2) && key != b"GNU.sparse.offset")
                        || (sparse_map.len() % 2 == 1 && key != b"GNU.sparse.numbytes")
                        || value.contains(&b',')
                    {
                        return Err(Error::Header.into());
                    }
                    sparse_map.push(value);
                }
                _ => {
                    pax_hdrs.insert(key.to_vec(), value.to_vec());
                }
            }
        }
        if !sparse_map.is_empty() {
            pax_hdrs.insert(b"GNU.sparse.map".to_vec(), sparse_map.join(&b','));
        }
        Ok(pax_hdrs)
    }

    /// `readHeader`: the next header block, the input at a block's start.
    /// The end of the archive (`io.EOF`) is the input's end before a block,
    /// after one block of zeros, or two blocks of zeros.
    fn read_header(&mut self) -> Result<(Header, Block), GoErr> {
        read_full(&mut Raw(&mut self.r), &mut self.blk[..])?;
        if self.blk.iter().all(|&c| c == 0) {
            read_full(&mut Raw(&mut self.r), &mut self.blk[..])?;
            if self.blk.iter().all(|&c| c == 0) {
                return Err(GoErr::Eof);
            }
            return Err(Error::Header.into()); // Zeros, then not.
        }

        let b: &Block = &self.blk;
        let format = get_format(b);
        if format == Format::UNKNOWN {
            return Err(Error::Header.into());
        }

        let mut p = Parser::default();
        let mut hdr = Header {
            typeflag: get(b, field::TYPE_FLAG)[0],
            name: p.parse_string(get(b, field::NAME)),
            linkname: p.parse_string(get(b, field::LINK_NAME)),
            ..Header::default()
        };
        hdr.size = p.parse_numeric(get(b, field::SIZE));
        hdr.mode = p.parse_numeric(get(b, field::MODE));
        hdr.uid = p.parse_numeric(get(b, field::UID));
        hdr.gid = p.parse_numeric(get(b, field::GID));
        hdr.mod_time = Some(Time::unix(p.parse_numeric(get(b, field::MOD_TIME)), 0));

        if format.bits() > Format::V7.bits() {
            hdr.uname = p.parse_string(get(b, field::USER_NAME));
            hdr.gname = p.parse_string(get(b, field::GROUP_NAME));
            hdr.devmajor = p.parse_numeric(get(b, field::DEV_MAJOR));
            hdr.devminor = p.parse_numeric(get(b, field::DEV_MINOR));

            let mut prefix = Vec::new();
            if format.has(Format::USTAR.union(Format::PAX)) {
                hdr.format = format;
                prefix = p.parse_string(get(b, field::USTAR_PREFIX));

                // USTAR is stricter than the parsing: ASCII only, and the
                // numeric fields ending with a NUL.
                if b.iter().any(|&c| c >= 0x80) {
                    hdr.format = Format::UNKNOWN;
                }
                let nul = |f: (usize, usize)| get(b, f)[f.1 - 1] == 0;
                if !(nul(field::SIZE)
                    && nul(field::MODE)
                    && nul(field::UID)
                    && nul(field::GID)
                    && nul(field::MOD_TIME)
                    && nul(field::DEV_MAJOR)
                    && nul(field::DEV_MINOR))
                {
                    hdr.format = Format::UNKNOWN;
                }
            } else if format.has(Format::STAR) {
                prefix = p.parse_string(get(b, field::STAR_PREFIX));
                hdr.access_time = Some(Time::unix(
                    p.parse_numeric(get(b, field::STAR_ACCESS_TIME)),
                    0,
                ));
                hdr.change_time = Some(Time::unix(
                    p.parse_numeric(get(b, field::STAR_CHANGE_TIME)),
                    0,
                ));
            } else if format.has(Format::GNU) {
                hdr.format = format;
                let mut p2 = Parser::default();
                let atime = get(b, field::GNU_ACCESS_TIME);
                if atime[0] != 0 {
                    hdr.access_time = Some(Time::unix(p2.parse_numeric(atime), 0));
                }
                let ctime = get(b, field::GNU_CHANGE_TIME);
                if ctime[0] != 0 {
                    hdr.change_time = Some(Time::unix(p2.parse_numeric(ctime), 0));
                }

                // Go's Writer before 1.8 wrote a USTAR prefix into GNU
                // headers, over the atime and ctime: if those do not parse
                // and the prefix looks like ASCII, it is taken as a prefix
                // (Go issues 12594 and 21005).
                if p2.err {
                    hdr.access_time = None;
                    hdr.change_time = None;
                    let s = p.parse_string(get(b, field::USTAR_PREFIX));
                    if is_ascii(&s) {
                        prefix = s;
                    }
                    hdr.format = Format::UNKNOWN; // Not GNU.
                }
            }
            if !prefix.is_empty() {
                prefix.push(b'/');
                prefix.extend_from_slice(&hdr.name);
                hdr.name = prefix;
            }
        }
        if p.err {
            return Err(Error::Header.into());
        }
        Ok((hdr, *self.blk))
    }

    /// `readOldGNUSparseMap`: the map in the header, and in the extension
    /// blocks after it if it has more than four entries.
    fn read_old_gnu_sparse_map(
        &mut self,
        hdr: &mut Header,
        blk: &Block,
    ) -> Result<Option<Vec<SparseEntry>>, GoErr> {
        // STAR's sparse header has the same type but another layout.
        if get_format(blk) != Format::GNU {
            return Err(Error::Header.into());
        }
        hdr.format.may_only_be(Format::GNU);

        let mut p = Parser::default();
        hdr.size = p.parse_numeric(get(blk, field::GNU_REAL_SIZE));
        if p.err {
            return Err(Error::Header.into());
        }
        let mut ext: Block = *blk;
        let mut s_range = field::GNU_SPARSE;
        let mut spd = Vec::new();
        let mut total_size = s_range.1;
        while total_size < MAX_SPECIAL_FILE_SIZE {
            let s = SparseArray(&ext[s_range.0..s_range.0 + s_range.1]);
            for i in 0..s.max_entries() {
                let (offset, length) = s.entry(i);
                // As GNU and BSD tar end it.
                if offset[0] == 0 {
                    break; // The extension headers are still read.
                }
                let offset = p.parse_numeric(offset);
                let length = p.parse_numeric(length);
                if p.err {
                    return Err(Error::Header.into());
                }
                append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
            }
            if s.is_extended() > 0 {
                // More entries, in an extension block.
                let (_, err) = must_read_full(&mut Raw(&mut self.r), &mut ext[..]);
                if let Some(e) = err {
                    return Err(e);
                }
                s_range = (0, BLOCK_SIZE);
                total_size += BLOCK_SIZE;
                continue;
            }
            return Ok(Some(spd));
        }
        Err(Error::SparseTooLong.into())
    }

    /// `readSpecialFile`: the whole of a meta entry's data, 1 MiB at most.
    fn read_special_file(&mut self) -> Result<Vec<u8>, GoErr> {
        let limit = MAX_SPECIAL_FILE_SIZE + 1;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut err = None;
        while buf.len() < limit {
            let want = (limit - buf.len()).min(chunk.len());
            let (n, e) = self.reg().go_read(&mut chunk[..want]);
            buf.extend_from_slice(&chunk[..n]);
            match e {
                None => {}
                Some(GoErr::Eof) => break,
                Some(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        if buf.len() > MAX_SPECIAL_FILE_SIZE {
            return Err(Error::FieldTooLong.into());
        }
        match err {
            None => Ok(buf),
            Some(e) => Err(e),
        }
    }

    /// `discard`: `n` bytes of the input skipped.
    fn discard(&mut self, n: i64) -> Result<(), GoErr> {
        let mut left = n;
        // Up to the last byte, as seeking is lazy about reporting errors: the
        // read after it finds that the input was cut short. Not every input
        // that says it seeks can: an innocent seek finds out.
        if let Some(seek) = self.seek
            && n > 1
            && let Ok(before) = seek(&mut self.r, 0)
        {
            let after = seek(&mut self.r, n - 1).map_err(Error::from)?;
            left = left.wrapping_sub(after.wrapping_sub(before) as i64);
        }
        let mut chunk = [0u8; 8192];
        while left > 0 {
            let want = left.min(chunk.len() as i64) as usize;
            let (got, err) = Raw(&mut self.r).go_read(&mut chunk[..want]);
            left -= got as i64;
            match err {
                None => {}
                Some(GoErr::Eof) if left > 0 => return Err(Error::UnexpectedEof.into()),
                Some(GoErr::Eof) => return Ok(()),
                Some(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// `mergePAX`: the records that USTAR's fields have, over them; an empty
/// value keeps the field. The records are kept in the header.
fn merge_pax(hdr: &mut Header, pax_hdrs: Option<Records>) -> Result<(), GoErr> {
    let Some(pax_hdrs) = pax_hdrs else {
        hdr.pax_records = Records::new();
        return Ok(());
    };
    for (k, v) in &pax_hdrs {
        if v.is_empty() {
            continue; // The USTAR value stays.
        }
        let bad = || GoErr::Err(Error::Header);
        match &k[..] {
            b"path" => hdr.name = v.clone(),
            b"linkpath" => hdr.linkname = v.clone(),
            b"uname" => hdr.uname = v.clone(),
            b"gname" => hdr.gname = v.clone(),
            b"uid" => hdr.uid = parse_int(v).ok_or_else(bad)?,
            b"gid" => hdr.gid = parse_int(v).ok_or_else(bad)?,
            b"atime" => hdr.access_time = Some(parse_pax_time(v).ok_or_else(bad)?),
            b"mtime" => hdr.mod_time = Some(parse_pax_time(v).ok_or_else(bad)?),
            b"ctime" => hdr.change_time = Some(parse_pax_time(v).ok_or_else(bad)?),
            b"size" => hdr.size = parse_int(v).ok_or_else(bad)?,
            _ => {
                if let Some(name) = k.strip_prefix(b"SCHILY.xattr.") {
                    hdr.xattrs.insert(name.to_vec(), v.clone());
                }
            }
        }
    }
    hdr.pax_records = pax_hdrs;
    Ok(())
}

/// `appendSparseEntry`: a million entries at most.
fn append_sparse_entry(spd: &mut Vec<SparseEntry>, ent: SparseEntry) -> Result<(), GoErr> {
    if spd.len() >= MAX_SPARSE_FILE_ENTRIES {
        return Err(Error::SparseTooLong.into());
    }
    spd.push(ent);
    Ok(())
}

/// `readGNUSparseMap1x0`: GNU's PAX sparse format 1.0, whose map is at the
/// start of the data: lines of decimal numbers, the count of entries, then
/// an offset and a length for each, to the end of the block that holds the
/// last newline.
fn read_gnu_sparse_map_1x0(r: &mut impl GoReader) -> Result<Vec<SparseEntry>, GoErr> {
    let mut cnt_newline: i64 = 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut at = 0;
    let mut blk = [0u8; BLOCK_SIZE];
    let mut total_size = 0usize;

    // `feedTokens`: blocks into buf until it has n newlines.
    let mut feed_tokens = |n: i64, buf: &mut Vec<u8>, cnt: &mut i64| -> Result<(), GoErr> {
        while *cnt < n {
            total_size += BLOCK_SIZE;
            if total_size > MAX_SPECIAL_FILE_SIZE {
                return Err(Error::SparseTooLong.into());
            }
            let (_, err) = must_read_full(r, &mut blk);
            if let Some(e) = err {
                return Err(e);
            }
            buf.extend_from_slice(&blk);
            *cnt += blk.iter().filter(|&&c| c == b'\n').count() as i64;
        }
        Ok(())
    };
    // `nextToken`: up to the next newline.
    let next_token = |buf: &Vec<u8>, at: &mut usize, cnt: &mut i64| -> Vec<u8> {
        *cnt -= 1;
        let rest = &buf[*at..];
        let end = rest
            .iter()
            .position(|&c| c == b'\n')
            .map_or(rest.len(), |i| i + 1);
        let tok = &rest[..end];
        *at += end;
        tok.strip_suffix(b"\n").unwrap_or(tok).to_vec()
    };

    feed_tokens(1, &mut buf, &mut cnt_newline)?;
    let num_entries = parse_int(&next_token(&buf, &mut at, &mut cnt_newline));
    let num_entries = match num_entries {
        Some(n) if n >= 0 && n.wrapping_mul(2) >= n => n,
        _ => return Err(Error::Header.into()),
    };
    // Trusted from here: feed_tokens bounds the tokens.
    feed_tokens(2 * num_entries, &mut buf, &mut cnt_newline)?;
    let mut spd = Vec::new();
    for _ in 0..num_entries {
        let offset = parse_int(&next_token(&buf, &mut at, &mut cnt_newline));
        let length = parse_int(&next_token(&buf, &mut at, &mut cnt_newline));
        let (Some(offset), Some(length)) = (offset, length) else {
            return Err(Error::Header.into());
        };
        append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
    }
    Ok(spd)
}

/// `readGNUSparseMap0x1`: GNU's PAX sparse format 0.1, the map in the
/// records `GNU.sparse.numblocks` and `GNU.sparse.map`.
fn read_gnu_sparse_map_0x1(pax_hdrs: &Records) -> Result<Vec<SparseEntry>, GoErr> {
    let get = |k: &[u8]| pax_hdrs.get(k).map_or(&b""[..], |v| &v[..]);
    let num_entries = match parse_int(get(b"GNU.sparse.numblocks")) {
        Some(n) if n >= 0 && n.wrapping_mul(2) >= n => n,
        _ => return Err(Error::Header.into()),
    };
    let mut sparse_map: Vec<&[u8]> = get(b"GNU.sparse.map").split(|&c| c == b',').collect();
    if sparse_map.len() == 1 && sparse_map[0].is_empty() {
        sparse_map.clear();
    }
    if sparse_map.len() as i64 != num_entries.wrapping_mul(2) {
        return Err(Error::Header.into());
    }
    let mut spd = Vec::new();
    for pair in sparse_map.as_chunks::<2>().0 {
        let (Some(offset), Some(length)) = (parse_int(pair[0]), parse_int(pair[1])) else {
            return Err(Error::Header.into());
        };
        append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
    }
    Ok(spd)
}

impl<R: Read> Read for Reader<R> {
    /// `Read`: the current entry's data; a sparse file's holes are zeros.
    /// Types without data (links, directories, devices) have none, whatever
    /// their size says.
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match &self.err {
            Some(Stop::End) => return Ok(0),
            Some(Stop::Error(e)) => return Err(e.again().into()),
            None => {}
        }
        let (n, err) = match &mut self.curr {
            FileReader::Reg(fr) => reg_read(&mut self.r, fr, b),
            FileReader::Sparse(sr) => sparse_read(&mut self.r, sr, b),
        };
        match err {
            None | Some(GoErr::Eof) => Ok(n),
            Some(GoErr::Err(e)) => {
                // Go gives the bytes with the error; here they come first,
                // and the error at the next call, as it stays.
                self.err = Some(Stop::Error(e.again()));
                if n > 0 { Ok(n) } else { Err(e.into()) }
            }
        }
    }
}
