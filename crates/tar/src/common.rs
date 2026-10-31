//! What the reader, the writer and their callers share: port of `common.go`,
//! with the formats of `format.go`.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use crate::format::field;
use crate::strconv::{
    fits_in_base256, fits_in_octal, format_pax_time, has_nul, is_ascii, split_ustar_path,
    valid_pax_record,
};

/// `TypeReg`: a regular file.
pub const TYPE_REG: u8 = b'0';
/// `TypeRegA`: a regular file in old archives; the reader turns it into
/// [`TYPE_REG`], or [`TYPE_DIR`] when the name ends with `/`.
pub const TYPE_REG_A: u8 = 0;
/// `TypeLink`: a hard link.
pub const TYPE_LINK: u8 = b'1';
/// `TypeSymlink`: a symbolic link.
pub const TYPE_SYMLINK: u8 = b'2';
/// `TypeChar`: a character device.
pub const TYPE_CHAR: u8 = b'3';
/// `TypeBlock`: a block device.
pub const TYPE_BLOCK: u8 = b'4';
/// `TypeDir`: a directory.
pub const TYPE_DIR: u8 = b'5';
/// `TypeFifo`: a named pipe.
pub const TYPE_FIFO: u8 = b'6';
/// `TypeCont`: reserved; read as a regular file.
pub const TYPE_CONT: u8 = b'7';
/// `TypeXHeader`: PAX records for the next entry, which the reader merges.
pub const TYPE_X_HEADER: u8 = b'x';
/// `TypeXGlobalHeader`: PAX records for the whole archive, which the
/// reader returns as an entry of their own.
pub const TYPE_X_GLOBAL_HEADER: u8 = b'g';
/// `TypeGNUSparse`: a GNU sparse file in the old format.
pub const TYPE_GNU_SPARSE: u8 = b'S';
/// `TypeGNULongName`: GNU's long name for the next entry, merged.
pub const TYPE_GNU_LONG_NAME: u8 = b'L';
/// `TypeGNULongLink`: GNU's long link target for the next entry, merged.
pub const TYPE_GNU_LONG_LINK: u8 = b'K';

/// `isHeaderOnlyType`: the types whose entries have no data, whatever
/// their size says.
pub(crate) fn is_header_only_type(flag: u8) -> bool {
    matches!(
        flag,
        TYPE_LINK | TYPE_SYMLINK | TYPE_CHAR | TYPE_BLOCK | TYPE_DIR | TYPE_FIFO
    )
}

/// `blockSize`.
pub(crate) const BLOCK_SIZE: usize = 512;

/// `maxSpecialFileSize`: the largest PAX records or GNU long name taken.
pub(crate) const MAX_SPECIAL_FILE_SIZE: usize = 1 << 20;

/// `maxSparseFileEntries`.
pub(crate) const MAX_SPARSE_FILE_ENTRIES: usize = 1 << 20;

/// `nameSize`: the name field of a V7 block, and of the others.
pub(crate) const NAME_SIZE: usize = 100;

/// `prefixSize`: the prefix field of a USTAR block.
pub(crate) const PREFIX_SIZE: usize = 155;

/// `blockPadding`: the padding after `offset` bytes, to a block's end.
pub(crate) fn block_padding(offset: i64) -> i64 {
    offset.wrapping_neg() & (BLOCK_SIZE as i64 - 1)
}

/// The formats an entry may be in: Go's `Format`, a set of bits.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Format(u32);

impl Format {
    /// `FormatUnknown`.
    pub const UNKNOWN: Format = Format(0);
    /// `formatV7`: the original Unix format.
    pub const V7: Format = Format(1);
    /// `FormatUSTAR`: POSIX.1-1988.
    pub const USTAR: Format = Format(2);
    /// `FormatPAX`: POSIX.1-2001, USTAR with PAX records.
    pub const PAX: Format = Format(4);
    /// `FormatGNU`.
    pub const GNU: Format = Format(8);
    /// `formatSTAR`: Schily's.
    pub const STAR: Format = Format(16);

    /// `has`: whether any of `f2`'s formats are in this set.
    pub fn has(self, f2: Format) -> bool {
        self.0 & f2.0 != 0
    }

    /// `mayOnlyBe`.
    pub(crate) fn may_only_be(&mut self, f2: Format) {
        self.0 &= f2.0;
    }

    /// `mustNotBe`.
    fn must_not_be(&mut self, f2: Format) {
        self.0 &= !f2.0;
    }

    /// The formats of both sets: `f | f2` in Go. A header can say more than
    /// one format, and the writer picks among them.
    pub fn union(self, f2: Format) -> Format {
        Format(self.0 | f2.0)
    }

    /// The bits, as Go's `Format` holds them.
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// As Go's `Format.String`: `USTAR`, `(USTAR | PAX)`, `<unknown>`.
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (1, "V7"),
            (2, "USTAR"),
            (4, "PAX"),
            (8, "GNU"),
            (16, "STAR"),
        ];
        let ss: Vec<&str> = names
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, n)| *n)
            .collect();
        match ss.len() {
            0 => f.write_str("<unknown>"),
            1 => f.write_str(ss[0]),
            _ => write!(f, "({})", ss.join(" | ")),
        }
    }
}

impl fmt::Debug for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A time as Go's `time.Unix` makes it: seconds since 1970, and
/// nanoseconds from 0 to 999,999,999.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub secs: i64,
    /// Nanoseconds past them.
    pub nanos: u32,
}

impl Time {
    /// `time.Unix`: `nsec` outside a second carried into the seconds, with
    /// Go's wrapping arithmetic.
    pub(crate) fn unix(mut sec: i64, mut nsec: i64) -> Time {
        if !(0..1_000_000_000).contains(&nsec) {
            let n = nsec / 1_000_000_000;
            sec = sec.wrapping_add(n);
            nsec -= n * 1_000_000_000;
            if nsec < 0 {
                nsec += 1_000_000_000;
                sec = sec.wrapping_sub(1);
            }
        }
        Time {
            secs: sec,
            nanos: nsec as u32,
        }
    }

    /// `Time.IsZero`: January 1 of year 1, which Go's zero time is.
    pub(crate) fn is_zero(self) -> bool {
        self.secs == -62_135_596_800 && self.nanos == 0
    }

    /// `Time.Round(time.Second)`: halves go up.
    fn round_to_second(self) -> Time {
        Time {
            secs: self.secs.wrapping_add(i64::from(self.nanos >= 500_000_000)),
            nanos: 0,
        }
    }
}

/// Keys and values of PAX records, and of extended attributes: bytes, as
/// Go's strings hold them.
pub type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// An entry's header: Go's `Header`. Names are bytes, as tar keeps them;
/// most archives write UTF-8.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The type, one of the `TYPE_` constants or another byte.
    pub typeflag: u8,
    /// The entry's name, with USTAR's prefix, GNU's long name or PAX's
    /// `path` applied.
    pub name: Vec<u8>,
    /// A link's target.
    pub linkname: Vec<u8>,
    /// The size of the data, as the file will have it (sparse files take
    /// less in the archive).
    pub size: i64,
    /// The mode: permission bits, and in some archives the type's.
    pub mode: i64,
    /// The owner.
    pub uid: i64,
    /// The group.
    pub gid: i64,
    /// The owner's name.
    pub uname: Vec<u8>,
    /// The group's name.
    pub gname: Vec<u8>,
    /// The time of the last change of the data. `None` only for a global
    /// PAX header when reading; when writing, 1970 for other entries.
    pub mod_time: Option<Time>,
    /// The time of the last access, if the archive has it (PAX, GNU, STAR).
    /// Written only with a `format` chosen.
    pub access_time: Option<Time>,
    /// The time of the last change of the inode, if the archive has it.
    /// Written only with a `format` chosen.
    pub change_time: Option<Time>,
    /// A device's major number.
    pub devmajor: i64,
    /// A device's minor number.
    pub devminor: i64,
    /// Extended attributes, from PAX's `SCHILY.xattr.` records (Go's
    /// deprecated `Xattrs`).
    pub xattrs: Records,
    /// All the PAX records that applied to the entry. When writing, those
    /// that the fields above hold, and `GNU.sparse.` ones, are left out unless
    /// they say the same as the field.
    pub pax_records: Records,
    /// The formats the entry may be in. When writing, the ones allowed, or
    /// [`Format::UNKNOWN`] for any.
    pub format: Format,
}

/// `verifyTime`'s and the writer's view of a time: normalised as `time.Unix`
/// makes it, `None` for Go's zero time however it is said.
fn set_time(t: Option<Time>) -> Option<Time> {
    t.map(|t| Time::unix(t.secs, i64::from(t.nanos)))
        .filter(|t| !t.is_zero())
}

/// What `Writer.WriteHeader` makes of a header: Go's shallow copy of it,
/// which it changes, without copying the names.
#[derive(Clone, Copy)]
pub(crate) struct HeaderView<'a> {
    pub(crate) typeflag: u8,
    pub(crate) name: &'a [u8],
    pub(crate) linkname: &'a [u8],
    pub(crate) size: i64,
    pub(crate) mode: i64,
    pub(crate) uid: i64,
    pub(crate) gid: i64,
    pub(crate) uname: &'a [u8],
    pub(crate) gname: &'a [u8],
    pub(crate) mod_time: Option<Time>,
    pub(crate) access_time: Option<Time>,
    pub(crate) change_time: Option<Time>,
    pub(crate) devmajor: i64,
    pub(crate) devminor: i64,
    pub(crate) xattrs: &'a Records,
    pub(crate) pax_records: &'a Records,
    pub(crate) format: Format,
}

impl<'a> HeaderView<'a> {
    /// The start of `WriteHeader`: `TypeRegA` becomes what it stands for, and
    /// without a format chosen the modification time is rounded and the other
    /// two left out, so that ordinary headers do not take PAX's extra 1 KiB.
    pub(crate) fn new(h: &'a Header) -> HeaderView<'a> {
        let mut view = HeaderView {
            typeflag: h.typeflag,
            name: &h.name,
            linkname: &h.linkname,
            size: h.size,
            mode: h.mode,
            uid: h.uid,
            gid: h.gid,
            uname: &h.uname,
            gname: &h.gname,
            mod_time: set_time(h.mod_time),
            access_time: set_time(h.access_time),
            change_time: set_time(h.change_time),
            devmajor: h.devmajor,
            devminor: h.devminor,
            xattrs: &h.xattrs,
            pax_records: &h.pax_records,
            format: h.format,
        };
        if view.typeflag == TYPE_REG_A {
            view.typeflag = if view.name.ends_with(b"/") {
                TYPE_DIR
            } else {
                TYPE_REG
            };
        }
        if view.format == Format::UNKNOWN {
            view.mod_time = set_time(view.mod_time.map(Time::round_to_second));
            view.access_time = None;
            view.change_time = None;
        }
        view
    }
}

/// `basicKeys`: the PAX keys that the fields of a header hold.
fn is_basic_key(k: &[u8]) -> bool {
    matches!(
        k,
        b"path"
            | b"linkpath"
            | b"size"
            | b"uid"
            | b"gid"
            | b"uname"
            | b"gname"
            | b"mtime"
            | b"atime"
            | b"ctime"
    )
}

/// `paxNone`: no PAX key can hold the field.
const PAX_NONE: &[u8] = b"";

/// The closures of `allowedFormats`, and what they find.
struct Check<'h, 'a> {
    h: &'h HeaderView<'a>,
    format: Format,
    pax_hdrs: Records,
    why_no_ustar: String,
    why_no_pax: String,
    why_no_gnu: String,
    prefer_pax: bool,
}

impl Check<'_, '_> {
    /// Keeps a record the caller gave, if it says what the field does.
    fn keep_same(&mut self, pax_key: &[u8], value: &[u8]) {
        if let Some(v) = self.h.pax_records.get(pax_key)
            && v == value
        {
            self.pax_hdrs.insert(pax_key.to_vec(), v.clone());
        }
    }

    /// `verifyString`.
    fn verify_string(&mut self, s: &[u8], size: usize, name: &str, pax_key: &[u8]) {
        // The NUL at the end is optional for path and linkpath. It is needed
        // for uname and gname, but neither GNU nor BSD tar checks for it.
        let too_long = s.len() > size;
        let allow_long_gnu = pax_key == b"path" || pax_key == b"linkpath";
        if has_nul(s) || (too_long && !allow_long_gnu) {
            self.why_no_gnu = format!("GNU cannot encode {name}={:?}", String::from_utf8_lossy(s));
            self.format.must_not_be(Format::GNU);
        }
        if !is_ascii(s) || too_long {
            let can_split_ustar = pax_key == b"path";
            if !can_split_ustar || split_ustar_path(s).is_none() {
                self.why_no_ustar = format!(
                    "USTAR cannot encode {name}={:?}",
                    String::from_utf8_lossy(s)
                );
                self.format.must_not_be(Format::USTAR);
            }
            if pax_key == PAX_NONE {
                self.why_no_pax =
                    format!("PAX cannot encode {name}={:?}", String::from_utf8_lossy(s));
                self.format.must_not_be(Format::PAX);
            } else {
                self.pax_hdrs.insert(pax_key.to_vec(), s.to_vec());
            }
        }
        self.keep_same(pax_key, s);
    }

    /// `verifyNumeric`.
    fn verify_numeric(&mut self, n: i64, size: usize, name: &str, pax_key: &[u8]) {
        if !fits_in_base256(size, n) {
            self.why_no_gnu = format!("GNU cannot encode {name}={n}");
            self.format.must_not_be(Format::GNU);
        }
        if !fits_in_octal(size, n) {
            self.why_no_ustar = format!("USTAR cannot encode {name}={n}");
            self.format.must_not_be(Format::USTAR);
            if pax_key == PAX_NONE {
                self.why_no_pax = format!("PAX cannot encode {name}={n}");
                self.format.must_not_be(Format::PAX);
            } else {
                self.pax_hdrs
                    .insert(pax_key.to_vec(), n.to_string().into_bytes());
            }
        }
        if !self.h.pax_records.is_empty() {
            self.keep_same(pax_key, n.to_string().as_bytes());
        }
    }

    /// `verifyTime`.
    fn verify_time(&mut self, ts: Option<Time>, size: usize, name: &str, pax_key: &[u8]) {
        let Some(ts) = ts else {
            return; // Always okay.
        };
        if !fits_in_base256(size, ts.secs) {
            self.why_no_gnu = format!("GNU cannot encode {name}={}", format_pax_time(ts));
            self.format.must_not_be(Format::GNU);
        }
        let is_mtime = pax_key == b"mtime";
        let fits_octal = fits_in_octal(size, ts.secs);
        if (is_mtime && !fits_octal) || !is_mtime {
            self.why_no_ustar = format!("USTAR cannot encode {name}={}", format_pax_time(ts));
            self.format.must_not_be(Format::USTAR);
        }
        let needs_nano = ts.nanos != 0;
        if !is_mtime || !fits_octal || needs_nano {
            self.prefer_pax = true; // USTAR may cut off fractions of a second.
            if pax_key == PAX_NONE {
                self.why_no_pax = format!("PAX cannot encode {name}={}", format_pax_time(ts));
                self.format.must_not_be(Format::PAX);
            } else {
                self.pax_hdrs
                    .insert(pax_key.to_vec(), format_pax_time(ts).into_bytes());
            }
        }
        if !self.h.pax_records.is_empty() {
            self.keep_same(pax_key, format_pax_time(ts).as_bytes());
        }
    }
}

/// `Header.allowedFormats`: the formats that can hold `h`, never
/// [`Format::UNKNOWN`], and the PAX records it would take; or why none can.
pub(crate) fn allowed_formats(h: &HeaderView<'_>) -> Result<(Format, Records), Error> {
    let mut c = Check {
        h,
        format: Format::USTAR.union(Format::PAX).union(Format::GNU),
        pax_hdrs: Records::new(),
        why_no_ustar: String::new(),
        why_no_pax: String::new(),
        why_no_gnu: String::new(),
        prefer_pax: false,
    };

    // The basic fields.
    c.verify_string(h.name, field::NAME.1, "Name", b"path");
    c.verify_string(h.linkname, field::LINK_NAME.1, "Linkname", b"linkpath");
    c.verify_string(h.uname, field::USER_NAME.1, "Uname", b"uname");
    c.verify_string(h.gname, field::GROUP_NAME.1, "Gname", b"gname");
    c.verify_numeric(h.mode, field::MODE.1, "Mode", PAX_NONE);
    c.verify_numeric(h.uid, field::UID.1, "Uid", b"uid");
    c.verify_numeric(h.gid, field::GID.1, "Gid", b"gid");
    c.verify_numeric(h.size, field::SIZE.1, "Size", b"size");
    c.verify_numeric(h.devmajor, field::DEV_MAJOR.1, "Devmajor", PAX_NONE);
    c.verify_numeric(h.devminor, field::DEV_MINOR.1, "Devminor", PAX_NONE);
    c.verify_time(h.mod_time, field::MOD_TIME.1, "ModTime", b"mtime");
    c.verify_time(
        h.access_time,
        field::GNU_ACCESS_TIME.1,
        "AccessTime",
        b"atime",
    );
    c.verify_time(
        h.change_time,
        field::GNU_CHANGE_TIME.1,
        "ChangeTime",
        b"ctime",
    );

    // The types.
    let mut why_only_pax = "";
    match h.typeflag {
        // Not links, which may stand for folders.
        TYPE_REG | TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO | TYPE_GNU_SPARSE => {
            if h.name.ends_with(b"/") {
                return Err(Error::CannotEncode(
                    "filename may not have trailing slash".into(),
                ));
            }
        }
        TYPE_X_HEADER | TYPE_GNU_LONG_NAME | TYPE_GNU_LONG_LINK => {
            return Err(Error::CannotEncode(
                "cannot manually encode TypeXHeader, TypeGNULongName, or TypeGNULongLink headers"
                    .into(),
            ));
        }
        TYPE_X_GLOBAL_HEADER => {
            let only_records = h.linkname.is_empty()
                && h.size == 0
                && h.mode == 0
                && h.uid == 0
                && h.gid == 0
                && h.uname.is_empty()
                && h.gname.is_empty()
                && h.mod_time.is_none()
                && h.access_time.is_none()
                && h.change_time.is_none()
                && h.devmajor == 0
                && h.devminor == 0;
            if !only_records {
                return Err(Error::CannotEncode(
                    "only PAXRecords should be set for TypeXGlobalHeader".into(),
                ));
            }
            why_only_pax = "only PAX supports TypeXGlobalHeader";
            c.format.may_only_be(Format::PAX);
        }
        _ => {}
    }
    if !is_header_only_type(h.typeflag) && h.size < 0 {
        return Err(Error::CannotEncode(
            "negative size on header-only type".into(),
        ));
    }

    // The PAX records.
    if !h.xattrs.is_empty() {
        for (k, v) in h.xattrs {
            let mut key = b"SCHILY.xattr.".to_vec();
            key.extend_from_slice(k);
            c.pax_hdrs.insert(key, v.clone());
        }
        why_only_pax = "only PAX supports Xattrs";
        c.format.may_only_be(Format::PAX);
    }
    if !h.pax_records.is_empty() {
        for (k, v) in h.pax_records {
            if c.pax_hdrs.contains_key(k) {
                continue; // What is there stays.
            }
            // Local records that may conflict with the fields are left out.
            if h.typeflag == TYPE_X_GLOBAL_HEADER
                || (!is_basic_key(k) && !k.starts_with(b"GNU.sparse."))
            {
                c.pax_hdrs.insert(k.clone(), v.clone());
            }
        }
        why_only_pax = "only PAX supports PAXRecords";
        c.format.may_only_be(Format::PAX);
    }
    for (k, v) in &c.pax_hdrs {
        if !valid_pax_record(k, v) {
            return Err(Error::CannotEncode(format!(
                "invalid PAX record: {:?}",
                String::from_utf8_lossy(&[&k[..], b" = ", &v[..]].concat())
            )));
        }
    }

    // The format asked for.
    if h.format != Format::UNKNOWN {
        let mut want = h.format;
        if want.has(Format::PAX) && !c.prefer_pax {
            want = want.union(Format::USTAR); // PAX allows USTAR too.
        }
        c.format.may_only_be(want);
    }
    if c.format == Format::UNKNOWN {
        let (no_ustar, no_pax, no_gnu) = (&*c.why_no_ustar, &*c.why_no_pax, &*c.why_no_gnu);
        let reasons: &[&str] = if h.format == Format::USTAR {
            &["Format specifies USTAR", no_ustar, why_only_pax]
        } else if h.format == Format::PAX {
            &["Format specifies PAX", no_pax]
        } else if h.format == Format::GNU {
            &["Format specifies GNU", no_gnu, why_only_pax]
        } else {
            &[no_ustar, no_pax, no_gnu, why_only_pax]
        };
        let reasons: Vec<&str> = reasons.iter().copied().filter(|s| !s.is_empty()).collect();
        return Err(Error::CannotEncode(reasons.join("; and ")));
    }
    Ok((c.format, c.pax_hdrs))
}

/// `sparseEntry`: a fragment of a sparse file, data or hole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SparseEntry {
    pub(crate) offset: i64,
    pub(crate) length: i64,
}

impl SparseEntry {
    /// `endOffset`.
    pub(crate) fn end_offset(self) -> i64 {
        self.offset.wrapping_add(self.length)
    }
}

/// `validateSparseEntries`: in order, not overlapping, within `size`.
pub(crate) fn validate_sparse_entries(sp: &[SparseEntry], size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre = SparseEntry::default();
    for &cur in sp {
        if cur.offset < 0 || cur.length < 0 {
            return false; // Negative values are never okay.
        }
        if cur.offset > i64::MAX - cur.length {
            return false; // Overflow with a large length.
        }
        if cur.end_offset() > size {
            return false; // Past the size.
        }
        if pre.end_offset() > cur.offset {
            return false; // Overlapping, or out of order.
        }
        pre = cur;
    }
    true
}

/// `invertSparseEntries`: the data fragments into the holes between them,
/// the last hole possibly empty, so that there is always one.
pub(crate) fn invert_sparse_entries(src: &[SparseEntry], size: i64) -> Vec<SparseEntry> {
    let mut dst = Vec::with_capacity(src.len() + 1);
    let mut pre = SparseEntry::default();
    for &cur in src {
        if cur.length == 0 {
            continue; // Empty fragments are skipped.
        }
        pre.length = cur.offset - pre.offset;
        if pre.length > 0 {
            dst.push(pre); // Only fragments that are not empty.
        }
        pre.offset = cur.end_offset();
    }
    pre.length = size - pre.offset; // Possibly the only empty fragment.
    dst.push(pre);
    dst
}

/// Why an archive could not be read or written: Go's errors.
#[derive(Debug)]
pub enum Error {
    /// `ErrHeader`: a header that is not valid.
    Header,
    /// `ErrFieldTooLong`: PAX records or a GNU long name over 1 MiB.
    FieldTooLong,
    /// `errSparseTooLong`: a sparse map over 1 MiB or a million entries.
    SparseTooLong,
    /// `errMissData`: a sparse file whose map needs more data than the
    /// archive has for it.
    MissData,
    /// `errUnrefData`: a sparse file with data its map does not use.
    UnrefData,
    /// `io.ErrUnexpectedEOF`: the archive ends in the middle of an entry.
    UnexpectedEof,
    /// `ErrWriteTooLong`: more data than the header's size says.
    WriteTooLong,
    /// `ErrWriteAfterClose`: the archive has been closed.
    WriteAfterClose,
    /// `missed writing %d bytes`: the entry before has this much data to
    /// come.
    MissedWriting(i64),
    /// `headerError`: no format can hold the header, or not the one asked
    /// for, and why. The wording of what it quotes is not always Go's.
    CannotEncode(String),
    /// Reading or writing failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Header => "archive/tar: invalid tar header",
            Error::FieldTooLong => "archive/tar: header field too long",
            Error::SparseTooLong => "archive/tar: sparse map too long",
            Error::MissData => "archive/tar: sparse file references non-existent data",
            Error::UnrefData => "archive/tar: sparse file contains unreferenced data",
            Error::UnexpectedEof => "unexpected EOF",
            Error::WriteTooLong => "archive/tar: write too long",
            Error::WriteAfterClose => "archive/tar: write after close",
            Error::MissedWriting(n) => {
                return write!(f, "archive/tar: missed writing {n} bytes");
            }
            Error::CannotEncode(why) if why.is_empty() => "archive/tar: cannot encode header",
            Error::CannotEncode(why) => {
                return write!(f, "archive/tar: cannot encode header: {why}");
            }
            Error::Io(e) => return e.fmt(f),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl Error {
    /// The same error again: `io::Error` cannot be cloned, so its kind and
    /// message are kept.
    pub(crate) fn again(&self) -> Error {
        match self {
            Error::Header => Error::Header,
            Error::FieldTooLong => Error::FieldTooLong,
            Error::SparseTooLong => Error::SparseTooLong,
            Error::MissData => Error::MissData,
            Error::UnrefData => Error::UnrefData,
            Error::UnexpectedEof => Error::UnexpectedEof,
            Error::WriteTooLong => Error::WriteTooLong,
            Error::WriteAfterClose => Error::WriteAfterClose,
            Error::MissedWriting(n) => Error::MissedWriting(*n),
            Error::CannotEncode(why) => Error::CannotEncode(why.clone()),
            Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
        }
    }
}

/// An error that came through `io::Read` comes out as itself.
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = error.into_inner()
                && let Ok(error) = inner.downcast::<Error>()
            {
                return *error;
            }
            return Error::Io(io::Error::other("lost error"));
        }
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Io(e) => e,
            Error::UnexpectedEof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, Error::UnexpectedEof)
            }
            error => io::Error::new(io::ErrorKind::InvalidData, error),
        }
    }
}
