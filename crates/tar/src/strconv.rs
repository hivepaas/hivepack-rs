//! The fields of a header, read and written: port of `strconv.go`, with what
//! it takes of Go's `strconv` and `time`.

use std::borrow::Cow;
use std::io::Write as _;

use crate::common::{NAME_SIZE, PREFIX_SIZE, Time};

/// Go's `strconv.ParseUint(s, base, 64)` for bases 8 and 10: digits only,
/// no sign, no underscores. `None` for a syntax or range error.
pub(crate) fn parse_uint(s: &[u8], base: u32) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in s {
        let d = (c as char).to_digit(base)?;
        n = n.checked_mul(u64::from(base))?.checked_add(u64::from(d))?;
    }
    Some(n)
}

/// Go's `strconv.ParseInt(s, 10, 64)`: an optional sign, then digits.
/// Go's `int`, which archive/tar also parses some fields as, is taken to
/// be 64 bits, as on the machines Go mostly runs on.
pub(crate) fn parse_int(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let un = parse_uint(digits, 10)?;
    if neg {
        if un > 1 << 63 {
            return None;
        }
        Some((un as i64).wrapping_neg())
    } else {
        i64::try_from(un).ok()
    }
}

/// `isASCII`: no byte at or above 0x80, and no NUL. Go looks at runes, but
/// an invalid UTF-8 byte is `RuneError`, above 0x80 too.
pub(crate) fn is_ascii(s: &[u8]) -> bool {
    s.iter().all(|&c| c < 0x80 && c != 0)
}

/// `hasNUL`.
pub(crate) fn has_nul(s: &[u8]) -> bool {
    s.contains(&0)
}

/// `toASCII`: `s` without what [`is_ascii`] refuses. Go drops runes, and so
/// every byte of a multi-byte or invalid one.
pub(crate) fn to_ascii(s: &[u8]) -> Cow<'_, [u8]> {
    if is_ascii(s) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.iter().copied().filter(|&c| c < 0x80 && c != 0).collect())
}

/// `splitUSTARPath`: a name too long for USTAR's name field, cut at a slash
/// into its prefix and name fields, if it can be.
pub(crate) fn split_ustar_path(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut length = name.len();
    if length <= NAME_SIZE || !is_ascii(name) {
        return None;
    } else if length > PREFIX_SIZE + 1 {
        length = PREFIX_SIZE + 1;
    } else if name[length - 1] == b'/' {
        length -= 1;
    }
    let i = name[..length].iter().rposition(|&c| c == b'/')?;
    let nlen = name.len() - i - 1; // The suffix's length.
    if i == 0 || nlen > NAME_SIZE || nlen == 0 || i > PREFIX_SIZE {
        return None;
    }
    Some((&name[..i], &name[i + 1..]))
}

/// `fitsInBase256`: whether `x` fits a field of `n` bytes in base-256.
pub(crate) fn fits_in_base256(n: usize, x: i64) -> bool {
    if n >= 9 {
        return true;
    }
    let bin_bits = (n - 1) * 8;
    x >= -1i64 << bin_bits && x < 1i64 << bin_bits
}

/// `fitsInOctal`: whether `x` fits a field of `n` bytes in octal, with room
/// for a NUL.
pub(crate) fn fits_in_octal(n: usize, x: i64) -> bool {
    if n >= 22 {
        return x >= 0;
    }
    x >= 0 && x < 1i64 << ((n - 1) * 3)
}

/// `formatter`: what failed is kept, and the fields after it are still
/// written.
#[derive(Default)]
pub(crate) struct Formatter {
    pub(crate) err: bool,
}

impl Formatter {
    /// `formatString`: as much of `s` as fits, then a NUL if there is room.
    pub(crate) fn format_string(&mut self, b: &mut [u8], s: &[u8]) {
        let n = s.len().min(b.len());
        b[..n].copy_from_slice(&s[..n]);
        if s.len() < b.len() {
            b[s.len()] = 0;
        }
        if s.len() > b.len() {
            self.err = true;
            // Some buggy readers take a regular file with a slash at the end of
            // the name field for a folder, even when a PAX record has the whole
            // name without one.
            if b.last() == Some(&b'/') {
                let mut n = b.len() - 1;
                while n > 0 && s[n - 1] == b'/' {
                    n -= 1;
                }
                b[n] = 0;
            }
        }
    }

    /// `formatNumeric`: octal if it fits, or else GNU's base-256.
    pub(crate) fn format_numeric(&mut self, b: &mut [u8], mut x: i64) {
        if fits_in_octal(b.len(), x) {
            self.format_octal(b, x);
        } else if fits_in_base256(b.len(), x) {
            for c in b.iter_mut().rev() {
                *c = x as u8;
                x >>= 8;
            }
            b[0] |= 0x80; // The top bit says base-256.
        } else {
            self.format_octal(b, 0); // The last resort.
            self.err = true;
        }
    }

    /// `formatOctal`: leading zeros and a NUL, or zero if it does not fit.
    pub(crate) fn format_octal(&mut self, b: &mut [u8], mut x: i64) {
        if !fits_in_octal(b.len(), x) {
            x = 0; // The last resort.
            self.err = true;
        }
        let Some((last, digits)) = b.split_last_mut() else {
            return;
        };
        if digits.is_empty() {
            *last = b'0'; // Only zero fits one byte, and without a NUL.
            return;
        }
        *last = 0;
        for c in digits.iter_mut().rev() {
            *c = b'0' + (x & 7) as u8;
            x >>= 3;
        }
    }
}

/// `formatPAXTime`: seconds and up to nine digits of a fraction, without
/// zeros at its end.
pub(crate) fn format_pax_time(ts: Time) -> String {
    let (mut secs, mut nsecs) = (ts.secs, ts.nanos);
    if nsecs == 0 {
        return secs.to_string();
    }
    let mut sign = "";
    if secs < 0 {
        sign = "-"; // A second is added to the seconds and taken from the fraction.
        secs = -(secs + 1);
        nsecs = 1_000_000_000 - nsecs;
    }
    let text = format!("{sign}{secs}.{nsecs:09}");
    text.trim_end_matches('0').to_string()
}

/// `formatPAXRecord`, added to `out`: `"%d %s=%s\n"`, the number being the
/// length of it all, itself included. `false` is `ErrHeader`.
pub(crate) fn append_pax_record(out: &mut Vec<u8>, k: &[u8], v: &[u8]) -> bool {
    if !valid_pax_record(k, v) {
        return false;
    }
    const PADDING: usize = 3; // ' ', '=' and '\n'.
    let decimal = |n: usize| n.to_string().len();
    let base = k.len() + v.len() + PADDING;
    let mut size = base + decimal(base);
    // Adding the size can make it longer, once.
    size = base + decimal(size);
    out.reserve(size);
    // Writing to a Vec does not fail.
    let _ = write!(out, "{size} ");
    out.extend_from_slice(k);
    out.push(b'=');
    out.extend_from_slice(v);
    out.push(b'\n');
    true
}

/// `parser`: what failed is kept, and the fields after it are still read.
#[derive(Default)]
pub(crate) struct Parser {
    pub(crate) err: bool,
}

impl Parser {
    /// `parseString`: up to the first NUL.
    pub(crate) fn parse_string(&self, b: &[u8]) -> Vec<u8> {
        match b.iter().position(|&c| c == 0) {
            Some(i) => b[..i].to_vec(),
            None => b.to_vec(),
        }
    }

    /// `parseNumeric`: octal, or base-256 when the first byte's top bit is
    /// set (GNU's extension for values octal cannot hold).
    pub(crate) fn parse_numeric(&mut self, b: &[u8]) -> i64 {
        if !b.is_empty() && b[0] & 0x80 != 0 {
            // 0x00 if positive or zero, 0xff if negative.
            let inv = if b[0] & 0x40 != 0 { 0xff } else { 0x00 };
            let mut x: u64 = 0;
            for (i, &c) in b.iter().enumerate() {
                let mut c = c ^ inv;
                if i == 0 {
                    c &= 0x7f; // The signal bit.
                }
                if (x >> 56) > 0 {
                    self.err = true; // Overflow.
                    return 0;
                }
                x = x << 8 | u64::from(c);
            }
            if (x >> 63) > 0 {
                self.err = true; // Overflow.
                return 0;
            }
            if inv == 0xff {
                return !(x as i64);
            }
            return x as i64;
        }
        self.parse_octal(b)
    }

    /// `parseOctal`: spaces and NULs trimmed from both ends, then up to a
    /// NUL. A value past `i64::MAX` comes back negative, as Go's
    /// `int64(uint64)` makes it.
    pub(crate) fn parse_octal(&mut self, b: &[u8]) -> i64 {
        let trim = |c: &u8| *c != b' ' && *c != 0;
        let start = b.iter().position(trim).unwrap_or(b.len());
        let end = b.iter().rposition(trim).map_or(start, |i| i + 1);
        let b = &b[start..end];
        if b.is_empty() {
            return 0;
        }
        match parse_uint(&self.parse_string(b), 8) {
            Some(x) => x as i64,
            None => {
                self.err = true;
                // Go's ParseUint returns the largest value on overflow, 0
                // on a syntax error; either way the header fails.
                0
            }
        }
    }
}

/// `parsePAXTime`: seconds, then up to nine digits of a fraction (more are
/// checked and dropped). `None` is `ErrHeader`.
pub(crate) fn parse_pax_time(s: &[u8]) -> Option<Time> {
    let (ss, sn) = match s.iter().position(|&c| c == b'.') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &s[s.len()..]),
    };
    let secs = parse_int(ss)?;
    if sn.is_empty() {
        return Some(Time::unix(secs, 0));
    }
    let mut nano_digits = *b"000000000";
    for (i, &c) in sn.iter().enumerate() {
        if !c.is_ascii_digit() {
            return None;
        }
        if i < nano_digits.len() {
            nano_digits[i] = c;
        }
    }
    let nsecs = parse_int(&nano_digits).unwrap_or(0);
    if ss.first() == Some(&b'-') {
        return Some(Time::unix(secs, -nsecs)); // Negative correction.
    }
    Some(Time::unix(secs, nsecs))
}

/// `parsePAXRecord`: a record `"%d %s=%s\n"` from the start of `s`: the
/// key, the value and what follows. `None` is `ErrHeader`.
pub(crate) fn parse_pax_record(s: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let space = s.iter().position(|&c| c == b' ')?;
    let (n_str, rest) = (&s[..space], &s[space + 1..]);
    let n = parse_int(n_str)?;
    if n < 5 || n > s.len() as i64 {
        return None;
    }
    // From an index in s to one in rest.
    let n = n - (n_str.len() as i64 + 1);
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    let (rec, nl, rem) = (&rest[..n - 1], &rest[n - 1..n], &rest[n..]);
    if nl != b"\n" {
        return None;
    }
    let eq = rec.iter().position(|&c| c == b'=')?;
    let (k, v) = (&rec[..eq], &rec[eq + 1..]);
    if !valid_pax_record(k, v) {
        return None;
    }
    Some((k, v, rem))
}

/// `validPAXRecord`: a key without `=`, and no NUL in the value of the
/// keys that USTAR's fields hold, or in any other key.
pub(crate) fn valid_pax_record(k: &[u8], v: &[u8]) -> bool {
    if k.is_empty() || k.contains(&b'=') {
        return false;
    }
    match k {
        b"path" | b"linkpath" | b"uname" | b"gname" => !v.contains(&0),
        _ => !k.contains(&0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cases from Go's strconv_test.go.
    #[test]
    fn parse_numeric_as_go() {
        let cases: &[(&[u8], i64, bool)] = &[
            (b"", 0, true),
            (b"\x80", 0, true),
            (b"\x80\x00", 0, true),
            (b"\x80\x00\x00", 0, true),
            (b"\xbf", (1 << 6) - 1, true),
            (b"\xbf\xff", (1 << 14) - 1, true),
            (b"\xbf\xff\xff", (1 << 22) - 1, true),
            (b"\xff", -1, true),
            (b"\xff\xff", -1, true),
            (b"\xff\xff\xff", -1, true),
            (b"\xc0", -(1 << 6), true),
            (b"\xc0\x00", -(1 << 14), true),
            (b"\xc0\x00\x00", -(1 << 22), true),
            (
                b"\x87\x76\xa2\x22\xeb\x8a\x72\x61",
                537795476381659745,
                true,
            ),
            (
                b"\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61",
                537795476381659745,
                true,
            ),
            (
                b"\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
                -615126028225187231,
                true,
            ),
            (
                b"\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
                -615126028225187231,
                true,
            ),
            (b"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", i64::MAX, true),
            (b"\x80\x80\x00\x00\x00\x00\x00\x00\x00", 0, false),
            (b"\xff\x80\x00\x00\x00\x00\x00\x00\x00", i64::MIN, true),
            (b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff", 0, false),
            (
                b"\xf5\xec\xd1\xc7\x7e\x5f\x26\x48\x81\x9f\x8f\x9b",
                0,
                false,
            ),
            (b"0000000\x00", 0, true),
            (b" \x0000000\x00", 0, true),
            (b" \x0000003\x00", 3, true),
            (b"00000000227\x00", 0o227, true),
            (b"032033\x00 ", 0o32033, true),
            (b"320330\x00 ", 0o320330, true),
            (b"0000660\x00 ", 0o660, true),
            (b"\x00 0000660\x00 ", 0o660, true),
            (b"0123456789abcdef", 0, false),
            (b"0123456789\x00abcdef", 0, false),
            (b"01234567\x0089abcdef", 0o1234567, true),
            (b"0123\x7e\x5f\x264123", 0, false),
        ];
        for &(input, want, ok) in cases {
            let mut p = Parser::default();
            let got = p.parse_numeric(input);
            assert_eq!(!p.err, ok, "{input:x?}");
            if ok {
                assert_eq!(got, want, "{input:x?}");
            }
        }
    }

    #[test]
    fn parse_pax_time_as_go() {
        type Want = Option<(i64, u32)>;
        let cases: &[(&[u8], Want)] = &[
            (b"1350244992.023960108", Some((1350244992, 23960108))),
            (b"1350244992.02396010", Some((1350244992, 23960100))),
            (b"1350244992.0239601089", Some((1350244992, 23960108))),
            (b"1350244992.3", Some((1350244992, 300000000))),
            (b"1350244992", Some((1350244992, 0))),
            (b"-1.000000001", Some((-2, 999999999))),
            (b"-1.000001", Some((-2, 999999000))),
            (b"-1.001000", Some((-2, 999000000))),
            (b"-1", Some((-1, 0))),
            (b"-1.999000", Some((-2, 1000000))),
            (b"-1.999999", Some((-2, 1000))),
            (b"-1.999999999", Some((-2, 1))),
            (b"0.000000001", Some((0, 1))),
            (b"0.000001", Some((0, 1000))),
            (b"0.001000", Some((0, 1000000))),
            (b"0", Some((0, 0))),
            (b"0.999000", Some((0, 999000000))),
            (b"0.999999", Some((0, 999999000))),
            (b"0.999999999", Some((0, 999999999))),
            (b"1.000000001", Some((1, 1))),
            (b"1.000001", Some((1, 1000))),
            (b"1.001000", Some((1, 1000000))),
            (b"1", Some((1, 0))),
            (b"1.999000", Some((1, 999000000))),
            (b"1.999999", Some((1, 999999000))),
            (b"1.999999999", Some((1, 999999999))),
            (b"-1350244992.023960108", Some((-1350244993, 976039892))),
            (b"-1350244992.02396010", Some((-1350244993, 976039900))),
            (b"-1350244992.0239601089", Some((-1350244993, 976039892))),
            (b"-1350244992.3", Some((-1350244993, 700000000))),
            (b"-1350244992", Some((-1350244992, 0))),
            (b"", None),
            (b"0", Some((0, 0))),
            (b"1.", Some((1, 0))),
            (b"0.0", Some((0, 0))),
            (b".5", None),
            (b"-1.3", Some((-2, 700000000))),
            (b"-1.0", Some((-1, 0))),
            (b"-0.0", Some((0, 0))),
            (b"-0.1", Some((-1, 900000000))),
            (b"-0.01", Some((-1, 990000000))),
            (b"-0.99", Some((-1, 10000000))),
            (b"-0.98", Some((-1, 20000000))),
            (b"-1.1", Some((-2, 900000000))),
            (b"-1.01", Some((-2, 990000000))),
            (b"-2.99", Some((-3, 10000000))),
            (b"-5.98", Some((-6, 20000000))),
            (b"-", None),
            (b"+", None),
            (b"-1.-1", None),
            (b"99999999999999999999999999999999999999999999999", None),
            (b"0.123456789abcdef", None),
            (b"foo", None),
            (b"\x00", None),
            (b"\xf0\x9d\x9f\xb5\xf0\x9d\x9f\xb4\xf0\x9d\x9f\xb3\xf0\x9d\x9f\xb2\xf0\x9d\x9f\xb1.\xf0\x9d\x9f\xb0\xf0\x9d\x9f\xaf\xf0\x9d\x9f\xae\xf0\x9d\x9f\xad\xf0\x9d\x9f\xac", None),
            (b"98765\xef\xb9\x9243210", None),
        ];
        for &(input, want) in cases {
            let got = parse_pax_time(input).map(|t| (t.secs, t.nanos));
            assert_eq!(got, want, "{input:x?}");
        }
    }

    #[test]
    fn parse_pax_record_as_go() {
        type Want = Option<(&'static [u8], &'static [u8], &'static [u8])>;
        let cases: &[(&[u8], Want)] = &[
            (b"6 k=v\x0a\x0a", Some((b"k", b"v", b"\x0a"))),
            (b"19 path=/etc/hosts\x0a", Some((b"path", b"/etc/hosts", b""))),
            (b"9 foo=ba\x0a", Some((b"foo", b"ba", b""))),
            (b"11 foo=bar\x0a\x00", Some((b"foo", b"bar", b"\x00"))),
            (b"18 foo=b=\x0aar=\x0a==\x00\x0a", Some((b"foo", b"b=\x0aar=\x0a==\x00", b""))),
            (b"27 foo=hello9 foo=ba\x0aworld\x0a", Some((b"foo", b"hello9 foo=ba\x0aworld", b""))),
            (b"27 \xe2\x98\xba\xe2\x98\xbb\xe2\x98\xb9=\xe6\x97\xa5a\xe6\x9c\xacb\xe8\xaa\x9e\xc3\xa7\x0ameow mix", Some((b"\xe2\x98\xba\xe2\x98\xbb\xe2\x98\xb9", b"\xe6\x97\xa5a\xe6\x9c\xacb\xe8\xaa\x9e\xc3\xa7", b"meow mix"))),
            (b"17 \x00hello=\x00world\x0a", None),
            (b"1 k=1\x0a", None),
            (b"6 k~1\x0a", None),
            (b"6_k=1\x0a", None),
            (b"6 k=1 ", None),
            (b"632 k=1\x0a", None),
            (b"16 longkeyname=hahaha\x0a", None),
            (b"3 somelongkey=\x0a", None),
            (b"50 tooshort=\x0a", None),
            (b"0000000000000000000000000000000030 mtime=1432668921.098285006\x0a30 ctime=2147483649.15163319", None),
            (b"06 k=v\x0a", None),
            (b"00006 k=v\x0a", None),
            (b"000006 k=v\x0a", None),
            (b"000000 k=v\x0a", None),
            (b"0 k=v\x0a", None),
            (b"000005 x=\x0a", None),
        ];
        for &(input, want) in cases {
            assert_eq!(parse_pax_record(input), want, "{input:x?}");
        }
    }

    #[test]
    fn format_numeric_as_go() {
        let cases: &[(i64, &[u8], bool)] = &[
            // Octal.
            (0, b"0\x00", true),
            (7, b"7\x00", true),
            (8, b"\x80\x08", true),
            (0o77, b"77\x00", true),
            (0o100, b"\x80\x00\x40", true),
            (0, b"0000000\x00", true),
            (0o123, b"0000123\x00", true),
            (0o7654321, b"7654321\x00", true),
            (0o7777777, b"7777777\x00", true),
            (0o10000000, b"\x80\x00\x00\x00\x00\x20\x00\x00", true),
            (0, b"00000000000\x00", true),
            (0o1234567, b"00001234567\x00", true),
            (0o76543210321, b"76543210321\x00", true),
            (0o12345670123, b"12345670123\x00", true),
            (0o77777777777, b"77777777777\x00", true),
            (
                0o100000000000,
                b"\x80\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
                true,
            ),
            (i64::MAX, b"777777777777777777777\x00", true),
            // Base-256.
            (-1, b"\xff", true),
            (-1, b"\xff\xff", true),
            (-1, b"\xff\xff\xff", true),
            (1, b"0", false),
            ((1 << 8) - 1, b"\x80\xff", true),
            (1 << 8, b"0\x00", false),
            ((1 << 16) - 1, b"\x80\xff\xff", true),
            (1 << 16, b"00\x00", false),
            (-1, b"\xff", true),
            (-2, b"0", false),
            (-(1 << 8), b"\xff\x00", true),
            (-(1 << 8) - 1, b"0\x00", false),
            (-(1 << 16), b"\xff\x00\x00", true),
            (-(1 << 16) - 1, b"00\x00", false),
            (537795476381659745, b"0000000\x00", false),
            (
                537795476381659745,
                b"\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61",
                true,
            ),
            (-615126028225187231, b"0000000\x00", false),
            (
                -615126028225187231,
                b"\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
                true,
            ),
            (i64::MAX, b"0000000\x00", false),
            (
                i64::MAX,
                b"\x80\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff",
                true,
            ),
            (i64::MIN, b"0000000\x00", false),
            (
                i64::MIN,
                b"\xff\xff\xff\xff\x80\x00\x00\x00\x00\x00\x00\x00",
                true,
            ),
            (i64::MAX, b"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", true),
            (i64::MIN, b"\xff\x80\x00\x00\x00\x00\x00\x00\x00", true),
        ];
        for &(input, want, ok) in cases {
            let mut f = Formatter::default();
            let mut got = vec![0; want.len()];
            f.format_numeric(&mut got, input);
            assert_eq!(!f.err, ok, "{input}, {want:x?}");
            assert_eq!(got, want, "{input}");
        }
    }

    #[test]
    fn format_pax_time_as_go() {
        let cases: &[(i64, i64, &str)] = &[
            (1350244992, 0, "1350244992"),
            (1350244992, 300000000, "1350244992.3"),
            (1350244992, 23960100, "1350244992.0239601"),
            (1350244992, 23960108, "1350244992.023960108"),
            (1, 999999999, "1.999999999"),
            (1, 999999000, "1.999999"),
            (1, 999000000, "1.999"),
            (1, 0, "1"),
            (1, 1000000, "1.001"),
            (1, 1000, "1.000001"),
            (1, 1, "1.000000001"),
            (0, 999999999, "0.999999999"),
            (0, 999999000, "0.999999"),
            (0, 999000000, "0.999"),
            (0, 0, "0"),
            (0, 1000000, "0.001"),
            (0, 1000, "0.000001"),
            (0, 1, "0.000000001"),
            (-1, -999999999, "-1.999999999"),
            (-1, -999999000, "-1.999999"),
            (-1, -999000000, "-1.999"),
            (-1, 0, "-1"),
            (-1, -1000000, "-1.001"),
            (-1, -1000, "-1.000001"),
            (-1, -1, "-1.000000001"),
            (-1350244992, 0, "-1350244992"),
            (-1350244992, -300000000, "-1350244992.3"),
            (-1350244992, -23960100, "-1350244992.0239601"),
            (-1350244992, -23960108, "-1350244992.023960108"),
        ];
        for &(sec, nsec, want) in cases {
            assert_eq!(format_pax_time(Time::unix(sec, nsec)), want);
        }
    }

    #[test]
    fn format_pax_record_as_go() {
        let med = "CD".repeat(50);
        let long = "AB".repeat(100);
        let (want_long, want_med) = (format!("210 path={long}\n"), format!("110 path={med}\n"));
        type Case<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>);
        let cases: &[Case<'_>] = &[
            (b"k", b"v", Some(b"6 k=v\n")),
            (b"path", b"/etc/hosts", Some(b"19 path=/etc/hosts\n")),
            (b"path", long.as_bytes(), Some(want_long.as_bytes())),
            (b"path", med.as_bytes(), Some(want_med.as_bytes())),
            (b"foo", b"ba", Some(b"9 foo=ba\n")),
            (b"foo", b"bar", Some(b"11 foo=bar\n")),
            (
                b"foo",
                b"b=\nar=\n==\x00",
                Some(b"18 foo=b=\nar=\n==\x00\n"),
            ),
            (
                b"foo",
                b"hello9 foo=ba\nworld",
                Some(b"27 foo=hello9 foo=ba\nworld\n"),
            ),
            (
                "☺☻☹".as_bytes(),
                "日a本b語ç".as_bytes(),
                Some("27 ☺☻☹=日a本b語ç\n".as_bytes()),
            ),
            (b"xhello", b"\x00world", Some(b"17 xhello=\x00world\n")),
            (b"path", b"null\x00", None),
            (b"null\x00", b"value", None),
            (
                b"SCHILY.xattr.key",
                b"null\x00",
                Some(b"26 SCHILY.xattr.key=null\x00\n"),
            ),
        ];
        for &(k, v, want) in cases {
            let mut got = Vec::new();
            let ok = append_pax_record(&mut got, k, v);
            assert_eq!(ok, want.is_some(), "{k:x?}");
            assert_eq!(got, want.unwrap_or(b""), "{k:x?}");
        }
    }

    #[test]
    fn split_ustar_path_as_go() {
        let sr = |s: &str, n: usize| s.repeat(n);
        let (name, prefix) = (NAME_SIZE, PREFIX_SIZE);
        let a = |n| sr("a", n);
        let cases = [
            (String::new(), None),
            ("abc".to_string(), None),
            ("用戶名".to_string(), None),
            (a(name), None),
            (a(name) + "/", None),
            (a(name) + "/a", Some((a(name), "a".to_string()))),
            (a(prefix) + "/", None),
            (a(prefix) + "/a", Some((a(prefix), "a".to_string()))),
            (a(name + 1), None),
            (
                sr("/", name + 1),
                Some((sr("/", name - 1), "/".to_string())),
            ),
            (
                a(prefix) + "/" + &sr("b", name),
                Some((a(prefix), sr("b", name))),
            ),
            (a(prefix) + "//" + &sr("b", name), None),
            (sr("a/", name), Some((sr("a/", 77) + "a", sr("a/", 22)))),
        ];
        for (input, want) in &cases {
            let got = split_ustar_path(input.as_bytes());
            let want = want.as_ref().map(|(p, s)| (p.as_bytes(), s.as_bytes()));
            assert_eq!(got, want, "{input}");
        }
    }

    #[test]
    fn fits_in_base256_as_go() {
        let cases = [
            (1, 8, true),
            (0, 8, true),
            (-1, 8, true),
            (1 << 56, 8, false),
            ((1 << 56) - 1, 8, true),
            (-1 << 56, 8, true),
            ((-1 << 56) - 1, 8, false),
            (121654, 8, true),
            (-9849849, 8, true),
            (i64::MAX, 9, true),
            (0, 9, true),
            (i64::MIN, 9, true),
            (i64::MAX, 12, true),
            (0, 12, true),
            (i64::MIN, 12, true),
        ];
        for (input, width, ok) in cases {
            assert_eq!(fits_in_base256(width, input), ok, "{input}, {width}");
        }
    }

    #[test]
    fn fits_in_octal_as_go() {
        let cases = [
            (-1, 1, false),
            (-1, 2, false),
            (-1, 3, false),
            (0, 1, true),
            (1, 1, false),
            (0, 2, true),
            (0o7, 2, true),
            (0o7 + 1, 2, false),
            (0, 4, true),
            (0o777, 4, true),
            (0o777 + 1, 4, false),
            (0, 8, true),
            (0o7777777, 8, true),
            (0o7777777 + 1, 8, false),
            (0, 12, true),
            (0o77777777777, 12, true),
            (0o77777777777 + 1, 12, false),
            (i64::MAX, 22, true),
            (0o12345670123, 12, true),
            (0o1564164, 12, true),
            (-0o12345670123, 12, false),
            (-0o1564164, 12, false),
            (-1564164, 30, false),
        ];
        for (input, width, ok) in cases {
            assert_eq!(fits_in_octal(width, input), ok, "{input}, {width}");
        }
    }
}
