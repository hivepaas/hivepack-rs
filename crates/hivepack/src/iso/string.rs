//! The part of libarchive's `archive_string.c` that turns Joliet names,
//! UTF-16BE, into the locale's charset, here always UTF-8: `utf16nbytes`,
//! `utf16_to_unicode`, `unicode_to_utf8` and
//! `archive_string_append_unicode`.
//!
//! Differs from libarchive: libarchive also normalizes the names it
//! converts, to Unicode NFC (NFD on macOS) with tables of Unicode 6.0; the
//! port gives them as the image has them.

/// `UNICODE_R_CHAR`, the replacement character.
const UNICODE_R_CHAR: u32 = 0xfffd;

/// `UNICODE_MAX`.
const UNICODE_MAX: u32 = 0x10ffff;

/// `utf16nbytes`: how many bytes of `s` come before the first U+0000
/// (whole code units only).
fn utf16nbytes(s: &[u8]) -> usize {
    let mut n = 0;
    while n + 1 < s.len() && (s[n] != 0 || s[n + 1] != 0) {
        n += 2;
    }
    n
}

/// `utf16_to_unicode`, big-endian: the code point at the start of `s` and
/// how many bytes it took, negative when it is not valid UTF-16 (the code
/// point is then U+FFFD).
fn utf16be_to_unicode(s: &[u8]) -> (u32, isize) {
    if s.is_empty() {
        return (0, 0);
    }
    if s.len() == 1 {
        return (UNICODE_R_CHAR, -1);
    }
    let mut uc = u32::from(u16::from_be_bytes([s[0], s[1]]));
    let mut used = 2;
    // A surrogate pair makes one code point.
    if (0xd800..=0xdbff).contains(&uc) {
        let uc2 = if s.len() >= 4 {
            u32::from(u16::from_be_bytes([s[2], s[3]]))
        } else {
            0
        };
        if (0xdc00..=0xdfff).contains(&uc2) {
            uc = ((uc - 0xd800) << 10) + (uc2 - 0xdc00) + 0x10000;
            used += 2;
        } else {
            return (UNICODE_R_CHAR, -2);
        }
    }
    // Surrogates are only for UTF-16, and Unicode stops at U+10FFFF.
    if (0xd800..=0xdfff).contains(&uc) || uc > UNICODE_MAX {
        return (UNICODE_R_CHAR, -(used as isize));
    }
    (uc, used as isize)
}

/// `unicode_to_utf8`.
fn unicode_to_utf8(out: &mut Vec<u8>, mut uc: u32) {
    if uc > UNICODE_MAX {
        uc = UNICODE_R_CHAR;
    }
    if uc <= 0x7f {
        out.push(uc as u8);
    } else if uc <= 0x7ff {
        out.push(0xc0 | ((uc >> 6) & 0x1f) as u8);
        out.push(0x80 | (uc & 0x3f) as u8);
    } else if uc <= 0xffff {
        out.push(0xe0 | ((uc >> 12) & 0x0f) as u8);
        out.push(0x80 | ((uc >> 6) & 0x3f) as u8);
        out.push(0x80 | (uc & 0x3f) as u8);
    } else {
        out.push(0xf0 | ((uc >> 18) & 0x07) as u8);
        out.push(0x80 | ((uc >> 12) & 0x3f) as u8);
        out.push(0x80 | ((uc >> 6) & 0x3f) as u8);
        out.push(0x80 | (uc & 0x3f) as u8);
    }
}

/// `archive_strncpy_l` from UTF-16BE to UTF-8, as
/// `archive_mstring_copy_mbs_len_l` uses it: the name up to its first
/// U+0000, or `None` when some of it is not valid UTF-16 (libarchive then
/// leaves the name unset).
pub(crate) fn utf16be_to_utf8(s: &[u8]) -> Option<Vec<u8>> {
    let mut s = &s[..utf16nbytes(s)];
    let mut out = Vec::with_capacity(s.len() * 3 / 2);
    let mut ok = true;
    loop {
        let (uc, n) = utf16be_to_unicode(s);
        if n == 0 {
            break;
        }
        if n < 0 {
            ok = false;
        }
        s = &s[n.unsigned_abs()..];
        unicode_to_utf8(&mut out, uc);
    }
    ok.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn converts_and_stops_at_nul() {
        assert_eq!(
            utf16be_to_utf8(&be(&[0x61, 0xe9, 0x4e2d])),
            Some("aé中".into())
        );
        assert_eq!(utf16be_to_utf8(&be(&[0xd83d, 0xde00])), Some("😀".into()));
        assert_eq!(
            utf16be_to_utf8(&be(&[0x61, 0, 0xd800])),
            Some(b"a".to_vec())
        );
        assert_eq!(utf16be_to_utf8(&[0x00, 0x61, 0x00]), Some(b"a".to_vec()));
        assert_eq!(utf16be_to_utf8(&[]), Some(Vec::new()));
    }

    #[test]
    fn refuses_lone_surrogates() {
        assert_eq!(utf16be_to_utf8(&be(&[0xd800, 0x61])), None);
        assert_eq!(utf16be_to_utf8(&be(&[0xdc00])), None);
        assert_eq!(utf16be_to_utf8(&be(&[0x61, 0xdbff])), None);
    }
}
