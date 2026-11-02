//! The parts of libarchive's `archive_string.c` the XAR reader uses: C
//! strings that stop at a NUL (`archive_strncat`), and the copy of a name
//! from the archive's UTF-8 to the locale's, UTF-8 too
//! (`strncat_from_utf8_to_utf8`), which checks it.
//!
//! As in hivepack::iso, libarchive's Unicode normalization of converted
//! names (NFC, or NFD on macOS) is left out: names come out as the archive
//! has them.

/// `archive_strncat`: `src` up to its first NUL, appended to `dst`.
pub(crate) fn strncat(dst: &mut Vec<u8>, src: &[u8]) {
    let n = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    dst.extend_from_slice(&src[..n]);
}

/// `utf8_count`: how many bytes a sequence starting with this byte has; 0
/// for one that cannot start one.
fn utf8_count(c: u8) -> usize {
    match c {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// `_utf8_to_unicode`: the code point of the UTF-8 sequence at the start
/// of `s` and its length; a negative length (with U+FFFD) for an invalid
/// sequence, as many bytes as are replaced; 0 at the end or a NUL.
fn utf8_to_unicode_raw(s: &[u8]) -> (u32, i32) {
    let n = s.len();
    if n == 0 {
        return (0, 0);
    }
    let ch = s[0];
    if ch == 0 {
        return (0, 0);
    }
    let mut cnt = utf8_count(ch);
    let invalid = |cnt: usize| (0xfffd, -(cnt as i32));
    // Not as many bytes as needed.
    if cnt > 0 && n < cnt {
        let mut c = n;
        for (i, &b) in s.iter().enumerate().take(n).skip(1) {
            if b & 0xc0 != 0x80 {
                c = i;
                break;
            }
        }
        return invalid(c);
    }
    let wc: u32;
    match cnt {
        1 => return (u32::from(ch & 0x7f), 1),
        2 => {
            if s[1] & 0xc0 != 0x80 {
                return invalid(1);
            }
            return ((u32::from(ch & 0x1f) << 6) | u32::from(s[1] & 0x3f), 2);
        }
        3 => {
            if s[1] & 0xc0 != 0x80 {
                return invalid(1);
            }
            if s[2] & 0xc0 != 0x80 {
                return invalid(2);
            }
            wc = (u32::from(ch & 0x0f) << 12)
                | (u32::from(s[1] & 0x3f) << 6)
                | u32::from(s[2] & 0x3f);
            if wc < 0x800 {
                return invalid(3);
            }
        }
        4 => {
            if s[1] & 0xc0 != 0x80 {
                return invalid(1);
            }
            if s[2] & 0xc0 != 0x80 {
                return invalid(2);
            }
            if s[3] & 0xc0 != 0x80 {
                return invalid(3);
            }
            wc = (u32::from(ch & 0x07) << 18)
                | (u32::from(s[1] & 0x3f) << 12)
                | (u32::from(s[2] & 0x3f) << 6)
                | u32::from(s[3] & 0x3f);
            if wc < 0x10000 {
                return invalid(4);
            }
        }
        _ => {
            // Every other first byte: as many bytes replaced as its
            // sequence would have, up to the first that does not follow.
            cnt = match ch {
                0xc0 | 0xc1 => 2,
                0xf5..=0xf7 => 4,
                0xf8..=0xfb => 5,
                0xfc | 0xfd => 6,
                _ => 1,
            };
            cnt = cnt.min(n);
            for (i, &b) in s.iter().enumerate().take(cnt).skip(1) {
                if b & 0xc0 != 0x80 {
                    cnt = i;
                    break;
                }
            }
            return invalid(cnt);
        }
    }
    if wc > 0x10_ffff {
        return invalid(cnt);
    }
    (wc, cnt as i32)
}

/// `utf8_to_unicode`: and a surrogate is not a code point.
fn utf8_to_unicode(s: &[u8]) -> (u32, i32) {
    let (wc, cnt) = utf8_to_unicode_raw(s);
    if cnt == 3 && (0xd800..=0xdfff).contains(&wc) {
        return (wc, -3);
    }
    (wc, cnt)
}

/// `cesu8_to_unicode`: a surrogate pair of CESU-8 as one code point.
fn cesu8_to_unicode(s: &[u8]) -> (u32, i32) {
    let (wc, cnt) = utf8_to_unicode_raw(s);
    if cnt == 3 && (0xd800..=0xdbff).contains(&wc) {
        if s.len() - 3 < 3 {
            return (0xfffd, -3);
        }
        let (wc2, cnt2) = utf8_to_unicode_raw(&s[3..]);
        if cnt2 != 3 || !(0xdc00..=0xdfff).contains(&wc2) {
            // Replaced: what follows does not matter, as the copy fails.
            return (0xfffd, -3);
        }
        let uc = (wc - 0xd800) * 0x400 + (wc2 - 0xdc00) + 0x10000;
        return (uc, 6);
    } else if cnt == 3 && (0xdc00..=0xdfff).contains(&wc) {
        return (0xfffd, -3);
    }
    (wc, cnt)
}

/// `strncat_from_utf8_to_utf8`, through `archive_strncpy_l`: `src`, up to
/// a NUL, as UTF-8, with surrogate pairs of CESU-8 made one character;
/// `None` if a sequence had to be replaced, which makes libarchive give no
/// string at all.
pub(crate) fn utf8_to_utf8(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len());
    let mut s = src;
    loop {
        // The sequences that need no conversion.
        let mut e = 0;
        let mut n;
        loop {
            (_, n) = utf8_to_unicode(&s[e..]);
            if n <= 0 {
                break;
            }
            e += n as usize;
        }
        out.extend_from_slice(&s[..e]);
        s = &s[e..];
        if n == 0 {
            return Some(out);
        }
        let (mut uc, mut n) = utf8_to_unicode(s);
        if n == -3 && (0xd800..=0xdfff).contains(&uc) {
            (uc, n) = cesu8_to_unicode(s);
        }
        if n < 0 {
            return None;
        }
        s = &s[n as usize..];
        let mut tmp = [0u8; 4];
        let c = char::from_u32(uc).unwrap_or(char::REPLACEMENT_CHARACTER);
        out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::utf8_to_utf8;

    #[test]
    fn utf8() {
        assert_eq!(utf8_to_utf8(b"abc"), Some(b"abc".to_vec()));
        assert_eq!(
            utf8_to_utf8("é€😀".as_bytes()),
            Some("é€😀".as_bytes().to_vec())
        );
        assert_eq!(utf8_to_utf8(b"a\0b"), Some(b"a".to_vec()));
        assert_eq!(utf8_to_utf8(b"\xff"), None);
        assert_eq!(utf8_to_utf8(b"\xc0\x80"), None);
        assert_eq!(utf8_to_utf8(b"\xe0\x80\x80"), None);
        assert_eq!(utf8_to_utf8(b"\xc3"), None);
        assert_eq!(utf8_to_utf8(b"\xf4\x90\x80\x80"), None);
        // A surrogate pair in CESU-8 is one character; a lone one is not.
        assert_eq!(
            utf8_to_utf8(b"\xed\xa0\x80\xed\xb0\x80"),
            Some("\u{10000}".as_bytes().to_vec())
        );
        assert_eq!(utf8_to_utf8(b"\xed\xa0\x80"), None);
        assert_eq!(utf8_to_utf8(b"\xed\xb0\x80"), None);
    }
}
