//! Port of the RFC 3986 parser of libxml2's `uri.c`, as far as the parser
//! asks it about a namespace name: whether it is a URI reference at all,
//! and whether it has a scheme (`xmlParseURISafe`).
//!
//! The C fills in an `xmlURI`; here only where the parse ends matters. A
//! string ends at its end as the C's at its NUL: [`at`] gives 0 past it.

/// The byte at `i`, or 0 past the end, as the C reads its terminator.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// `ISA_DIGIT`.
fn isa_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// `ISA_ALPHA`.
fn isa_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// `ISA_HEXDIG`.
fn isa_hexdig(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// `ISA_SUB_DELIM`.
fn isa_sub_delim(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'$' | b'&' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b'\''
    )
}

/// `ISA_UNRESERVED` with no cleanup flags (`xmlIsUnreserved`): RFC 3986's
/// unreserved characters.
fn isa_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// `ISA_PCT_ENCODED`.
fn isa_pct_encoded(s: &[u8], p: usize) -> bool {
    at(s, p) == b'%' && isa_hexdig(at(s, p + 1)) && isa_hexdig(at(s, p + 2))
}

/// `ISA_PCHAR`.
fn isa_pchar(s: &[u8], p: usize) -> bool {
    let c = at(s, p);
    isa_unreserved(c) || isa_pct_encoded(s, p) || isa_sub_delim(c) || c == b':' || c == b'@'
}

/// `NEXT`: past a character, or an escape.
fn next(s: &[u8], p: usize) -> usize {
    if at(s, p) == b'%' { p + 3 } else { p + 1 }
}

/// `xmlParse3986Scheme`: 0 and the end, or 1.
fn parse_3986_scheme(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    if !isa_alpha(at(s, cur)) {
        return 1;
    }
    cur += 1;
    while {
        let c = at(s, cur);
        isa_alpha(c) || isa_digit(c) || c == b'+' || c == b'-' || c == b'.'
    } {
        cur += 1;
    }
    *p = cur;
    0
}

/// `xmlParse3986Fragment`.
fn parse_3986_fragment(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    while isa_pchar(s, cur) || matches!(at(s, cur), b'/' | b'?' | b'[' | b']') {
        cur = next(s, cur);
    }
    *p = cur;
    0
}

/// `xmlParse3986Query`.
fn parse_3986_query(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    while isa_pchar(s, cur) || matches!(at(s, cur), b'/' | b'?') {
        cur = next(s, cur);
    }
    *p = cur;
    0
}

/// `xmlParse3986Port`.
fn parse_3986_port(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    let mut port: i32 = 0;
    if !isa_digit(at(s, cur)) {
        return 1;
    }
    while isa_digit(at(s, cur)) {
        let digit = i32::from(at(s, cur) - b'0');
        if port > i32::MAX / 10 {
            return 1;
        }
        port *= 10;
        if port > i32::MAX - digit {
            return 1;
        }
        port += digit;
        cur += 1;
    }
    *p = cur;
    0
}

/// `xmlParse3986Userinfo`.
fn parse_3986_userinfo(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    while {
        let c = at(s, cur);
        isa_unreserved(c) || isa_pct_encoded(s, cur) || isa_sub_delim(c) || c == b':'
    } {
        cur = next(s, cur);
    }
    if at(s, cur) == b'@' {
        *p = cur;
        return 0;
    }
    1
}

/// `xmlParse3986DecOctet`, with its last test as the C has it (of the
/// second digit where the third is meant).
fn parse_3986_dec_octet(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    let (c0, c1, c2) = (at(s, cur), at(s, cur + 1), at(s, cur + 2));
    if !isa_digit(c0) {
        return 1;
    }
    if !isa_digit(c1) {
        cur += 1;
    } else if c0 != b'0' && isa_digit(c1) && !isa_digit(c2) {
        cur += 2;
    } else if (c0 == b'1' && isa_digit(c1) && isa_digit(c2))
        || (c0 == b'2' && (b'0'..=b'4').contains(&c1) && isa_digit(c2))
        || (c0 == b'2' && c1 == b'5' && c2 >= b'0' && c1 <= b'5')
    {
        cur += 3;
    } else {
        return 1;
    }
    *p = cur;
    0
}

/// `xmlParse3986Host`.
fn parse_3986_host(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    // An IPv6 or future address, in brackets.
    if at(s, cur) == b'[' {
        cur += 1;
        while at(s, cur) != b']' && at(s, cur) != 0 {
            cur += 1;
        }
        if at(s, cur) != b']' {
            return 1;
        }
        *p = cur + 1;
        return 0;
    }
    // An IPv4 address. As the C, the second and third dots are not
    // skipped, so that only three numbers in a row can make one.
    if isa_digit(at(s, cur)) {
        let ipv4 = (|| {
            if parse_3986_dec_octet(s, &mut cur) != 0 || at(s, cur) != b'.' {
                return false;
            }
            cur += 1;
            if parse_3986_dec_octet(s, &mut cur) != 0 || at(s, cur) != b'.' {
                return false;
            }
            if parse_3986_dec_octet(s, &mut cur) != 0 || at(s, cur) != b'.' {
                return false;
            }
            parse_3986_dec_octet(s, &mut cur) == 0
        })();
        if ipv4 {
            *p = cur;
            return 0;
        }
        cur = *p;
    }
    // A host name, which can be empty.
    while {
        let c = at(s, cur);
        isa_unreserved(c) || isa_pct_encoded(s, cur) || isa_sub_delim(c)
    } {
        cur = next(s, cur);
    }
    *p = cur;
    0
}

/// `xmlParse3986Authority`.
fn parse_3986_authority(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    let ret = parse_3986_userinfo(s, &mut cur);
    if ret != 0 || at(s, cur) != b'@' {
        cur = *p;
    } else {
        cur += 1;
    }
    let ret = parse_3986_host(s, &mut cur);
    if ret != 0 {
        return ret;
    }
    if at(s, cur) == b':' {
        cur += 1;
        let ret = parse_3986_port(s, &mut cur);
        if ret != 0 {
            return ret;
        }
    }
    *p = cur;
    0
}

/// `xmlParse3986Segment`.
fn parse_3986_segment(s: &[u8], p: &mut usize, forbid: u8, empty: bool) -> i32 {
    let mut cur = *p;
    if !isa_pchar(s, cur) || at(s, cur) == forbid {
        return if empty { 0 } else { 1 };
    }
    cur = next(s, cur);
    while isa_pchar(s, cur) && at(s, cur) != forbid {
        cur = next(s, cur);
    }
    *p = cur;
    0
}

/// `xmlParse3986PathAbEmpty`.
fn parse_3986_path_ab_empty(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    while at(s, cur) == b'/' {
        cur += 1;
        let ret = parse_3986_segment(s, &mut cur, 0, true);
        if ret != 0 {
            return ret;
        }
    }
    *p = cur;
    0
}

/// `xmlParse3986PathAbsolute`.
fn parse_3986_path_absolute(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    if at(s, cur) != b'/' {
        return 1;
    }
    cur += 1;
    if parse_3986_segment(s, &mut cur, 0, false) == 0 {
        while at(s, cur) == b'/' {
            cur += 1;
            let ret = parse_3986_segment(s, &mut cur, 0, true);
            if ret != 0 {
                return ret;
            }
        }
    }
    *p = cur;
    0
}

/// `xmlParse3986PathRootless` and `xmlParse3986PathNoScheme`, which
/// forbids a colon in the first segment.
fn parse_3986_path_rootless(s: &[u8], p: &mut usize, forbid: u8) -> i32 {
    let mut cur = *p;
    let ret = parse_3986_segment(s, &mut cur, forbid, false);
    if ret != 0 {
        return ret;
    }
    while at(s, cur) == b'/' {
        cur += 1;
        let ret = parse_3986_segment(s, &mut cur, 0, true);
        if ret != 0 {
            return ret;
        }
    }
    *p = cur;
    0
}

/// `xmlParse3986HierPart`.
fn parse_3986_hier_part(s: &[u8], p: &mut usize) -> i32 {
    let mut cur = *p;
    if at(s, cur) == b'/' && at(s, cur + 1) == b'/' {
        cur += 2;
        let ret = parse_3986_authority(s, &mut cur);
        if ret != 0 {
            return ret;
        }
        let ret = parse_3986_path_ab_empty(s, &mut cur);
        if ret != 0 {
            return ret;
        }
        *p = cur;
        return 0;
    } else if at(s, cur) == b'/' {
        let ret = parse_3986_path_absolute(s, &mut cur);
        if ret != 0 {
            return ret;
        }
    } else if isa_pchar(s, cur) {
        let ret = parse_3986_path_rootless(s, &mut cur, 0);
        if ret != 0 {
            return ret;
        }
    }
    *p = cur;
    0
}

/// The optional query and fragment, then the end of the string.
fn parse_3986_tail(s: &[u8], mut p: usize) -> i32 {
    if at(s, p) == b'?' {
        p += 1;
        let ret = parse_3986_query(s, &mut p);
        if ret != 0 {
            return ret;
        }
    }
    if at(s, p) == b'#' {
        p += 1;
        let ret = parse_3986_fragment(s, &mut p);
        if ret != 0 {
            return ret;
        }
    }
    if at(s, p) != 0 { 1 } else { 0 }
}

/// `xmlParse3986RelativeRef`.
fn parse_3986_relative_ref(s: &[u8]) -> i32 {
    let mut p = 0;
    if at(s, 0) == b'/' && at(s, 1) == b'/' {
        p = 2;
        let ret = parse_3986_authority(s, &mut p);
        if ret != 0 {
            return ret;
        }
        let ret = parse_3986_path_ab_empty(s, &mut p);
        if ret != 0 {
            return ret;
        }
    } else if at(s, 0) == b'/' {
        let ret = parse_3986_path_absolute(s, &mut p);
        if ret != 0 {
            return ret;
        }
    } else if isa_pchar(s, 0) {
        let ret = parse_3986_path_rootless(s, &mut p, b':');
        if ret != 0 {
            return ret;
        }
    }
    parse_3986_tail(s, p)
}

/// `xmlParse3986URI`.
fn parse_3986_uri(s: &[u8]) -> i32 {
    let mut p = 0;
    let ret = parse_3986_scheme(s, &mut p);
    if ret != 0 {
        return ret;
    }
    if at(s, p) != b':' {
        return 1;
    }
    p += 1;
    let ret = parse_3986_hier_part(s, &mut p);
    if ret != 0 {
        return ret;
    }
    parse_3986_tail(s, p)
}

/// `xmlParseURISafe`, through `xmlParse3986URIReference`: `None` if `s`
/// (up to a NUL, as the C string) is not a URI reference, else whether it
/// has a scheme.
pub(crate) fn parse_uri_safe(s: &[u8]) -> Option<bool> {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    if parse_3986_uri(s) == 0 {
        return Some(true);
    }
    if parse_3986_relative_ref(s) == 0 {
        return Some(false);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_uri_safe;

    #[test]
    fn uris() {
        assert_eq!(parse_uri_safe(b"http://example.com/a?b#c"), Some(true));
        assert_eq!(parse_uri_safe(b"urn:x"), Some(true));
        assert_eq!(parse_uri_safe(b"relative/path"), Some(false));
        assert_eq!(parse_uri_safe(b""), Some(false));
        assert_eq!(parse_uri_safe(b"a b"), None);
        assert_eq!(parse_uri_safe(b"%zz"), None);
        assert_eq!(parse_uri_safe(b"http://[::1]:80/"), Some(true));
        assert_eq!(parse_uri_safe(b"http://1.2.3.4/"), Some(true));
        assert_eq!(parse_uri_safe(b"a:b:c"), Some(true));
        assert_eq!(parse_uri_safe(b":x"), None);
    }
}
