// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Names as UnRAR on Linux reads them, in a UTF-8 locale: RAR 4's encoded
//! Unicode names (encname.cpp), names in the system's code page
//! (`CharToWide`, unicode.cpp), RAR 5's UTF-8 (`UtfToWide`), and the path
//! separators (`ConvertFileHeader`, arcread.cpp).

use crate::rar::headers::{Format, HostSystem, WideString};

/// Where UnRAR maps bytes that are not UTF-8 in a name: U+E080 to U+E0FF,
/// after a U+FFFE mark.
const MAP_AREA_START: u32 = 0xe000;
const MAPPED_STRING_MARK: u32 = 0xfffe;

/// A `char`, which is signed on the systems UnRAR's Linux build runs on,
/// as a `wchar_t`.
fn signed_char(byte: u8) -> u32 {
    i32::from(byte as i8) as u32
}

/// RAR 4's Unicode name: `EncodeFileName::Decode`. `name` is the whole
/// name field, its ASCII part first; `enc` is what follows the ASCII part's
/// zero byte.
pub(crate) fn decode_encoded(name: &[u8], enc: &[u8], out: &mut WideString) {
    let at = |i: usize| name.get(i).copied().unwrap_or(0);
    let mut enc_pos = 0;
    let mut dec_pos = 0;
    let high_byte = if enc.is_empty() {
        0
    } else {
        enc_pos += 1;
        enc[0]
    };
    let mut flags: u8 = 0;
    let mut flag_bits = 0;
    let put = |out: &mut WideString, pos: usize, value: u32| {
        out.resize(pos + 1, 0);
        out[pos] = value;
    };
    while enc_pos < enc.len() {
        if flag_bits == 0 {
            flags = enc[enc_pos];
            enc_pos += 1;
            flag_bits = 8;
        }
        match flags >> 6 {
            0 => {
                if enc_pos < enc.len() {
                    put(out, dec_pos, u32::from(enc[enc_pos]));
                    dec_pos += 1;
                    enc_pos += 1;
                }
            }
            1 => {
                if enc_pos < enc.len() {
                    put(
                        out,
                        dec_pos,
                        u32::from(enc[enc_pos]) + (u32::from(high_byte) << 8),
                    );
                    dec_pos += 1;
                    enc_pos += 1;
                }
            }
            2 => {
                if enc_pos + 1 < enc.len() {
                    put(
                        out,
                        dec_pos,
                        u32::from(enc[enc_pos]) + (u32::from(enc[enc_pos + 1]) << 8),
                    );
                    dec_pos += 1;
                    enc_pos += 2;
                }
            }
            _ => {
                if enc_pos < enc.len() {
                    let mut length = u32::from(enc[enc_pos]);
                    enc_pos += 1;
                    if length & 0x80 != 0 {
                        if enc_pos < enc.len() {
                            let correction = enc[enc_pos];
                            enc_pos += 1;
                            length = (length & 0x7f) + 2;
                            while length > 0 && dec_pos < name.len() {
                                let low = (signed_char(at(dec_pos))
                                    .wrapping_add(u32::from(correction)))
                                    & 0xff;
                                put(out, dec_pos, low + (u32::from(high_byte) << 8));
                                length -= 1;
                                dec_pos += 1;
                            }
                        }
                    } else {
                        length += 2;
                        while length > 0 && dec_pos < name.len() {
                            put(out, dec_pos, signed_char(at(dec_pos)));
                            length -= 1;
                            dec_pos += 1;
                        }
                    }
                }
            }
        }
        flags <<= 2;
        flag_bits -= 2;
    }
}

/// One character of UTF-8 as glibc's `mbrtowc` takes it in a UTF-8 locale
/// (`utf8_internal_loop`, gconv_simple.c): the character and its length,
/// or `None` if the bytes are not one. glibc takes four-byte sequences up
/// to U+1FFFFF, past Unicode's end, and refuses overlong forms and
/// surrogates.
fn mbrtowc(bytes: &[u8]) -> Option<(u32, usize)> {
    let first = *bytes.first()?;
    let (count, mut c) = match first {
        0x00..=0x7f => return Some((u32::from(first), 1)),
        0xc2..=0xdf => (2, u32::from(first & 0x1f)),
        0xe0..=0xef => (3, u32::from(first & 0x0f)),
        0xf0..=0xf7 => (4, u32::from(first & 0x07)),
        _ => return None,
    };
    for i in 1..count {
        let byte = *bytes.get(i)?;
        if byte & 0xc0 != 0x80 {
            return None;
        }
        c = (c << 6) | u32::from(byte & 0x3f);
    }
    if count > 2 && c >> (5 * count - 4) == 0 || (0xd800..=0xdfff).contains(&c) {
        return None;
    }
    Some((c, count))
}

/// A name in the system's code page, a UTF-8 locale here: `CharToWide` for
/// Unix, up to the first zero byte. Bytes that are not UTF-8 are mapped as
/// UnRAR maps them.
pub(crate) fn char_to_wide(src: &[u8]) -> WideString {
    let src = &src[..src.iter().position(|&b| b == 0).unwrap_or(src.len())];
    // The buffer UnRAR's std::string overload converts into.
    let dest_size = 2 * src.len() + 1;
    // mbsrtowcs, the whole name, if it is all UTF-8 to glibc.
    let mut out = WideString::new();
    let mut pos = 0;
    while let Some((c, len)) = mbrtowc(&src[pos..]) {
        out.push(c);
        pos += len;
    }
    if pos == src.len() {
        out.truncate(dest_size - 1);
        return out;
    }
    // CharToWideMap.
    let mut out = WideString::new();
    let mut mark_added = false;
    let mut pos = 0;
    while out.len() < dest_size {
        if pos >= src.len() {
            break;
        }
        match mbrtowc(&src[pos..]) {
            Some((c, len)) => {
                out.push(c);
                pos += len;
            }
            None => {
                // Low ASCII is never mapped: no new separators or dots.
                if src[pos] < 0x80 {
                    break;
                }
                if !mark_added {
                    out.push(MAPPED_STRING_MARK);
                    mark_added = true;
                    if out.len() >= dest_size {
                        break;
                    }
                }
                out.push(u32::from(src[pos]) + MAP_AREA_START);
                pos += 1;
            }
        }
    }
    out.truncate(dest_size - 1);
    out
}

/// A name in the archive's code page: `ArcCharToWide`, which on Unix is
/// `CharToWide` for anything but low ASCII.
pub(crate) fn arc_char_to_wide(src: &[u8]) -> WideString {
    let src = &src[..src.iter().position(|&b| b == 0).unwrap_or(src.len())];
    if src.iter().all(|&b| b <= 127) {
        return src.iter().map(|&b| u32::from(b)).collect();
    }
    let mut out = char_to_wide(src);
    truncate_at_zero(&mut out);
    out
}

/// RAR 5's UTF-8: `UtfToWide`, which stops at the first zero byte, and at
/// the first sequence it cannot take, keeping what came before.
pub(crate) fn utf_to_wide(src: &[u8]) -> WideString {
    let at = |i: usize| src.get(i).copied().unwrap_or(0);
    let mut out = WideString::new();
    let mut pos = 0;
    while at(pos) != 0 {
        let c = u32::from(at(pos));
        pos += 1;
        let d;
        if c < 0x80 {
            d = c;
        } else if c >> 5 == 6 {
            if at(pos) & 0xc0 != 0x80 {
                break;
            }
            d = ((c & 0x1f) << 6) | u32::from(at(pos) & 0x3f);
            pos += 1;
        } else if c >> 4 == 14 {
            if at(pos) & 0xc0 != 0x80 || at(pos + 1) & 0xc0 != 0x80 {
                break;
            }
            d = ((c & 0xf) << 12)
                | (u32::from(at(pos) & 0x3f) << 6)
                | u32::from(at(pos + 1) & 0x3f);
            pos += 2;
        } else if c >> 3 == 30 {
            if at(pos) & 0xc0 != 0x80 || at(pos + 1) & 0xc0 != 0x80 || at(pos + 2) & 0xc0 != 0x80 {
                break;
            }
            d = ((c & 7) << 18)
                | (u32::from(at(pos) & 0x3f) << 12)
                | (u32::from(at(pos + 1) & 0x3f) << 6)
                | u32::from(at(pos + 2) & 0x3f);
            pos += 3;
        } else {
            break;
        }
        // Past U+10FFFF: left out, and the rest read on.
        if d > 0x10ffff {
            continue;
        }
        out.push(d);
    }
    out
}

pub(crate) fn truncate_at_zero(name: &mut WideString) {
    if let Some(pos) = name.iter().position(|&c| c == 0) {
        name.truncate(pos);
    }
}

/// The path separators of a file header, as UnRAR on Unix makes them: `/`
/// for RAR 4's backslashes, `_` for backslashes in a RAR 5 name archived on
/// Windows, where they cannot be part of a name. Then cut at a zero.
pub(crate) fn convert_file_header(name: &mut WideString, format: Format, hs_type: HostSystem) {
    for c in name.iter_mut() {
        if *c == u32::from(b'\\') && format == Format::Rar50 && hs_type == HostSystem::Windows {
            *c = u32::from(b'_');
        }
        if *c == u32::from(b'/') || (*c == u32::from(b'\\') && format != Format::Rar50) {
            *c = u32::from(b'/');
        }
    }
    truncate_at_zero(name);
}

/// `ConvertPath`, on Linux: what is left of a name once any `..` in it, and
/// whatever leads up to its first real part, is taken away. Names of nothing
/// but those, like `/` and `../`, are left with nothing.
pub fn convert_path(s: &[u32]) -> &[u32] {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let is_div = |c: u32| c == u32::from(b'/');
    let dot = u32::from(b'.');
    let mut dest = 0;
    // No "/../" in any part, and no "/.." at the end.
    for i in 0..s.len() {
        if is_div(at(i))
            && at(i + 1) == dot
            && at(i + 2) == dot
            && (is_div(at(i + 3)) || at(i + 3) == 0)
        {
            dest = if at(i + 3) == 0 { i + 3 } else { i + 4 };
        }
    }
    // No "//server/share/", nor any run of "." and "/", at the start.
    while dest < s.len() {
        let mut i = dest;
        if is_div(at(i)) && is_div(at(i + 1)) {
            let mut slashes = 0;
            for j in i + 2..s.len() {
                if is_div(at(j)) {
                    slashes += 1;
                    if slashes == 2 {
                        i = j + 1;
                        break;
                    }
                }
            }
        }
        let start = i;
        for j in start..s.len() {
            if is_div(at(j)) {
                i = j + 1;
            } else if at(j) != dot {
                break;
            }
        }
        if i == dest {
            break;
        }
        dest = i;
    }
    &s[dest.min(s.len())..]
}

/// A name as text: nothing if any of it is not a character.
pub fn to_string(name: &[u32]) -> Option<String> {
    // U+FFFE marks what could not be decoded: U+E080 to U+E0FF after it.
    name.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| char::from_u32(c).filter(|&c| c != '\u{fffe}'))
        .collect()
}

/// A name as text: its characters, U+FFFD for what is not one.
pub fn to_string_lossy(name: &[u32]) -> String {
    name.iter()
        .map(|&c| char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> WideString {
        s.chars().map(u32::from).collect()
    }

    #[test]
    fn names_not_in_utf8_are_mapped() {
        assert_eq!(char_to_wide(b"abc"), wide("abc"));
        assert_eq!(char_to_wide("é".as_bytes()), wide("é"));
        // 0xe9 alone (Latin-1 é): marked, then mapped.
        assert_eq!(
            char_to_wide(b"caf\xe9"),
            vec![0x63, 0x61, 0x66, 0xfffe, 0xe0e9]
        );
    }

    #[test]
    fn utf8_stops_at_what_it_cannot_take() {
        assert_eq!(utf_to_wide("aé€😀".as_bytes()), wide("aé€😀"));
        assert_eq!(utf_to_wide(b"ab\xffcd"), wide("ab"));
        assert_eq!(utf_to_wide(b"ab\0cd"), wide("ab"));
    }

    #[test]
    fn convert_path_leaves_what_unrar_leaves() {
        for (name, left) in [
            ("a/b", "a/b"),
            ("/a", "a"),
            ("./a", "a"),
            ("../../a", "a"),
            ("a/../b", "b"),
            ("a/b/..", ""),
            ("/", ""),
            ("../", ""),
            ("//server/share/a", "a"),
            ("..", ".."),
            ("...", "..."),
            ("a..", "a.."),
            ("a/..b", "a/..b"),
        ] {
            let wide: Vec<u32> = name.bytes().map(u32::from).collect();
            let want: Vec<u32> = left.bytes().map(u32::from).collect();
            assert_eq!(convert_path(&wide), want, "{name}");
        }
    }

    #[test]
    fn separators_are_unixs() {
        let mut name = wide("a\\b/c");
        convert_file_header(&mut name, Format::Rar15, HostSystem::Windows);
        assert_eq!(name, wide("a/b/c"));
        let mut name = wide("a\\b/c");
        convert_file_header(&mut name, Format::Rar50, HostSystem::Windows);
        assert_eq!(name, wide("a_b/c"));
        let mut name = wide("a\\b");
        convert_file_header(&mut name, Format::Rar50, HostSystem::Unix);
        assert_eq!(name, wide("a\\b"));
    }
}

/// `GetNamePos`, on the name of a path.
fn name_pos(name: &[char]) -> usize {
    let is_div = |c: char| c == '/' || cfg!(windows) && c == '\\';
    name.iter().rposition(|&c| is_div(c)).map_or(0, |i| i + 1)
}

/// `GetExtPos`.
fn ext_pos(name: &[char]) -> Option<usize> {
    let dot = name.iter().rposition(|&c| c == '.')?;
    (dot >= name_pos(name)).then_some(dot)
}

/// `GetVolNumPos`.
fn vol_num_pos(name: &[char]) -> usize {
    let name_at = name_pos(name);
    if name_at == name.len() {
        return name_at;
    }
    let digit = |i: usize| name[i].is_ascii_digit();
    let mut pos = name.len() - 1;
    while !digit(pos) && pos > name_at {
        pos -= 1;
    }
    let mut num_pos = pos;
    while digit(num_pos) && num_pos > name_at {
        num_pos -= 1;
    }
    // The first number of a name like name.part##of##.rar, up to a dot.
    while num_pos > name_at && name[num_pos] != '.' {
        if digit(num_pos) {
            let dot = name[name_at..].iter().position(|&c| c == '.');
            if dot.is_some_and(|d| d + name_at < num_pos) {
                pos = num_pos;
            }
            break;
        }
        num_pos -= 1;
    }
    pos
}

/// A character one up: `++ArcName[NumPos]`, which wrong names get to as well.
fn increment(c: &mut char) {
    *c = char::from_u32(u32::from(*c) + 1).unwrap_or('\u{e000}');
}

/// `NextVolumeName`: the name of the volume after this one, `old_numbering`
/// for `.rar`, `.r00`, `.r01` and on.
pub fn next_volume_name(name: &str, old_numbering: bool) -> String {
    let mut name: Vec<char> = name.chars().collect();
    let dot_pos = match ext_pos(&name) {
        None => {
            name.extend(".rar".chars());
            name.len() - 4
        }
        Some(dot) => {
            let ext: String = name[dot + 1..].iter().collect();
            if ext.is_empty() || ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("sfx")
            {
                name.truncate(dot);
                name.extend(".rar".chars());
            }
            dot
        }
    };

    if !old_numbering {
        let mut num_pos = vol_num_pos(&name);
        if num_pos == name.len() {
            // A name that ends in a separator: nothing there to go up by.
            return name.into_iter().collect();
        }
        loop {
            increment(&mut name[num_pos]);
            if name[num_pos] != ':' {
                break;
            }
            name[num_pos] = '0';
            if num_pos == 0 {
                break;
            }
            num_pos -= 1;
            if !name[num_pos].is_ascii_digit() {
                // From .part9.rar to part10.rar.
                name.insert(num_pos + 1, '1');
                break;
            }
        }
    } else {
        if name.len() - dot_pos < 3 {
            name.truncate(dot_pos + 1);
            name.extend("rar".chars());
        }
        let digit = |i: usize| name.get(i).is_some_and(char::is_ascii_digit);
        if !digit(dot_pos + 2) || !digit(dot_pos + 3) {
            name.truncate(dot_pos + 2);
            name.extend("00".chars());
        } else {
            let mut num_pos = name.len() - 1;
            loop {
                increment(&mut name[num_pos]);
                if name[num_pos] != ':' {
                    break;
                }
                if num_pos == 0 || name[num_pos - 1] == '.' {
                    // From .999 to .a00.
                    name[num_pos] = 'a';
                    break;
                }
                name[num_pos] = '0';
                num_pos -= 1;
            }
        }
    }
    name.into_iter().collect()
}

#[cfg(test)]
mod next_volume_tests {
    use super::next_volume_name as next;

    #[test]
    fn names_go_up_as_unrar_has_them() {
        assert_eq!(next("a.part1.rar", false), "a.part2.rar");
        assert_eq!(next("a.part9.rar", false), "a.part10.rar");
        assert_eq!(next("a.part09.rar", false), "a.part10.rar");
        assert_eq!(next("a.part1of3.rar", false), "a.part2of3.rar");
        assert_eq!(next("dir.1/a.part1.rar", false), "dir.1/a.part2.rar");
        assert_eq!(next("a.rar", true), "a.r00");
        assert_eq!(next("a.r00", true), "a.r01");
        assert_eq!(next("a.r09", true), "a.r10");
        assert_eq!(next("a.r99", true), "a.s00");
        assert_eq!(next("a.999", true), "a.a00");
        assert_eq!(next("a", true), "a.r00");
        assert_eq!(next("a.exe", true), "a.r00");
        assert_eq!(next("a.part1.sfx", false), "a.part2.rar");
    }
}
