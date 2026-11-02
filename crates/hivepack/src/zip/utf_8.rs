//! Telling ASCII, UTF-8 and CP437 apart, and converting CP437 to UTF-8:
//! port of `zip_utf-8.c`.

use crate::zip::zipint::Encoding;

/// `_cp437_to_unicode`.
#[rustfmt::skip]
static CP437_TO_UNICODE: [u16; 256] = [
    /* 0x00 - 0x0F */
    0x0000, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25D8, 0x25CB, 0x25D9, 0x2642, 0x2640, 0x266A, 0x266B, 0x263C,
    /* 0x10 - 0x1F */
    0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8, 0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC,
    /* 0x20 - 0x2F */
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    /* 0x30 - 0x3F */
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    /* 0x40 - 0x4F */
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    /* 0x50 - 0x5F */
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    /* 0x60 - 0x6F */
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    /* 0x70 - 0x7F */
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x2302,
    /* 0x80 - 0x8F */
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    /* 0x90 - 0x9F */
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    /* 0xA0 - 0xAF */
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    /* 0xB0 - 0xBF */
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    /* 0xC0 - 0xCF */
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    /* 0xD0 - 0xDF */
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    /* 0xE0 - 0xEF */
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    /* 0xF0 - 0xFF */
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

const UTF_8_LEN_2_MASK: u8 = 0xe0;
const UTF_8_LEN_2_MATCH: u8 = 0xc0;
const UTF_8_LEN_3_MASK: u8 = 0xf0;
const UTF_8_LEN_3_MATCH: u8 = 0xe0;
const UTF_8_LEN_4_MASK: u8 = 0xf8;
const UTF_8_LEN_4_MATCH: u8 = 0xf0;
const UTF_8_CONTINUE_MASK: u8 = 0xc0;
const UTF_8_CONTINUE_MATCH: u8 = 0x80;
const UTF_8_CONTINUE_VALUE_MASK: u8 = 0x3f;

/// smallest code point that has to be encoded with a sequence of the given
/// length, indexed by number of continuation bytes
const UTF8_MINIMUM_CODE_POINT: [u32; 4] = [0, 0x80, 0x800, 0x10000];

/// What the bytes `name` are, given what they are expected to be: the
/// analysis of `_zip_guess_encoding`, which keeps the answer in the string
/// (see `ZipString::guess_encoding`).
pub(crate) fn guess(name: &[u8], expected_encoding: Encoding) -> Encoding {
    let mut can_be_ascii = true;
    let mut can_be_utf8 = true;
    let mut has_control_characters = false;

    let mut i = 0;
    'done: while i < name.len() {
        if name[i] < 128 {
            if name[i] < 32 && name[i] != b'\r' && name[i] != b'\n' && name[i] != b'\t' {
                has_control_characters = true;
            }
            i += 1;
            continue;
        }

        can_be_ascii = false;
        let ulen;
        let mut codepoint;
        if (name[i] & UTF_8_LEN_2_MASK) == UTF_8_LEN_2_MATCH {
            ulen = 1;
            codepoint = u32::from(name[i] & !UTF_8_LEN_2_MASK);
        } else if (name[i] & UTF_8_LEN_3_MASK) == UTF_8_LEN_3_MATCH {
            ulen = 2;
            codepoint = u32::from(name[i] & !UTF_8_LEN_3_MASK);
        } else if (name[i] & UTF_8_LEN_4_MASK) == UTF_8_LEN_4_MATCH {
            ulen = 3;
            codepoint = u32::from(name[i] & !UTF_8_LEN_4_MASK);
        } else {
            can_be_utf8 = false;
            break;
        }

        if i + ulen >= name.len() {
            can_be_utf8 = false;
            break;
        }

        for j in 1..=ulen {
            if (name[i + j] & UTF_8_CONTINUE_MASK) != UTF_8_CONTINUE_MATCH {
                can_be_utf8 = false;
                break 'done;
            }
            codepoint = (codepoint << 6) | u32::from(name[i + j] & UTF_8_CONTINUE_VALUE_MASK);
        }
        // reject overlong encodings, surrogate halves, and code points
        // above U+10FFFF
        if codepoint < UTF8_MINIMUM_CODE_POINT[ulen]
            || (0xd800..=0xdfff).contains(&codepoint)
            || codepoint > 0x10ffff
        {
            can_be_utf8 = false;
            break 'done;
        }
        i += ulen + 1;
    }

    match expected_encoding {
        Encoding::Utf8Known | Encoding::Utf8Guessed => {
            if can_be_utf8 {
                Encoding::Utf8Known
            } else {
                Encoding::Error
            }
        }
        Encoding::Ascii => {
            if can_be_ascii && !has_control_characters {
                Encoding::Ascii
            } else {
                Encoding::Error
            }
        }
        Encoding::Cp437 => Encoding::Cp437,
        Encoding::Unknown => {
            if can_be_ascii && !has_control_characters {
                // only bytes from 0x20-0x7F
                Encoding::Ascii
            } else if can_be_ascii && has_control_characters {
                // only bytes from 0x00-0x7F
                Encoding::Cp437
            } else if can_be_utf8 {
                // contains bytes from 0x80-0xFF and is valid UTF-8
                Encoding::Utf8Guessed
            } else {
                // fallback
                Encoding::Cp437
            }
        }
        // invalid, shouldn't happen
        Encoding::Error => Encoding::Error,
    }
}

/// `_zip_unicode_to_utf8`, appending.
fn unicode_to_utf8(codepoint: u32, buf: &mut Vec<u8>) {
    if codepoint < 0x0080 {
        buf.push(codepoint as u8);
    } else if codepoint < 0x0800 {
        buf.push(UTF_8_LEN_2_MATCH | ((codepoint >> 6) & 0x1f) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | (codepoint & 0x3f) as u8);
    } else if codepoint < 0x10000 {
        buf.push(UTF_8_LEN_3_MATCH | ((codepoint >> 12) & 0x0f) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | ((codepoint >> 6) & 0x3f) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | (codepoint & 0x3f) as u8);
    } else {
        buf.push(UTF_8_LEN_4_MATCH | ((codepoint >> 18) & 0x07) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | ((codepoint >> 12) & 0x3f) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | ((codepoint >> 6) & 0x3f) as u8);
        buf.push(UTF_8_CONTINUE_MATCH | (codepoint & 0x3f) as u8);
    }
}

/// The CP437 bytes `cp437buf` in UTF-8: port of `_zip_cp437_to_utf8`.
pub(crate) fn cp437_to_utf8(cp437buf: &[u8]) -> Vec<u8> {
    let mut utf8buf = Vec::with_capacity(cp437buf.len() * 3);
    for &byte in cp437buf {
        unicode_to_utf8(u32::from(CP437_TO_UNICODE[usize::from(byte)]), &mut utf8buf);
    }
    utf8buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_as_libzip() {
        assert_eq!(guess(b"plain.txt", Encoding::Unknown), Encoding::Ascii);
        assert_eq!(guess(b"tab\tok", Encoding::Unknown), Encoding::Ascii);
        assert_eq!(guess(b"bell\x07", Encoding::Unknown), Encoding::Cp437);
        assert_eq!(
            guess("caf\u{e9}".as_bytes(), Encoding::Unknown),
            Encoding::Utf8Guessed
        );
        assert_eq!(guess(b"caf\xe9", Encoding::Unknown), Encoding::Cp437);
        assert_eq!(guess(b"caf\xe9", Encoding::Utf8Known), Encoding::Error);
        // Overlong, surrogate, and cut short.
        assert_eq!(guess(b"\xc0\x80", Encoding::Utf8Known), Encoding::Error);
        assert_eq!(guess(b"\xed\xa0\x80", Encoding::Utf8Known), Encoding::Error);
        assert_eq!(guess(b"a\xe2\x82", Encoding::Utf8Known), Encoding::Error);
        assert_eq!(
            guess("\u{10ffff}".as_bytes(), Encoding::Utf8Known),
            Encoding::Utf8Known
        );
        assert_eq!(
            cp437_to_utf8(b"\x01\x80\xff"),
            "\u{263a}\u{c7}\u{a0}".as_bytes()
        );
    }
}
