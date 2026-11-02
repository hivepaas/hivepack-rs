//! File names and comments, with the encoding they are known or guessed to
//! have: port of `zip_string.c`.

use std::sync::OnceLock;

use crate::deflate::crc32;

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::utf_8::{cp437_to_utf8, guess};
use crate::zip::zip::Flags;
use crate::zip::zipint::{Encoding, FL_ENCODING_ALL};

/// `zip_string_t`: the raw bytes, their encoding, and, once asked for, the
/// bytes converted from CP437 to UTF-8.
#[derive(Clone, Debug)]
pub(crate) struct ZipString {
    raw: Vec<u8>,
    encoding: Encoding,
    converted: OnceLock<Vec<u8>>,
}

impl ZipString {
    /// A string of `raw`, or `None` if it is empty. With
    /// `Flags::ENC_UTF_8` or `Flags::ENC_CP437`, the string must be valid
    /// in that encoding, or this fails with `ZIP_ER_INVAL`. Port of
    /// `_zip_string_new`.
    pub(crate) fn new(raw: &[u8], flags: Flags) -> Result<Option<ZipString>> {
        if raw.is_empty() {
            return Ok(None);
        }
        let expected = match Flags(flags.0 & FL_ENCODING_ALL.0) {
            Flags::ENC_GUESS => Encoding::Unknown,
            Flags::ENC_UTF_8 => Encoding::Utf8Known,
            Flags::ENC_CP437 => Encoding::Cp437,
            _ => return Err(Error::new(ErrorCode::Inval, 0)),
        };
        let mut s = ZipString {
            raw: raw.to_vec(),
            encoding: Encoding::Unknown,
            converted: OnceLock::new(),
        };
        if expected != Encoding::Unknown && s.guess_encoding(expected) == Encoding::Error {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        Ok(Some(s))
    }

    /// The raw bytes.
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The encoding, guessed if it is not known yet, and kept: port of
    /// `_zip_guess_encoding`.
    pub(crate) fn guess_encoding(&mut self, expected: Encoding) -> Encoding {
        if self.encoding == Encoding::Unknown {
            self.encoding = guess(&self.raw, expected);
        }
        self.encoding
    }

    /// Takes the string to be UTF-8, as libzip does with a name or comment
    /// it is given that is guessed to be.
    pub(crate) fn set_utf8_known(&mut self) {
        self.encoding = Encoding::Utf8Known;
    }

    /// The encoding as `_zip_string_get` finds it: the one known, or the
    /// guess without an expectation. Differs from libzip, which keeps that
    /// guess in the string: it depends only on the bytes.
    fn encoding(&self) -> Encoding {
        match self.encoding {
            Encoding::Unknown => guess(&self.raw, Encoding::Unknown),
            known => known,
        }
    }

    /// Whether every byte is ASCII: `_zip_string_is_ascii`.
    pub(crate) fn is_ascii(&self) -> bool {
        self.encoding == Encoding::Ascii || self.raw.iter().all(|&b| b < 0x80)
    }
}

/// The encoding of `str`, guessed if it is not known yet, and kept; ASCII
/// for no string: port of `_zip_guess_encoding`.
pub(crate) fn guess_encoding(str: Option<&mut ZipString>, expected: Encoding) -> Encoding {
    match str {
        Some(s) => s.guess_encoding(expected),
        None => Encoding::Ascii,
    }
}

/// `_zip_string_crc32`: the CRC-32 of the raw bytes.
pub(crate) fn string_crc32(s: Option<&ZipString>) -> u32 {
    crc32(0, s.map_or(&[], |s| s.raw()))
}

/// `_zip_string_equal`: the same raw bytes, or both absent.
pub(crate) fn string_equal(a: Option<&ZipString>, b: Option<&ZipString>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.raw == b.raw,
        (a, b) => a.is_none() && b.is_none(),
    }
}

/// `_zip_string_length`.
pub(crate) fn string_length(s: Option<&ZipString>) -> u16 {
    s.map_or(0, |s| s.raw.len() as u16)
}

/// The string as asked for: raw with `Flags::ENC_RAW`, else converted to
/// UTF-8 if it is CP437 (or, with `Flags::ENC_STRICT`, not known to be ASCII
/// or UTF-8). Port of `_zip_string_get`; an absent string is empty.
pub(crate) fn string_get(string: Option<&ZipString>, flags: Flags) -> &[u8] {
    let Some(string) = string else {
        return &[];
    };
    if !flags.intersects(Flags::ENC_RAW) {
        let encoding = string.encoding();
        if (flags.intersects(Flags::ENC_STRICT)
            && encoding != Encoding::Ascii
            && encoding != Encoding::Utf8Known)
            || encoding == Encoding::Cp437
        {
            return string.converted.get_or_init(|| cp437_to_utf8(&string.raw));
        }
    }
    &string.raw
}
