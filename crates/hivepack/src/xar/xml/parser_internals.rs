//! Port of the parts of libxml2's `parserInternals.c` the push parser uses:
//! reading characters from the input (`xmlCurrentChar`, `xmlNextChar`,
//! `xmlCopyChar`), finding the encoding (`xmlDetectEncoding`,
//! `xmlSetDeclaredEncoding`), and reporting errors (`xmlCtxtVErr`,
//! `xmlCtxtErrIO`), with the character classes of `chvalid.h`.
//!
//! The input is UTF-8, or US-ASCII when the document says so. Differs from
//! libxml2: the other encodings it knows (UTF-16, ISO-8859-1 and the ones
//! iconv adds) fail with [`Code::UnsupportedEncoding`]; see `docs/xar.md`.

use super::parser::{Code, Level, ParserCtxt, Severity};

/// `XML_INVALID_CHAR`: what `xmlCurrentChar` gives for a byte that does
/// not start a UTF-8 character.
pub(crate) const XML_INVALID_CHAR: i32 = 0x20_0000;

/// `XML_MAX_ERRORS`: how many warnings, and how many errors, are reported.
const XML_MAX_ERRORS: u32 = 100;

/// `IS_BLANK_CH`.
pub(crate) fn is_blank_ch(c: u8) -> bool {
    c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d
}

/// `IS_BYTE_CHAR` (`xmlIsChar_ch`).
pub(crate) fn is_byte_char(c: u8) -> bool {
    c == 0x09 || c == 0x0a || c == 0x0d || c >= 0x20
}

/// `IS_CHAR` (`xmlIsCharQ`): XML 1.0's Char production.
pub(crate) fn is_char(c: i32) -> bool {
    if c < 0x100 {
        c >= 0 && is_byte_char(c as u8)
    } else {
        (0x100..=0xd7ff).contains(&c)
            || (0xe000..=0xfffd).contains(&c)
            || (0x10000..=0x10ffff).contains(&c)
    }
}

/// `IS_PUBIDCHAR_CH`.
pub(crate) fn is_pubid_char(c: u8) -> bool {
    c == 0x20
        || c == 0x0d
        || c == 0x0a
        || c.is_ascii_alphanumeric()
        || b"-'()+,./:=?;!*#@$_%".contains(&c)
}

/// `xmlCopyCharMultiByte`: `val` in UTF-8, appended to `out`.
pub(crate) fn copy_char(out: &mut Vec<u8>, val: i32) {
    let mut tmp = [0u8; 4];
    let s = char::from_u32(val as u32)
        .unwrap_or(char::REPLACEMENT_CHARACTER)
        .encode_utf8(&mut tmp);
    out.extend_from_slice(s.as_bytes());
}

/// The length `xmlCopyCharMultiByte` writes for `val`.
pub(crate) fn char_len(val: i32) -> usize {
    match val {
        v if v < 0x80 => 1,
        v if v < 0x800 => 2,
        v if v < 0x10000 => 3,
        _ => 4,
    }
}

impl ParserCtxt {
    /// `xmlCtxtVErr`: an error, a warning, or a fatal error (which stops
    /// the parse), counted as libxml2 counts them, and handed to the error
    /// handler (as `xmlTextReaderStructuredRelay` does) unless the counts
    /// say not to.
    pub(crate) fn err(&mut self, level: Level, code: Code, msg: String) {
        // PARSER_STOPPED: nothing after a resource limit.
        if self.disable_sax > 1 {
            return;
        }
        if level == Level::Warning {
            if self.nb_warnings >= XML_MAX_ERRORS {
                return;
            }
            self.nb_warnings += 1;
        } else {
            // xmlIsCatastrophicError: none of the codes raised here is one
            // but XML_ERR_INTERNAL_ERROR's, which the port never raises.
            if code == Code::ResourceLimit {
                // Really stop the parser.
                self.disable_sax = 2;
            } else {
                // Report at least one fatal error.
                if self.nb_errors >= XML_MAX_ERRORS && (level != Level::Fatal || !self.well_formed)
                {
                    return;
                }
                if level == Level::Fatal {
                    self.disable_sax = 1;
                }
            }
            if level == Level::Fatal {
                self.well_formed = false;
            }
            self.err_no = Some(code);
            self.nb_errors += 1;
        }
        let severity = if level == Level::Warning {
            Severity::Warning
        } else {
            Severity::Error
        };
        self.messages.push((severity, msg));
    }

    /// `xmlFatalErr` and `xmlFatalErrMsg`: a well-formedness error.
    pub(crate) fn fatal(&mut self, code: Code, msg: &str) {
        self.err(Level::Fatal, code, format!("{msg}\n"));
    }

    /// `xmlNsErr`: a namespace error, which does not stop the parse.
    pub(crate) fn ns_err(&mut self, code: Code, msg: String) {
        self.err(Level::Error, code, msg);
    }

    /// `xmlWarningMsg` and `xmlNsWarn`.
    pub(crate) fn warning(&mut self, code: Code, msg: String) {
        self.err(Level::Warning, code, msg);
    }

    /// `xmlCtxtErrIO`: a failure to read or convert the input. Fatal, as
    /// for every code but the ones of missing files, which xml2_read_cb's
    /// errors are not.
    pub(crate) fn err_io(&mut self, code: Code) {
        let msg = match code {
            Code::InvalidEncoding => "Invalid bytes in character encoding\n".to_string(),
            Code::UnsupportedEncoding => "Unsupported encoding\n".to_string(),
            _ => "I/O error\n".to_string(),
        };
        self.err(Level::Fatal, code, msg);
    }

    /// Whether a fatal error stopped the parse (SAX callbacks disabled).
    pub(crate) fn stopped(&self) -> bool {
        self.disable_sax != 0
    }

    /// The byte at the position plus `n`, or 0 past the end, as the C reads
    /// the NUL after its buffer.
    pub(crate) fn nxt(&self, n: usize) -> u8 {
        self.buf.get(self.cur + n).copied().unwrap_or(0)
    }

    /// `RAW` and `CUR`.
    pub(crate) fn raw(&self) -> u8 {
        self.nxt(0)
    }

    /// `input->end - input->cur`.
    pub(crate) fn avail(&self) -> usize {
        self.buf.len().saturating_sub(self.cur)
    }

    /// The byte at `i` in the buffer, or 0 past the end.
    pub(crate) fn at(&self, i: usize) -> u8 {
        self.buf.get(i).copied().unwrap_or(0)
    }

    /// `SKIP`, `NEXT1` and `NEXTL`: past `n` bytes.
    pub(crate) fn skip(&mut self, n: usize) {
        self.cur += n;
    }

    /// `CMPn`.
    pub(crate) fn cmp(&self, s: &[u8]) -> bool {
        s.iter().enumerate().all(|(i, &c)| self.nxt(i) == c)
    }

    /// The first encoding error is reported, the others not
    /// (`XML_INPUT_ENCODING_ERROR`).
    fn encoding_error(&mut self) {
        if !self.encoding_error_seen {
            self.err_io(Code::InvalidEncoding);
            self.encoding_error_seen = true;
        }
    }

    /// `xmlNextChar`: past the character at the position; a CR before an
    /// LF goes with it.
    pub(crate) fn next_char(&mut self) {
        let avail = self.avail();
        if avail == 0 {
            return;
        }
        let c = self.raw();
        if c < 0x80 {
            if c == b'\r' {
                self.cur += if self.nxt(1) == b'\n' { 2 } else { 1 };
            } else {
                self.cur += 1;
            }
            return;
        }
        let c1 = self.nxt(1);
        let ok = (|| {
            if avail < 2 || (c1 & 0xc0) != 0x80 {
                return None;
            }
            if c < 0xe0 {
                if c < 0xc2 {
                    return None;
                }
                return Some(2);
            }
            let val = (u32::from(c) << 8) | u32::from(c1);
            if avail < 3 || (self.nxt(2) & 0xc0) != 0x80 {
                return None;
            }
            if c < 0xf0 {
                if val < 0xe0a0 || (0xeda0..0xee00).contains(&val) {
                    return None;
                }
                return Some(3);
            }
            if avail < 4 || (self.nxt(3) & 0xc0) != 0x80 {
                return None;
            }
            if !(0xf090..0xf490).contains(&val) {
                return None;
            }
            Some(4)
        })();
        match ok {
            Some(n) => self.cur += n,
            None => {
                self.encoding_error();
                self.cur += 1;
            }
        }
    }

    /// `xmlCurrentChar`: the character at the position and its length in
    /// bytes. A CR is an LF, and a CR before an LF is skipped (the C moves
    /// the position over it, as here). At the end, and before a UTF-8
    /// sequence the buffer has only part of, 0 with length 0.
    pub(crate) fn current_char(&mut self) -> (i32, usize) {
        let avail = self.avail();
        let c = self.raw();
        if c < 0x80 {
            if c < 0x20 {
                if c == b'\r' {
                    if self.nxt(1) == b'\n' {
                        self.cur += 1;
                    }
                    return (i32::from(b'\n'), 1);
                }
                if c == 0 {
                    if self.cur >= self.buf.len() {
                        return (0, 0);
                    }
                    self.fatal(Code::InvalidChar, "Char 0x0 out of allowed range");
                    return (0, 1);
                }
            }
            return (i32::from(c), 1);
        }
        let c = i32::from(c);
        if avail < 2 {
            return (0, 0);
        }
        let c1 = i32::from(self.nxt(1));
        if (c1 & 0xc0) != 0x80 {
            self.encoding_error();
            return (XML_INVALID_CHAR, 1);
        }
        if c < 0xe0 {
            if c < 0xc2 {
                self.encoding_error();
                return (XML_INVALID_CHAR, 1);
            }
            return (((c & 0x1f) << 6) | (c1 & 0x3f), 2);
        }
        if avail < 3 {
            return (0, 0);
        }
        let c2 = i32::from(self.nxt(2));
        if (c2 & 0xc0) != 0x80 {
            self.encoding_error();
            return (XML_INVALID_CHAR, 1);
        }
        if c < 0xf0 {
            let val = ((c & 0xf) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f);
            if val < 0x800 || (0xd800..0xe000).contains(&val) {
                self.encoding_error();
                return (XML_INVALID_CHAR, 1);
            }
            return (val, 3);
        }
        if avail < 4 {
            return (0, 0);
        }
        let c3 = i32::from(self.nxt(3));
        if (c3 & 0xc0) != 0x80 {
            self.encoding_error();
            return (XML_INVALID_CHAR, 1);
        }
        let val = ((c & 0x0f) << 18) | ((c1 & 0x3f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
        if !(0x10000..0x110000).contains(&val) {
            self.encoding_error();
            return (XML_INVALID_CHAR, 1);
        }
        (val, 4)
    }

    /// `xmlCurrentCharRecover`: as [`ParserCtxt::current_char`], with
    /// U+FFFD for what is not UTF-8.
    pub(crate) fn current_char_recover(&mut self) -> (i32, usize) {
        let (c, l) = self.current_char();
        if c == XML_INVALID_CHAR {
            (0xfffd, l)
        } else {
            (c, l)
        }
    }

    /// `xmlUTF8MultibyteLen`: the length of the UTF-8 sequence at `i`, or 0
    /// (after an encoding error) if it is not one.
    pub(crate) fn utf8_multibyte_len(&mut self, i: usize, err_msg: &str) -> usize {
        let c = self.at(i);
        let c1 = self.at(i + 1);
        let len = (|| {
            if (c1 & 0xc0) != 0x80 {
                return None;
            }
            if c < 0xe0 {
                if c < 0xc2 {
                    return None;
                }
                return Some((2, false));
            }
            let c2 = self.at(i + 2);
            if (c2 & 0xc0) != 0x80 {
                return None;
            }
            if c < 0xf0 {
                if (c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 >= 0xa0) {
                    return None;
                }
                // U+FFFE and U+FFFF are not Chars.
                return Some((3, c == 0xef && c1 == 0xbf && c2 >= 0xbe));
            }
            if (self.at(i + 3) & 0xc0) != 0x80 {
                return None;
            }
            if (c == 0xf0 && c1 < 0x90) || (c >= 0xf4 && (c > 0xf4 || c1 >= 0x90)) {
                return None;
            }
            Some((4, false))
        })();
        match len {
            Some((n, not_char)) => {
                if not_char {
                    self.fatal(Code::InvalidChar, err_msg.trim_end());
                }
                n
            }
            None => {
                self.encoding_error();
                0
            }
        }
    }

    /// `xmlSkipBlankChars`: past the blanks, and how many there were.
    pub(crate) fn skip_blanks(&mut self) -> usize {
        let start = self.cur;
        while is_blank_ch(self.raw()) && self.cur < self.buf.len() {
            self.cur += 1;
        }
        self.cur - start
    }

    /// `xmlDetectEncoding`: a byte order mark, or the first bytes of a
    /// declaration in another encoding than UTF-8.
    pub(crate) fn detect_encoding(&mut self) {
        if self.avail() < 4 {
            return;
        }
        let (b0, b1, b2, b3) = (self.nxt(0), self.nxt(1), self.nxt(2), self.nxt(3));
        let other = match b0 {
            0x00 => (b1 == 0 && b2 == 0 && b3 == 0x3c) || (b1 == 0x3c && b2 == 0 && b3 == 0x3f),
            0x3c => b1 == 0 && ((b2 == 0 && b3 == 0) || (b2 == 0x3f && b3 == 0)),
            0x4c => b1 == 0x6f && b2 == 0xa7 && b3 == 0x94,
            0xfe => b1 == 0xff,
            0xff => b1 == 0xfe,
            0xef => {
                if b1 == 0xbb && b2 == 0xbf {
                    // UTF-8's byte order mark.
                    self.cur += 3;
                    self.has_encoding = true;
                    self.auto_utf8 = true;
                }
                false
            }
            _ => false,
        };
        if other {
            // Differs from libxml2, which switches to UTF-16, UCS-4 or
            // EBCDIC: the port reads only UTF-8 and US-ASCII.
            self.has_encoding = true;
            self.err(
                Level::Fatal,
                Code::UnsupportedEncoding,
                "Unsupported encoding (not UTF-8)\n".to_string(),
            );
        }
    }

    /// `xmlSetDeclaredEncoding`: the encoding the declaration names, if none
    /// was found before (only checked against it then).
    pub(crate) fn set_declared_encoding(&mut self, encoding: Vec<u8>) {
        let name = String::from_utf8_lossy(&encoding).to_ascii_lowercase();
        if !self.has_encoding {
            match name.as_str() {
                // The names of xmlEncTable for UTF-8, which needs no
                // conversion.
                "utf-8" | "utf8" | "unicode-1-1-utf-8" | "unicode11utf8" | "unicode20utf8"
                | "x-unicode20utf8" => {}
                // And for US-ASCII: the bytes after the position are
                // checked now, the ones pushed later as they come.
                "us-ascii" | "ascii" | "ansi_x3.4-1968" => {
                    self.ascii = true;
                    // xmlInputSetEncodingHandler drops what was parsed.
                    self.buf.drain(..self.cur);
                    self.cur = 0;
                    if let Some(at) = self.buf.iter().position(|&b| b >= 0x80) {
                        self.buf.truncate(at);
                        self.buf_error = true;
                        self.err_io(Code::InvalidEncoding);
                        return;
                    }
                }
                // Differs from libxml2, which converts the others it knows
                // (ISO-8859-1, UTF-16 and, with iconv, many more) and fails
                // with XML_ERR_UNSUPPORTED_ENCODING on the rest: the port
                // fails on all of them.
                _ => {
                    self.err(
                        Level::Fatal,
                        Code::UnsupportedEncoding,
                        format!(
                            "Unsupported encoding: {}\n",
                            String::from_utf8_lossy(&encoding)
                        ),
                    );
                    return;
                }
            }
            self.has_encoding = true;
        } else if self.auto_utf8 && name != "utf-8" && name != "utf8" {
            self.warning(
                Code::Other,
                format!(
                    "Encoding '{}' doesn't match auto-detected 'UTF-8'\n",
                    String::from_utf8_lossy(&encoding)
                ),
            );
        }
        self.encoding = Some(encoding);
    }
}
