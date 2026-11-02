//! The header of an age file: port of `internal/format/format.go`.
//!
//! ```text
//! age-encryption.org/v1
//! -> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
//! hjabGXwSLQ9c3S6Lw2i+S2Tu2fiwQHHslbBN6B41FLE
//! --- WyJp9F/9FOZh7gJdheq2WIJcwHgYc8NIVh3ddwhrcNg
//! ```
//!
//! An intro line, then recipient stanzas: an opening line with a type and
//! arguments, then a body in base64 lines of 64 columns, the last shorter,
//! perhaps empty. A closing line with the header's MAC ends it, and the
//! payload follows.

use std::io::{self, BufRead};

use crate::age::base64;
use crate::age::error::Error;

/// `ColumnsPerLine`: the width of a stanza's body lines.
pub(crate) const COLUMNS_PER_LINE: usize = 64;

/// `BytesPerLine`: the bytes in a full body line.
pub(crate) const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;

const INTRO: &[u8] = b"age-encryption.org/v1\n";
const STANZA_PREFIX: &[u8] = b"->";
const FOOTER_PREFIX: &[u8] = b"---";

const MAX_HEADER_BYTES: usize = 2 << 20;
const MAX_RECIPIENT_STANZAS: usize = 1024;
const MAX_STANZA_ARGS: usize = 128;

/// A recipient stanza: `Stanza`. What an [`Identity`](crate::age::Identity)
/// unwraps the file key from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stanza {
    /// The type, such as `X25519` or `scrypt` (Go's `Type`).
    pub kind: String,
    /// The arguments after the type.
    pub args: Vec<String>,
    /// The body, decoded.
    pub body: Vec<u8>,
}

/// A parsed header: `Header`.
#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) recipients: Vec<Stanza>,
    pub(crate) mac: [u8; 32],
}

/// `DecodeString`: strict base64 without padding, and without the CR or
/// LF that Go's decoder would skip.
pub(crate) fn decode_string(s: &[u8]) -> Result<Vec<u8>, String> {
    if s.iter().any(|&c| c == b'\n' || c == b'\r') {
        return Err("unexpected newline character".into());
    }
    base64::decode(s, false).ok_or_else(|| "illegal base64 data".into())
}

/// `EncodeToString`.
pub(crate) fn encode_to_string(data: &[u8]) -> String {
    base64::encode(data)
}

/// Go's `%q` of bytes, near enough for messages.
fn quote(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

impl Stanza {
    /// `Marshal`, into `w`.
    fn marshal(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(STANZA_PREFIX);
        w.push(b' ');
        w.extend_from_slice(self.kind.as_bytes());
        for a in &self.args {
            w.push(b' ');
            w.extend_from_slice(a.as_bytes());
        }
        w.push(b'\n');
        // `WrappedBase64Encoder`: a newline after each full line, so that
        // the last line is shorter than a full one, perhaps empty.
        let encoded = encode_to_string(&self.body);
        let (lines, rest) = encoded.as_bytes().as_chunks::<COLUMNS_PER_LINE>();
        for line in lines {
            w.extend_from_slice(line);
            w.push(b'\n');
        }
        w.extend_from_slice(rest);
        w.push(b'\n');
    }
}

impl Header {
    /// `MarshalWithoutMAC`: the header up to the closing line's `---`,
    /// which the MAC is computed over. A header parsed strictly gives back
    /// the bytes it was parsed from.
    pub(crate) fn marshal_without_mac(&self) -> Vec<u8> {
        let mut w = INTRO.to_vec();
        for r in &self.recipients {
            r.marshal(&mut w);
        }
        w.extend_from_slice(FOOTER_PREFIX);
        w
    }

    /// `Marshal`: the whole header, with its MAC.
    pub(crate) fn marshal(&self) -> Vec<u8> {
        let mut w = self.marshal_without_mac();
        w.push(b' ');
        w.extend_from_slice(encode_to_string(&self.mac).as_bytes());
        w.push(b'\n');
        w
    }
}

/// A line as `ReadBytes('\n')` returns it: with its newline, or without
/// one at the end of the input.
struct Line {
    bytes: Vec<u8>,
    complete: bool,
}

/// `headerReader`: lines from the input, no more than 2 MiB of them.
struct HeaderReader<'a, R> {
    r: &'a mut R,
    n: usize,
}

impl<R: BufRead> HeaderReader<'_, R> {
    /// `ReadBytes('\n')`.
    fn read_line(&mut self) -> Result<Line, Error> {
        let mut bytes = Vec::new();
        loop {
            let buf = match self.r.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if buf.is_empty() {
                return Ok(Line {
                    bytes,
                    complete: false,
                });
            }
            let (frag, complete) = match buf.iter().position(|&c| c == b'\n') {
                Some(at) => (&buf[..=at], true),
                None => (buf, false),
            };
            if frag.len() > MAX_HEADER_BYTES - self.n {
                return Err(errorf("header exceeds 2 MiB".into()));
            }
            self.n += frag.len();
            bytes.extend_from_slice(frag);
            let used = frag.len();
            self.r.consume(used);
            if complete {
                return Ok(Line { bytes, complete });
            }
        }
    }
}

/// `errorf`: a `ParseError`.
fn errorf(message: String) -> Error {
    Error::Header(format!("parsing age header: {message}"))
}

/// `ReadStanza`, its opening line already read.
fn read_stanza<R: BufRead>(hr: &mut HeaderReader<'_, R>, line: Line) -> Result<Stanza, Error> {
    let failed = |message: String| Error::Header(format!("failed to parse header: {message}"));
    if !line.complete {
        return Err(failed("failed to read line: EOF".into()));
    }
    let line = line.bytes;
    if !line.starts_with(STANZA_PREFIX) {
        return Err(failed(format!(
            "malformed stanza opening line: {}",
            quote(&line)
        )));
    }
    let (prefix, args) = split_args(&line);
    if prefix != STANZA_PREFIX || args.is_empty() {
        return Err(failed(format!("malformed stanza: {}", quote(&line))));
    }
    let mut args = args.into_iter();
    let mut s = Stanza {
        kind: args.next().unwrap_or_default(),
        args: args.collect(),
        body: Vec::new(),
    };

    loop {
        let line = hr.read_line()?;
        if !line.complete {
            return Err(failed("failed to read line: EOF".into()));
        }
        let line = line.bytes;
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let b = match decode_string(text) {
            Ok(b) => b,
            Err(e) => {
                if line.starts_with(FOOTER_PREFIX) || line.starts_with(STANZA_PREFIX) {
                    return Err(failed(format!(
                        "malformed body line {}: stanza ended without a short line\n\
                         note: this might be a file encrypted with an old beta version of age \
                         or rage; use age v1.0.0-beta6 or rage to decrypt it",
                        quote(&line)
                    )));
                }
                return Err(errorf(format!("malformed body line {}: {e}", quote(&line))));
            }
        };
        if b.len() > BYTES_PER_LINE {
            return Err(errorf(format!(
                "malformed body line {}: too long",
                quote(&line)
            )));
        }
        let short = b.len() < BYTES_PER_LINE;
        s.body.extend_from_slice(&b);
        // A stanza's body always ends with a short line.
        if short {
            return Ok(s);
        }
    }
}

/// `describeIntro`: a bad intro line quoted, or nothing if it holds a
/// private key, which should not end up in a message.
fn describe_intro(line: &[u8]) -> Option<String> {
    for prefix in [&b"AGE-SECRET-KEY-"[..], b"AGE-PLUGIN-"] {
        if line.starts_with(prefix) {
            return None;
        }
    }
    Some(quote(&line[..line.len().min(INTRO.len())]))
}

/// `Parse`: the header, read from `input`, which is left at the start of
/// the payload.
pub(crate) fn parse<R: BufRead>(input: &mut R) -> Result<Header, Error> {
    let mut hr = HeaderReader { r: input, n: 0 };

    let line = hr.read_line()?;
    if !line.complete {
        if line.bytes.is_empty() {
            return Err(errorf("file is empty".into()));
        }
        return Err(match describe_intro(&line.bytes) {
            Some(description) => errorf(format!("unexpected EOF reading intro: {description}")),
            None => errorf(format!(
                "unexpected EOF reading intro, expected {}",
                quote(INTRO)
            )),
        });
    }
    if line.bytes != INTRO {
        return Err(match describe_intro(&line.bytes) {
            Some(description) => errorf(format!("unexpected intro: {description}")),
            None => errorf(format!("unexpected intro, expected {}", quote(INTRO))),
        });
    }

    let mut recipients = Vec::new();
    let mac = loop {
        // Differs from age: the next line is read whole, where age peeks
        // at three bytes for the closing line's `---` first. A stanza's
        // opening line starts with `->`, so the two cannot be confused.
        let line = hr.read_line()?;
        if line.bytes.starts_with(FOOTER_PREFIX) {
            if !line.complete {
                return Err(Error::Header("failed to read header: EOF".into()));
            }
            let (prefix, args) = split_args(&line.bytes);
            if prefix != FOOTER_PREFIX || args.len() != 1 {
                return Err(errorf(format!(
                    "malformed closing line: {}",
                    quote(&line.bytes)
                )));
            }
            match decode_string(args[0].as_bytes()) {
                Ok(mac) => match <[u8; 32]>::try_from(mac) {
                    Ok(mac) => break mac,
                    Err(_) => {
                        return Err(errorf(format!(
                            "malformed closing line {}: <nil>",
                            quote(&line.bytes)
                        )));
                    }
                },
                Err(e) => {
                    return Err(errorf(format!(
                        "malformed closing line {}: {e}",
                        quote(&line.bytes)
                    )));
                }
            }
        }
        if recipients.len() == MAX_RECIPIENT_STANZAS {
            return Err(errorf(format!(
                "header contains more than {MAX_RECIPIENT_STANZAS} recipient stanzas"
            )));
        }
        recipients.push(read_stanza(&mut hr, line)?);
    };
    if recipients.is_empty() {
        return Err(errorf("no recipient stanzas".into()));
    }
    Ok(Header { recipients, mac })
}

/// `splitArgs`: the prefix, and the arguments after it, unless one of them
/// is empty or not printable ASCII, or there are too many, in which case
/// the whole line is the prefix.
fn split_args(line: &[u8]) -> (&[u8], Vec<String>) {
    let l = line.strip_suffix(b"\n").unwrap_or(line);
    let Some(space) = l.iter().position(|&c| c == b' ') else {
        return (l, Vec::new());
    };
    let (prefix, rest) = (&l[..space], &l[space + 1..]);
    let mut args = Vec::new();
    for arg in rest.split(|&c| c == b' ') {
        if !is_valid_string(arg) || args.len() > MAX_STANZA_ARGS {
            return (l, Vec::new());
        }
        args.push(String::from_utf8_lossy(arg).into_owned());
    }
    (prefix, args)
}

/// `isValidString`: not empty, and printable ASCII without spaces.
fn is_valid_string(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|c| (33..=126).contains(c))
}
