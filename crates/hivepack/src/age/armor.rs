//! The ASCII armor, age's PEM-like text form: port of `armor/armor.go`.
//!
//! ```text
//! -----BEGIN AGE ENCRYPTED FILE-----
//! YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
//! -----END AGE ENCRYPTED FILE-----
//! ```
//!
//! Strict base64 with padding, in lines of 64 columns, the last shorter;
//! line ends may be CRLF, and up to 1 KiB of whitespace is allowed before
//! the first line and after the last.

use std::io::{self, BufRead, Read, Write};

use crate::age::base64;
use crate::age::error::Error;
use crate::age::format::{BYTES_PER_LINE, COLUMNS_PER_LINE};

/// `Header`: the first line.
pub const HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// `Footer`: the last line.
pub const FOOTER: &str = "-----END AGE ENCRYPTED FILE-----";

/// `maxWhitespace`.
pub(crate) const MAX_WHITESPACE: usize = 1024;

/// Differs from age, which reads a line whole whatever its length: a line
/// is read up to this many bytes. Longer, it fails as age would fail it,
/// as too long or not the first line, with a shorter message.
const MAX_LINE: usize = 4 * MAX_WHITESPACE;

/// Go's `bytes.TrimSpace`, the start only: Unicode's white space, which
/// Rust's `char::is_whitespace` and Go's `unicode.IsSpace` agree on, in
/// valid UTF-8; an invalid byte is not space.
pub(crate) fn trim_space_start(b: &[u8]) -> &[u8] {
    let mut at = 0;
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            if !c.is_whitespace() {
                return &b[at..];
            }
            at += c.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            return &b[at..];
        }
    }
    &b[at..]
}

/// Whether `bytes.TrimSpace(b)` is empty.
fn is_space(b: &[u8]) -> bool {
    trim_space_start(b).is_empty()
}

/// What stopped the reader, kept to be returned again.
#[derive(Clone, Debug)]
enum Stop {
    End,
    Armor(String),
    Io(io::ErrorKind, String),
}

impl Stop {
    fn to_error(&self) -> io::Error {
        match self {
            Stop::End => io::Error::from(io::ErrorKind::UnexpectedEof),
            Stop::Armor(message) => Error::Armor(message.clone()).into(),
            Stop::Io(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }
}

/// `armoredReader`: the bytes an armored file encodes, read from `r`.
///
/// Errors come as `io::Error`s of kind `InvalidData` that hold an
/// [`Error::Armor`], which `Error::from` takes back out; once one is
/// returned, every later read returns it again.
#[derive(Debug)]
pub struct ArmoredReader<R> {
    r: R,
    started: bool,
    buf: [u8; BYTES_PER_LINE],
    start: usize,
    end: usize,
    err: Option<Stop>,
}

impl<R: BufRead> ArmoredReader<R> {
    /// `NewReader`.
    pub fn new(r: R) -> ArmoredReader<R> {
        ArmoredReader {
            r,
            started: false,
            buf: [0; BYTES_PER_LINE],
            start: 0,
            end: 0,
            err: None,
        }
    }

    /// `getLine`: the next line, without its LF or CRLF; the last may end
    /// without one. At the end, `UnexpectedEof`.
    fn get_line(&mut self) -> Result<Vec<u8>, Stop> {
        let mut line = Vec::new();
        let mut complete = false;
        loop {
            let buf = match self.r.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Stop::Io(e.kind(), e.to_string())),
            };
            if buf.is_empty() {
                break;
            }
            let take = match buf.iter().position(|&c| c == b'\n') {
                Some(at) => {
                    complete = true;
                    at + 1
                }
                None => buf.len(),
            };
            let room = MAX_LINE + 2 - line.len();
            if take > room {
                return Err(Stop::Armor("line too long".into()));
            }
            line.extend_from_slice(&buf[..take]);
            self.r.consume(take);
            if complete {
                break;
            }
        }
        if !complete && line.is_empty() {
            return Err(Stop::Armor("unexpected EOF".into()));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    /// `drainTrailing`: after the footer, only white space, and no more
    /// than 1 KiB of it.
    fn drain_trailing(&mut self) -> Stop {
        let mut buf = Vec::with_capacity(MAX_WHITESPACE);
        if let Err(e) = (&mut self.r)
            .take(MAX_WHITESPACE as u64)
            .read_to_end(&mut buf)
        {
            return Stop::Io(e.kind(), e.to_string());
        }
        if !is_space(&buf) {
            return Stop::Armor("trailing data after armored file".into());
        }
        if buf.len() == MAX_WHITESPACE {
            return Stop::Armor("too much trailing whitespace".into());
        }
        Stop::End
    }

    fn fail(&mut self, stop: Stop) -> io::Error {
        let error = stop.to_error();
        self.err = Some(stop);
        error
    }

    /// What most lines are, without a copy or an allocation: a full line of data,
    /// already read, with its line end. Anything else, and anything wrong with
    /// it, is left for the rest of `next_line`, with nothing consumed.
    fn next_full_line(&mut self) -> bool {
        let Ok(buf) = self.r.fill_buf() else {
            return false;
        };
        let Some((line, rest)) = buf.split_first_chunk::<COLUMNS_PER_LINE>() else {
            return false;
        };
        let end = match rest {
            [b'\n', ..] => 1,
            [b'\r', b'\n', ..] => 2,
            _ => return false,
        };
        if !base64::decode_groups(line, &mut self.buf) {
            return false;
        }
        self.r.consume(COLUMNS_PER_LINE + end);
        self.start = 0;
        self.end = BYTES_PER_LINE;
        true
    }

    /// The next line of data into `buf`, and the footer after a short one.
    fn next_line(&mut self) -> Result<(), Stop> {
        let mut removed_whitespace = 0;
        while !self.started {
            let line = self.get_line()?;
            if is_space(&line) {
                removed_whitespace += line.len() + 1;
                if removed_whitespace > MAX_WHITESPACE {
                    return Err(Stop::Armor("too much leading whitespace".into()));
                }
                continue;
            }
            if line != HEADER.as_bytes() {
                return Err(Stop::Armor(format!(
                    "invalid first line: {:?}",
                    String::from_utf8_lossy(&line)
                )));
            }
            self.started = true;
        }
        if self.next_full_line() {
            return Ok(());
        }
        let line = self.get_line()?;
        if line == FOOTER.as_bytes() {
            return Err(self.drain_trailing());
        }
        if line.is_empty() {
            return Err(Stop::Armor("empty line in armored data".into()));
        }
        if line.len() > COLUMNS_PER_LINE {
            return Err(Stop::Armor("column limit exceeded".into()));
        }
        if line.iter().any(|&c| c == b'\n' || c == b'\r') {
            return Err(Stop::Armor("unexpected newline character".into()));
        }
        let Some(data) = base64::decode(&line, true) else {
            return Err(Stop::Armor("illegal base64 data".into()));
        };
        // At most 64 columns: at most 48 bytes.
        self.buf[..data.len()].copy_from_slice(&data);
        self.start = 0;
        self.end = data.len();
        if data.len() < BYTES_PER_LINE {
            let line = self.get_line()?;
            if line != FOOTER.as_bytes() {
                return Err(Stop::Armor(format!(
                    "invalid closing line: {:?}",
                    String::from_utf8_lossy(&line)
                )));
            }
            self.err = Some(self.drain_trailing());
        }
        Ok(())
    }
}

impl<R: BufRead> Read for ArmoredReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.start < self.end {
            let n = p.len().min(self.end - self.start);
            p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
            self.start += n;
            return Ok(n);
        }
        if let Some(stop) = &self.err {
            return match stop {
                Stop::End => Ok(0),
                stop => Err(stop.to_error()),
            };
        }
        match self.next_line() {
            Ok(()) => {}
            Err(Stop::End) => {
                self.err = Some(Stop::End);
                return Ok(0);
            }
            Err(stop) => return Err(self.fail(stop)),
        }
        let n = p.len().min(self.end - self.start);
        p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

/// `armoredWriter`: writes what it is given to `dst` as an armored file, which
/// [`ArmoredWriter::finish`] ends. Without it, the file has no last line, and
/// does not read.
///
/// A failure of `dst` is kept, and returned again by every later write and by
/// `finish`. `io::Error` cannot be cloned, so those are its kind and message.
#[derive(Debug)]
pub struct ArmoredWriter<W> {
    dst: W,
    started: bool,
    /// The bytes of a line not whole yet.
    partial: [u8; BYTES_PER_LINE],
    partial_len: usize,
    out: Vec<u8>,
    err: Option<(io::ErrorKind, String)>,
}

impl<W: Write> ArmoredWriter<W> {
    /// `NewWriter`.
    pub fn new(dst: W) -> ArmoredWriter<W> {
        ArmoredWriter {
            dst,
            started: false,
            partial: [0; BYTES_PER_LINE],
            partial_len: 0,
            out: Vec::new(),
            err: None,
        }
    }

    /// The failure kept, if there is one.
    fn check(&self) -> io::Result<()> {
        match &self.err {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    /// `writeHeader`, into what is to be written.
    fn write_header(&mut self) {
        if !self.started {
            self.out.extend_from_slice(HEADER.as_bytes());
            self.out.push(b'\n');
            self.started = true;
        }
    }

    /// A whole line, into what is to be written.
    fn push_line(out: &mut Vec<u8>, data: &[u8; BYTES_PER_LINE]) {
        let mut line = [0; COLUMNS_PER_LINE];
        base64::encode_line(data, &mut line);
        out.extend_from_slice(&line);
        out.push(b'\n');
    }

    /// Writes what is to be written, keeping a failure.
    fn send(&mut self) -> io::Result<()> {
        let sent = self.dst.write_all(&self.out);
        self.out.clear();
        sent.inspect_err(|e| self.err = Some((e.kind(), e.to_string())))
    }

    /// `Close`: the rest and the last line, then `dst` flushed and given back.
    pub fn finish(mut self) -> io::Result<W> {
        self.check()?;
        self.write_header();
        if self.partial_len > 0 {
            let rest = base64::encode_padded(&self.partial[..self.partial_len]);
            self.out.extend_from_slice(rest.as_bytes());
            self.out.push(b'\n');
        }
        self.out.extend_from_slice(FOOTER.as_bytes());
        self.out.push(b'\n');
        self.send()?;
        self.dst.flush()?;
        Ok(self.dst)
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    /// `Write`.
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.write_header();
        let total = p.len();
        let mut p = p;
        if self.partial_len > 0 {
            let n = p.len().min(BYTES_PER_LINE - self.partial_len);
            self.partial[self.partial_len..self.partial_len + n].copy_from_slice(&p[..n]);
            self.partial_len += n;
            p = &p[n..];
            if self.partial_len == BYTES_PER_LINE {
                Self::push_line(&mut self.out, &self.partial);
                self.partial_len = 0;
            }
        }
        let (lines, rest) = p.as_chunks::<BYTES_PER_LINE>();
        self.out.reserve(lines.len() * (COLUMNS_PER_LINE + 1));
        for line in lines {
            Self::push_line(&mut self.out, line);
        }
        if !rest.is_empty() {
            self.partial[..rest.len()].copy_from_slice(rest);
            self.partial_len = rest.len();
        }
        self.send()?;
        Ok(total)
    }

    /// Flushes `dst`. The bytes of a line not whole yet stay here.
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.dst.flush()
    }
}

#[cfg(test)]
mod full_line_tests {
    use super::*;

    /// All of what the reader gives, in pieces, and the error that ends it.
    fn read_all(input: &[u8], capacity: usize) -> (Vec<u8>, Option<String>) {
        let mut reader = ArmoredReader::new(io::BufReader::with_capacity(capacity, input));
        let mut out = Vec::new();
        let mut buf = [0; 100];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Some(e.to_string())),
            }
        }
    }

    /// A buffer of one byte never holds a full line, so that every line takes
    /// the path that checks it: full lines change nothing else, on armor that is
    /// right and armor that is not.
    #[test]
    fn full_lines_read_as_any_other() {
        let mut state = 0x5eedu64;
        let mut next = move |below: usize| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize % below
        };
        let line = crate::age::base64::encode(&[0x5A; 48]);
        let mut checked = 0;
        for _ in 0..3000 {
            let mut text = format!("{HEADER}\n").into_bytes();
            for _ in 0..next(6) {
                text.extend_from_slice(line.as_bytes());
                text.extend_from_slice(if next(4) == 0 { b"\r\n" } else { b"\n" });
            }
            if next(2) == 0 {
                text.extend_from_slice(b"Zm9v\n");
            }
            text.extend_from_slice(FOOTER.as_bytes());
            text.push(b'\n');
            for _ in 0..next(3) {
                let at = next(text.len());
                match next(4) {
                    0 => text[at] = [b'=', b'\n', b'\r', b'-', 0xFF, b' '][next(6)],
                    1 => text.truncate(at),
                    2 => text.insert(at, b'A'),
                    _ => {
                        text.remove(at);
                    }
                }
                if text.is_empty() {
                    break;
                }
            }
            assert_eq!(
                read_all(&text, 1 << 13),
                read_all(&text, 1),
                "{}",
                String::from_utf8_lossy(&text)
            );
            checked += 1;
        }
        assert_eq!(checked, 3000);
    }
}
