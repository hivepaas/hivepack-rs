//! PEM blocks, in which SSH keys are written: port of `Decode` from Go's
//! `encoding/pem` (Go 1.27).

use std::collections::BTreeMap;

use crate::age::base64;

const PEM_START: &[u8] = b"\n-----BEGIN ";
const PEM_END: &[u8] = b"\n-----END ";
const PEM_END_OF_LINE: &[u8] = b"-----";

/// `Block`: a PEM block's type, headers and decoded bytes.
#[derive(Debug)]
pub(crate) struct Block {
    pub(crate) kind: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) bytes: Vec<u8>,
}

impl Drop for Block {
    fn drop(&mut self) {
        self.bytes.fill(0);
        std::hint::black_box(&mut self.bytes);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

fn trim_right<'a>(b: &'a [u8], cut: &[u8]) -> &'a [u8] {
    let end = b
        .iter()
        .rposition(|c| !cut.contains(c))
        .map_or(0, |i| i + 1);
    &b[..end]
}

/// Go's `bytes.TrimSpace` for the ASCII white space PEM headers have.
fn trim_space(b: &[u8]) -> &[u8] {
    let b = trim_right(b, b" \t\n\r\x0b\x0c");
    let start = b
        .iter()
        .position(|c| !b" \t\n\r\x0b\x0c".contains(c))
        .unwrap_or(b.len());
    &b[start..]
}

/// `getLine`: the first line, without its LF, a CR before it, or the
/// spaces and tabs that end it; the rest; and how many bytes were used.
fn get_line(data: &[u8]) -> (&[u8], &[u8], usize) {
    let (mut i, j) = match data.iter().position(|&c| c == b'\n') {
        Some(i) => (i, i + 1),
        None => (data.len(), data.len()),
    };
    if j > i && i > 0 && data[i - 1] == b'\r' {
        i -= 1;
    }
    (trim_right(&data[..i], b" \t"), &data[j..], j)
}

/// `Decode`: the first PEM block in `data`, or `None`. Text around it is
/// ignored.
pub(crate) fn decode(data: &[u8]) -> Option<Block> {
    let mut rest = data;
    let mut end_trailer_index: isize = 0;
    loop {
        if end_trailer_index < 0 || end_trailer_index as usize > rest.len() {
            return None;
        }
        rest = &rest[end_trailer_index as usize..];

        let mut end_index = find(rest, PEM_END)? as isize;
        end_trailer_index = end_index + PEM_END.len() as isize;
        let Some(begin_index) = rfind(&rest[..end_index as usize], &PEM_START[1..]) else {
            continue;
        };
        if begin_index > 0 && rest[begin_index - 1] != b'\n' {
            continue;
        }
        let skip = begin_index + PEM_START.len() - 1;
        rest = &rest[skip..];
        end_index -= skip as isize;
        end_trailer_index -= skip as isize;

        let (type_line, next, consumed) = get_line(rest);
        rest = next;
        end_index -= consumed as isize;
        end_trailer_index -= consumed as isize;
        let Some(type_line) = type_line.strip_suffix(PEM_END_OF_LINE) else {
            continue;
        };

        let mut p = Block {
            kind: String::from_utf8_lossy(type_line).into_owned(),
            headers: BTreeMap::new(),
            bytes: Vec::new(),
        };

        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next, consumed) = get_line(rest);
            let Some(colon) = line.iter().position(|&c| c == b':') else {
                break;
            };
            let key = trim_space(&line[..colon]);
            let val = trim_space(&line[colon + 1..]);
            p.headers.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(val).into_owned(),
            );
            rest = next;
            end_index -= consumed as isize;
            end_trailer_index -= consumed as isize;
        }

        if !p.headers.is_empty() && end_index < 0 {
            continue;
        }
        if end_trailer_index < 0 || end_trailer_index as usize > rest.len() {
            continue;
        }

        let end_trailer = &rest[end_trailer_index as usize..];
        let end_trailer_len = type_line.len() + PEM_END_OF_LINE.len();
        if end_trailer.len() < end_trailer_len {
            continue;
        }
        let rest_of_end_line = &end_trailer[end_trailer_len..];
        let end_trailer = &end_trailer[..end_trailer_len];
        if !end_trailer.starts_with(type_line) || !end_trailer.ends_with(PEM_END_OF_LINE) {
            continue;
        }
        if !get_line(rest_of_end_line).0.is_empty() {
            continue;
        }

        if end_index > 0 {
            let base64_data: Vec<u8> = rest[..end_index as usize]
                .iter()
                .copied()
                .filter(|&c| c != b' ' && c != b'\t')
                .collect();
            let Some(bytes) = base64::decode_lenient(&base64_data) else {
                continue;
            };
            p.bytes = bytes;
        }
        return Some(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_blocks_as_go_does() {
        let block =
            decode(b"junk\n-----BEGIN THING-----\nZm9v\nYmFy\n-----END THING-----\n").unwrap();
        assert_eq!(block.kind, "THING");
        assert_eq!(block.bytes, b"foobar");

        // Headers, CRLF and trailing spaces.
        let block = decode(
            b"-----BEGIN RSA PRIVATE KEY-----  \r\nProc-Type: 4,ENCRYPTED\r\n\r\nZm9v\r\n-----END RSA PRIVATE KEY-----\r\n",
        )
        .unwrap();
        assert_eq!(block.kind, "RSA PRIVATE KEY");
        assert_eq!(block.headers["Proc-Type"], "4,ENCRYPTED");
        assert_eq!(block.bytes, b"foo");

        // An empty block, its END right after the BEGIN line.
        let block = decode(b"-----BEGIN X-----\n-----END X-----").unwrap();
        assert!(block.bytes.is_empty());

        // An END of another type, bad base64, no END, BEGIN not at a line's
        // start.
        assert!(decode(b"-----BEGIN A-----\nZm9v\n-----END B-----\n").is_none());
        assert!(decode(b"-----BEGIN A-----\nZm9v!\n-----END A-----\n").is_none());
        assert!(decode(b"-----BEGIN A-----\nZm9v\n").is_none());
        assert!(decode(b"x-----BEGIN A-----\nZm9v\n-----END A-----\n").is_none());
    }
}
