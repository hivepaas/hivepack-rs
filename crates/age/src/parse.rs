//! Identity files, as `age-keygen` writes them: port of `parse.go`, the
//! identities half.

use std::io::Read;

use crate::age::Identity;
use crate::pq::HybridIdentity;
use crate::x25519::X25519Identity;

/// `privateKeySizeLimit`.
const PRIVATE_KEY_SIZE_LIMIT: usize = 1 << 24;

/// `bufio.MaxScanTokenSize`: the longest line Go's scanner reads.
const MAX_SCAN_TOKEN_SIZE: usize = 64 * 1024;

/// An identity read from a file.
pub type BoxedIdentity = Box<dyn Identity + Send + Sync>;

/// `ParseIdentities`: the identities in a file, one per line; lines that
/// are empty or start with `#` are skipped. 16 MiB at most.
pub fn parse_identities<R: Read>(f: R) -> Result<Vec<BoxedIdentity>, String> {
    let mut data = Wiped(Vec::new());
    f.take(PRIVATE_KEY_SIZE_LIMIT as u64 + 1)
        .read_to_end(&mut data.0)
        .map_err(|e| format!("failed to read identities file: {e}"))?;
    let data = &data.0;

    let mut ids: Vec<BoxedIdentity> = Vec::new();
    let mut rest = &data[..];
    let mut n = 0;
    while !rest.is_empty() {
        // bufio.ScanLines: up to a LF, which is dropped with a CR before
        // it; the last line may lack it.
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= MAX_SCAN_TOKEN_SIZE {
            return Err("failed to read identities file: bufio.Scanner: token too long".into());
        }
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        n += 1;
        if line.starts_with(b"#") || line.is_empty() {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return Err("identities file is not valid UTF-8".into());
        };
        let i = parse_identity(line).map_err(|e| format!("error at line {n}: {e}"))?;
        ids.push(i);
    }
    if data.len() > PRIVATE_KEY_SIZE_LIMIT {
        return Err("identities file is too long".into());
    }
    if ids.is_empty() {
        return Err("no identities found".into());
    }
    Ok(ids)
}

/// The file's bytes, overwritten when they are dropped (best effort).
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// `parseIdentity`: one line of an identities file.
fn parse_identity(arg: &str) -> Result<BoxedIdentity, String> {
    if arg.starts_with("AGE-SECRET-KEY-1") {
        return Ok(Box::new(X25519Identity::parse(arg)?));
    }
    if arg.starts_with("AGE-SECRET-KEY-PQ-1") {
        return Ok(Box::new(HybridIdentity::parse(arg)?));
    }
    Err("unknown identity type".into())
}
