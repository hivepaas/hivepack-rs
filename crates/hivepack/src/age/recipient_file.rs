//! Recipients as `age -r` and `age -R` read them: port of `parseRecipient`,
//! `parseRecipientsFile` and `unsupportedSSHKey` in `cmd/age/parse.go`.
//!
//! Differs from age: what the port cannot encrypt to is refused, and a file that
//! has one fails, rather than leave a person out of it without a word. That is
//! `ssh-rsa` keys that age takes, of 2048 bits or more, tagged recipients, and
//! plugins, which are programs that the port does not run. The
//! keys age skips with a warning are skipped here too, and listed for the caller
//! to show: other SSH key types, and RSA keys of fewer bits.

use std::io::Read;

use crate::age::age::BoxedRecipient;
use crate::age::agessh::SshEd25519Recipient;
use crate::age::base64;
use crate::age::pq::HybridRecipient;
use crate::age::ssh_keys::{parse_authorized_key, rsa_modulus_bits};
use crate::age::x25519::X25519Recipient;

/// `recipientFileSizeLimit`.
const RECIPIENT_FILE_SIZE_LIMIT: usize = 16 << 20;

/// `lineLengthLimit`, the same as sshd(8)'s.
const LINE_LENGTH_LIMIT: usize = 8 << 10;

/// `bufio.MaxScanTokenSize`: the longest line Go's scanner reads.
const MAX_SCAN_TOKEN_SIZE: usize = 64 * 1024;

/// What the port does not encrypt to, whose lines say so by their start.
fn not_supported(arg: &str) -> Option<&'static str> {
    if arg.starts_with("age1tag1") || arg.starts_with("age1tagpq1") {
        Some("tagged recipients are not supported yet")
    } else if !arg.starts_with("age1pq1") && arg.starts_with("age1") && arg.matches('1').count() > 1
    {
        Some("plugins are not supported")
    } else {
        None
    }
}

/// `parseRecipient`: a recipient as `age -r` takes it, `age1…` or an SSH public
/// key.
pub fn parse_recipient(arg: &str) -> Result<BoxedRecipient, String> {
    if let Some(message) = not_supported(arg) {
        return Err(message.into());
    }
    if arg.starts_with("age1pq1") {
        return Ok(Box::new(HybridRecipient::parse(arg)?));
    }
    if arg.starts_with("age1") {
        return Ok(Box::new(X25519Recipient::parse(arg)?));
    }
    if arg.starts_with("ssh-") {
        return Ok(Box::new(SshEd25519Recipient::parse(arg)?));
    }
    if arg.starts_with("github:") {
        return Err("\"github:\" recipients are not supported".into());
    }
    Err(format!("unknown recipient type: {arg:?}"))
}

/// The recipients of a file.
pub struct Recipients {
    /// What to encrypt to, in the file's order.
    pub recipients: Vec<BoxedRecipient>,
    /// The SSH keys left out, about which age prints a warning.
    pub skipped: Vec<SkippedKey>,
}

/// An SSH key a recipients file has that cannot be encrypted to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedKey {
    /// The line it is on, from 1.
    pub line: usize,
    /// Its type, such as `ecdsa-sha2-nistp256`.
    pub kind: String,
}

impl std::fmt::Debug for Recipients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recipients")
            .field("recipients", &self.recipients.len())
            .field("skipped", &self.skipped)
            .finish()
    }
}

/// `unsupportedSSHKey`: the type of a valid SSH public key that is to be skipped.
fn unsupported_ssh_key(s: &str) -> Option<String> {
    let mut fields = s.split(' ');
    let kind = fields.next()?;
    let key = base64::decode_lenient(fields.next()?.as_bytes())?;
    let (len, rest) = key.split_first_chunk::<4>()?;
    let type_bytes = rest.get(..u32::from_be_bytes(*len) as usize)?;
    if kind.as_bytes() != type_bytes {
        return None;
    }
    match kind {
        "ssh-ed25519" => None,
        "ssh-rsa" => {
            parse_authorized_key(s.as_bytes()).ok()?;
            (rsa_modulus_bits(&key)? < 2048).then(|| kind.to_string())
        }
        _ => Some(kind.to_string()),
    }
}

/// An `ssh-rsa` key that age would encrypt to, and the port cannot.
fn is_rsa_key_of_age(s: &str) -> bool {
    parse_authorized_key(s.as_bytes()).is_ok_and(|key| key.kind == "ssh-rsa")
}

/// `parseRecipientsFile`: the recipients in a file, one per line, as `age -R`
/// reads it, such as what `age-keygen -y` writes or an `authorized_keys` file;
/// lines that are empty or start with `#` are skipped. 16 MiB at most.
///
/// As in age, a line that is not a recipient is not shown in the error, as it
/// might be from a confidential file.
pub fn parse_recipients_file<R: Read>(f: R) -> Result<Recipients, String> {
    let mut data = Vec::new();
    f.take(RECIPIENT_FILE_SIZE_LIMIT as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("failed to read recipients file: {e}"))?;

    let mut recipients = Vec::new();
    let mut skipped = Vec::new();
    let mut rest = &data[..];
    let mut n = 0;
    while !rest.is_empty() {
        // bufio.ScanLines: up to a LF, which is dropped with a CR before it;
        // the last line may lack it.
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= MAX_SCAN_TOKEN_SIZE {
            return Err("failed to read recipients file: bufio.Scanner: token too long".into());
        }
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        n += 1;
        if line.starts_with(b"#") || line.is_empty() {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return Err("recipients file is not valid UTF-8".into());
        };
        if line.len() > LINE_LENGTH_LIMIT {
            return Err(format!("line {n} is too long"));
        }
        match parse_recipient(line) {
            Ok(r) => recipients.push(r),
            Err(_) => {
                if let Some(kind) = unsupported_ssh_key(line) {
                    skipped.push(SkippedKey { line: n, kind });
                } else if line.starts_with("AGE-") {
                    return Err(format!(
                        "error at line {n}: apparent identity found in recipients file"
                    ));
                } else if let Some(message) = not_supported(line) {
                    return Err(format!("error at line {n}: {message}"));
                } else if is_rsa_key_of_age(line) {
                    return Err(format!(
                        "error at line {n}: ssh-rsa keys are not supported yet"
                    ));
                } else {
                    return Err(format!("malformed recipient at line {n}"));
                }
            }
        }
    }
    if data.len() > RECIPIENT_FILE_SIZE_LIMIT {
        return Err("recipients file is too long".into());
    }
    if recipients.is_empty() {
        return Err("no recipients found".into());
    }
    Ok(Recipients {
        recipients,
        skipped,
    })
}
