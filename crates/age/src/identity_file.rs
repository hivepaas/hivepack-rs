//! Identity files as `age --decrypt -i FILE` reads them: port of
//! `parseIdentitiesFile` and `parseIdentities` in `cmd/age/parse.go`, and of
//! `cmd/age/encrypted_keys.go`.
//!
//! A file is one of three things, told apart by its start: an age file,
//! armored or not, whose plaintext is a file of keys, encrypted with a
//! passphrase; an SSH private key in PEM; or lines of keys.
//!
//! Differs from age: plugin identities (`AGE-PLUGIN-…`) are refused, as
//! plugins are programs that the port does not run; the warning age prints
//! when an encrypted key file matches nothing is left to the caller.

use std::io::Read;
use std::sync::{Mutex, PoisonError};

use crate::age::{BoxedRecipient, FileKey, INCORRECT_IDENTITY, Identity, UnwrapError, decrypt};
use crate::agessh::{self, PassphraseFn, SshIdentity};
use crate::armor::{ArmoredReader, HEADER as ARMOR_HEADER, MAX_WHITESPACE, trim_space_start};
use crate::error::Error;
use crate::format::Stanza;
use crate::parse::BoxedIdentity;
use crate::pq::HybridIdentity;
use crate::scrypt::{DEFAULT_MAX_WORK_FACTOR, ScryptIdentity};
use crate::x25519::X25519Identity;

/// What a passphrase is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseFor {
    /// The file being decrypted, encrypted with a passphrase.
    File,
    /// A file of keys encrypted with age and a passphrase.
    IdentityFile,
    /// An SSH private key protected by a passphrase.
    SshKey,
}

/// What asks the person for a passphrase, told what for; the passphrase,
/// or why there is none.
pub type PassphrasePrompt =
    std::sync::Arc<dyn Fn(PassphraseFor) -> Result<Vec<u8>, String> + Send + Sync>;

/// `privateKeySizeLimit` for key files and encrypted ones.
const PRIVATE_KEY_SIZE_LIMIT: usize = 1 << 24;

/// `privateKeySizeLimit` for SSH keys.
const SSH_KEY_SIZE_LIMIT: usize = 1 << 14;

/// `bufio.MaxScanTokenSize`.
const MAX_SCAN_TOKEN_SIZE: usize = 64 * 1024;

/// Bytes overwritten when they are dropped (best effort).
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// Up to `limit` bytes of `r`; `Err` if it has `limit` or more.
fn read_limited<R: Read>(r: R, limit: usize) -> Result<Wiped, String> {
    let mut contents = Wiped(Vec::new());
    r.take(limit as u64)
        .read_to_end(&mut contents.0)
        .map_err(|e| format!("failed to read: {e}"))?;
    if contents.0.len() == limit {
        return Err("failed to read: file too long".into());
    }
    Ok(contents)
}

/// `parseIdentitiesFile`: the identities in `f`, a file of keys, an SSH
/// key or an encrypted file of keys. `passphrase` is asked when one is
/// needed, which is not before a file is being decrypted: an SSH key's
/// when a stanza is for it, a key file's when one of its keys is first
/// needed.
pub fn parse_identities_file<R: Read>(
    mut f: R,
    passphrase: PassphrasePrompt,
) -> Result<Vec<BoxedIdentity>, String> {
    let mut start = Wiped(Vec::new());
    (&mut f)
        .take((MAX_WHITESPACE + ARMOR_HEADER.len()) as u64)
        .read_to_end(&mut start.0)
        .map_err(|e| format!("failed to read: {e}"))?;
    let p = &start.0[..];
    let trimmed = trim_space_start(p);
    let rest = std::io::Cursor::new(p.to_vec()).chain(f);

    if p.starts_with(b"age-encryption") || trimmed.starts_with(ARMOR_HEADER.as_bytes()) {
        let contents = if trimmed.starts_with(ARMOR_HEADER.as_bytes()) {
            read_limited(
                ArmoredReader::new(std::io::BufReader::new(rest)),
                PRIVATE_KEY_SIZE_LIMIT,
            )?
        } else {
            read_limited(rest, PRIVATE_KEY_SIZE_LIMIT)?
        };
        return Ok(vec![Box::new(EncryptedIdentity {
            contents: contents.0.clone(),
            passphrase,
            identities: Mutex::new(None),
        })]);
    }
    if trimmed.starts_with(b"-----BEGIN") {
        let contents = read_limited(rest, SSH_KEY_SIZE_LIMIT)?;
        let prompt = passphrase.clone();
        let ssh_passphrase: PassphraseFn =
            std::sync::Arc::new(move || prompt(PassphraseFor::SshKey));
        return match agessh::parse_identity(&contents.0, ssh_passphrase)? {
            SshIdentity::Plain(identity) => Ok(vec![Box::new(identity)]),
            SshIdentity::Encrypted(identity) => Ok(vec![Box::new(identity)]),
        };
    }
    parse_identities(rest)
}

/// `parseIdentity` of `cmd/age`.
fn parse_identity(s: &str) -> Result<BoxedIdentity, String> {
    if s.starts_with("AGE-PLUGIN-") {
        return Err("plugins are not supported".into());
    }
    if s.starts_with("AGE-SECRET-KEY-1") {
        return Ok(Box::new(X25519Identity::parse(s)?));
    }
    if s.starts_with("AGE-SECRET-KEY-PQ-1") {
        return Ok(Box::new(HybridIdentity::parse(s)?));
    }
    Err("unknown identity type".into())
}

/// `parseIdentities` of `cmd/age`: lines of keys, as the library's
/// [`parse_identities`](crate::parse_identities) reads them, with a clearer
/// message for a public key found among them.
fn parse_identities<R: Read>(f: R) -> Result<Vec<BoxedIdentity>, String> {
    let mut data = Wiped(Vec::new());
    f.take(PRIVATE_KEY_SIZE_LIMIT as u64 + 1)
        .read_to_end(&mut data.0)
        .map_err(|e| format!("failed to read identities file: {e}"))?;
    let data = &data.0;
    let mut ids = Vec::new();
    let mut rest = &data[..];
    let mut n = 0;
    while !rest.is_empty() {
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
        match parse_identity(line) {
            Ok(i) => ids.push(i),
            Err(_) if line.starts_with("age1") => {
                return Err(format!(
                    "error at line {n}: apparent recipient found in identities file"
                ));
            }
            Err(e) => return Err(format!("error at line {n}: {e}")),
        }
    }
    if data.len() > PRIVATE_KEY_SIZE_LIMIT {
        return Err("identities file is too long".into());
    }
    if ids.is_empty() {
        return Err("no identities found".into());
    }
    Ok(ids)
}

/// `LazyScryptIdentity` (`cmd/age/encrypted_keys.go`): a passphrase asked
/// for only when the file turns out to be encrypted with one; nothing is
/// asked for a file encrypted to keys.
pub struct LazyScryptIdentity {
    passphrase: PassphrasePrompt,
    what: PassphraseFor,
    max_work_factor: u8,
}

impl LazyScryptIdentity {
    /// An identity that asks `passphrase` (told [`PassphraseFor::File`])
    /// only for a file encrypted with a passphrase, which it then unwraps;
    /// a wrong one fails the file ("incorrect passphrase"), as
    /// `age --decrypt` does.
    pub fn new(passphrase: PassphrasePrompt) -> LazyScryptIdentity {
        LazyScryptIdentity {
            passphrase,
            what: PassphraseFor::File,
            max_work_factor: DEFAULT_MAX_WORK_FACTOR,
        }
    }

    /// The largest scrypt work factor to accept, as
    /// [`ScryptIdentity::set_max_work_factor`] takes it. As in age, the
    /// passphrase is asked for first: a file that asks for more then fails
    /// without the work being done.
    pub fn set_max_work_factor(&mut self, log_n: u8) {
        self.max_work_factor = log_n.clamp(1, 30);
    }
}

impl std::fmt::Debug for LazyScryptIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyScryptIdentity").finish_non_exhaustive()
    }
}

impl Identity for LazyScryptIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        if stanzas.len() != 1 && stanzas.iter().any(|s| s.kind == "scrypt") {
            return Err(UnwrapError::Invalid(
                "an scrypt recipient must be the only one".into(),
            ));
        }
        if stanzas.len() != 1 || stanzas[0].kind != "scrypt" {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }
        let mut pass = (self.passphrase)(self.what)
            .map_err(|e| UnwrapError::Invalid(format!("could not read passphrase: {e}")))?;
        let ii = ScryptIdentity::new(&pass);
        pass.fill(0);
        let mut ii = ii.map_err(UnwrapError::Invalid)?;
        ii.set_max_work_factor(self.max_work_factor);
        match ii.unwrap(stanzas) {
            Err(UnwrapError::Incorrect(_)) => {
                Err(UnwrapError::Invalid("incorrect passphrase".into()))
            }
            result => result,
        }
    }
}

/// `EncryptedIdentity`: a file of keys encrypted with age and a
/// passphrase, decrypted the first time one of its keys is needed.
struct EncryptedIdentity {
    contents: Vec<u8>,
    passphrase: PassphrasePrompt,
    identities: Mutex<Option<Vec<BoxedIdentity>>>,
}

impl EncryptedIdentity {
    /// `decrypt`.
    fn decrypt(&self) -> Result<Vec<BoxedIdentity>, String> {
        let lazy = LazyScryptIdentity {
            passphrase: self.passphrase.clone(),
            what: PassphraseFor::IdentityFile,
            max_work_factor: DEFAULT_MAX_WORK_FACTOR,
        };
        let d = match decrypt(&self.contents[..], &[&lazy]) {
            Ok(d) => d,
            Err(Error::NoMatch(_)) => {
                return Err("identity file is encrypted with age but not with a passphrase".into());
            }
            Err(e) => return Err(format!("failed to decrypt identity file: {e}")),
        };
        parse_identities(d)
    }
}

impl Identity for EncryptedIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        let mut identities = self
            .identities
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if identities.is_none() {
            *identities = Some(self.decrypt().map_err(UnwrapError::Invalid)?);
        }
        for id in identities.iter().flatten() {
            match id.unwrap(stanzas) {
                Err(UnwrapError::Incorrect(_)) => continue,
                result => return result,
            }
        }
        Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()))
    }

    /// `Recipients`: decrypts the file of keys, if that is not done yet.
    fn recipients(&self) -> Result<Vec<BoxedRecipient>, String> {
        let mut identities = self
            .identities
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if identities.is_none() {
            *identities = Some(self.decrypt()?);
        }
        let mut recipients = Vec::new();
        for id in identities.iter().flatten() {
            recipients.extend(id.recipients()?);
        }
        Ok(recipients)
    }
}

impl Drop for EncryptedIdentity {
    fn drop(&mut self) {
        self.contents.fill(0);
        std::hint::black_box(&mut self.contents);
    }
}
