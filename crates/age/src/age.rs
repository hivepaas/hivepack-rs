//! Encrypting and decrypting a file: port of `age.go`.

use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;

use hivepack_crypto::{RandomSource, equal, system_random};

use crate::error::{EncryptError, Error, NoIdentityMatch};
use crate::format::{self, Header, Stanza};
use crate::primitives::{header_mac, stream_key};
use crate::stream::{DecryptReader, EncryptWriter};

/// `fileKeySize`.
pub(crate) const FILE_KEY_SIZE: usize = 16;

/// `streamNonceSize`.
const STREAM_NONCE_SIZE: usize = 16;

/// The key a file's payload is derived from, which each recipient stanza
/// wraps. age's own stanzas wrap 16 bytes; `ssh-ed25519`'s do not check,
/// and take what the stanza holds, as age does. It is overwritten when it
/// is dropped (best effort).
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey(pub(crate) Vec<u8>);

impl FileKey {
    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// Shows nothing of the key.
impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(..)")
    }
}

/// Why an identity did not unwrap the file key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnwrapError {
    /// The stanzas are not for this identity, or the passphrase is wrong:
    /// `ErrIncorrectIdentity`, with what age adds to it. The next identity
    /// is tried.
    Incorrect(String),
    /// A stanza for this identity is malformed, or asks for too much work:
    /// the file fails with [`Error::Header`] without trying the others.
    Invalid(String),
}

/// A key that can unwrap a file key: `Identity`.
pub trait Identity {
    /// `Unwrap`: the file key, from one of the header's stanzas.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError>;

    /// Whether this is one of age's own identities (X25519 or scrypt
    /// here), which `Decrypt` tries before the others: they are quick,
    /// and need nothing from the person.
    fn is_native(&self) -> bool {
        false
    }
}

/// A file key known already, from [`Decryptor::file_key`]:
/// `NewInjectedFileKeyIdentity`. It unwraps it for any header; the header's
/// MAC then tells whether it is the file's.
#[derive(Clone, Debug)]
pub struct FileKeyIdentity(pub FileKey);

impl Identity for FileKeyIdentity {
    fn unwrap(&self, _stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        Ok(self.0.clone())
    }
}

/// A key or passphrase a file key can be wrapped for: `Recipient`, with
/// `RecipientWithLabels` as a method of it.
pub trait Recipient {
    /// `Wrap`: the stanzas that hold `file_key` for this recipient, with their
    /// random bytes from `random`.
    fn wrap(&self, file_key: &FileKey, random: &RandomSource) -> Result<Vec<Stanza>, EncryptError>;

    /// `WrapWithLabels`: the stanzas, and what a file's other recipients must
    /// say too. [`encrypt`] refuses recipients whose labels differ. None by
    /// default, as in age for a recipient without the method.
    fn wrap_with_labels(
        &self,
        file_key: &FileKey,
        random: &RandomSource,
    ) -> Result<(Vec<Stanza>, Vec<String>), EncryptError> {
        Ok((self.wrap(file_key, random)?, Vec::new()))
    }
}

/// Fills `bytes` from `random`.
pub(crate) fn fill(random: &RandomSource, bytes: &mut [u8]) -> Result<(), EncryptError> {
    random(bytes).map_err(EncryptError::Random)
}

/// `incompatibleLabelsError`.
fn incompatible_labels_error(l1: &[String], l2: &[String]) -> EncryptError {
    let has_pq = |labels: &[String]| labels.iter().any(|l| l == "postquantum");
    EncryptError::Recipient(if has_pq(l1) != has_pq(l2) {
        "incompatible recipients: can't mix post-quantum and classic recipients, or the file \
         would be vulnerable to quantum computers"
            .into()
    } else {
        format!("incompatible recipients: {l1:?} and {l2:?} can't be mixed")
    })
}

/// `encryptHdr`: the header that holds `file_key` for `recipients`.
fn encrypt_hdr(
    file_key: &FileKey,
    recipients: &[&dyn Recipient],
    random: &RandomSource,
) -> Result<Header, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::Recipient("no recipients specified".into()));
    }
    let mut hdr = Header {
        recipients: Vec::new(),
        mac: [0; 32],
    };
    let mut labels = Vec::new();
    for (i, r) in recipients.iter().enumerate() {
        let (stanzas, mut l) = r.wrap_with_labels(file_key, random).map_err(|e| match e {
            EncryptError::Recipient(message) => {
                EncryptError::Recipient(format!("failed to wrap key for recipient #{i}: {message}"))
            }
            other => other,
        })?;
        l.sort();
        if i == 0 {
            labels = l;
        } else if labels != l {
            return Err(incompatible_labels_error(&labels, &l));
        }
        hdr.recipients.extend(stanzas);
    }
    if hdr.recipients.is_empty() {
        return Err(EncryptError::Recipient(
            "failed to compute header MAC: no recipient stanzas".into(),
        ));
    }
    hdr.mac = header_mac(&file_key.0, &hdr);
    Ok(hdr)
}

/// `Encrypt`: an age file written to `dst`, for `recipients`, of what is
/// written to the [`Encryptor`] returned.
///
/// Its random bytes come from `random`, or with `None` from the system
/// ([`system_random`]), which only works on Unix. If they cannot be had, nothing
/// is written. A file can have any number of keys as recipients, but a
/// passphrase only as its one recipient.
///
/// The header and the nonce are written before this returns; the payload a
/// chunk of 64 KiB at a time. [`Encryptor::finish`] ends the file: without it,
/// the file lacks its last chunk and fails to decrypt. For an armored file, `dst`
/// is an [`ArmoredWriter`](crate::ArmoredWriter), finished after this.
pub fn encrypt<W: Write>(
    mut dst: W,
    recipients: &[&dyn Recipient],
    random: Option<&RandomSource>,
) -> Result<Encryptor<W>, EncryptError> {
    let random = random
        .cloned()
        .unwrap_or_else(|| Arc::new(system_random) as RandomSource);

    let mut file_key = FileKey(vec![0; FILE_KEY_SIZE]);
    fill(&random, &mut file_key.0)?;

    let hdr = encrypt_hdr(&file_key, recipients, &random)?;

    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    fill(&random, &mut nonce)?;

    dst.write_all(&hdr.marshal()).map_err(EncryptError::Io)?;
    dst.write_all(&nonce).map_err(EncryptError::Io)?;

    Ok(Encryptor {
        writer: EncryptWriter::new(stream_key(&file_key.0, &nonce), dst),
    })
}

/// The payload of an age file being written: what [`encrypt`] returns.
///
/// A failure of the destination is returned again by every later write and by
/// [`finish`](Encryptor::finish).
#[derive(Debug)]
pub struct Encryptor<W> {
    writer: EncryptWriter<W>,
}

impl<W: Write> Encryptor<W> {
    /// `Close`: ends the file with its last chunk, flushes the destination and
    /// gives it back.
    pub fn finish(self) -> io::Result<W> {
        self.writer.finish()
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    /// Flushes the destination. What is in the chunk being written stays
    /// there: a chunk is sealed only when it is full or the last.
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// `ErrIncorrectIdentity`'s message.
pub(crate) const INCORRECT_IDENTITY: &str = "incorrect identity for recipient block";

/// `multiUnwrap`: the first stanza `unwrap` takes, skipping those that are
/// not for it.
pub(crate) fn multi_unwrap(
    unwrap: impl Fn(&Stanza) -> Result<FileKey, UnwrapError>,
    stanzas: &[Stanza],
) -> Result<FileKey, UnwrapError> {
    for s in stanzas {
        match unwrap(s) {
            Err(UnwrapError::Incorrect(_)) => continue,
            result => return result,
        }
    }
    Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()))
}

/// `decryptHdr`: the file key, from the first identity that unwraps it,
/// checked against the header's MAC.
fn decrypt_hdr(hdr: &Header, identities: &[&dyn Identity]) -> Result<FileKey, Error> {
    if identities.is_empty() {
        return Err(Error::Header("no identities specified".into()));
    }
    let mut identities = identities.to_vec();
    identities.sort_by_key(|i| !i.is_native());

    let mut no_match = NoIdentityMatch {
        errors: Vec::new(),
        stanza_types: hdr.recipients.iter().map(|s| s.kind.clone()).collect(),
    };
    let mut file_key = None;
    for id in identities {
        match id.unwrap(&hdr.recipients) {
            Ok(key) => {
                file_key = Some(key);
                break;
            }
            Err(UnwrapError::Incorrect(message)) => no_match.errors.push(message),
            Err(UnwrapError::Invalid(message)) => return Err(Error::Header(message)),
        }
    }
    let Some(file_key) = file_key else {
        return Err(Error::NoMatch(no_match));
    };

    if !equal(&header_mac(&file_key.0, hdr), &hdr.mac) {
        return Err(Error::HeaderMac);
    }
    Ok(file_key)
}

/// `Decrypt`: the plaintext of the age file `src`, with the first of
/// `identities` that matches one of its recipient stanzas.
///
/// The header is read and checked before this returns; the payload is
/// decrypted as it is read, a chunk of 64 KiB at a time, each chunk
/// authenticated before any of it is given out. A payload that is cut
/// short, changed or goes on after its end fails when that is reached:
/// what was read before it is authentic, but not all there is.
///
/// `src` is an armored file's [`ArmoredReader`](crate::ArmoredReader), or
/// a binary file as it is; [`decrypt_file`](crate::decrypt_file) tells the
/// two apart.
pub fn decrypt<R: BufRead>(
    mut src: R,
    identities: &[&dyn Identity],
) -> Result<Decryptor<R>, Error> {
    let hdr = format::parse(&mut src).map_err(|e| match e {
        Error::Header(message) => Error::Header(format!("failed to read header: {message}")),
        other => other,
    })?;

    let file_key = decrypt_hdr(&hdr, identities)?;

    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    let mut n = 0;
    while n < STREAM_NONCE_SIZE {
        match src.read(&mut nonce[n..]) {
            Ok(0) => {
                let message = if n == 0 { "EOF" } else { "unexpected EOF" };
                return Err(Error::Header(format!("failed to read nonce: {message}")));
            }
            Ok(read) => n += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(Decryptor {
        stanza_types: hdr.recipients.iter().map(|s| s.kind.clone()).collect(),
        reader: DecryptReader::new(stream_key(&file_key.0, &nonce), src),
        file_key,
    })
}

/// The plaintext of an age file, as it is read: what [`decrypt`] and
/// [`decrypt_file`](crate::decrypt_file) return.
///
/// A payload that fails gives an `io::Error` of kind `InvalidData`, which
/// `Error::from` turns back into an [`Error::Payload`] (or an
/// [`Error::Armor`]).
#[derive(Debug)]
pub struct Decryptor<R> {
    stanza_types: Vec<String>,
    file_key: FileKey,
    reader: DecryptReader<R>,
}

impl<R> Decryptor<R> {
    /// The types of the header's recipient stanzas, such as `X25519`.
    pub fn stanza_types(&self) -> &[String] {
        &self.stanza_types
    }

    /// The file key the header's stanza unwrapped, checked against its MAC:
    /// with [`FileKeyIdentity`], the same file decrypts again without its
    /// identity, its passphrase asked for or scrypt run again.
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}
