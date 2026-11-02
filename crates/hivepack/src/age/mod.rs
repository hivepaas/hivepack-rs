//! Decrypting and encrypting [age](https://age-encryption.org) files in safe
//! Rust, ported from age v1.3.2, the reference implementation in Go
//! (`filippo.io/age`).
//!
//! age encrypts a file to one or more recipients: each recipient stanza in
//! the header wraps the same file key, and the payload is encrypted with a
//! key derived from it, in authenticated chunks of 64 KiB. Files are often
//! archives: `tar | zstd | age`, `backup.tar.zst.age`.
//!
//! - [`decrypt_file`] reads a file as `age --decrypt` does, armored or not;
//!   [`decrypt`] reads a binary one, as the Go package's `Decrypt`.
//! - [`ScryptIdentity`] is a passphrase; [`X25519Identity`] an age key,
//!   `AGE-SECRET-KEY-1…`; [`parse_identities`] reads a file of keys, as
//!   `age-keygen` writes them.
//! - [`parse_identities_file`] reads what `age -i` takes: a file of keys,
//!   one encrypted with age and a passphrase, or an SSH Ed25519 private
//!   key ([`SshEd25519Identity`]), protected by a passphrase or not
//!   ([`EncryptedSshIdentity`]). Passphrases are asked for through a
//!   callback, only once one is needed.
//! - [`Error`] tells why a file did not decrypt, in the categories of
//!   C2SP's test vectors: a malformed header, no matching identity, a
//!   header MAC that does not match, malformed armor, or a payload that
//!   fails.
//! - [`encrypt`] writes a file, as the Go package's `Encrypt`, to
//!   [`X25519Recipient`]s, [`SshEd25519Recipient`]s or a [`ScryptRecipient`],
//!   armored through an [`ArmoredWriter`], byte for byte as age writes it with
//!   the same random bytes.
//! - [`HybridIdentity`] and [`HybridRecipient`] are post-quantum keys,
//!   `AGE-SECRET-KEY-PQ-1…` and `age1pq1…`, which a file cannot mix with others.
//! - [`parse_recipient`] and [`parse_recipients_file`] read what `age -r` and
//!   `age -R` take, [`identities_to_recipients`] what encrypts to the keys of
//!   `age -i`, and [`X25519Identity::generate`] makes a key, as `age-keygen`.
//!
//! The cryptography is hivepack::crypto's, in place of Go's
//! `golang.org/x/crypto`. SSH RSA keys and plugins are not ported yet. How the port follows age, and how it is
//! checked, is in the repository: `docs/age.md`.
//!
//! ```no_run
//! use std::io::Read;
//! use hivepack::age::{Identity, ScryptIdentity, decrypt_file};
//!
//! let file = std::fs::File::open("backup.tar.zst.age")?;
//! let passphrase = ScryptIdentity::new(b"correct horse battery staple")?;
//! let mut plaintext = decrypt_file(file, &[&passphrase as &dyn Identity])?;
//! let mut data = Vec::new();
//! plaintext.read_to_end(&mut data)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```no_run
//! use std::io::Write;
//! use hivepack::age::{Recipient, X25519Recipient, encrypt};
//!
//! let key = X25519Recipient::parse("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")?;
//! let file = std::fs::File::create("notes.txt.age")?;
//! let mut w = encrypt(file, &[&key as &dyn Recipient], None)?;
//! w.write_all(b"the plaintext")?;
//! w.finish()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod age;
mod agessh;
mod armor;
mod base64;
mod bcrypt_pbkdf;
mod bech32;
mod blowfish;
mod error;
mod format;
mod identity_file;
mod parse;
mod pem;
mod pq;
mod primitives;
mod recipient_file;
mod scrypt;
mod ssh_keys;
mod stream;
mod x25519;

use std::io::{self, BufRead, BufReader, Read};

pub use crate::crypto::RandomSource;
pub use age::{
    BoxedRecipient, Decryptor, Encryptor, FileKey, FileKeyIdentity, Identity, Recipient,
    UnwrapError, decrypt, encrypt, identities_to_recipients,
};
pub use agessh::{EncryptedSshIdentity, SshEd25519Identity, SshEd25519Recipient};
pub use armor::{ArmoredReader, ArmoredWriter, FOOTER as ARMOR_FOOTER, HEADER as ARMOR_HEADER};
pub use error::{EncryptError, Error, NoIdentityMatch};
pub use format::Stanza;
pub use identity_file::{
    LazyScryptIdentity, PassphraseFor, PassphrasePrompt, parse_identities_file,
};
pub use parse::{BoxedIdentity, parse_identities};
pub use pq::{HybridIdentity, HybridRecipient};
pub use recipient_file::{Recipients, SkippedKey, parse_recipient, parse_recipients_file};
pub use scrypt::{DEFAULT_MAX_WORK_FACTOR, DEFAULT_WORK_FACTOR, ScryptIdentity, ScryptRecipient};
pub use ssh_keys::{
    Ed25519PrivateKey as SshPrivateKey, KeyError as SshKeyError, parse_ssh_private_key,
    parse_ssh_public_key,
};
pub use x25519::{X25519Identity, X25519Recipient};

/// The age release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.3.2";

/// `crlfMangledIntro`: the intro line after PowerShell's redirection has
/// turned its LF into CRLF, as long as the intro.
const CRLF_MANGLED_INTRO: &[u8] = b"age-encryption.org/v1\r";

/// `utf16MangledIntro`: the intro after PowerShell's redirection has
/// written it as UTF-16, as long as the intro.
const UTF16_MANGLED_INTRO: &[u8] = b"\xff\xfea\x00g\x00e\x00-\x00e\x00n\x00c\x00r\x00y\x00p\x00";

/// The start of a file, read ahead, then the rest.
type Peeked<R> = BufReader<io::Chain<io::Cursor<Vec<u8>>, R>>;

/// A file as [`decrypt_file`] reads it: binary, or armored.
#[derive(Debug)]
pub enum Input<R> {
    /// A binary file.
    Binary(Peeked<R>),
    /// An armored file, decoded.
    Armored(BufReader<ArmoredReader<Peeked<R>>>),
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Input::Binary(r) => r.read(buf),
            Input::Armored(r) => r.read(buf),
        }
    }
}

impl<R: Read> BufRead for Input<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Input::Binary(r) => r.fill_buf(),
            Input::Armored(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Input::Binary(r) => r.consume(amt),
            Input::Armored(r) => r.consume(amt),
        }
    }
}

/// Reads up to `len` bytes of `src`: fewer only at its end.
fn peek<R: Read>(src: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut start = Vec::with_capacity(len);
    src.take(len as u64).read_to_end(&mut start)?;
    Ok(start)
}

/// The age file `src`, decrypted with the first of `identities` that
/// matches, as `age --decrypt` reads it (`decrypt` in `cmd/age/age.go`):
/// an armored file is told apart from a binary one by its first line,
/// after up to 1 KiB of white space, and a file whose intro PowerShell's
/// redirection mangled fails with a message that says so.
pub fn decrypt_file<R: Read>(
    mut src: R,
    identities: &[&dyn Identity],
) -> Result<Decryptor<Input<R>>, Error> {
    let start = peek(&mut src, armor::MAX_WHITESPACE + ARMOR_HEADER.len())?;
    let intro = &start[..start.len().min(CRLF_MANGLED_INTRO.len())];
    if intro == CRLF_MANGLED_INTRO || intro == UTF16_MANGLED_INTRO {
        return Err(Error::Header(
            "invalid header intro: it looks like this file was corrupted by PowerShell \
             redirection"
                .into(),
        ));
    }
    let armored = armor::trim_space_start(&start).starts_with(ARMOR_HEADER.as_bytes());
    let rr = BufReader::new(io::Cursor::new(start).chain(src));
    let input = if armored {
        Input::Armored(BufReader::new(ArmoredReader::new(rr)))
    } else {
        Input::Binary(rr)
    };
    decrypt(input, identities)
}
