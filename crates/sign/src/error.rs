//! Why a key or a signature was not taken.

use std::fmt;
use std::io;

use hivepack_age::SshKeyError;

/// Why signing or checking stopped. [`Error::is_forged`] tells a file that fails
/// its signature from a signature that could not be read.
#[derive(Debug)]
pub enum Error {
    /// The private key is encrypted, and no passphrase was given.
    PassphraseNeeded,
    /// The private key file could not be read, or the passphrase is wrong.
    PrivateKey(SshKeyError),
    /// The private key file's public key is not its private key's.
    KeyMismatch,
    /// The public key's line could not be read.
    PublicKey(String),
    /// A key of a type other than Ed25519.
    UnsupportedKey(String),
    /// No namespace, or one that a signature cannot hold.
    BadNamespace,
    /// The text is not an armored signature.
    NotArmored,
    /// The signature does not read as the format says, for this reason.
    Malformed(&'static str),
    /// A version of the format other than 1.
    UnsupportedVersion(u32),
    /// A hash other than SHA-256 and SHA-512.
    UnsupportedHash(String),
    /// The signature is for something else: another use of the key.
    WrongNamespace {
        /// The namespace that was asked for.
        expected: String,
        /// The one the signature has.
        found: String,
    },
    /// The signature is by another key than the one trusted.
    WrongKey,
    /// The file is not what was signed, or the signature was changed.
    BadSignature,
    /// The file could not be read.
    Io(io::Error),
}

impl Error {
    /// Whether the signature read and names the key trusted, but does not match
    /// the file.
    pub fn is_forged(&self) -> bool {
        matches!(self, Error::BadSignature)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PassphraseNeeded => f.write_str("the private key needs a passphrase"),
            Error::PrivateKey(e) => write!(f, "private key: {e}"),
            Error::KeyMismatch => {
                f.write_str("the private key file's public key is not its private key's")
            }
            Error::PublicKey(e) => write!(f, "public key: {e}"),
            Error::UnsupportedKey(kind) => write!(f, "keys of type {kind:?} are not supported"),
            Error::BadNamespace => f.write_str("a namespace cannot be empty or hold a NUL"),
            Error::NotArmored => f.write_str("not an armored SSH signature"),
            Error::Malformed(why) => write!(f, "malformed signature: {why}"),
            Error::UnsupportedVersion(version) => {
                write!(
                    f,
                    "version {version} of the signature format is not supported"
                )
            }
            Error::UnsupportedHash(hash) => write!(f, "hash {hash:?} is not supported"),
            Error::WrongNamespace { expected, found } => {
                write!(f, "the signature is for {found:?}, not {expected:?}")
            }
            Error::WrongKey => f.write_str("the signature is by another key"),
            Error::BadSignature => f.write_str("the signature does not match the file"),
            Error::Io(e) => write!(f, "reading the file: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}
