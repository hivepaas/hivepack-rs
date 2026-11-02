//! Why a file did not decrypt. age's Go code returns errors that tests tell
//! apart by type (`*format.ParseError`, `*age.NoIdentityMatchError`,
//! `*armor.Error`) or by message ("bad header MAC"); here they are the
//! variants of [`Error`], which match the outcomes C2SP's test vectors
//! name: header failure, no match, HMAC failure, armor failure and payload
//! failure.

use std::fmt;
use std::io;

/// Why a file did not decrypt.
#[derive(Debug)]
pub enum Error {
    /// The header did not parse, or a recipient stanza is malformed for its
    /// type, or the payload's nonce is missing: what age's tests call a
    /// header failure. The message is age's.
    Header(String),
    /// The header parsed, but none of the identities unwrapped the file
    /// key from any of its stanzas (`NoIdentityMatchError`).
    NoMatch(NoIdentityMatch),
    /// An identity unwrapped a file key, but the header's MAC does not
    /// match it: the header was changed, or the stanza was made to unwrap
    /// to the wrong key.
    HeaderMac,
    /// The ASCII armor around the file is malformed (`armor.Error`).
    Armor(String),
    /// The payload failed to decrypt and authenticate: it was cut short,
    /// changed, or goes on after its last chunk. What was read before is
    /// authentic.
    Payload(String),
    /// Reading failed.
    Io(io::Error),
}

/// Why a file could not be encrypted.
#[derive(Debug)]
pub enum EncryptError {
    /// There are no recipients, they cannot be mixed, or one could not take
    /// the file key. The message is age's.
    Recipient(String),
    /// The source of random bytes failed. Nothing was written.
    Random(io::Error),
    /// Writing failed.
    Io(io::Error),
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::Recipient(message) => f.write_str(message),
            EncryptError::Random(e) => write!(f, "no random bytes: {e}"),
            EncryptError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for EncryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EncryptError::Recipient(_) => None,
            EncryptError::Random(e) | EncryptError::Io(e) => Some(e),
        }
    }
}

/// None of the identities matched: `NoIdentityMatchError`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoIdentityMatch {
    /// What each identity said, in the order they were tried.
    pub errors: Vec<String>,
    /// The type of each of the header's stanzas, such as `X25519`,
    /// `scrypt` or `ssh-ed25519`, which tells what key the file needs.
    pub stanza_types: Vec<String>,
}

impl fmt::Display for NoIdentityMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.errors[..] {
            [only] => write!(f, "identity did not match any of the recipients: {only}"),
            _ => f.write_str("no identity matched any of the recipients"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Header(message) => f.write_str(message),
            Error::NoMatch(no_match) => no_match.fmt(f),
            Error::HeaderMac => f.write_str("bad header MAC"),
            Error::Armor(message) => write!(f, "invalid armor: {message}"),
            Error::Payload(message) => f.write_str(message),
            Error::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// An error that came through `io::Read`: the armor's and the payload's
/// errors travel inside an `io::Error`, and come out as themselves.
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = error.into_inner()
                && let Ok(error) = inner.downcast::<Error>()
            {
                return *error;
            }
            return Error::Io(io::Error::other("lost error"));
        }
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Io(error) => error,
            error => io::Error::new(io::ErrorKind::InvalidData, error),
        }
    }
}
