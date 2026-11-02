//! Ed25519 keys, read as SSH keeps them.

use std::fmt;

use hivepack_age::{SshKeyError, parse_ssh_private_key, parse_ssh_public_key};
use hivepack_crypto::{ED25519_PUBLIC_LENGTH, ED25519_SEED_LENGTH, Sha256, ed25519_public};

use crate::base64;
use crate::error::Error;

pub(crate) const KEY_TYPE: &str = "ssh-ed25519";

/// A string of the SSH wire format: its length, then its bytes.
pub(crate) fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub(crate) [u8; ED25519_PUBLIC_LENGTH]);

impl PublicKey {
    /// The key of a line of an `.pub` file or of `authorized_keys`:
    /// `ssh-ed25519 AAAA… comment`.
    pub fn parse(line: &[u8]) -> Result<PublicKey, Error> {
        match parse_ssh_public_key(line) {
            Ok((_, Some(key))) => Ok(PublicKey(key)),
            Ok((kind, None)) => Err(Error::UnsupportedKey(kind)),
            Err(e) => Err(Error::PublicKey(e.to_string())),
        }
    }

    /// The key itself.
    pub fn from_bytes(key: [u8; ED25519_PUBLIC_LENGTH]) -> PublicKey {
        PublicKey(key)
    }

    /// The key itself.
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_LENGTH] {
        &self.0
    }

    /// As `ssh-keygen -l` shows it: `SHA256:`, then Base64 without padding.
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(&self.blob());
        let text = base64::encode(&hash.out());
        format!("SHA256:{}", text.trim_end_matches('='))
    }

    /// In the SSH wire format.
    pub(crate) fn blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(51);
        put_string(&mut out, KEY_TYPE.as_bytes());
        put_string(&mut out, &self.0);
        out
    }
}

/// As a `.pub` file's line, without a comment.
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{KEY_TYPE} {}", base64::encode(&self.blob()))
    }
}

/// An Ed25519 private key, cleared when dropped.
pub struct PrivateKey {
    pub(crate) seed: [u8; ED25519_SEED_LENGTH],
    public: PublicKey,
}

impl PrivateKey {
    /// The key of an SSH private key file, as `ssh-keygen -t ed25519` writes one.
    /// `passphrase` is used if the key is encrypted, and [`Error::PassphraseNeeded`]
    /// asks for one if it is and there is none.
    ///
    /// The file holds the public key beside the private one, and they must match:
    /// a signature made with another public key than its own gives the private key
    /// away, to whoever sees both signatures.
    pub fn parse(file: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey, Error> {
        let read = parse_ssh_private_key(file, passphrase).map_err(|e| match e {
            SshKeyError::PassphraseMissing(_) => Error::PassphraseNeeded,
            e => Error::PrivateKey(e),
        })?;
        let mut seed = [0u8; ED25519_SEED_LENGTH];
        seed.copy_from_slice(read.seed());
        let key = PrivateKey::from_seed(seed);
        if read.public() != key.public.0 {
            return Err(Error::KeyMismatch);
        }
        Ok(key)
    }

    /// The key of a seed of 32 random bytes.
    pub fn from_seed(seed: [u8; ED25519_SEED_LENGTH]) -> PrivateKey {
        PrivateKey {
            public: PublicKey(ed25519_public(&seed)),
            seed,
        }
    }

    /// Its public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.seed.fill(0);
        std::hint::black_box(&mut self.seed);
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
