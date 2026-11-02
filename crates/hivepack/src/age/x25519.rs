//! age's X25519 keys: port of `x25519.go`.
//!
//! A stanza is `-> X25519 <ephemeral share>`; its body is the file key
//! sealed with a key derived from the shared secret, the share and the
//! recipient's public key.

use std::io;

use crate::crypto::{RandomSource, X25519_LENGTH, system_random, x25519, x25519_base};

use crate::age::age::{
    BoxedRecipient, FILE_KEY_SIZE, FileKey, INCORRECT_IDENTITY, Identity, Recipient, UnwrapError,
    fill, multi_unwrap,
};
use crate::age::bech32;
use crate::age::error::EncryptError;
use crate::age::format::{Stanza, decode_string, encode_to_string};
use crate::age::primitives::{AeadError, aead_decrypt, aead_encrypt, hkdf_32};

/// `x25519Label`.
const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

/// An X25519 public key to encrypt to, `age1…`: `X25519Recipient`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519Recipient {
    their_public_key: [u8; X25519_LENGTH],
}

impl X25519Recipient {
    /// `ParseX25519Recipient`: a key as `age-keygen` shows it, `age1` and
    /// Bech32.
    pub fn parse(s: &str) -> Result<X25519Recipient, String> {
        let (t, k) = bech32::decode(s).map_err(|e| format!("malformed recipient {s:?}: {e}"))?;
        if t != "age" {
            return Err(format!("malformed recipient {s:?}: invalid type {t:?}"));
        }
        let their_public_key = k
            .try_into()
            .map_err(|_| format!("malformed recipient {s:?}: invalid X25519 public key"))?;
        Ok(X25519Recipient { their_public_key })
    }
}

/// `String`: `age1` and Bech32.
impl std::fmt::Display for X25519Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bech32::encode("age", &self.their_public_key).unwrap_or_default())
    }
}

impl Recipient for X25519Recipient {
    /// `Wrap`.
    fn wrap(&self, file_key: &FileKey, random: &RandomSource) -> Result<Vec<Stanza>, EncryptError> {
        let mut ephemeral = [0u8; X25519_LENGTH];
        fill(random, &mut ephemeral)?;
        let our_public_key = x25519_base(&ephemeral);
        let mut shared_secret = x25519(&ephemeral, &self.their_public_key);
        ephemeral.fill(0);
        if shared_secret == [0; X25519_LENGTH] {
            return Err(EncryptError::Recipient(
                "bad input point: low order point".into(),
            ));
        }

        let mut salt = [0u8; 2 * X25519_LENGTH];
        salt[..X25519_LENGTH].copy_from_slice(&our_public_key);
        salt[X25519_LENGTH..].copy_from_slice(&self.their_public_key);
        let mut wrapping_key = hkdf_32(&shared_secret, Some(&salt), X25519_LABEL);
        shared_secret.fill(0);
        let body = aead_encrypt(&wrapping_key, file_key.as_bytes());
        wrapping_key.fill(0);

        Ok(vec![Stanza {
            kind: "X25519".into(),
            args: vec![encode_to_string(&our_public_key)],
            body,
        }])
    }
}

/// An X25519 secret key, `AGE-SECRET-KEY-1…`: `X25519Identity`.
///
/// The secret is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct X25519Identity {
    secret_key: [u8; X25519_LENGTH],
    our_public_key: [u8; X25519_LENGTH],
}

impl X25519Identity {
    /// `newX25519IdentityFromScalar`.
    fn from_scalar(secret_key: &[u8]) -> Result<X25519Identity, String> {
        let secret_key: [u8; X25519_LENGTH] = secret_key
            .try_into()
            .map_err(|_| "invalid X25519 secret key".to_string())?;
        Ok(X25519Identity {
            our_public_key: x25519_base(&secret_key),
            secret_key,
        })
    }

    /// `GenerateX25519Identity`: a new key, with its random bytes from `random`,
    /// or with `None` from the system, which only works on Unix.
    pub fn generate(random: Option<&RandomSource>) -> io::Result<X25519Identity> {
        let mut secret_key = [0u8; X25519_LENGTH];
        match random {
            Some(random) => random(&mut secret_key)?,
            None => system_random(&mut secret_key)?,
        }
        let identity = X25519Identity {
            our_public_key: x25519_base(&secret_key),
            secret_key,
        };
        secret_key.fill(0);
        Ok(identity)
    }

    /// `String`: the secret key as `age-keygen` writes it. The text is not
    /// overwritten when it is dropped: that is for the caller.
    pub fn to_secret_string(&self) -> String {
        bech32::encode("AGE-SECRET-KEY-", &self.secret_key).unwrap_or_default()
    }

    /// What `age-keygen` writes to a file for this key, with `created` as its
    /// date, such as `2026-11-02T10:00:00Z`.
    pub fn to_key_file(&self, created: &str) -> String {
        format!(
            "# created: {created}\n# public key: {}\n{}\n",
            self.recipient(),
            self.to_secret_string()
        )
    }

    /// `Recipient`: what encrypts to this key.
    pub fn to_recipient(&self) -> X25519Recipient {
        X25519Recipient {
            their_public_key: self.our_public_key,
        }
    }

    /// `ParseX25519Identity`: a key as `age-keygen` writes it,
    /// `AGE-SECRET-KEY-1` and Bech32.
    pub fn parse(s: &str) -> Result<X25519Identity, String> {
        let (t, mut k) = bech32::decode(s).map_err(|e| format!("malformed secret key: {e}"))?;
        if t != "AGE-SECRET-KEY-" {
            k.fill(0);
            return Err(format!("malformed secret key: unknown type {t:?}"));
        }
        let identity =
            X25519Identity::from_scalar(&k).map_err(|e| format!("malformed secret key: {e}"));
        k.fill(0);
        identity
    }

    /// `Recipient`: the public key that files are encrypted to, `age1…`.
    pub fn recipient(&self) -> String {
        bech32::encode("age", &self.our_public_key).unwrap_or_default()
    }

    /// `unwrap` of one stanza.
    fn unwrap_one(&self, block: &Stanza) -> Result<FileKey, UnwrapError> {
        if block.kind != "X25519" {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }
        if block.args.len() != 1 {
            return Err(UnwrapError::Invalid(
                "invalid X25519 recipient block".into(),
            ));
        }
        let public_key = decode_string(block.args[0].as_bytes())
            .map_err(|e| UnwrapError::Invalid(format!("failed to parse X25519 recipient: {e}")))?;
        let public_key: [u8; X25519_LENGTH] = public_key
            .try_into()
            .map_err(|_| UnwrapError::Invalid("invalid X25519 recipient block".into()))?;

        let mut shared_secret = x25519(&self.secret_key, &public_key);
        if shared_secret == [0; X25519_LENGTH] {
            return Err(UnwrapError::Invalid(
                "invalid X25519 recipient: bad input point: low order point".into(),
            ));
        }

        let mut salt = [0u8; 2 * X25519_LENGTH];
        salt[..X25519_LENGTH].copy_from_slice(&public_key);
        salt[X25519_LENGTH..].copy_from_slice(&self.our_public_key);
        let mut wrapping_key = hkdf_32(&shared_secret, Some(&salt), X25519_LABEL);
        shared_secret.fill(0);

        let file_key = aead_decrypt(&wrapping_key, FILE_KEY_SIZE, &block.body);
        wrapping_key.fill(0);
        match file_key {
            Ok(file_key) => Ok(FileKey(file_key)),
            Err(AeadError::Size) => Err(UnwrapError::Invalid(
                "invalid X25519 recipient block: incorrect file key size".into(),
            )),
            Err(AeadError::Tag) => Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into())),
        }
    }
}

impl Identity for X25519Identity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        multi_unwrap(|s| self.unwrap_one(s), stanzas)
    }

    fn is_native(&self) -> bool {
        true
    }

    fn recipients(&self) -> Result<Vec<BoxedRecipient>, String> {
        Ok(vec![Box::new(self.to_recipient())])
    }
}

impl Drop for X25519Identity {
    fn drop(&mut self) {
        self.secret_key.fill(0);
        std::hint::black_box(&mut self.secret_key);
    }
}

/// Shows the public key, not the secret.
impl std::fmt::Debug for X25519Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Identity")
            .field("recipient", &self.recipient())
            .finish_non_exhaustive()
    }
}
