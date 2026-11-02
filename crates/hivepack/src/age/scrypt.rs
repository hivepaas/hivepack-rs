//! Passphrases: port of `scrypt.go`.
//!
//! A stanza is `-> scrypt <salt> <work factor>`; its body is the file key
//! sealed with a key that scrypt derives from the passphrase, with N =
//! 2^(work factor), r = 8 and p = 1. Such a stanza must be the file's only
//! one.

use crate::crypto::{RandomSource, scrypt};

use crate::age::age::{
    FILE_KEY_SIZE, FileKey, INCORRECT_IDENTITY, Identity, Recipient, UnwrapError, fill,
};
use crate::age::error::EncryptError;
use crate::age::format::{Stanza, decode_string, encode_to_string};
use crate::age::primitives::{AeadError, aead_decrypt, aead_encrypt};

/// `scryptLabel`.
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";

/// `scryptSaltSize`.
const SCRYPT_SALT_SIZE: usize = 16;

/// The work factor `NewScryptIdentity` allows: 2^22, which takes 4 GiB of
/// memory and about 5 seconds on a Ryzen 9 9950X ("15s on a modern
/// machine", age says).
pub const DEFAULT_MAX_WORK_FACTOR: u8 = 22;

/// The work factor a passphrase is encrypted with by default: 2^18, which takes
/// 256 MiB of memory and about 0.3 seconds on a Ryzen 9 9950X.
pub const DEFAULT_WORK_FACTOR: u8 = 18;

/// A passphrase to encrypt with: `ScryptRecipient`. It must be a file's only
/// recipient.
///
/// The passphrase is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct ScryptRecipient {
    password: Vec<u8>,
    work_factor: u8,
}

impl ScryptRecipient {
    /// `NewScryptRecipient`: a recipient for `password`, which cannot be empty,
    /// with the work factor [`DEFAULT_WORK_FACTOR`].
    pub fn new(password: &[u8]) -> Result<ScryptRecipient, String> {
        if password.is_empty() {
            return Err("passphrase can't be empty".into());
        }
        Ok(ScryptRecipient {
            password: password.to_vec(),
            work_factor: DEFAULT_WORK_FACTOR,
        })
    }

    /// `SetWorkFactor`: each step doubles the time and the memory, to encrypt
    /// and to decrypt. Differs from age, which panics: a value out of 1 to 30
    /// is brought into the range.
    pub fn set_work_factor(&mut self, log_n: u8) {
        self.work_factor = log_n.clamp(1, 30);
    }
}

impl Recipient for ScryptRecipient {
    /// `Wrap`.
    fn wrap(&self, file_key: &FileKey, random: &RandomSource) -> Result<Vec<Stanza>, EncryptError> {
        let mut salt = [0u8; SCRYPT_SALT_SIZE];
        fill(random, &mut salt)?;
        let log_n = self.work_factor;

        let mut full_salt = SCRYPT_LABEL.to_vec();
        full_salt.extend_from_slice(&salt);
        let mut k = [0u8; 32];
        // log_n is from 1 to 30, with r = 8 and p = 1, which scrypt takes; it
        // can still fail to find the memory.
        scrypt(&self.password, &full_salt, log_n, 8, 1, &mut k)
            .map_err(|e| EncryptError::Recipient(format!("failed to generate scrypt hash: {e}")))?;
        let body = aead_encrypt(&k, file_key.as_bytes());
        k.fill(0);

        Ok(vec![Stanza {
            kind: "scrypt".into(),
            args: vec![encode_to_string(&salt), log_n.to_string()],
            body,
        }])
    }

    /// `WrapWithLabels`: a random label, which no other recipient has, so that
    /// a passphrase is a file's only recipient.
    fn wrap_with_labels(
        &self,
        file_key: &FileKey,
        random: &RandomSource,
    ) -> Result<(Vec<Stanza>, Vec<String>), EncryptError> {
        let stanzas = self.wrap(file_key, random)?;
        let mut label = [0u8; 16];
        fill(random, &mut label)?;
        let label = label.iter().map(|b| format!("{b:02x}")).collect();
        Ok((stanzas, vec![label]))
    }
}

impl Drop for ScryptRecipient {
    fn drop(&mut self) {
        self.password.fill(0);
        std::hint::black_box(&mut self.password);
    }
}

/// Shows the work factor, not the passphrase.
impl std::fmt::Debug for ScryptRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScryptRecipient")
            .field("work_factor", &self.work_factor)
            .finish_non_exhaustive()
    }
}

/// A passphrase: `ScryptIdentity`.
///
/// The passphrase is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct ScryptIdentity {
    password: Vec<u8>,
    max_work_factor: u8,
}

impl ScryptIdentity {
    /// `NewScryptIdentity`: an identity for `password`, which cannot be
    /// empty, allowing work factors up to [`DEFAULT_MAX_WORK_FACTOR`].
    pub fn new(password: &[u8]) -> Result<ScryptIdentity, String> {
        if password.is_empty() {
            return Err("passphrase can't be empty".into());
        }
        Ok(ScryptIdentity {
            password: password.to_vec(),
            max_work_factor: DEFAULT_MAX_WORK_FACTOR,
        })
    }

    /// `SetMaxWorkFactor`: the largest work factor to accept, from 1 to 30.
    /// A file that asks for more fails without the work being done: each
    /// step up doubles both the time and the memory, 1 GiB at 20.
    ///
    /// Differs from age, which panics for a value out of range: here it is
    /// brought into the range.
    pub fn set_max_work_factor(&mut self, log_n: u8) {
        self.max_work_factor = log_n.clamp(1, 30);
    }

    /// `unwrap` of the scrypt stanza.
    fn unwrap_one(&self, block: &Stanza) -> Result<FileKey, UnwrapError> {
        if block.args.len() != 2 {
            return Err(UnwrapError::Invalid(
                "invalid scrypt recipient block".into(),
            ));
        }
        let salt = decode_string(block.args[0].as_bytes())
            .map_err(|e| UnwrapError::Invalid(format!("failed to parse scrypt salt: {e}")))?;
        if salt.len() != SCRYPT_SALT_SIZE {
            return Err(UnwrapError::Invalid(
                "invalid scrypt recipient block".into(),
            ));
        }
        // `^[1-9][0-9]*$`: decimal, without a sign or leading zeros.
        let w = block.args[1].as_bytes();
        if w.first().is_none_or(|c| !(b'1'..=b'9').contains(c)) || !w.iter().all(u8::is_ascii_digit)
        {
            return Err(UnwrapError::Invalid(format!(
                "scrypt work factor encoding invalid: {:?}",
                block.args[1]
            )));
        }
        // Go's Atoi takes up to 64 bits; more is an error.
        let log_n = block.args[1].parse::<i64>().map_err(|_| {
            UnwrapError::Invalid(format!(
                "failed to parse scrypt work factor: strconv.Atoi: parsing {:?}: value out of range",
                block.args[1]
            ))
        })?;
        if log_n > i64::from(self.max_work_factor) {
            return Err(UnwrapError::Invalid(format!(
                "scrypt work factor too large: {log_n}"
            )));
        }

        let mut full_salt = SCRYPT_LABEL.to_vec();
        full_salt.extend_from_slice(&salt);
        let mut k = [0u8; 32];
        // log_n is from 1 to 30 here, with r = 8 and p = 1, which scrypt
        // takes; it can still fail to find the memory.
        scrypt(&self.password, &full_salt, log_n as u8, 8, 1, &mut k)
            .map_err(|e| UnwrapError::Invalid(format!("failed to generate scrypt hash: {e}")))?;

        let file_key = aead_decrypt(&k, FILE_KEY_SIZE, &block.body);
        k.fill(0);
        match file_key {
            Ok(file_key) => Ok(FileKey(file_key)),
            Err(AeadError::Size) => Err(UnwrapError::Invalid(
                "invalid scrypt recipient block: incorrect file key size".into(),
            )),
            Err(AeadError::Tag) => Err(UnwrapError::Incorrect(format!(
                "{INCORRECT_IDENTITY}: incorrect passphrase"
            ))),
        }
    }
}

impl Identity for ScryptIdentity {
    /// `Unwrap`: an scrypt stanza must be the only one.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        if stanzas.len() != 1 && stanzas.iter().any(|s| s.kind == "scrypt") {
            return Err(UnwrapError::Invalid(
                "an scrypt recipient must be the only one".into(),
            ));
        }
        match stanzas.iter().find(|s| s.kind == "scrypt") {
            Some(s) => self.unwrap_one(s),
            None => Err(UnwrapError::Incorrect(format!(
                "{INCORRECT_IDENTITY}: file is not passphrase-encrypted"
            ))),
        }
    }

    fn is_native(&self) -> bool {
        true
    }
}

impl Drop for ScryptIdentity {
    fn drop(&mut self) {
        self.password.fill(0);
        std::hint::black_box(&mut self.password);
    }
}

/// Shows nothing of the passphrase.
impl std::fmt::Debug for ScryptIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScryptIdentity")
            .field("max_work_factor", &self.max_work_factor)
            .finish_non_exhaustive()
    }
}
