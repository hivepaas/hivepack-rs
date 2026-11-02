//! age's post-quantum keys: port of `pq.go`.
//!
//! A stanza is `-> mlkem768x25519 <encapsulated key>`, whose body is the file key
//! sealed with HPKE and X-Wing (ML-KEM-768 with X25519). A file with one has only
//! such recipients, or it would not be safe from a quantum computer.

use std::io;

use crate::crypto::{
    RandomSource, XWING_ENC_LENGTH, XWING_PUBLIC_LENGTH, XWING_SEED_LENGTH, XwingOpenError,
    system_random, xwing_hpke_open, xwing_hpke_seal, xwing_public, xwing_public_is_valid,
};

use crate::age::age::{
    BoxedRecipient, FILE_KEY_SIZE, FileKey, INCORRECT_IDENTITY, Identity, Recipient, UnwrapError,
    multi_unwrap,
};
use crate::age::bech32;
use crate::age::error::EncryptError;
use crate::age::format::{Stanza, decode_string, encode_to_string};

/// `pqLabel`.
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";

/// The tag of the sealed file key.
const TAG_SIZE: usize = 16;

/// A post-quantum public key to encrypt to, `age1pq1…`: `HybridRecipient`. Such a
/// file can only have recipients like it.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridRecipient {
    public: Box<[u8; XWING_PUBLIC_LENGTH]>,
}

impl HybridRecipient {
    /// `ParseHybridRecipient`: a key as `age-keygen -pq` shows it, `age1pq1` and
    /// Bech32.
    pub fn parse(s: &str) -> Result<HybridRecipient, String> {
        // The whole key is 2,000 characters: what the messages show is its start.
        let start: String = s.chars().take(16).collect();
        let (t, k) =
            bech32::decode(s).map_err(|e| format!("malformed recipient {start:?}: {e}"))?;
        if t != "age1pq" {
            return Err(format!("malformed recipient {start:?}: invalid type {t:?}"));
        }
        let invalid =
            || format!("malformed recipient {start:?}: invalid MLKEM768-X25519 public key");
        if !xwing_public_is_valid(&k) {
            return Err(invalid());
        }
        let public: [u8; XWING_PUBLIC_LENGTH] = k.try_into().map_err(|_| invalid())?;
        Ok(HybridRecipient {
            public: Box::new(public),
        })
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_LENGTH] {
        &self.public
    }
}

/// `String`: `age1pq1` and Bech32.
impl std::fmt::Display for HybridRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bech32::encode("age1pq", &self.public[..]).unwrap_or_default())
    }
}

/// Shows the start of the key, of 2,000 characters.
impl std::fmt::Debug for HybridRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = self.to_string();
        f.debug_tuple("HybridRecipient")
            .field(&&text[..text.len().min(16)])
            .finish()
    }
}

impl Recipient for HybridRecipient {
    /// `Wrap`.
    fn wrap(&self, file_key: &FileKey, random: &RandomSource) -> Result<Vec<Stanza>, EncryptError> {
        let (enc, body) = xwing_hpke_seal(
            &self.public[..],
            PQ_LABEL,
            file_key.as_bytes(),
            Some(random),
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidInput {
                EncryptError::Recipient(format!("failed to set up HPKE sender: {e}"))
            } else {
                EncryptError::Random(e)
            }
        })?;
        Ok(vec![Stanza {
            kind: "mlkem768x25519".into(),
            args: vec![encode_to_string(&enc)],
            body,
        }])
    }

    /// `WrapWithLabels`: the label keeps other recipients out, who would defeat its
    /// post-quantum security.
    fn wrap_with_labels(
        &self,
        file_key: &FileKey,
        random: &RandomSource,
    ) -> Result<(Vec<Stanza>, Vec<String>), EncryptError> {
        Ok((self.wrap(file_key, random)?, vec!["postquantum".into()]))
    }
}

/// A post-quantum secret key, `AGE-SECRET-KEY-PQ-1…`: `HybridIdentity`.
///
/// The secret is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct HybridIdentity {
    seed: [u8; XWING_SEED_LENGTH],
    recipient: HybridRecipient,
}

impl HybridIdentity {
    /// `newHybridIdentity`.
    fn from_seed(seed: [u8; XWING_SEED_LENGTH]) -> Result<HybridIdentity, String> {
        let public = xwing_public(&seed).ok_or("invalid MLKEM768-X25519 secret key".to_string())?;
        Ok(HybridIdentity {
            seed,
            recipient: HybridRecipient {
                public: Box::new(public),
            },
        })
    }

    /// `GenerateHybridIdentity`: a new key, with its random bytes from `random`, or
    /// with `None` from the system, which only works on Unix.
    pub fn generate(random: Option<&RandomSource>) -> io::Result<HybridIdentity> {
        let mut seed = [0u8; XWING_SEED_LENGTH];
        match random {
            Some(random) => random(&mut seed)?,
            None => system_random(&mut seed)?,
        }
        let identity = HybridIdentity::from_seed(seed).map_err(io::Error::other);
        seed.fill(0);
        identity
    }

    /// `ParseHybridIdentity`: a key as `age-keygen -pq` writes it,
    /// `AGE-SECRET-KEY-PQ-1` and Bech32.
    pub fn parse(s: &str) -> Result<HybridIdentity, String> {
        let (t, mut k) = bech32::decode(s).map_err(|e| format!("malformed secret key: {e}"))?;
        if t != "AGE-SECRET-KEY-PQ-" {
            k.fill(0);
            return Err(format!("malformed secret key: unknown type {t:?}"));
        }
        let seed: Result<[u8; XWING_SEED_LENGTH], _> = k.as_slice().try_into();
        k.fill(0);
        let mut seed =
            seed.map_err(|_| "malformed secret key: invalid MLKEM768-X25519 secret key")?;
        let identity =
            HybridIdentity::from_seed(seed).map_err(|e| format!("malformed secret key: {e}"));
        seed.fill(0);
        identity
    }

    /// `String`: the secret key as `age-keygen -pq` writes it. The text is not
    /// overwritten when it is dropped: that is for the caller.
    pub fn to_secret_string(&self) -> String {
        bech32::encode("AGE-SECRET-KEY-PQ-", &self.seed).unwrap_or_default()
    }

    /// What `age-keygen -pq` writes to a file for this key, with `created` as its
    /// date, such as `2026-11-02T10:00:00Z`.
    pub fn to_key_file(&self, created: &str) -> String {
        format!(
            "# created: {created}\n# public key: {}\n{}\n",
            self.recipient,
            self.to_secret_string()
        )
    }

    /// `Recipient`: what encrypts to this key.
    pub fn to_recipient(&self) -> HybridRecipient {
        self.recipient.clone()
    }

    /// `unwrap` of one stanza.
    fn unwrap_one(&self, block: &Stanza) -> Result<FileKey, UnwrapError> {
        if block.kind != "mlkem768x25519" {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }
        if block.args.len() != 1 {
            return Err(UnwrapError::Invalid(
                "invalid mlkem768x25519 recipient block".into(),
            ));
        }
        let enc = decode_string(block.args[0].as_bytes()).map_err(|e| {
            UnwrapError::Invalid(format!("failed to parse mlkem768x25519 recipient: {e}"))
        })?;
        if block.body.len() != FILE_KEY_SIZE + TAG_SIZE {
            return Err(UnwrapError::Invalid(
                "invalid mlkem768x25519 recipient block: incorrect file key size".into(),
            ));
        }
        let enc: [u8; XWING_ENC_LENGTH] = enc.try_into().map_err(|_| {
            UnwrapError::Invalid(
                "invalid mlkem768x25519 recipient: invalid encapsulated key".into(),
            )
        })?;
        match xwing_hpke_open(&self.seed, &enc, PQ_LABEL, &block.body) {
            Ok(file_key) => Ok(FileKey(file_key)),
            Err(XwingOpenError::LowOrderPoint) => Err(UnwrapError::Invalid(
                "invalid mlkem768x25519 recipient: bad input point: low order point".into(),
            )),
            Err(XwingOpenError::NoMatch) => Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into())),
        }
    }
}

impl Identity for HybridIdentity {
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

impl Drop for HybridIdentity {
    fn drop(&mut self) {
        self.seed.fill(0);
        std::hint::black_box(&mut self.seed);
    }
}

/// Shows the start of the public key, not the secret.
impl std::fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridIdentity")
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}
