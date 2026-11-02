//! SSH keys: port of `agessh/agessh.go` and `agessh/encrypted_keys.go`, for
//! Ed25519.
//!
//! A stanza is `-> ssh-ed25519 <fingerprint> <ephemeral share>`: the
//! fingerprint is the first four bytes of the SHA-256 of the public key in
//! SSH's wire format, so that a key that is not the recipient is passed
//! over without any work. The Ed25519 key becomes an X25519 key, the
//! SHA-512 of its seed, and the shared secret is tweaked with a scalar
//! derived from the public key.
//!
//! Differs from age: no `ssh-rsa`, whose keys are refused as not supported
//! yet.

use std::sync::{Arc, Mutex, PoisonError};

use crate::crypto::{
    RandomSource, Sha256, Sha512, X25519_LENGTH, ed25519_public_to_x25519, x25519, x25519_base,
};

use crate::age::age::{
    BoxedRecipient, FileKey, INCORRECT_IDENTITY, Identity, Recipient, UnwrapError, fill,
    multi_unwrap,
};
use crate::age::error::EncryptError;
use crate::age::format::{Stanza, encode_to_string};
use crate::age::primitives::{AeadError, aead_decrypt, aead_encrypt, hkdf_32};
use crate::age::ssh_keys::{
    Ed25519PrivateKey, KEY_ALGO_ED25519, KeyError, marshal_ed25519, parse_authorized_key,
    parse_public_key, parse_raw_private_key, parse_raw_private_key_with_passphrase,
};

/// `ed25519Label`.
const ED25519_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";

/// What asks the person for a passphrase, when one is needed: the
/// passphrase, or why there is none.
pub type PassphraseFn = Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>;

/// `sshFingerprint`: the first four bytes of the SHA-256 of the public key
/// in the wire format, in base64.
fn ssh_fingerprint(ssh_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(ssh_key);
    encode_to_string(&h.out()[..4])
}

/// An SSH Ed25519 public key to encrypt to: `Ed25519Recipient`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshEd25519Recipient {
    ssh_key: Vec<u8>,
    their_public_key: [u8; X25519_LENGTH],
}

impl SshEd25519Recipient {
    /// `ParseRecipient`: a key as an `authorized_keys` line has it, such as
    /// `ssh-ed25519 AAAA… me@host`.
    ///
    /// Differs from age: `ssh-rsa` keys are refused as not supported yet.
    pub fn parse(s: &str) -> Result<SshEd25519Recipient, String> {
        let malformed = |e: &dyn std::fmt::Display| format!("malformed SSH recipient: {s:?}: {e}");
        let key = parse_authorized_key(s.as_bytes()).map_err(|e| malformed(&e))?;
        match key.ed25519 {
            Some(public) => Self::new(&public).map_err(|e| malformed(&e)),
            None if key.kind == "ssh-rsa" => Err("ssh-rsa keys are not supported yet".into()),
            None => Err(format!("unknown SSH recipient type: {:?}", key.kind)),
        }
    }

    /// `NewEd25519Recipient`.
    fn new(public: &[u8; 32]) -> Result<SshEd25519Recipient, String> {
        let their_public_key = ed25519_public_to_x25519(public)
            .ok_or("invalid Ed25519 public key: edwards25519: invalid point encoding")?;
        Ok(SshEd25519Recipient {
            ssh_key: marshal_ed25519(public),
            their_public_key,
        })
    }
}

/// The key as an `authorized_keys` line has it, without a comment.
impl std::fmt::Display for SshEd25519Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{KEY_ALGO_ED25519} {}",
            crate::age::base64::encode_padded(&self.ssh_key)
        )
    }
}

impl Recipient for SshEd25519Recipient {
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

        let mut tweak = hkdf_32(&[], Some(&self.ssh_key), ED25519_LABEL);
        let mut tweaked = x25519(&tweak, &shared_secret);
        tweak.fill(0);
        shared_secret.fill(0);
        // age drops the error of an all-zero result, which leaves the shared
        // secret empty; it cannot happen for a point that passed the check above.
        let ikm: &[u8] = if tweaked == [0; X25519_LENGTH] {
            &[]
        } else {
            &tweaked
        };

        let mut salt = [0u8; 2 * X25519_LENGTH];
        salt[..X25519_LENGTH].copy_from_slice(&our_public_key);
        salt[X25519_LENGTH..].copy_from_slice(&self.their_public_key);
        let mut wrapping_key = hkdf_32(ikm, Some(&salt), ED25519_LABEL);
        tweaked.fill(0);
        let body = aead_encrypt(&wrapping_key, file_key.as_bytes());
        wrapping_key.fill(0);

        Ok(vec![Stanza {
            kind: KEY_ALGO_ED25519.into(),
            args: vec![
                ssh_fingerprint(&self.ssh_key),
                encode_to_string(&our_public_key),
            ],
            body,
        }])
    }
}

/// An SSH Ed25519 private key: `Ed25519Identity`.
///
/// The secret is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct SshEd25519Identity {
    secret_key: [u8; X25519_LENGTH],
    our_public_key: [u8; X25519_LENGTH],
    ssh_key: Vec<u8>,
}

impl SshEd25519Identity {
    /// `NewEd25519Identity`: the key's public half is the one the private
    /// key holds, as Go's `ed25519.PrivateKey.Public` takes it.
    fn new(key: &Ed25519PrivateKey) -> SshEd25519Identity {
        let mut public = [0u8; 32];
        public.copy_from_slice(&key.0[32..]);
        // `ed25519PrivateKeyToCurve25519`: the SHA-512 of the seed, the
        // first half; X25519 clamps it.
        let mut h = Sha512::new();
        h.update(&key.0[..32]);
        let mut out = h.out();
        let mut secret_key = [0u8; X25519_LENGTH];
        secret_key.copy_from_slice(&out[..X25519_LENGTH]);
        out.fill(0);
        SshEd25519Identity {
            our_public_key: x25519_base(&secret_key),
            secret_key,
            ssh_key: marshal_ed25519(&public),
        }
    }

    /// `unwrap` of one stanza.
    fn unwrap_one(&self, block: &Stanza) -> Result<FileKey, UnwrapError> {
        if block.kind != KEY_ALGO_ED25519 {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }
        if block.args.len() != 2 {
            return Err(UnwrapError::Invalid(
                "invalid ssh-ed25519 recipient block".into(),
            ));
        }
        let public_key =
            crate::age::format::decode_string(block.args[1].as_bytes()).map_err(|e| {
                UnwrapError::Invalid(format!("failed to parse ssh-ed25519 recipient: {e}"))
            })?;
        let public_key: [u8; X25519_LENGTH] = public_key
            .try_into()
            .map_err(|_| UnwrapError::Invalid("invalid ssh-ed25519 recipient block".into()))?;
        if block.args[0] != ssh_fingerprint(&self.ssh_key) {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }

        let mut shared_secret = x25519(&self.secret_key, &public_key);
        if shared_secret == [0; X25519_LENGTH] {
            return Err(UnwrapError::Invalid(
                "invalid X25519 recipient: bad input point: low order point".into(),
            ));
        }
        let mut tweak = hkdf_32(&[], Some(&self.ssh_key), ED25519_LABEL);
        let mut tweaked = x25519(&tweak, &shared_secret);
        tweak.fill(0);
        shared_secret.fill(0);
        // age drops the error of an all-zero result, which leaves the
        // shared secret empty; it cannot happen for a share that passed
        // the check above.
        let ikm: &[u8] = if tweaked == [0; X25519_LENGTH] {
            &[]
        } else {
            &tweaked
        };

        let mut salt = [0u8; 2 * X25519_LENGTH];
        salt[..X25519_LENGTH].copy_from_slice(&public_key);
        salt[X25519_LENGTH..].copy_from_slice(&self.our_public_key);
        let mut wrapping_key = hkdf_32(ikm, Some(&salt), ED25519_LABEL);
        tweaked.fill(0);

        // agessh's own `aeadDecrypt`, which takes a file key of any length.
        let size = block.body.len().saturating_sub(16);
        let file_key = aead_decrypt(&wrapping_key, size, &block.body);
        wrapping_key.fill(0);
        match file_key {
            Ok(file_key) => Ok(FileKey(file_key)),
            Err(AeadError::Size | AeadError::Tag) => {
                Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()))
            }
        }
    }
}

impl Identity for SshEd25519Identity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        multi_unwrap(|s| self.unwrap_one(s), stanzas)
    }

    /// `Recipient`.
    fn recipients(&self) -> Result<Vec<BoxedRecipient>, String> {
        Ok(vec![Box::new(SshEd25519Recipient {
            ssh_key: self.ssh_key.clone(),
            their_public_key: self.our_public_key,
        })])
    }
}

impl Drop for SshEd25519Identity {
    fn drop(&mut self) {
        self.secret_key.fill(0);
        std::hint::black_box(&mut self.secret_key);
    }
}

/// Shows the fingerprint, not the secret.
impl std::fmt::Debug for SshEd25519Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshEd25519Identity")
            .field("fingerprint", &ssh_fingerprint(&self.ssh_key))
            .finish_non_exhaustive()
    }
}

/// An SSH key protected by a passphrase: `EncryptedSSHIdentity`. The
/// passphrase is asked for only when a stanza is for this key, which its
/// fingerprint tells, and the key is decrypted once.
pub struct EncryptedSshIdentity {
    pub_key: Vec<u8>,
    recipient: SshEd25519Recipient,
    pem_bytes: Vec<u8>,
    passphrase: PassphraseFn,
    decrypted: Mutex<Option<SshEd25519Identity>>,
}

impl EncryptedSshIdentity {
    /// `NewEncryptedSSHIdentity`: the key `pem_bytes`, whose public key
    /// `pub_key` is in the wire format.
    fn new(
        pub_key: Vec<u8>,
        pem_bytes: &[u8],
        passphrase: PassphraseFn,
    ) -> Result<EncryptedSshIdentity, String> {
        let (kind, public) = parse_public_key(&pub_key).map_err(|e| e.to_string())?;
        let Some(public) = public else {
            if kind == "ssh-rsa" {
                return Err("ssh-rsa keys are not supported yet".into());
            }
            return Err(format!("unsupported SSH key type: {kind}"));
        };
        Ok(EncryptedSshIdentity {
            pub_key,
            recipient: SshEd25519Recipient::new(&public)?,
            pem_bytes: pem_bytes.to_vec(),
            passphrase,
            decrypted: Mutex::new(None),
        })
    }
}

impl Identity for EncryptedSshIdentity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError> {
        let mut decrypted = self
            .decrypted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(identity) = &*decrypted {
            return identity.unwrap(stanzas);
        }
        let fingerprint = ssh_fingerprint(&self.pub_key);
        let mut matched = false;
        for s in stanzas {
            if s.kind != KEY_ALGO_ED25519 {
                continue;
            }
            if s.args.is_empty() {
                return Err(UnwrapError::Invalid(
                    "invalid ssh-ed25519 recipient block".into(),
                ));
            }
            if s.args[0] != fingerprint {
                continue;
            }
            matched = true;
            break;
        }
        if !matched {
            return Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()));
        }

        let mut passphrase = (self.passphrase)()
            .map_err(|e| UnwrapError::Invalid(format!("failed to obtain passphrase: {e}")))?;
        let key = parse_raw_private_key_with_passphrase(&self.pem_bytes, &passphrase);
        passphrase.fill(0);
        let key =
            key.map_err(|e| UnwrapError::Invalid(format!("failed to decrypt SSH key file: {e}")))?;
        let identity = SshEd25519Identity::new(&key);
        if identity.ssh_key != self.pub_key {
            return Err(UnwrapError::Invalid(
                "mismatched private and public SSH key".into(),
            ));
        }
        let result = identity.unwrap(stanzas);
        *decrypted = Some(identity);
        result
    }

    /// `Recipient`: no passphrase is needed for it.
    fn recipients(&self) -> Result<Vec<BoxedRecipient>, String> {
        Ok(vec![Box::new(self.recipient.clone())])
    }
}

impl Drop for EncryptedSshIdentity {
    fn drop(&mut self) {
        self.pem_bytes.fill(0);
        std::hint::black_box(&mut self.pem_bytes);
    }
}

/// Shows the fingerprint, not the key.
impl std::fmt::Debug for EncryptedSshIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSshIdentity")
            .field("fingerprint", &ssh_fingerprint(&self.pub_key))
            .finish_non_exhaustive()
    }
}

/// An identity from an SSH private key file.
pub(crate) enum SshIdentity {
    Plain(SshEd25519Identity),
    Encrypted(EncryptedSshIdentity),
}

/// `ParseIdentity`, and what `parseSSHIdentity` in `cmd/age/parse.go` does
/// with a key that needs a passphrase: an [`EncryptedSshIdentity`] that
/// asks `passphrase` when it is needed.
pub(crate) fn parse_identity(
    pem_bytes: &[u8],
    passphrase: PassphraseFn,
) -> Result<SshIdentity, String> {
    match parse_raw_private_key(pem_bytes) {
        Ok(key) => Ok(SshIdentity::Plain(SshEd25519Identity::new(&key))),
        Err(KeyError::PassphraseMissing(Some(pub_key))) => Ok(SshIdentity::Encrypted(
            EncryptedSshIdentity::new(pub_key, pem_bytes, passphrase)?,
        )),
        // age reads the public key from the `.pub` file next to the key
        // then; only the old PEM formats lack it, which the port does not
        // read.
        Err(KeyError::PassphraseMissing(None)) => Err(
            "encrypted PEM keys are not supported yet; convert the key to a modern format with \
             \"ssh-keygen -p -m RFC4716\""
                .into(),
        ),
        Err(e) => Err(format!("malformed SSH identity: {e}")),
    }
}
