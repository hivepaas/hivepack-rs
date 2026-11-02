//! Keys: Ed25519, read as SSH keeps them, and Ed25519 with ML-DSA-65, in files of
//! this crate's.

use std::fmt;
use std::io::{Read, Write};

use crate::age::{
    ARMOR_HEADER, ArmoredWriter, Error as AgeError, Identity, RandomSource, Recipient,
    ScryptIdentity, ScryptRecipient, SshKeyError, decrypt_file, encrypt, parse_ssh_private_key,
    parse_ssh_public_key,
};
use crate::crypto::{
    ED25519_PUBLIC_LENGTH, ED25519_SEED_LENGTH, MLDSA65_PUBLIC_LENGTH, MLDSA65_SEED_LENGTH, Sha256,
    ed25519_public, mldsa65_public,
};

use crate::sign::base64;
use crate::sign::error::Error;
use crate::sign::signature::Wire;

pub(crate) const ED25519_TYPE: &str = "ssh-ed25519";
/// A name of SSH's form for a type of one's own: `name@domain`.
pub(crate) const HYBRID_TYPE: &str = "mldsa65-ed25519@hivepaas.com";

const KEY_BEGIN: &str = "-----BEGIN HIVEPACK SIGNING KEY-----";
const KEY_END: &str = "-----END HIVEPACK SIGNING KEY-----";

/// A string of the SSH wire format: its length, then its bytes.
pub(crate) fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum PublicKind {
    Ed25519([u8; ED25519_PUBLIC_LENGTH]),
    Hybrid {
        ed25519: [u8; ED25519_PUBLIC_LENGTH],
        mldsa: Box<[u8; MLDSA65_PUBLIC_LENGTH]>,
    },
}

/// A public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(pub(crate) PublicKind);

impl PublicKey {
    /// The key of a line of a `.pub` file or of `authorized_keys`, as
    /// `ssh-ed25519 AAAA… comment`, or as [`PublicKey`]'s `Display` writes a hybrid
    /// key, with or without a comment.
    pub fn parse(line: &[u8]) -> Result<PublicKey, Error> {
        let line = line.trim_ascii();
        let mut words = line.split(|c| c.is_ascii_whitespace());
        if words.next() == Some(HYBRID_TYPE.as_bytes()) {
            let text = words
                .next()
                .ok_or_else(|| Error::PublicKey("no key".into()))?;
            let blob = base64::decode(text).ok_or_else(|| Error::PublicKey("not Base64".into()))?;
            return PublicKey::from_blob(&blob).map_err(|e| Error::PublicKey(e.to_string()));
        }
        match parse_ssh_public_key(line) {
            Ok((_, Some(key))) => Ok(PublicKey(PublicKind::Ed25519(key))),
            Ok((kind, None)) => Err(Error::UnsupportedKey(kind)),
            Err(e) => Err(Error::PublicKey(e.to_string())),
        }
    }

    /// An Ed25519 key itself.
    pub fn from_ed25519(key: [u8; ED25519_PUBLIC_LENGTH]) -> PublicKey {
        PublicKey(PublicKind::Ed25519(key))
    }

    /// The Ed25519 key itself, if this is one rather than a hybrid key.
    pub fn as_ed25519(&self) -> Option<&[u8; ED25519_PUBLIC_LENGTH]> {
        match &self.0 {
            PublicKind::Ed25519(key) => Some(key),
            PublicKind::Hybrid { .. } => None,
        }
    }

    /// Its type, as it is written: `ssh-ed25519` or `mldsa65-ed25519@hivepaas.com`.
    pub fn key_type(&self) -> &'static str {
        match self.0 {
            PublicKind::Ed25519(_) => ED25519_TYPE,
            PublicKind::Hybrid { .. } => HYBRID_TYPE,
        }
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
        put_string(&mut out, self.key_type().as_bytes());
        match &self.0 {
            PublicKind::Ed25519(key) => put_string(&mut out, key),
            PublicKind::Hybrid { ed25519, mldsa } => {
                put_string(&mut out, ed25519);
                put_string(&mut out, &mldsa[..]);
            }
        }
        out
    }

    /// From the SSH wire format.
    pub(crate) fn from_blob(blob: &[u8]) -> Result<PublicKey, Error> {
        let mut wire = Wire(blob);
        let kind = wire.string("no key type")?;
        let key = if kind == ED25519_TYPE.as_bytes() {
            PublicKind::Ed25519(wire.array("no key", "a key of the wrong size")?)
        } else if kind == HYBRID_TYPE.as_bytes() {
            PublicKind::Hybrid {
                ed25519: wire.array("no key", "a key of the wrong size")?,
                mldsa: Box::new(wire.array("no key", "a key of the wrong size")?),
            }
        } else {
            return Err(Error::UnsupportedKey(
                String::from_utf8_lossy(kind).into_owned(),
            ));
        };
        wire.end()?;
        Ok(PublicKey(key))
    }
}

/// As a `.pub` file's line, without a comment.
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.key_type(), base64::encode(&self.blob()))
    }
}

pub(crate) enum PrivateKind {
    Ed25519([u8; ED25519_SEED_LENGTH]),
    Hybrid {
        ed25519: [u8; ED25519_SEED_LENGTH],
        mldsa: [u8; MLDSA65_SEED_LENGTH],
    },
}

/// A private key, cleared when dropped.
pub struct PrivateKey {
    pub(crate) kind: PrivateKind,
    public: PublicKey,
}

impl PrivateKey {
    /// The key of a file: an SSH private key file, as `ssh-keygen -t ed25519` writes
    /// one, or a hybrid key's, as [`PrivateKey::to_file`] writes one. `passphrase` is
    /// used if the key is encrypted, and [`Error::PassphraseNeeded`] asks for one if
    /// it is and there is none.
    ///
    /// An SSH key's file holds the public key beside the private one, and they must
    /// match: a signature made with another public key than its own gives the private
    /// key away, to whoever sees both signatures.
    pub fn parse(file: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey, Error> {
        let text = file.trim_ascii_start();
        if text.starts_with(ARMOR_HEADER.as_bytes()) {
            return PrivateKey::from_encrypted(file, passphrase);
        }
        if text.starts_with(KEY_BEGIN.as_bytes()) {
            return PrivateKey::from_text(text);
        }
        let read = parse_ssh_private_key(file, passphrase).map_err(|e| match e {
            SshKeyError::PassphraseMissing(_) => Error::PassphraseNeeded,
            e => Error::PrivateKey(e),
        })?;
        let mut seed = [0u8; ED25519_SEED_LENGTH];
        seed.copy_from_slice(read.seed());
        let key = PrivateKey::from_seed(seed);
        let PublicKind::Ed25519(public) = &key.public.0 else {
            return Err(Error::KeyMismatch);
        };
        if read.public() != public {
            return Err(Error::KeyMismatch);
        }
        Ok(key)
    }

    /// An Ed25519 key, of a seed of 32 random bytes.
    pub fn from_seed(seed: [u8; ED25519_SEED_LENGTH]) -> PrivateKey {
        PrivateKey {
            public: PublicKey(PublicKind::Ed25519(ed25519_public(&seed))),
            kind: PrivateKind::Ed25519(seed),
        }
    }

    /// A hybrid key, of two seeds of 32 random bytes each.
    pub fn from_hybrid_seeds(
        ed25519: [u8; ED25519_SEED_LENGTH],
        mldsa: [u8; MLDSA65_SEED_LENGTH],
    ) -> PrivateKey {
        PrivateKey {
            public: PublicKey(PublicKind::Hybrid {
                ed25519: ed25519_public(&ed25519),
                mldsa: Box::new(mldsa65_public(&mldsa)),
            }),
            kind: PrivateKind::Hybrid { ed25519, mldsa },
        }
    }

    /// A new hybrid key, of Ed25519 and ML-DSA-65, its seeds from `random`. Signing
    /// with it needs no random bytes.
    pub fn generate_hybrid(random: &RandomSource) -> Result<PrivateKey, Error> {
        let mut ed25519 = [0u8; ED25519_SEED_LENGTH];
        let mut mldsa = [0u8; MLDSA65_SEED_LENGTH];
        random(&mut ed25519).map_err(|e| Error::MakingKey(e.to_string()))?;
        random(&mut mldsa).map_err(|e| Error::MakingKey(e.to_string()))?;
        let key = PrivateKey::from_hybrid_seeds(ed25519, mldsa);
        ed25519.fill(0);
        mldsa.fill(0);
        Ok(key)
    }

    /// A hybrid key as a file for [`PrivateKey::parse`]: with a passphrase, an armored
    /// age file that scrypt opens, which `age --decrypt` opens too. `random` is for
    /// that encryption. An Ed25519 key's file is SSH's: there is none to write here.
    pub fn to_file(
        &self,
        passphrase: Option<&[u8]>,
        random: &RandomSource,
    ) -> Result<Vec<u8>, Error> {
        let PrivateKind::Hybrid { ed25519, mldsa } = &self.kind else {
            return Err(Error::MakingKey(
                "an Ed25519 key's file is written by ssh-keygen".into(),
            ));
        };
        let mut blob = Vec::with_capacity(112);
        put_string(&mut blob, HYBRID_TYPE.as_bytes());
        put_string(&mut blob, ed25519);
        put_string(&mut blob, mldsa);
        let mut text = format!("{KEY_BEGIN}\n{}\n{KEY_END}\n", base64::encode(&blob)).into_bytes();
        blob.fill(0);
        let Some(passphrase) = passphrase else {
            return Ok(text);
        };
        let written = encrypt_text(&text, passphrase, random);
        text.fill(0);
        written.map_err(Error::MakingKey)
    }

    fn from_encrypted(file: &[u8], passphrase: Option<&[u8]>) -> Result<PrivateKey, Error> {
        let passphrase = passphrase.ok_or(Error::PassphraseNeeded)?;
        let identity = ScryptIdentity::new(passphrase).map_err(|_| Error::WrongPassphrase)?;
        let identities: [&dyn Identity; 1] = [&identity];
        let mut reader = decrypt_file(file, &identities).map_err(|e| match e {
            AgeError::NoMatch(_) => Error::WrongPassphrase,

            e => Error::KeyFile(e.to_string()),
        })?;
        let mut text = Vec::new();
        let read = reader.read_to_end(&mut text);
        let key = match read {
            Ok(_) => PrivateKey::from_text(text.trim_ascii()),
            Err(e) => Err(Error::KeyFile(e.to_string())),
        };
        text.fill(0);
        key
    }

    /// A hybrid key's text, without the white space around it.
    fn from_text(text: &[u8]) -> Result<PrivateKey, Error> {
        let bad = |why: &str| Error::KeyFile(why.to_owned());
        let body = text
            .trim_ascii()
            .strip_prefix(KEY_BEGIN.as_bytes())
            .and_then(|rest| rest.strip_suffix(KEY_END.as_bytes()))
            .ok_or_else(|| bad("no armor"))?;
        let mut blob = base64::decode(body.trim_ascii()).ok_or_else(|| bad("not Base64"))?;
        let mut wire = Wire(&blob);
        let parts = (|| {
            if wire.string("no key type")? != HYBRID_TYPE.as_bytes() {
                return Err(Error::Malformed("another type of key"));
            }
            let ed25519: [u8; ED25519_SEED_LENGTH] =
                wire.array("no key", "a seed of the wrong size")?;
            let mldsa: [u8; MLDSA65_SEED_LENGTH] =
                wire.array("no key", "a seed of the wrong size")?;
            wire.end()?;
            Ok((ed25519, mldsa))
        })();
        let key = parts
            .map(|(ed25519, mldsa)| PrivateKey::from_hybrid_seeds(ed25519, mldsa))
            .map_err(|e| Error::KeyFile(e.to_string()));
        blob.fill(0);
        key
    }

    /// Its public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

fn encrypt_text(text: &[u8], passphrase: &[u8], random: &RandomSource) -> Result<Vec<u8>, String> {
    let recipient = ScryptRecipient::new(passphrase)?;
    let recipients: [&dyn Recipient; 1] = [&recipient];
    let armored = ArmoredWriter::new(Vec::new());
    let mut writer = encrypt(armored, &recipients, Some(random)).map_err(|e| e.to_string())?;
    writer.write_all(text).map_err(|e| e.to_string())?;
    let armored = writer.finish().map_err(|e| e.to_string())?;
    armored.finish().map_err(|e| e.to_string())
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        match &mut self.kind {
            PrivateKind::Ed25519(seed) => {
                seed.fill(0);
                std::hint::black_box(seed);
            }
            PrivateKind::Hybrid { ed25519, mldsa } => {
                ed25519.fill(0);
                mldsa.fill(0);
                std::hint::black_box((ed25519, mldsa));
            }
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
