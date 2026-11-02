//! SSH signatures: OpenSSH's `PROTOCOL.sshsig`.

use std::io::{self, Read};

use hivepack_crypto::{
    ED25519_SIGNATURE_LENGTH, MLDSA65_SIGNATURE_LENGTH, Sha256, Sha512, ed25519_sign,
    ed25519_verify, mldsa65_sign, mldsa65_verify,
};

use crate::base64;
use crate::error::Error;
use crate::key::{HYBRID_TYPE, PrivateKey, PrivateKind, PublicKey, PublicKind, put_string};

/// The namespace for signing files, as `PROTOCOL.sshsig` suggests. A signature for
/// one namespace does not pass for another, so that a key's signatures for one use
/// cannot be taken for another's.
pub const FILE_NAMESPACE: &str = "file";

const MAGIC: &[u8; 6] = b"SSHSIG";
/// What a hybrid signature's signed data starts with in place of [`MAGIC`], so that
/// neither half can be taken for a signature of another kind: its Ed25519 half for
/// `ssh-keygen`'s, by a key that also signs that way.
const HYBRID_MAGIC: &[u8] = b"hivepack-hybrid-signature-v1";
const VERSION: u32 = 1;
const BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
const END: &[u8] = b"-----END SSH SIGNATURE-----";
/// `ssh-keygen`'s lines of Base64.
const LINE: usize = 70;

/// The hash a signature covers a file by. Signing uses SHA-512, as `ssh-keygen`
/// does by default; both are read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashAlgorithm {
    /// `sha256`.
    Sha256,
    /// `sha512`.
    Sha512,
}

impl HashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    /// The hash of everything `data` gives.
    fn hash<R: Read>(self, mut data: R) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 64 << 10];
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        loop {
            let read = match data.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            match self {
                HashAlgorithm::Sha256 => sha256.update(&buffer[..read]),
                HashAlgorithm::Sha512 => sha512.update(&buffer[..read]),
            }
        }
        Ok(match self {
            HashAlgorithm::Sha256 => sha256.out().to_vec(),
            HashAlgorithm::Sha512 => sha512.out().to_vec(),
        })
    }
}

/// A signature, as it is kept in a `.sig` file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    public: PublicKey,
    namespace: String,
    hash: HashAlgorithm,
    signature: Bytes,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Bytes {
    Ed25519([u8; ED25519_SIGNATURE_LENGTH]),
    Hybrid {
        ed25519: [u8; ED25519_SIGNATURE_LENGTH],
        mldsa: Box<[u8; MLDSA65_SIGNATURE_LENGTH]>,
    },
}

/// What is signed: never the file itself, so that a signature cannot be taken for
/// one over something else the key signs. A hybrid key's also names the key, both
/// halves of it, so that neither half of its signature can stand for another key.
fn signed_data(public: &PublicKey, namespace: &str, hash: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + namespace.len() + digest.len());
    match public.0 {
        PublicKind::Ed25519(_) => out.extend_from_slice(MAGIC),
        PublicKind::Hybrid { .. } => {
            out.extend_from_slice(HYBRID_MAGIC);
            put_string(&mut out, &public.blob());
        }
    }
    put_string(&mut out, namespace.as_bytes());
    // `reserved`, empty when signing and when checking, whatever the file says.
    put_string(&mut out, b"");
    put_string(&mut out, hash.name().as_bytes());
    put_string(&mut out, digest);
    out
}

fn check_namespace(namespace: &str) -> Result<(), Error> {
    if namespace.is_empty() || namespace.contains('\0') {
        return Err(Error::BadNamespace);
    }
    Ok(())
}

/// The signature of everything `data` gives, by `key`, for `namespace`
/// ([`FILE_NAMESPACE`] for a file).
pub fn sign<R: Read>(key: &PrivateKey, namespace: &str, data: R) -> Result<Signature, Error> {
    check_namespace(namespace)?;
    let hash = HashAlgorithm::Sha512;
    let digest = hash.hash(data).map_err(Error::Io)?;
    let signed = signed_data(key.public(), namespace, hash, &digest);
    let signature = match &key.kind {
        PrivateKind::Ed25519(seed) => Bytes::Ed25519(ed25519_sign(seed, &signed)),
        PrivateKind::Hybrid { ed25519, mldsa } => Bytes::Hybrid {
            ed25519: ed25519_sign(ed25519, &signed),
            mldsa: Box::new(
                mldsa65_sign(mldsa, &signed, HYBRID_TYPE.as_bytes()).ok_or(Error::BadNamespace)?,
            ),
        },
    };
    Ok(Signature {
        public: key.public().clone(),
        namespace: namespace.to_owned(),
        hash,
        signature,
    })
}

/// Checks that `signature` is `trusted`'s, for `namespace`, of everything `data`
/// gives. The key must come from somewhere the signature does not: the one it names
/// says only who claims to have signed. The file is read only if the namespace and
/// the key are the ones asked for.
pub fn verify<R: Read>(
    signature: &Signature,
    trusted: &PublicKey,
    namespace: &str,
    data: R,
) -> Result<(), Error> {
    check_namespace(namespace)?;
    if signature.namespace != namespace {
        return Err(Error::WrongNamespace {
            expected: namespace.to_owned(),
            found: signature.namespace.clone(),
        });
    }
    if signature.public != *trusted {
        return Err(Error::WrongKey);
    }
    let digest = signature.hash.hash(data).map_err(Error::Io)?;
    let signed = signed_data(trusted, namespace, signature.hash, &digest);
    let holds = match (&trusted.0, &signature.signature) {
        (PublicKind::Ed25519(key), Bytes::Ed25519(bytes)) => ed25519_verify(key, &signed, bytes),
        // Both, or a break of one would be enough.
        (
            PublicKind::Hybrid { ed25519, mldsa },
            Bytes::Hybrid {
                ed25519: ed25519_bytes,
                mldsa: mldsa_bytes,
            },
        ) => {
            ed25519_verify(ed25519, &signed, ed25519_bytes)
                && mldsa65_verify(mldsa, &signed, HYBRID_TYPE.as_bytes(), mldsa_bytes)
        }
        _ => false,
    };
    if holds {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

/// Reading the wire format.
pub(crate) struct Wire<'a>(pub(crate) &'a [u8]);

impl<'a> Wire<'a> {
    fn take(&mut self, length: usize, why: &'static str) -> Result<&'a [u8], Error> {
        if self.0.len() < length {
            return Err(Error::Malformed(why));
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken)
    }

    fn u32(&mut self, why: &'static str) -> Result<u32, Error> {
        let bytes = self.take(4, why)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn string(&mut self, why: &'static str) -> Result<&'a [u8], Error> {
        let length = self.u32(why)?;
        self.take(length as usize, why)
    }

    /// A string of exactly `N` bytes.
    pub(crate) fn array<const N: usize>(
        &mut self,
        why: &'static str,
        size: &'static str,
    ) -> Result<[u8; N], Error> {
        self.string(why)?
            .try_into()
            .map_err(|_| Error::Malformed(size))
    }

    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("bytes after the end"))
        }
    }
}

impl Signature {
    /// A signature in the armor of a `.sig` file.
    pub fn parse(armored: &[u8]) -> Result<Signature, Error> {
        let text = armored.trim_ascii();
        let body = text
            .strip_prefix(BEGIN)
            .and_then(|rest| rest.strip_suffix(END))
            .ok_or(Error::NotArmored)?;
        let compact: Vec<u8> = body
            .iter()
            .copied()
            .filter(|c| !matches!(c, b'\n' | b'\r'))
            .collect();
        let blob = base64::decode(&compact).ok_or(Error::Malformed("the armor is not Base64"))?;
        Signature::from_blob(&blob)
    }

    /// A signature in the binary form its armor holds.
    pub fn from_blob(blob: &[u8]) -> Result<Signature, Error> {
        let mut wire = Wire(blob);
        if wire.take(MAGIC.len(), "no magic")? != MAGIC {
            return Err(Error::Malformed("no magic"));
        }
        let version = wire.u32("no version")?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let public = PublicKey::from_blob(wire.string("no public key")?)?;

        let namespace = wire.string("no namespace")?;
        let namespace = std::str::from_utf8(namespace)
            .map_err(|_| Error::Malformed("a namespace that is not UTF-8"))?;
        check_namespace(namespace)?;
        // Not covered by what is signed: anything but empty could be changed
        // without the signature showing it.
        if !wire.string("nothing reserved")?.is_empty() {
            return Err(Error::Malformed("reserved bytes"));
        }
        let hash = match wire.string("no hash")? {
            b"sha256" => HashAlgorithm::Sha256,
            b"sha512" => HashAlgorithm::Sha512,
            other => {
                return Err(Error::UnsupportedHash(
                    String::from_utf8_lossy(other).into_owned(),
                ));
            }
        };

        // Hybrid signatures have no past to read: one hash, one form.
        if hash != HashAlgorithm::Sha512 && matches!(public.0, PublicKind::Hybrid { .. }) {
            return Err(Error::UnsupportedHash(hash.name().to_owned()));
        }

        let mut inner = Wire(wire.string("no signature")?);
        wire.end()?;
        let kind = inner.string("no signature type")?;
        if kind != public.key_type().as_bytes() {
            return Err(Error::UnsupportedKey(
                String::from_utf8_lossy(kind).into_owned(),
            ));
        }
        let size = "a signature of the wrong size";
        let signature = match public.0 {
            PublicKind::Ed25519(_) => Bytes::Ed25519(inner.array("no signature bytes", size)?),
            PublicKind::Hybrid { .. } => Bytes::Hybrid {
                ed25519: inner.array("no signature bytes", size)?,
                mldsa: Box::new(inner.array("no signature bytes", size)?),
            },
        };
        inner.end()?;

        Ok(Signature {
            public,
            namespace: namespace.to_owned(),
            hash,
            signature,
        })
    }

    /// In the binary form its armor holds.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut inner = Vec::with_capacity(83);
        put_string(&mut inner, self.public.key_type().as_bytes());
        match &self.signature {
            Bytes::Ed25519(bytes) => put_string(&mut inner, bytes),
            Bytes::Hybrid { ed25519, mldsa } => {
                put_string(&mut inner, ed25519);
                put_string(&mut inner, &mldsa[..]);
            }
        }
        let mut out = Vec::with_capacity(160 + self.namespace.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        put_string(&mut out, &self.public.blob());
        put_string(&mut out, self.namespace.as_bytes());
        put_string(&mut out, b"");
        put_string(&mut out, self.hash.name().as_bytes());
        put_string(&mut out, &inner);
        out
    }

    /// In armor, as `ssh-keygen -Y sign` writes it, byte for byte, for an Ed25519 key.
    pub fn to_armored(&self) -> String {
        let text = base64::encode(&self.to_blob());
        let mut out = String::with_capacity(text.len() + 80);
        out.push_str("-----BEGIN SSH SIGNATURE-----\n");
        for line in text.as_bytes().chunks(LINE) {
            out.push_str(&String::from_utf8_lossy(line));
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }

    /// The key it names. This says who claims to have signed, not who did: only
    /// [`verify`], against a key from elsewhere, shows that.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// What it is for.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The hash it covers the file by.
    pub fn hash(&self) -> HashAlgorithm {
        self.hash
    }
}
