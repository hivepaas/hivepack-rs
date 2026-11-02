//! SSH signatures: OpenSSH's `PROTOCOL.sshsig`.

use std::io::{self, Read};

use hivepack_crypto::{
    ED25519_PUBLIC_LENGTH, ED25519_SIGNATURE_LENGTH, Sha256, Sha512, ed25519_sign, ed25519_verify,
};

use crate::base64;
use crate::error::Error;
use crate::key::{KEY_TYPE, PrivateKey, PublicKey, put_string};

/// The namespace for signing files, as `PROTOCOL.sshsig` suggests. A signature for
/// one namespace does not pass for another, so that a key's signatures for one use
/// cannot be taken for another's.
pub const FILE_NAMESPACE: &str = "file";

const MAGIC: &[u8; 6] = b"SSHSIG";
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
    signature: [u8; ED25519_SIGNATURE_LENGTH],
}

/// What is signed: never the file itself, so that a signature cannot be taken for
/// one over something else the key signs.
fn signed_data(namespace: &str, hash: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + namespace.len() + digest.len());
    out.extend_from_slice(MAGIC);
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
    let signature = ed25519_sign(&key.seed, &signed_data(namespace, hash, &digest));
    Ok(Signature {
        public: *key.public(),
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
    let signed = signed_data(namespace, signature.hash, &digest);
    if ed25519_verify(trusted.as_bytes(), &signed, &signature.signature) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

/// Reading the wire format.
struct Wire<'a>(&'a [u8]);

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

    fn string(&mut self, why: &'static str) -> Result<&'a [u8], Error> {
        let length = self.u32(why)?;
        self.take(length as usize, why)
    }

    fn end(&self) -> Result<(), Error> {
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

        let mut key = Wire(wire.string("no public key")?);
        let kind = key.string("no key type")?;
        if kind != KEY_TYPE.as_bytes() {
            return Err(Error::UnsupportedKey(
                String::from_utf8_lossy(kind).into_owned(),
            ));
        }
        let public: [u8; ED25519_PUBLIC_LENGTH] = key
            .string("no key")?
            .try_into()
            .map_err(|_| Error::Malformed("a key of the wrong size"))?;
        key.end()?;

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

        let mut inner = Wire(wire.string("no signature")?);
        wire.end()?;
        let kind = inner.string("no signature type")?;
        if kind != KEY_TYPE.as_bytes() {
            return Err(Error::UnsupportedKey(
                String::from_utf8_lossy(kind).into_owned(),
            ));
        }
        let signature: [u8; ED25519_SIGNATURE_LENGTH] = inner
            .string("no signature bytes")?
            .try_into()
            .map_err(|_| Error::Malformed("a signature of the wrong size"))?;
        inner.end()?;

        Ok(Signature {
            public: PublicKey(public),
            namespace: namespace.to_owned(),
            hash,
            signature,
        })
    }

    /// In the binary form its armor holds.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut inner = Vec::with_capacity(83);
        put_string(&mut inner, KEY_TYPE.as_bytes());
        put_string(&mut inner, &self.signature);
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

    /// In armor, as `ssh-keygen -Y sign` writes it, byte for byte.
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
