//! What this crate checks wherever it runs: signatures `ssh-keygen` made, what is
//! refused and why, and a private key whose two halves do not match.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io;

use hivepack_sign::{
    Error, FILE_NAMESPACE, HashAlgorithm, PrivateKey, PublicKey, Signature, sign, verify,
};

// A key made for these tests with `ssh-keygen -t ed25519`, used for nothing else,
// and what `ssh-keygen -Y sign -n file` made of MESSAGE.
const SEED: &str = "87ed78be163c0bf23afe7122afff9357fba2ec4927bcb03d54b9c477eb805e6e";
const PUBLIC: &[u8] =
    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDlTKisMspbylYInenWA8QwXizIlxCs5eT50FbHj3K/f vector\n";
const FINGERPRINT: &str = "SHA256:Upad8YEHqjP4CMCtieq+CT5a7YDWCzPf9LrVbRRe05c";
const MESSAGE: &[u8] = b"signed by ssh-keygen\n";
const SHA512: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgOVMqKwyylvKVgid6dYDxDBeLMi
XEKzl5PnQVsePcr98AAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEB/hQVC5vF2jBdR/vV5ZFNXLeeFEiPnz3XzhpXtudx5X6Ob/Js2S5fmg3Yc0hlZoQ
OWzQIn2ZplGuMwNJ50bWYC
-----END SSH SIGNATURE-----
";
const SHA256: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgOVMqKwyylvKVgid6dYDxDBeLMi
XEKzl5PnQVsePcr98AAAAEZmlsZQAAAAAAAAAGc2hhMjU2AAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEAgzl34qhw9wnZR+qNlKYRJhEa2/j0k+jHikeanIH7lwg+cVWKKGRDJaxugpdwYFd
uxHUYBQPn1wAvPrbXEHpsF
-----END SSH SIGNATURE-----
";

fn key() -> PrivateKey {
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&SEED[2 * i..2 * i + 2], 16).unwrap();
    }
    PrivateKey::from_seed(seed)
}

fn ed25519_of(key: &PublicKey) -> [u8; 32] {
    *key.as_ed25519().unwrap()
}

fn public() -> PublicKey {
    PublicKey::parse(PUBLIC).unwrap()
}

#[test]
fn signs_as_ssh_keygen_signed() {
    let signature = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap();
    assert_eq!(signature.to_armored(), SHA512);
    assert_eq!(signature.hash(), HashAlgorithm::Sha512);
    assert_eq!(signature.namespace(), "file");
    assert_eq!(key().public(), &public());
    assert_eq!(public().fingerprint(), FINGERPRINT);
    assert_eq!(
        public().to_string().as_bytes(),
        PUBLIC.strip_suffix(b" vector\n").unwrap()
    );
}

#[test]
fn checks_what_ssh_keygen_signed() {
    for (armored, hash) in [
        (SHA512, HashAlgorithm::Sha512),
        (SHA256, HashAlgorithm::Sha256),
    ] {
        let read = Signature::parse(armored.as_bytes()).unwrap();
        assert_eq!(read.hash(), hash);
        assert_eq!(read.to_armored(), armored);
        assert_eq!(read.public_key(), &public());
        verify(&read, &public(), FILE_NAMESPACE, MESSAGE).unwrap();
        let error = verify(&read, &public(), FILE_NAMESPACE, &b"changed"[..]).unwrap_err();
        assert!(error.is_forged(), "{error}");
    }
}

#[test]
fn a_signature_is_for_one_key_and_one_use() {
    let signature = Signature::parse(SHA512.as_bytes()).unwrap();
    let other = PrivateKey::from_seed([1; 32]);
    assert!(matches!(
        verify(&signature, other.public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::WrongKey)
    ));
    assert!(matches!(
        verify(&signature, &public(), "email", MESSAGE),
        Err(Error::WrongNamespace { .. })
    ));
    // Signed by another key that names this one: the signature must still hold.
    let mut blob = sign(&other, FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    let named = ed25519_of(&public());
    let at = blob
        .windows(32)
        .position(|w| w == ed25519_of(other.public()))
        .unwrap();
    blob[at..at + 32].copy_from_slice(&named);
    let forged = Signature::from_blob(&blob).unwrap();
    assert_eq!(forged.public_key(), &public());
    assert!(matches!(
        verify(&forged, &public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::BadSignature)
    ));
}

/// A file is not read when the signature cannot be for it, and an error reading it
/// is not a signature that fails.
#[test]
fn reading_the_file() {
    struct Fails;
    impl io::Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("no"))
        }
    }
    let signature = Signature::parse(SHA512.as_bytes()).unwrap();
    assert!(matches!(
        verify(&signature, &public(), FILE_NAMESPACE, Fails),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        verify(&signature, &public(), "email", Fails),
        Err(Error::WrongNamespace { .. })
    ));
    assert!(matches!(
        verify(&signature, key().public(), FILE_NAMESPACE, Fails),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        sign(&key(), FILE_NAMESPACE, Fails),
        Err(Error::Io(_))
    ));
}

#[test]
fn namespaces_that_cannot_be() {
    for namespace in ["", "a\0b"] {
        assert!(matches!(
            sign(&key(), namespace, MESSAGE),
            Err(Error::BadNamespace)
        ));
    }
}

/// Fields the signature does not cover, which `ssh-keygen` lets pass: here one
/// signature has one form.
#[test]
fn what_nothing_signs_is_not_left_to_change() {
    let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    // The version.
    let mut changed = blob.clone();
    changed[9] = 0;
    assert!(matches!(
        Signature::from_blob(&changed),
        Err(Error::UnsupportedVersion(0))
    ));
    // Reserved bytes: after the magic, the version, the key and the namespace.
    let at = 6 + 4 + (4 + 51) + (4 + 4);
    let mut changed = blob[..at].to_vec();
    changed.extend_from_slice(&[0, 0, 0, 1, b'x']);
    changed.extend_from_slice(&blob[at + 4..]);
    assert!(matches!(
        Signature::from_blob(&changed),
        Err(Error::Malformed("reserved bytes"))
    ));
    // Bytes after the end.
    let mut changed = blob.clone();
    changed.push(0);
    assert!(matches!(
        Signature::from_blob(&changed),
        Err(Error::Malformed("bytes after the end"))
    ));
}

#[test]
fn what_is_not_a_signature() {
    for text in [
        &b""[..],
        b"not a signature",
        b"-----BEGIN SSH SIGNATURE-----\n",
        b"-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\nmore",
    ] {
        assert!(matches!(Signature::parse(text), Err(Error::NotArmored)));
    }
    assert!(matches!(
        Signature::parse(b"-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        Signature::parse(b"-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----"),
        Err(Error::Malformed("no magic"))
    ));
    // Every length of a true signature, cut.
    let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    for end in 0..blob.len() {
        assert!(Signature::from_blob(&blob[..end]).is_err(), "{end}");
    }
}

/// An unencrypted key file, its public key as given.
fn key_file(seed: &[u8; 32], public: &[u8; 32]) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }
    let mut blob = Vec::new();
    string(&mut blob, b"ssh-ed25519");
    string(&mut blob, public);

    let mut private = vec![1, 2, 3, 4, 1, 2, 3, 4];
    string(&mut private, b"ssh-ed25519");
    string(&mut private, public);
    let mut both = seed.to_vec();
    both.extend_from_slice(public);
    string(&mut private, &both);
    string(&mut private, b"");
    let mut pad = 1;
    while !private.len().is_multiple_of(8) {
        private.push(pad);
        pad += 1;
    }

    let mut file = b"openssh-key-v1\0".to_vec();
    string(&mut file, b"none");
    string(&mut file, b"none");
    string(&mut file, b"");
    file.extend_from_slice(&1u32.to_be_bytes());
    string(&mut file, &blob);
    string(&mut file, &private);

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in file.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                text.push(ALPHABET[(bits >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                text.push('=');
            }
        }
    }
    format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{text}\n-----END OPENSSH PRIVATE KEY-----\n")
        .into_bytes()
}

/// Signing with a public key other than the seed's gives the private key away.
#[test]
fn a_key_whose_halves_do_not_match_is_refused() {
    let seed = [3u8; 32];
    let own = ed25519_of(PrivateKey::from_seed(seed).public());
    let read = PrivateKey::parse(&key_file(&seed, &own), None).unwrap();
    assert_eq!(ed25519_of(read.public()), own);
    // A passphrase is not asked of a key that has none, nor used.
    PrivateKey::parse(&key_file(&seed, &own), Some(b"unused")).unwrap();

    let other = ed25519_of(PrivateKey::from_seed([4; 32]).public());
    assert!(matches!(
        PrivateKey::parse(&key_file(&seed, &other), None),
        Err(Error::KeyMismatch)
    ));
}

#[test]
fn a_private_key_is_not_printed() {
    let shown = format!("{:?}", key());
    assert!(!shown.contains("seed"), "{shown}");
}

/// A signature's blob from its parts, each as given.
fn blob_of(key: &[u8], signature: &[u8]) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }
    let mut blob = b"SSHSIG\0\0\0\x01".to_vec();
    string(&mut blob, key);
    string(&mut blob, b"file");
    string(&mut blob, b"");
    string(&mut blob, b"sha512");
    string(&mut blob, signature);
    blob
}

fn typed(bytes: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut out = 11u32.to_be_bytes().to_vec();
    out.extend_from_slice(b"ssh-ed25519");
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(extra);
    out
}

#[test]
fn bytes_after_the_end_of_what_is_inside() {
    let (key, signature) = ([9u8; 32], [8u8; 64]);
    assert!(Signature::from_blob(&blob_of(&typed(&key, b""), &typed(&signature, b""))).is_ok());
    for blob in [
        blob_of(&typed(&key, b"x"), &typed(&signature, b"")),
        blob_of(&typed(&key, b""), &typed(&signature, b"x")),
    ] {
        assert!(matches!(
            Signature::from_blob(&blob),
            Err(Error::Malformed("bytes after the end"))
        ));
    }
}

/// The key of small order, with which `R` and `S` that hold for any message can be
/// made without a private key.
#[test]
fn a_key_of_small_order_signs_nothing() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut signature = [0u8; 64];
    signature[0] = 1;
    let read = Signature::from_blob(&blob_of(&typed(&identity, b""), &typed(&signature, b"")));
    let read = read.unwrap();
    let public = PublicKey::from_ed25519(identity);
    assert!(matches!(
        verify(&read, &public, FILE_NAMESPACE, MESSAGE),
        Err(Error::BadSignature)
    ));
}

/// Line ends in the armor, as a mail or Windows may leave them, and nothing else.
#[test]
fn only_line_ends_inside_the_armor() {
    let crlf = SHA512.replace('\n', "\r\n");
    assert_eq!(
        Signature::parse(crlf.as_bytes()).unwrap(),
        Signature::parse(SHA512.as_bytes()).unwrap()
    );
    let spaced = SHA512.replace("OQAAAEB", "OQAA AEB");
    assert!(matches!(
        Signature::parse(spaced.as_bytes()),
        Err(Error::Malformed(_))
    ));
}

/// A read that is interrupted goes on.
#[test]
fn an_interrupted_read_is_not_an_error() {
    struct Interrupted<'a>(&'a [u8], bool);
    impl io::Read for Interrupted<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.1 = !self.1;
            if self.1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            io::Read::read(&mut self.0, buffer)
        }
    }
    let read = Signature::parse(SHA512.as_bytes()).unwrap();
    verify(
        &read,
        &public(),
        FILE_NAMESPACE,
        Interrupted(MESSAGE, false),
    )
    .unwrap();
}
