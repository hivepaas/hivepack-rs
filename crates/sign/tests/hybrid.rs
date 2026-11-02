//! Hybrid keys of Ed25519 and ML-DSA-65: the format rebuilt by hand, each half
//! checked apart from this crate's check, either half alone not enough, and key files.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::sync::Arc;

use hivepack_age::{Identity, RandomSource, ScryptIdentity, decrypt_file};
use hivepack_crypto::{Sha512, ed25519_public, ed25519_verify, mldsa65_public, mldsa65_verify};
use hivepack_sign::{Error, FILE_NAMESPACE, PrivateKey, PublicKey, Signature, sign, verify};

const TYPE: &[u8] = b"mldsa65-ed25519@hivepaas.com";
const MESSAGE: &[u8] = b"a file";
const ED: [u8; 32] = [11; 32];
const ML: [u8; 32] = [22; 32];

fn key() -> PrivateKey {
    PrivateKey::from_hybrid_seeds(ED, ML)
}

fn counting_random() -> RandomSource {
    let next = std::sync::atomic::AtomicU8::new(1);
    Arc::new(move |bytes: &mut [u8]| {
        bytes.fill(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        Ok(())
    })
}

fn string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// The public key's and the signature's bytes, by hand, from docs/sign.md.
fn public_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    string(&mut blob, TYPE);
    string(&mut blob, &ed25519_public(&ED));
    string(&mut blob, &mldsa65_public(&ML));
    blob
}

fn signed_by_hand() -> Vec<u8> {
    let mut digest = Sha512::new();
    digest.update(MESSAGE);
    let mut signed = b"hivepack-hybrid-signature-v1".to_vec();
    string(&mut signed, &public_blob());
    string(&mut signed, b"file");
    string(&mut signed, b"");
    string(&mut signed, b"sha512");
    string(&mut signed, &digest.out());
    signed
}

/// The two halves of a signature's bytes, at the end of its blob.
fn halves(blob: &[u8]) -> ([u8; 64], [u8; 3309]) {
    let mldsa = &blob[blob.len() - 3309..];
    let ed25519 = &blob[blob.len() - 3309 - 4 - 64..blob.len() - 3309 - 4];
    (ed25519.try_into().unwrap(), mldsa.try_into().unwrap())
}

#[test]
fn each_half_holds_apart_from_this_crate() {
    let signature = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap();
    let blob = signature.to_blob();
    let (ed25519, mldsa) = halves(&blob);
    let signed = signed_by_hand();
    assert!(ed25519_verify(&ed25519_public(&ED), &signed, &ed25519));
    assert!(mldsa65_verify(&mldsa65_public(&ML), &signed, TYPE, &mldsa));

    let mut expected = b"SSHSIG\0\0\0\x01".to_vec();
    string(&mut expected, &public_blob());
    string(&mut expected, b"file");
    string(&mut expected, b"");
    string(&mut expected, b"sha512");
    let mut inner = Vec::new();
    string(&mut inner, TYPE);
    string(&mut inner, &ed25519);
    string(&mut inner, &mldsa);
    string(&mut expected, &inner);
    assert_eq!(blob, expected);

    assert_eq!(
        Signature::parse(signature.to_armored().as_bytes()).unwrap(),
        signature
    );
    verify(&signature, key().public(), FILE_NAMESPACE, MESSAGE).unwrap();
    assert_eq!(sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap(), signature);
}

#[test]
fn neither_half_alone_is_enough() {
    let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    let mldsa_at = blob.len() - 3309;
    let ed25519_at = mldsa_at - 4 - 64;
    for at in [ed25519_at, ed25519_at + 63, mldsa_at, blob.len() - 1] {
        let mut changed = blob.clone();
        changed[at] ^= 1;
        let read = Signature::from_blob(&changed).unwrap();
        assert!(
            matches!(
                verify(&read, key().public(), FILE_NAMESPACE, MESSAGE),
                Err(Error::BadSignature)
            ),
            "{at}"
        );
    }
    assert!(matches!(
        verify(
            &Signature::from_blob(&blob).unwrap(),
            key().public(),
            FILE_NAMESPACE,
            &b"another"[..]
        ),
        Err(Error::BadSignature)
    ));
}

/// The same halves, under a key that shares one half with this one.
#[test]
fn a_half_does_not_stand_for_another_key() {
    let other = PrivateKey::from_hybrid_seeds(ED, [33; 32]);
    let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    let mut moved = Vec::from(&blob[..10]);
    let mut key_blob = Vec::new();
    string(&mut key_blob, TYPE);
    string(&mut key_blob, &ed25519_public(&ED));
    string(&mut key_blob, &mldsa65_public(&[33; 32]));
    string(&mut moved, &key_blob);
    moved.extend_from_slice(&blob[10 + 4 + public_blob().len()..]);
    let read = Signature::from_blob(&moved).unwrap();
    assert_eq!(read.public_key(), other.public());
    assert!(matches!(
        verify(&read, other.public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::BadSignature)
    ));
}

/// The Ed25519 half under the Ed25519 key alone: the signed data differs, so it is
/// no signature of that key's.
#[test]
fn the_ed25519_half_is_no_ssh_signature() {
    let hybrid = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    let (ed25519, _) = halves(&hybrid);
    let plain = PrivateKey::from_seed(ED);
    let mut blob = sign(&plain, FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    let at = blob.len() - 64;
    blob[at..].copy_from_slice(&ed25519);
    let read = Signature::from_blob(&blob).unwrap();
    assert!(matches!(
        verify(&read, plain.public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::BadSignature)
    ));

    #[cfg(unix)]
    if let Some(taken) = oracle::ssh_verifies(plain.public(), &read.to_armored(), MESSAGE) {
        assert!(!taken, "ssh-keygen took the half");
    }
}

#[test]
fn another_kind_of_key_does_not_check_it() {
    let hybrid = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap();
    let plain = PrivateKey::from_seed(ED);
    assert!(matches!(
        verify(&hybrid, plain.public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::WrongKey)
    ));
    let signature = sign(&plain, FILE_NAMESPACE, MESSAGE).unwrap();
    assert!(matches!(
        verify(&signature, key().public(), FILE_NAMESPACE, MESSAGE),
        Err(Error::WrongKey)
    ));
}

#[test]
fn what_a_hybrid_signature_cannot_be() {
    let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
    for end in 0..blob.len() {
        assert!(Signature::from_blob(&blob[..end]).is_err(), "{end}");
    }
    let mut longer = blob.clone();
    longer.push(0);
    assert!(Signature::from_blob(&longer).is_err());

    // SHA-256 is read only for what `ssh-keygen` writes.
    let at = blob.windows(6).position(|w| w == b"sha512").unwrap();
    let mut sha256 = blob.clone();
    sha256[at..at + 6].copy_from_slice(b"sha256");
    assert!(matches!(
        Signature::from_blob(&sha256),
        Err(Error::UnsupportedHash(_))
    ));

    // The signature's type must be the key's.
    let mut other_type = blob.clone();
    let at = other_type.len() - 3309 - 4 - 64 - 4 - TYPE.len();
    other_type[at] ^= 1;
    assert!(matches!(
        Signature::from_blob(&other_type),
        Err(Error::UnsupportedKey(_))
    ));
}

#[test]
fn public_keys_as_lines() {
    let line = key().public().to_string();
    assert!(
        line.starts_with("mldsa65-ed25519@hivepaas.com AAAA"),
        "{line}"
    );
    assert_eq!(&PublicKey::parse(line.as_bytes()).unwrap(), key().public());
    let commented = format!("{line} someone@example.com\n");
    assert_eq!(
        &PublicKey::parse(commented.as_bytes()).unwrap(),
        key().public()
    );
    assert_eq!(key().public().key_type(), "mldsa65-ed25519@hivepaas.com");
    assert!(key().public().as_ed25519().is_none());
    assert!(key().public().fingerprint().starts_with("SHA256:"));
    assert!(matches!(
        PublicKey::parse(b"mldsa65-ed25519@hivepaas.com"),
        Err(Error::PublicKey(_))
    ));
    assert!(matches!(
        PublicKey::parse(b"mldsa65-ed25519@hivepaas.com !!!!"),
        Err(Error::PublicKey(_))
    ));
}

#[test]
fn key_files() {
    let random = counting_random();
    let made = PrivateKey::generate_hybrid(&random).unwrap();
    // Each half with seeds of its own.
    assert_eq!(
        made.public(),
        PrivateKey::from_hybrid_seeds([1; 32], [2; 32]).public()
    );
    let another = PrivateKey::generate_hybrid(&random).unwrap();
    assert_ne!(made.public(), another.public());

    let plain = made.to_file(None, &random).unwrap();
    let read = PrivateKey::parse(&plain, None).unwrap();
    assert_eq!(read.public(), made.public());
    // A passphrase for a file that has none is not used.
    PrivateKey::parse(&plain, Some(b"unused")).unwrap();

    let encrypted = made.to_file(Some(b"a passphrase"), &random).unwrap();
    assert!(encrypted.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(matches!(
        PrivateKey::parse(&encrypted, None),
        Err(Error::PassphraseNeeded)
    ));
    assert!(matches!(
        PrivateKey::parse(&encrypted, Some(b"another")),
        Err(Error::WrongPassphrase)
    ));
    assert!(matches!(
        PrivateKey::parse(&encrypted, Some(b"")),
        Err(Error::WrongPassphrase)
    ));
    let read = PrivateKey::parse(&encrypted, Some(b"a passphrase")).unwrap();
    assert_eq!(read.public(), made.public());
    let signature = sign(&read, FILE_NAMESPACE, MESSAGE).unwrap();
    verify(&signature, made.public(), FILE_NAMESPACE, MESSAGE).unwrap();

    // An age file, as docs/sign.md says, whose text is the plain key's file.
    let identity = ScryptIdentity::new(b"a passphrase").unwrap();
    let identities: [&dyn Identity; 1] = [&identity];
    let mut text = Vec::new();
    decrypt_file(&encrypted[..], &identities)
        .unwrap()
        .read_to_end(&mut text)
        .unwrap();
    assert_eq!(text, plain);

    assert!(matches!(
        PrivateKey::from_seed(ED).to_file(None, &random),
        Err(Error::MakingKey(_))
    ));
}

#[test]
fn key_files_that_are_not() {
    let random = counting_random();
    let plain = key().to_file(None, &random).unwrap();
    let text = String::from_utf8(plain).unwrap();
    let begin = "-----BEGIN HIVEPACK SIGNING KEY-----";
    let end = "-----END HIVEPACK SIGNING KEY-----";
    for bad in [
        format!("{begin}\n"),
        format!("{begin}\n!!!!\n{end}\n"),
        format!("{begin}\n{end}\n"),
        format!("{begin}\nZm9v\n{end}\n"),
        text.replace(end, "-----END SOMETHING-----"),
    ] {
        assert!(
            matches!(
                PrivateKey::parse(bad.as_bytes(), None),
                Err(Error::KeyFile(_))
            ),
            "{bad}"
        );
    }
    let failing: RandomSource = Arc::new(|_: &mut [u8]| Err(std::io::Error::other("none")));
    assert!(matches!(
        PrivateKey::generate_hybrid(&failing),
        Err(Error::MakingKey(_))
    ));
    assert!(matches!(
        key().to_file(Some(b"x"), &failing),
        Err(Error::MakingKey(_))
    ));
    // Seeds are not printed.
    assert!(!format!("{:?}", key()).contains("seed"));
}

#[cfg(unix)]
mod oracle {
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::*;

    /// Whether `ssh-keygen -Y verify` takes a signature, if there is one.
    pub fn ssh_verifies(public: &PublicKey, armored: &str, data: &[u8]) -> Option<bool> {
        Command::new("ssh-keygen")
            .arg("-?")
            .stderr(Stdio::null())
            .status()
            .ok()?;
        let dir = std::env::temp_dir().join(format!(
            "hivepack-sign-hybrid-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let signers = dir.join("allowed");
        fs::write(&signers, format!("test {public}\n")).unwrap();
        let sig = dir.join("sig");
        fs::write(&sig, armored).unwrap();
        let mut child = Command::new("ssh-keygen")
            .args(["-q", "-Y", "verify", "-f"])
            .arg(&signers)
            .args(["-I", "test", "-n", "file", "-s"])
            .arg(&sig)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(data);
        let taken = child.wait().unwrap().success();
        let _ = fs::remove_dir_all(&dir);
        Some(taken)
    }

    #[test]
    fn ssh_keygen_refuses_the_type() {
        let signature = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap();
        if let Some(taken) = ssh_verifies(key().public(), &signature.to_armored(), MESSAGE) {
            assert!(!taken);
        }
    }

    /// The ML-DSA half, by OpenSSL, where it has ML-DSA.
    #[test]
    fn openssl_checks_the_mldsa_half() {
        let has = Command::new("openssl")
            .args(["list", "-signature-algorithms"])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("ML-DSA-65"));
        if !has {
            eprintln!("skipping: no OpenSSL with ML-DSA");
            return;
        }
        let dir = std::env::temp_dir().join(format!("hivepack-sign-ossl-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        let hex = |data: &[u8]| data.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let out = Command::new("openssl")
            .args(["genpkey", "-algorithm", "ML-DSA-65", "-pkeyopt"])
            .arg(format!("hexseed:{}", hex(&ML)))
            .args(["-out", &path("key.pem")])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let blob = sign(&key(), FILE_NAMESPACE, MESSAGE).unwrap().to_blob();
        fs::write(path("signed"), signed_by_hand()).unwrap();
        fs::write(path("sig"), &blob[blob.len() - 3309..]).unwrap();
        let out = Command::new("openssl")
            .args(["pkeyutl", "-verify", "-rawin", "-inkey", &path("key.pem")])
            .args(["-in", &path("signed"), "-sigfile", &path("sig"), "-pkeyopt"])
            .arg(format!("hexcontext-string:{}", hex(TYPE)))
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert!(out.status.success(), "{out:?}");
    }
}
