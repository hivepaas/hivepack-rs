//! Against `ssh-keygen`, where there is one: what this crate signs is what it
//! signs, byte for byte, each checks the other's, and of signatures and files
//! damaged at random, this crate takes none that `ssh-keygen` refuses.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack::sign::{Error, FILE_NAMESPACE, PrivateKey, PublicKey, Signature, sign, verify};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-sign-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn has_ssh_keygen() -> bool {
    let found = Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if !found {
        eprintln!("skipping: no ssh-keygen");
    }
    found
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new("ssh-keygen")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A new key, without a passphrase unless one is given.
fn new_key(dir: &Path, name: &str, kind: &str, passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    let out = run(&[
        "-q",
        "-t",
        kind,
        "-N",
        passphrase,
        "-C",
        "test",
        "-f",
        path.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    path
}

/// `ssh-keygen -Y sign` of `file`: what it writes to `<file>.sig`.
fn ssh_sign(key: &Path, namespace: &str, file: &Path, extra: &[&str]) -> Vec<u8> {
    let mut args = vec![
        "-q",
        "-Y",
        "sign",
        "-f",
        key.to_str().unwrap(),
        "-n",
        namespace,
    ];
    args.extend_from_slice(extra);
    args.push(file.to_str().unwrap());
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let sig = PathBuf::from(format!("{}.sig", file.display()));
    let read = fs::read(&sig).unwrap();
    fs::remove_file(&sig).unwrap();
    read
}

/// Whether `ssh-keygen -Y verify` takes a signature of `data`, by `public`.
fn ssh_verifies(dir: &Path, public: &PublicKey, namespace: &str, sig: &[u8], data: &[u8]) -> bool {
    let signers = dir.join("allowed_signers");
    fs::write(&signers, format!("test {public}\n")).unwrap();
    let sig_path = dir.join("checked.sig");
    fs::write(&sig_path, sig).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-q", "-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", "test", "-n", namespace, "-s"])
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // It may stop before it reads all of this.
    let _ = child.stdin.take().unwrap().write_all(data);
    child.wait().unwrap().success()
}

fn data_of(size: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9u32;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn signatures_are_ssh_keygens_byte_for_byte() {
    if !has_ssh_keygen() {
        return;
    }
    let s = Scratch::new();
    let path = new_key(&s.0, "key", "ed25519", "");
    let key = PrivateKey::parse(&fs::read(&path).unwrap(), None).unwrap();
    // Across the hash's block and this crate's buffer.
    for size in [0, 1, 111, 112, 128, 65_535, 65_536, 65_537, 1 << 20] {
        for namespace in [FILE_NAMESPACE, "hivepack", "a@example.com"] {
            let data = data_of(size);
            let file = s.0.join("data");
            fs::write(&file, &data).unwrap();
            let theirs = ssh_sign(&path, namespace, &file, &[]);
            let ours = sign(&key, namespace, &data[..]).unwrap();
            assert_eq!(
                ours.to_armored().as_bytes(),
                theirs,
                "{size} bytes, {namespace}"
            );
            assert_eq!(Signature::parse(&theirs).unwrap(), ours);
            assert!(ssh_verifies(
                &s.0,
                key.public(),
                namespace,
                ours.to_armored().as_bytes(),
                &data
            ));
            verify(&ours, key.public(), namespace, &data[..]).unwrap();
        }
    }
}

#[test]
fn sha256_signatures_are_read() {
    if !has_ssh_keygen() {
        return;
    }
    let s = Scratch::new();
    let path = new_key(&s.0, "key", "ed25519", "");
    let public = PublicKey::parse(&fs::read(s.0.join("key.pub")).unwrap()).unwrap();
    let file = s.0.join("data");
    fs::write(&file, b"some data").unwrap();
    let theirs = ssh_sign(&path, "file", &file, &["-O", "hashalg=sha256"]);
    let signature = Signature::parse(&theirs).unwrap();
    assert_eq!(signature.to_armored().as_bytes(), theirs);
    verify(&signature, &public, "file", &b"some data"[..]).unwrap();
    assert!(matches!(
        verify(&signature, &public, "file", &b"other data"[..]),
        Err(Error::BadSignature)
    ));
}

#[test]
fn keys_read_as_ssh_keygen_writes_them() {
    if !has_ssh_keygen() {
        return;
    }
    let s = Scratch::new();
    let path = new_key(&s.0, "key", "ed25519", "a passphrase");
    let file = fs::read(&path).unwrap();
    assert!(matches!(
        PrivateKey::parse(&file, None),
        Err(Error::PassphraseNeeded)
    ));
    assert!(matches!(
        PrivateKey::parse(&file, Some(b"another")),
        Err(Error::PrivateKey(_))
    ));
    let key = PrivateKey::parse(&file, Some(b"a passphrase")).unwrap();
    let public = PublicKey::parse(&fs::read(s.0.join("key.pub")).unwrap()).unwrap();
    assert_eq!(key.public(), &public);

    let shown = run(&["-l", "-f", s.0.join("key.pub").to_str().unwrap()]);
    let shown = String::from_utf8(shown.stdout).unwrap();
    assert_eq!(shown.split(' ').nth(1), Some(public.fingerprint().as_str()));

    let rsa = new_key(&s.0, "rsa", "rsa", "");
    assert!(PrivateKey::parse(&fs::read(&rsa).unwrap(), None).is_err());
    assert!(matches!(
        PublicKey::parse(&fs::read(s.0.join("rsa.pub")).unwrap()),
        Err(Error::UnsupportedKey(_))
    ));
    let rsa_signature = {
        let data = s.0.join("data");
        fs::write(&data, b"x").unwrap();
        ssh_sign(&rsa, "file", &data, &[])
    };
    assert!(matches!(
        Signature::parse(&rsa_signature),
        Err(Error::UnsupportedKey(_))
    ));
}

/// A byte of the signature's armor or of its bytes, or of the file, changed: what
/// this crate takes `ssh-keygen` takes too, and nothing of a changed file passes
/// either.
#[test]
fn damage_is_taken_by_neither_or_by_ssh_keygen_alone() {
    if !has_ssh_keygen() {
        return;
    }
    let count: u64 = std::env::var("HIVEPACK_SIGN_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(300);
    let s = Scratch::new();
    let path = new_key(&s.0, "key", "ed25519", "");
    let key = PrivateKey::parse(&fs::read(&path).unwrap(), None).unwrap();
    let data = data_of(300);
    let signature = sign(&key, "file", &data[..]).unwrap();
    let blob = signature.to_blob();
    let armored = signature.to_armored().into_bytes();
    let wrap = |blob: &[u8]| -> Vec<u8> {
        let mut text = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
        text.extend_from_slice(encode(blob).as_bytes());
        text.extend_from_slice(b"\n-----END SSH SIGNATURE-----\n");
        text
    };

    let mut x = 0x1234_5678_9abc_def1u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let (mut both, mut neither, mut only_theirs) = (0, 0, 0);
    for i in 0..count {
        let (sig, file) = match i % 3 {
            0 => {
                let mut changed = armored.clone();
                let at = next() as usize % changed.len();
                changed[at] = next() as u8;
                (changed, data.clone())
            }
            1 => {
                let mut changed = blob.clone();
                let at = next() as usize % changed.len();
                changed[at] ^= 1 << (next() % 8);
                (wrap(&changed), data.clone())
            }
            _ => {
                let mut changed = data.clone();
                let at = next() as usize % changed.len();
                changed[at] ^= 1 << (next() % 8);
                (armored.clone(), changed)
            }
        };
        let read = Signature::parse(&sig);
        let ours = read
            .as_ref()
            .is_ok_and(|read| verify(read, key.public(), "file", &file[..]).is_ok());
        // Only white space may differ: one signature has one form here.
        if ours {
            assert_eq!(read.unwrap().to_blob(), blob);
            assert_eq!(file, data);
        }
        let theirs = ssh_verifies(&s.0, key.public(), "file", &sig, &file);
        assert!(
            !ours || theirs,
            "taken here only: {}",
            String::from_utf8_lossy(&sig)
        );
        match (ours, theirs) {
            (true, _) => both += 1,
            (false, false) => neither += 1,
            (false, true) => {
                only_theirs += 1;
                assert_eq!(file, data, "a changed file passed ssh-keygen");
            }
        }
    }
    eprintln!("{both} taken by both, {neither} by neither, {only_theirs} by ssh-keygen alone");
    assert!(neither > count / 2, "{neither} of {count} refused");
}

fn encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(bits >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What `ssh-keygen` takes and this crate does not, each form made without the key
/// from a true signature, and in what way: docs/sign.md lists them.
#[test]
fn stricter_than_ssh_keygen() {
    if !has_ssh_keygen() {
        return;
    }
    let s = Scratch::new();
    let path = new_key(&s.0, "key", "ed25519", "");
    let key = PrivateKey::parse(&fs::read(&path).unwrap(), None).unwrap();
    let data = b"some data";
    let signature = sign(&key, "file", &data[..]).unwrap();
    let blob = signature.to_blob();
    let wrap = |blob: &[u8]| -> Vec<u8> {
        let mut text = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
        text.extend_from_slice(encode(blob).as_bytes());
        text.extend_from_slice(b"\n-----END SSH SIGNATURE-----\n");
        text
    };
    let mut forms: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut version = blob.clone();
    version[9] = 0;
    forms.push(("version 0", wrap(&version)));

    let at = 6 + 4 + (4 + 51) + (4 + 4);
    let mut reserved = blob[..at].to_vec();
    reserved.extend_from_slice(&[0, 0, 0, 1, b'x']);
    reserved.extend_from_slice(&blob[at + 4..]);
    forms.push(("reserved bytes", wrap(&reserved)));

    let mut after = blob.clone();
    after.push(0);
    forms.push(("bytes after the end", wrap(&after)));

    // The signature's S plus the group's order, while it still fits.
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut high_s = blob.clone();
    let start = high_s.len() - 32;
    let mut carry = 0u16;
    for (byte, add) in high_s[start..].iter_mut().zip(ORDER) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    forms.push(("S past the order", wrap(&high_s)));

    let mut text_after = signature.to_armored().into_bytes();
    text_after.extend_from_slice(b"more\n");
    forms.push(("text after the armor", text_after));

    let mut report = Vec::new();
    for (name, form) in &forms {
        let ours = Signature::parse(form)
            .and_then(|read| verify(&read, key.public(), "file", &data[..]))
            .is_ok();
        let theirs = ssh_verifies(&s.0, key.public(), "file", form, data);
        eprintln!("{name}: here {ours}, ssh-keygen {theirs}");
        report.push((*name, ours));
    }
    for (name, ours) in report {
        assert!(!ours, "{name} is taken here");
    }
}
