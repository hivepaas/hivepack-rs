//! ML-DSA-65 against OpenSSL 3.5's, where there is one, and against what it gave.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hivepack::crypto::{
    MLDSA65_PUBLIC_LENGTH, MLDSA65_SIGNATURE_LENGTH, Sha256, mldsa65_public, mldsa65_sign,
    mldsa65_verify,
};

fn sha256_hex(data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.out().iter().map(|b| format!("{b:02x}")).collect()
}

// What `openssl genpkey -algorithm ML-DSA-65 -pkeyopt hexseed:0707…` and
// `openssl pkeyutl -sign -rawin -pkeyopt deterministic:1 -pkeyopt hexcontext-string:616263`
// gave for the message `msg`.
const PUBLIC_SHA256: &str = "d3a1e51ecf491b79ca7691bd269271f8d8e8d94313a6abcc6c8ae8bc34b5f9aa";
const SIGNATURE_SHA256: &str = "5111f2c7f0744426b1263b56a4c24ba93f95b56297297370b6c2c34548a26b3e";

#[test]
fn as_openssl_gave() {
    let seed = [7u8; 32];
    let public = mldsa65_public(&seed);
    assert_eq!(sha256_hex(&public), PUBLIC_SHA256);
    let signature = mldsa65_sign(&seed, b"msg", b"abc").unwrap();
    assert_eq!(sha256_hex(&signature), SIGNATURE_SHA256);
    assert!(mldsa65_verify(&public, b"msg", b"abc", &signature));
    assert!(!mldsa65_verify(&public, b"msG", b"abc", &signature));
    assert!(!mldsa65_verify(&public, b"msg", b"abd", &signature));
    assert!(!mldsa65_verify(&public, b"msg", b"", &signature));
}

#[test]
fn context_of_255_bytes_at_most() {
    let seed = [1u8; 32];
    assert!(mldsa65_sign(&seed, b"m", &[0; 255]).is_some());
    assert!(mldsa65_sign(&seed, b"m", &[0; 256]).is_none());
    let public = mldsa65_public(&seed);
    let signature = mldsa65_sign(&seed, b"m", b"").unwrap();
    assert!(!mldsa65_verify(&public, b"m", &[0; 256], &signature));
}

#[test]
fn any_bytes_are_checked_without_a_panic() {
    let seed = [2u8; 32];
    let public = mldsa65_public(&seed);
    let signature = mldsa65_sign(&seed, b"m", b"").unwrap();
    let mut x = 0x9e37_79b9u32;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x as usize
    };
    for _ in 0..200 {
        let mut changed = signature;
        changed[next() % MLDSA65_SIGNATURE_LENGTH] ^= 1 << (next() % 8);
        assert!(!mldsa65_verify(&public, b"m", b"", &changed));
        let mut key = public;
        key[next() % MLDSA65_PUBLIC_LENGTH] ^= 1 << (next() % 8);
        assert!(!mldsa65_verify(&key, b"m", b"", &signature));
    }
    assert!(!mldsa65_verify(
        &public,
        b"m",
        b"",
        &[0xff; MLDSA65_SIGNATURE_LENGTH]
    ));
    assert!(!mldsa65_verify(
        &[0xff; MLDSA65_PUBLIC_LENGTH],
        b"m",
        b"",
        &signature
    ));
}

#[cfg(unix)]
mod openssl {
    use std::fs;
    use std::process::{Command, Stdio};

    use super::*;

    fn run(args: &[&str]) -> std::process::Output {
        Command::new("openssl")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// Whether this OpenSSL has ML-DSA, from 3.5.
    fn available() -> bool {
        let found = Command::new("openssl")
            .args(["list", "-signature-algorithms"])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("ML-DSA-65"));
        if !found {
            eprintln!("skipping: no OpenSSL with ML-DSA");
        }
        found
    }

    #[test]
    fn keys_and_signatures_are_openssls() {
        if !available() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("hivepack-mldsa-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        for round in 0u8..12 {
            let seed = [round.wrapping_mul(37).wrapping_add(1); 32];
            let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
            let key = path("key.pem");
            let out = run(&[
                "genpkey",
                "-algorithm",
                "ML-DSA-65",
                "-pkeyopt",
                &format!("hexseed:{hex}"),
                "-out",
                &key,
            ]);
            assert!(out.status.success(), "{out:?}");

            let der = path("public.der");
            let out = run(&[
                "pkey", "-in", &key, "-pubout", "-outform", "DER", "-out", &der,
            ]);
            assert!(out.status.success(), "{out:?}");
            let der_bytes = fs::read(&der).unwrap();
            let public = mldsa65_public(&seed);
            assert_eq!(der_bytes[der_bytes.len() - MLDSA65_PUBLIC_LENGTH..], public);

            // `pkeyutl` cannot take an empty file.
            let message = vec![round; 1 + usize::from(round) * 1000];
            let context = vec![b'c'; usize::from(round) * 20];
            let message_path = path("message");
            fs::write(&message_path, &message).unwrap();
            let context_opt = format!(
                "hexcontext-string:{}",
                context
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let signature_path = path("signature");
            let mut args = vec![
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                &key,
                "-in",
                &message_path,
                "-out",
                &signature_path,
                "-pkeyopt",
                "deterministic:1",
            ];
            if !context.is_empty() {
                args.extend(["-pkeyopt", &context_opt]);
            }
            let out = run(&args);
            assert!(out.status.success(), "{out:?}");
            let theirs = fs::read(&signature_path).unwrap();
            let ours = mldsa65_sign(&seed, &message, &context).unwrap();
            assert_eq!(ours[..], theirs[..], "round {round}");

            let mut changed = ours;
            changed[usize::from(round) * 200] ^= 1;
            for (signature, valid) in [(ours, true), (changed, false)] {
                fs::write(&signature_path, signature).unwrap();
                let mut args = vec![
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-inkey",
                    &key,
                    "-in",
                    &message_path,
                    "-sigfile",
                    &signature_path,
                ];
                if !context.is_empty() {
                    args.extend(["-pkeyopt", &context_opt]);
                }
                let out = run(&args);
                assert_eq!(out.status.success(), valid, "{out:?}");
                assert_eq!(
                    mldsa65_verify(&public, &message, &context, &signature),
                    valid
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
