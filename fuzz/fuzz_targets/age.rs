//! hivepack-age on any input: the bytes are a file, decrypted with
//! `decrypt_file` by CCTV's usual X25519 identity and the passphrase
//! `password` (work factors up to 2^4, so that a run stays quick), which
//! are those of the files `crates/age/tests/oracle.rs` records. A panic is
//! a bug.
//!
//! The file is read twice, in pieces of different sizes from its first
//! eight bytes' hash: both reads must give the same plaintext and end the
//! same way.

#![no_main]

use std::io::Read;
use std::sync::{Arc, OnceLock};

use hivepack_age::{
    Error, HybridIdentity, Identity, RandomSource, ScryptIdentity, X25519Identity, decrypt_file,
};
use libfuzzer_sys::fuzz_target;

const KEY: &str = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";

/// The plaintext given out, and how the reading ended.
fn read(data: &[u8], identities: &[&dyn Identity], mut seed: u64) -> (Vec<u8>, String) {
    let mut r = match decrypt_file(data, identities) {
        Ok(r) => r,
        Err(e) => return (Vec::new(), e.to_string()),
    };
    let mut out = Vec::new();
    loop {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut buf = vec![0; 1 + (seed >> 47) as usize];
        match r.read(&mut buf) {
            Ok(0) => return (out, "end".into()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => {
                let e = Error::from(e);
                assert!(
                    matches!(e, Error::Payload(_) | Error::Armor(_)),
                    "{e:?}"
                );
                return (out, e.to_string());
            }
        }
    }
}

/// A post-quantum key, made once: it takes longer than the rest.
fn hybrid() -> &'static HybridIdentity {
    static KEY: OnceLock<HybridIdentity> = OnceLock::new();
    KEY.get_or_init(|| {
        let source: RandomSource = Arc::new(|out: &mut [u8]| {
            out.fill(7);
            Ok(())
        });
        HybridIdentity::generate(Some(&source)).expect("a key")
    })
}

fuzz_target!(|data: &[u8]| {
    let key = X25519Identity::parse(KEY).expect("the key");
    let mut passphrase = ScryptIdentity::new(b"password").expect("a passphrase");
    passphrase.set_max_work_factor(4);
    let identities: [&dyn Identity; 3] = [&key, &passphrase, hybrid()];
    let seed = data.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let first = read(data, &identities, seed);
    let second = read(data, &identities, !seed);
    assert_eq!(first, second);
});
