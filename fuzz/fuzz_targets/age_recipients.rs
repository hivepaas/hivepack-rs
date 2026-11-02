//! Reading recipients with hivepack::age on any input: as a recipients file, as an
//! SSH public key, as `age -r` takes one, and its first 32 bytes as an Ed25519 key.
//! A recipient read gives text that reads back. A panic is a bug.
//!
//! `crates/hivepack/tests/age_encrypt.rs` compares what is read with age, by what it writes.

#![no_main]

use hivepack::age::{
    HybridIdentity, HybridRecipient, SshEd25519Recipient, parse_recipient, parse_recipients_file,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_recipients_file(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_recipient(text);
        if let Ok(r) = HybridRecipient::parse(text) {
            let again = HybridRecipient::parse(&r.to_string()).unwrap();
            assert!(again == r, "another post-quantum key came back");
        }
        let _ = HybridIdentity::parse(text);
        if let Ok(r) = SshEd25519Recipient::parse(text) {
            let again = SshEd25519Recipient::parse(&r.to_string()).unwrap();
            assert!(again == r, "another key came back");
        }
    }
    if let Some(key) = data.first_chunk::<32>() {
        let _ = hivepack::crypto::ed25519_public_to_x25519(key);
    }
});
