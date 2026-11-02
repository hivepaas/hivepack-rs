//! hivepack::age's identity files on any input: the bytes are read as
//! `age -i` reads a file, as a file of keys, an SSH private key in PEM, or
//! a file of keys encrypted with age. A panic is a bug.
//!
//! Only the parsing: what needs a passphrase is decrypted when a file is,
//! and an encrypted key file could ask scrypt for 4 GiB.

#![no_main]

use std::sync::Arc;

use hivepack::age::{PassphrasePrompt, parse_identities_file};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let prompt: PassphrasePrompt = Arc::new(|_| Ok(b"password".to_vec()));
    let _ = parse_identities_file(data, prompt);
});
