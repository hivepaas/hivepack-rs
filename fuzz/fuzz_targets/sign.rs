//! hivepack-sign's signatures on any input: read in armor and in binary, what
//! reads must write back as it came, and be checked without a panic. A signature
//! made here must pass, and fail for a changed file.

#![no_main]

use hivepack_sign::{FILE_NAMESPACE, PrivateKey, PublicKey, Signature, sign, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Signature::parse(data);
    if let Ok(read) = Signature::from_blob(data) {
        assert_eq!(read.to_blob(), data);
        assert_eq!(Signature::parse(read.to_armored().as_bytes()).unwrap(), read);
        let _ = verify(&read, read.public_key(), read.namespace(), &b"data"[..]);
    }
    let _ = PublicKey::parse(data);
    let _ = PrivateKey::parse(data, None);

    let mut changed = data.to_vec();
    changed.push(0);
    for key in [
        PrivateKey::from_seed([7; 32]),
        PrivateKey::from_hybrid_seeds([7; 32], [8; 32]),
    ] {
        let signature = sign(&key, FILE_NAMESPACE, data).unwrap();
        verify(&signature, key.public(), FILE_NAMESPACE, data).unwrap();
        assert!(verify(&signature, key.public(), FILE_NAMESPACE, &changed[..]).is_err());
    }
});
