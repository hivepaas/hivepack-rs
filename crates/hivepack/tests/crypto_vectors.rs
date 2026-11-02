//! The published test vectors: AES from FIPS-197 (appendix C) and NIST SP
//! 800-38A (F.1, ECB); SHA-1, SHA-256 and SHA-512 from FIPS 180; MD5 from
//! RFC 1321; HMAC-SHA1 and HMAC-MD5 from RFC 2202, HMAC-SHA256 and
//! HMAC-SHA512 from RFC 4231;
//! PBKDF2-HMAC-SHA1 from RFC 6070 and PBKDF2-HMAC-SHA256 from RFC 7914;
//! HKDF from RFC 5869; ChaCha20 and ChaCha20-Poly1305 from RFC 8439;
//! X25519 from RFC 7748; scrypt from RFC 7914. `tests/oracle.rs` compares
//! many more inputs with nettle, and `tests/go_oracle.rs` with Go.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "crypto_support/mod.rs"]
mod support;

use hivepack::crypto::{
    Aes, Digest, Hmac, HmacKey, Md5, ScryptError, Sha1, Sha256, Sha512, chacha20_poly1305_open,
    chacha20_poly1305_seal, equal, hkdf, pbkdf2, scrypt, x25519, x25519_base,
};
use support::{hex, unhex};

fn encrypt(key: &str, blocks: &str) -> String {
    let aes = Aes::new(&unhex(key)).expect("key length");
    let mut data = unhex(blocks);
    for block in data.as_chunks_mut().0 {
        aes.encrypt_block(block);
    }
    // The same, four blocks at a time.
    let mut again = unhex(blocks);
    let (fours, _) = again.as_chunks_mut();
    for blocks in fours.iter_mut() {
        aes.encrypt4(blocks);
    }
    let whole = 64 * fours.len();
    assert_eq!(data[..whole], again[..whole]);
    hex(&data)
}

#[test]
fn aes_fips_197() {
    let plaintext = "00112233445566778899aabbccddeeff";
    assert_eq!(
        encrypt("000102030405060708090a0b0c0d0e0f", plaintext),
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    );
    assert_eq!(
        encrypt(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            plaintext
        ),
        "dda97ca4864cdfe06eaf70a0ec0d7191"
    );
    assert_eq!(
        encrypt(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            plaintext
        ),
        "8ea2b7ca516745bfeafc49904b496089"
    );
}

#[test]
fn aes_sp_800_38a_ecb() {
    let plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    assert_eq!(
        encrypt("2b7e151628aed2a6abf7158809cf4f3c", plaintext),
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf\
         43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
    );
    assert_eq!(
        encrypt(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            plaintext
        ),
        "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef\
         ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"
    );
    assert_eq!(
        encrypt(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            plaintext
        ),
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870\
         b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"
    );
}

/// NIST SP 800-38A, F.2: CBC, the same blocks with each key size.
#[test]
fn aes_cbc_decrypts_sp_800_38a() {
    let plain = unhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
        .try_into()
        .expect("16 bytes");
    for (key, cipher) in [
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        ),
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
             571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        ),
    ] {
        let aes = Aes::new(&unhex(key)).expect("key length");
        let cipher = unhex(cipher);
        // In one call, and in pieces, which go on from the IV the last left.
        let mut data = cipher.clone();
        let mut next = iv;
        aes.cbc_decrypt(&mut next, &mut data);
        assert_eq!(data, plain, "{key}");
        assert_eq!(next[..], cipher[cipher.len() - 16..], "{key}");
        let mut data = cipher.clone();
        let mut next = iv;
        for block in data.chunks_mut(16) {
            aes.cbc_decrypt(&mut next, block);
        }
        assert_eq!(data, plain, "{key}");
    }
}

/// `decrypt4` undoes `encrypt4`, whose answers are checked against other
/// implementations; every key size, and blocks that differ in each position.
#[test]
fn aes_decrypts_what_it_encrypts() {
    for len in [16, 24, 32] {
        let mut key = vec![0u8; len];
        let mut state = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for _ in 0..200 {
            key.iter_mut().for_each(|b| *b = next());
            let aes = Aes::new(&key).expect("key length");
            let mut blocks = [0u8; 64];
            blocks.iter_mut().for_each(|b| *b = next());
            let plain = blocks;
            aes.encrypt4(&mut blocks);
            assert_ne!(blocks, plain);
            aes.decrypt4(&mut blocks);
            assert_eq!(blocks, plain, "a key of {len} bytes");
        }
    }
}

/// A partial block at the end is left as it is.
#[test]
fn aes_cbc_leaves_a_partial_block() {
    let aes = Aes::new(&[7; 32]).expect("key length");
    let mut iv = [0; 16];
    let mut data = [0xAA; 15];
    aes.cbc_decrypt(&mut iv, &mut data);
    assert_eq!(data, [0xAA; 15]);
    assert_eq!(iv, [0; 16]);
}

#[test]
fn aes_refuses_other_key_lengths() {
    for len in [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 64] {
        assert!(Aes::new(&vec![0; len]).is_none(), "{len}");
    }
}

fn sha1(data: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(data);
    hex(&sha1.out())
}

#[test]
fn sha1_fips_180() {
    assert_eq!(sha1(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        sha1(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ),
        "a49b2446a02c645bf419f995b67091253a04a259"
    );
    // A million times "a", a thousand at a time.
    let mut sha1 = Sha1::new();
    for _ in 0..1000 {
        sha1.update(&[b'a'; 1000]);
    }
    assert_eq!(hex(&sha1.out()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

#[test]
fn sha1_goes_on_after_out() {
    let mut sha1 = Sha1::new();
    sha1.update(b"ab");
    assert_eq!(hex(&sha1.out()), self::sha1(b"ab"));
    sha1.update(b"c");
    assert_eq!(hex(&sha1.out()), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

fn hmac(key: &[u8], data: &[u8]) -> String {
    hmac_with::<Sha1>(key, data)
}

fn hmac_with<H: Digest>(key: &[u8], data: &[u8]) -> String {
    let mut hmac = Hmac::new(&HmacKey::<H>::new(key));
    hmac.update(data);
    hex(hmac.out().as_ref())
}

#[test]
fn hmac_sha1_rfc_2202() {
    assert_eq!(
        hmac(&[0x0b; 20], b"Hi There"),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hmac(b"Jefe", b"what do ya want for nothing?"),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hmac(&[0xaa; 20], &[0xdd; 50]),
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    );
    let key: Vec<u8> = (1..=25).collect();
    assert_eq!(
        hmac(&key, &[0xcd; 50]),
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
    );
    assert_eq!(
        hmac(&[0x0c; 20], b"Test With Truncation"),
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
    );
    assert_eq!(
        hmac(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
    assert_eq!(
        hmac(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        ),
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    );
}

fn md5(data: &[u8]) -> String {
    let mut md5 = Md5::new();
    md5.update(data);
    hex(&md5.out())
}

/// RFC 1321, appendix A.5, and a million times "a".
#[test]
fn md5_rfc_1321() {
    assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5(b"a"), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md5(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    assert_eq!(
        md5(b"abcdefghijklmnopqrstuvwxyz"),
        "c3fcd3d76192e4007dfb496cca67e13b"
    );
    assert_eq!(
        md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        "d174ab98d277d9f5a5611c2c9f419d9f"
    );
    assert_eq!(
        md5(b"1234567890123456789012345678901234567890\
              1234567890123456789012345678901234567890"),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
    let mut md5 = Md5::new();
    for _ in 0..1000 {
        md5.update(&[b'a'; 1000]);
    }
    assert_eq!(hex(&md5.out()), "7707d6ae4e027c70eea2a935c2296f21");
}

#[test]
fn md5_goes_on_after_out() {
    let mut md5 = Md5::new();
    md5.update(b"ab");
    assert_eq!(hex(&md5.out()), self::md5(b"ab"));
    md5.update(b"c");
    assert_eq!(hex(&md5.out()), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn hmac_md5_rfc_2202() {
    assert_eq!(
        hmac_with::<Md5>(&[0x0b; 16], b"Hi There"),
        "9294727a3638bb1c13f48ef8158bfc9d"
    );
    assert_eq!(
        hmac_with::<Md5>(b"Jefe", b"what do ya want for nothing?"),
        "750c783e6ab0b503eaa86e310a5db738"
    );
    assert_eq!(
        hmac_with::<Md5>(&[0xaa; 16], &[0xdd; 50]),
        "56be34521d144c88dbb8c733f0e8b3f6"
    );
    let key: Vec<u8> = (1..=25).collect();
    assert_eq!(
        hmac_with::<Md5>(&key, &[0xcd; 50]),
        "697eaf0aca3a3aea3a75164746ffaa79"
    );
    assert_eq!(
        hmac_with::<Md5>(&[0x0c; 16], b"Test With Truncation"),
        "56461ef2342edc00f9bab995690efd4c"
    );
    assert_eq!(
        hmac_with::<Md5>(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
    );
    assert_eq!(
        hmac_with::<Md5>(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        ),
        "6f630fad67cda0ee1fb1f562db3aa53e"
    );
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> String {
    let mut out = vec![0; length];
    pbkdf2::<Sha1>(password, salt, iterations, &mut out);
    hex(&out)
}

#[test]
fn pbkdf2_hmac_sha1_rfc_6070() {
    assert_eq!(
        pbkdf2_sha1(b"password", b"salt", 1, 20),
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    );
    assert_eq!(
        pbkdf2_sha1(b"password", b"salt", 2, 20),
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    );
    assert_eq!(
        pbkdf2_sha1(b"password", b"salt", 4096, 20),
        "4b007901b765489abead49d926f721d065a429c1"
    );
    assert_eq!(
        pbkdf2_sha1(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25
        ),
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    );
    assert_eq!(
        pbkdf2_sha1(b"pass\0word", b"sa\0lt", 4096, 16),
        "56fa6aa75548099dcc37d7f03425e0c3"
    );
}

#[test]
#[ignore = "16,777,216 rounds"]
fn pbkdf2_hmac_sha1_rfc_6070_long() {
    assert_eq!(
        pbkdf2_sha1(b"password", b"salt", 16_777_216, 20),
        "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
    );
}

#[test]
fn pbkdf2_zero_rounds_count_as_one() {
    assert_eq!(
        pbkdf2_sha1(b"password", b"salt", 0, 20),
        pbkdf2_sha1(b"password", b"salt", 1, 20)
    );
}

fn digest<H: Digest>(data: &[u8]) -> String {
    let mut h = H::new();
    h.update(data);
    hex(h.out().as_ref())
}

#[test]
fn sha256_fips_180() {
    assert_eq!(
        digest::<Sha256>(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        digest::<Sha256>(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        digest::<Sha256>(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let mut sha256 = Sha256::new();
    for _ in 0..1000 {
        sha256.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&sha256.out()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha512_fips_180() {
    assert_eq!(
        digest::<Sha512>(b""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(
        digest::<Sha512>(b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        digest::<Sha512>(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
    let mut sha512 = Sha512::new();
    for _ in 0..1000 {
        sha512.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&sha512.out()),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
         de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

#[test]
fn hmac_sha256_and_sha512_rfc_4231() {
    let long_data: &[u8] = b"This is a test using a larger than block-size key and a larger \
        than block-size data. The key needs to be hashed before being used by the HMAC \
        algorithm.";
    let key4: Vec<u8> = (1..=25).collect();
    // Test cases 1 to 4, 6 and 7; case 5 truncates the output.
    let cases: [(&[u8], &[u8], &str, &str); 6] = [
        (
            &[0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
        (
            &key4,
            &[0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
        (
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
        (
            &[0xaa; 131],
            long_data,
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ];
    for (key, data, sha256, sha512) in cases {
        assert_eq!(hmac_with::<Sha256>(key, data), sha256);
        assert_eq!(hmac_with::<Sha512>(key, data), sha512);
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> String {
    let mut out = vec![0; length];
    pbkdf2::<Sha256>(password, salt, iterations, &mut out);
    hex(&out)
}

#[test]
fn pbkdf2_hmac_sha256_rfc_7914() {
    assert_eq!(
        pbkdf2_sha256(b"passwd", b"salt", 1, 64),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
         49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    );
    assert_eq!(
        pbkdf2_sha256(b"Password", b"NaCl", 80000, 64),
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
         a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
    );
}

/// HKDF-SHA256 of `ikm` with `salt` and `info`, `length` bytes.
fn hkdf_hex(ikm: &str, salt: Option<&str>, info: &str, length: usize) -> String {
    let salt = salt.map(unhex);
    let mut out = vec![0; length];
    assert!(hkdf::<Sha256>(
        salt.as_deref(),
        &unhex(ikm),
        &unhex(info),
        &mut out
    ));
    hex(&out)
}

#[test]
fn hkdf_sha256_rfc_5869() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    assert_eq!(
        hkdf_hex(
            ikm,
            Some("000102030405060708090a0b0c"),
            "f0f1f2f3f4f5f6f7f8f9",
            42
        ),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    let ikm_2: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    assert_eq!(
        hkdf_hex(&hex(&ikm_2), Some(&hex(&salt)), &hex(&info), 82),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );
    // Test case 3: no salt and no info; an empty salt is the same.
    for salt in [None, Some("-")] {
        assert_eq!(
            hkdf_hex(ikm, salt, "-", 42),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }
}

#[test]
fn hkdf_stops_at_255_blocks() {
    let mut out = vec![0; 255 * 32];
    assert!(hkdf::<Sha256>(None, b"", b"", &mut out));
    let mut out = vec![0; 255 * 32 + 1];
    assert!(!hkdf::<Sha256>(None, b"", b"", &mut out));
}

#[test]
fn chacha20_poly1305_rfc_8439() {
    // Section 2.8.2.
    let key: [u8; 32] = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
        only one tip for the future, sunscreen would be it.";
    let ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
        3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
        92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
        3ff4def08e4b7a9de576d26586cec64b6116";
    let tag = "1ae10b594f09e26a7e902ecbd0600691";

    let mut data = plaintext.to_vec();
    assert_eq!(
        hex(&chacha20_poly1305_seal(&key, &nonce, &mut data, &aad)),
        tag
    );
    assert_eq!(hex(&data), ciphertext);

    let tag: [u8; 16] = unhex(tag).try_into().unwrap();
    assert!(chacha20_poly1305_open(&key, &nonce, &mut data, &aad, &tag));
    assert_eq!(data, plaintext);

    // One bit off in the ciphertext fails, and leaves it as it was.
    let mut data = unhex(ciphertext);
    data[50] ^= 4;
    let before = data.clone();
    assert!(!chacha20_poly1305_open(&key, &nonce, &mut data, &aad, &tag));
    assert_eq!(data, before);
}

#[test]
fn equal_compares_whole_slices() {
    assert!(equal(b"", b""));
    assert!(equal(b"abc", b"abc"));
    assert!(!equal(b"abc", b"abd"));
    assert!(!equal(b"abc", b"ab"));
    assert!(!equal(&[0x80], &[0]));
}

fn x25519_hex(k: &str, u: &str) -> String {
    let k: [u8; 32] = unhex(k).try_into().unwrap();
    let u: [u8; 32] = unhex(u).try_into().unwrap();
    hex(&x25519(&k, &u))
}

#[test]
fn x25519_rfc_7748() {
    // Section 5.2.
    assert_eq!(
        x25519_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        ),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    );
    // This u-coordinate has its top bit set, which is ignored.
    assert_eq!(
        x25519_hex(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
        ),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    );

    // Section 6.1.
    let a = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    let b = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    let ka = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    let kb = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    let private = |k: &str| -> [u8; 32] { unhex(k).try_into().unwrap() };
    assert_eq!(hex(&x25519_base(&private(a))), ka);
    assert_eq!(hex(&x25519_base(&private(b))), kb);
    assert_eq!(x25519_hex(a, kb), shared);
    assert_eq!(x25519_hex(b, ka), shared);
}

fn x25519_iterations(count: u32) -> String {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = k;
    for _ in 0..count {
        let next = x25519(&k, &u);
        u = k;
        k = next;
    }
    hex(&k)
}

#[test]
fn x25519_rfc_7748_iterated() {
    assert_eq!(
        x25519_iterations(1),
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    );
    assert_eq!(
        x25519_iterations(1000),
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
    );
}

#[test]
#[ignore = "a million scalar multiplications"]
fn x25519_rfc_7748_iterated_long() {
    assert_eq!(
        x25519_iterations(1_000_000),
        "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
    );
}

#[test]
fn x25519_small_order_gives_zero() {
    let k = [0x42; 32];
    assert_eq!(x25519(&k, &[0; 32]), [0; 32]);
    let mut one = [0; 32];
    one[0] = 1;
    assert_eq!(x25519(&k, &one), [0; 32]);
}

fn scrypt_hex(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> String {
    let mut out = [0; 64];
    scrypt(password, salt, log_n, r, p, &mut out).unwrap();
    hex(&out)
}

#[test]
fn scrypt_rfc_7914() {
    assert_eq!(
        scrypt_hex(b"", b"", 4, 1, 1),
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
         fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    );
    assert_eq!(
        scrypt_hex(b"password", b"NaCl", 10, 8, 16),
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
         2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
    );
    assert_eq!(
        scrypt_hex(b"pleaseletmein", b"SodiumChloride", 14, 8, 1),
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
         d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    );
}

#[test]
#[ignore = "1 GiB of memory"]
fn scrypt_rfc_7914_large() {
    assert_eq!(
        scrypt_hex(b"pleaseletmein", b"SodiumChloride", 20, 8, 1),
        "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa47\
         8e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"
    );
}

#[test]
fn scrypt_refuses_parameters_outside_rfc_7914() {
    let mut out = [0; 32];
    for (log_n, r, p) in [
        (0, 8, 1),
        (64, 8, 1),
        (4, 0, 1),
        (4, 8, 0),
        (4, 1 << 15, 1 << 15),
    ] {
        assert_eq!(
            scrypt(b"", b"", log_n, r, p, &mut out),
            Err(ScryptError::Parameters),
            "{log_n} {r} {p}"
        );
    }
    // RFC 7914 wants N below 2^(16 r); like Go, the port does not check.
    assert!(scrypt(b"", b"", 16, 1, 1, &mut out).is_ok());
}

#[test]
fn scrypt_reports_memory_it_cannot_have() {
    let mut out = [0; 32];
    // 2^40 × 128 × 8 bytes, a pebibyte, are more than any machine's
    // address space; a 32-bit machine cannot even count them.
    let result = scrypt(b"", b"", 40, 8, 1, &mut out);
    assert!(
        matches!(result, Err(ScryptError::Memory | ScryptError::Parameters)),
        "{result:?}"
    );
}

/// RFC 7748, section 4.1: the base point of edwards25519 is that of curve25519.
/// And RFC 8032's first key: its X25519 form is what the SHA-512 of its seed gives,
/// as age has it. The rest is compared with Go in `crates/hivepack/tests/age_encrypt.rs`.
#[test]
fn ed25519_public_keys_as_x25519() {
    let unhex = |s: &str| -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    };
    let base = unhex("5866666666666666666666666666666666666666666666666666666666666666");
    let mut nine = [0; 32];
    nine[0] = 9;
    assert_eq!(
        hivepack::crypto::ed25519_public_to_x25519(&base),
        Some(nine)
    );

    let seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let mut h = hivepack::crypto::Sha512::new();
    h.update(&seed);
    let hash = h.out();
    let scalar: [u8; 32] = hash[..32].try_into().unwrap();
    assert_eq!(
        hivepack::crypto::ed25519_public_to_x25519(&public),
        Some(hivepack::crypto::x25519_base(&scalar))
    );

    // y = 1, whose u has no inverse to divide by, and y = 2, which is no point.
    let mut one = [0; 32];
    one[0] = 1;
    assert_eq!(
        hivepack::crypto::ed25519_public_to_x25519(&one),
        Some([0; 32])
    );
    let mut two = [0; 32];
    two[0] = 2;
    assert_eq!(hivepack::crypto::ed25519_public_to_x25519(&two), None);
}
