# hivepack::crypto

The cryptography of hivepack's formats, behind one small interface. This crate writes no cryptography: it calls crates many others depend on, and hivepack's other crates see only this interface.

| What | From | Used by |
|---|---|---|
| AES | `aes` | ZIP, 7z, RAR |
| SHA-1, SHA-256, SHA-512, MD5 | `sha1`, `sha2`, `md-5` | ZIP, RAR, XAR, age |
| HMAC, HKDF, PBKDF2 | `hmac`, `hkdf`, `pbkdf2` | ZIP, RAR, age |
| ChaCha20-Poly1305 | `chacha20poly1305` | age |
| X25519, Ed25519 public keys as X25519 | `curve25519-dalek` | age |
| scrypt | `scrypt` | age |
| BLAKE2s, BLAKE2sp | `blake2s_simd` | RAR |
| Comparing tags in constant time | `subtle` | age |

```rust
use hivepack::crypto::{Aes, Hmac, HmacKey, Sha1, pbkdf2};

// A WinZip AES-256 key: 32 bytes for AES, 32 for HMAC, 2 to check the password.
let mut derived = [0; 66];
pbkdf2::<Sha1>(b"password", &[0x5a; 16], 1000, &mut derived);
let aes = Aes::new(&derived[..32]).expect("a 32-byte key");
let mut block = [0; 16];
aes.encrypt_block(&mut block);
let mut hmac = Hmac::new(&HmacKey::<Sha1>::new(&derived[32..64]));
hmac.update(&block);
let mac = hmac.out();
```

This crate has no `unsafe` code of its own and forbids it. The crates it calls have some, for the processor's instructions, which they choose at run time. Which of them have been audited, how the interface is checked against nettle and Go, and its speed are in [docs/crypto.md](../../../../docs/crypto.md).

## License

The MIT license. See [LICENSE](LICENSE). The crates it calls keep their own: MIT or Apache-2.0, MIT for `blake2s_simd`, BSD-3-Clause for `curve25519-dalek` and `subtle`.
