# hivepack-crypto

`hivepack-crypto` has the cryptography of hivepack's formats, behind one small interface. It writes none of it. Each primitive comes from a crate many others depend on, and hivepack's other crates see only this interface: they forbid `unsafe` code and take cryptography from here.

Until November 2026 this crate was a port of BearSSL in safe Rust, with hand-written instructions behind a feature. That was about 4,700 lines of cryptography nobody else had reviewed, and programs that wanted speed ran the hand-written part. Crates that others audit and use are the better place for this, and the rule about dependencies with `unsafe` code ([safety.md](safety.md)) has an entry for them.

## What comes from where

| Interface | Crate | Audit its README states | What it is for |
|---|---|---|---|
| `Aes` | `aes` | NCC Group, one, no significant findings | WinZip AES (counter mode built on `encrypt4`), 7z and RAR (CBC, `cbc_decrypt`) |
| `chacha20_poly1305_seal`, `chacha20_poly1305_open` | `chacha20poly1305`, on `chacha20` and `poly1305` | NCC Group, one, no significant findings. `poly1305` notes that the audit predates its AVX2 backend, which has not been audited | age |
| `Sha1`, `Sha256`, `Sha512`, `Md5` | `sha1`, `sha2`, `md-5` | none stated | ZIP, RAR, XAR, age |
| `Hmac`, `HmacKey`, `hkdf`, `pbkdf2` | `hmac`, `hkdf`, `pbkdf2` | none stated | ZIP, RAR, age |
| `scrypt` | `scrypt`, on `salsa20` | none stated | age's passphrases |
| `x25519`, `x25519_base`, `ed25519_public_to_x25519` | `curve25519-dalek` | none stated in the README read | age's keys, SSH keys |
| `ed25519_public`, `ed25519_sign`, `ed25519_verify` | `ed25519-dalek`, on `curve25519-dalek` | none stated in the README read | [signatures](sign.md) |
| `Blake2s`, `Blake2sp` | `blake2s_simd` | none stated | RAR 5's file hashes. RustCrypto's `blake2` has no tree mode |
| `xwing_public`, `xwing_hpke_seal`, `xwing_hpke_open` | `hpke`, on `x-wing` and `ml-kem` | **`x-wing` and `ml-kem` state that they have never been independently audited.** `hpke` states no paid audit, and a review by Cloudflare of an earlier version | age's post-quantum keys |
| `equal` | `subtle` | none stated | age's tags and MACs |
| `RandomSource`, `system_random` | the standard library | | see below |

"Audited" is what each crate's README says about itself, as of the versions in `Cargo.lock`. An audit covers a version: none of this is a certification, and FIPS is not a goal.

`sha1` and `md-5` are here because formats require them. They are broken for signatures, and hivepack does not use them for anything a format does not ask.

## What the interface does

- **Nothing of its own that is cryptography.** Only what fits the formats: CBC with a little code around `aes`'s block functions, as they do eight blocks together with the processor's instructions; a counter mode is WinZip's, in `hivepack-zip`.
- **`chacha20_poly1305_open` checks before it decrypts.** A tag that does not match leaves the data as it was.
- **An Ed25519 public key** is a point of the curve or `None`, and its X25519 form is RFC 7748's map.
- **Edwards decoding as age has it.** `curve25519-dalek`'s `decompress` reads a `y` of the modulus or more, and an `x` of zero with its sign set, as `filippo.io/edwards25519` does. `y` = 1 maps to 0. Each of these is compared with age.
- **X-Wing refuses low-order points.** `x-wing` takes an X25519 part whose shared secret is all zeros, as its draft does not say, and its README says it will follow the RFC once that is published. age refuses it, as C2SP's vectors `hybrid_identity` and `hybrid_low_order` ask, so this crate checks the point first, in sealing and in opening.
- **`scrypt` looks for its memory first.** The crate allocates in a way that aborts the program if there is none, and age lets a file ask for up to 4 GiB. So that much is reserved and let go first, which gives `ScryptError::Memory` in the usual case. A system that overcommits memory may still find out later.

## Clearing secrets

`aes`, `chacha20poly1305` and `curve25519-dalek` are built with their `zeroize` features, and overwrite their key material when it is dropped. Callers overwrite what they hold, as `hivepack-age`'s keys do. Hash states are not cleared.

## Random numbers

The crate makes none: `system_random` reads `/dev/urandom` with the standard library on Unix, and fails elsewhere. WinZip AES needs a random salt for each entry, ZipCrypto eleven random bytes for its twelve-byte header, 7-Zip's AES a salt and IVs, and age its file keys, nonces and salts. Each takes a `RandomSource` from the caller; an application can use `getrandom` for that. A source that fails stops what encrypts.

## How it is shown

The interface is checked as the port was, so a change of crate or version that changes an answer fails here.

- **`tests/vectors.rs`**: the published vectors. AES from FIPS-197 (appendix C) and NIST SP 800-38A (F.1, ECB, four blocks with each key length); SHA-1, SHA-256 and SHA-512 from FIPS 180 (the empty message, `abc`, 448 or 896 bits, a million `a`); MD5 from RFC 1321 (appendix A.5, and a million `a`); HMAC-SHA1 and HMAC-MD5 from RFC 2202, HMAC-SHA256 and HMAC-SHA512 from RFC 4231 (all but the truncated test case 5); PBKDF2-HMAC-SHA1 from RFC 6070 (the 16,777,216-round vector is `#[ignore]`d) and PBKDF2-HMAC-SHA256 from RFC 7914, section 11; HKDF-SHA256 from RFC 5869 (test cases 1 to 3); ChaCha20-Poly1305 from RFC 8439 (section 2.8.2); X25519 from RFC 7748 (section 5.2, the iterated test to 1,000, its 1,000,000 `#[ignore]`d, and section 6.1); scrypt from RFC 7914, section 12 (the vector with N = 2^20, 1 GiB, `#[ignore]`d).
- **`tests/bearssl.rs`**: BearSSL's own tests from `test/test_crypto.c` for what the interface has: the 387 AES known answers (FIPS-197 and NIST's `ECBVarTxt128`, `192` and `256` files), each block encrypted alone and as each of four, and the Monte Carlo test of AES encryption with each key length (100 keys of 1,000 encryptions).
- **`tests/oracle.rs`**: comparison with [nettle](https://www.lysator.liu.se/~nisse/nettle/) 3.10.2, the library libzip's GnuTLS backend takes AES and PBKDF2 from, through `tools/nettle-oracle`, a small C program built from nettle's release by `scripts/testdata.py` (its tarball is signed by nettle's author, Niels Möller). AES with every key length, some keys of other lengths, and up to nine blocks; SHA-1, MD5 and HMAC-SHA1 on lengths around their 64-byte blocks and the 55-byte limit of their padding, with keys up to past a block, and the port given its data in pieces of random sizes; PBKDF2 with 1 to 40 and 1,000 rounds, outputs of 1 to 100 bytes and the 34, 50 and 66 that WinZip AES derives, and salts of 8, 12 and 16 bytes among others. The inputs are random bytes, zeros, ones and single bits. 7,500 requests are compared with nettle where the oracle is built (Linux and macOS in CI), and `testdata/oracle/crypto.txt` replays 1,000 everywhere else, including Windows, 32-bit and big-endian machines.
- **`tests/blake2.rs`**: BLAKE2s and BLAKE2sp on the reference implementation's 1,024 known answers, keyed and not, on inputs up to 255 bytes, and RFC 7693's example. BLAKE2sp keeps 512 bytes back, so the known answers do not reach its main path: 16 more vectors, up to 1 MB, are made with Python's `hashlib.blake2s` and its tree parameters, which give the unkeyed known answers too. Each is hashed whole and in pieces of random sizes around the blocks, with digests taken on the way (`tests/data/blake2-kat.txt`).
- **`tests/go_oracle.rs`**: comparison with what age runs, through `tools/age-oracle`, a small Go program built by `scripts/testdata.py` with the Go toolchain; its `go.sum` pins `golang.org/x/crypto` v0.55.0, the release age v1.3.2 requires, and the go command checks it against Go's checksum database. SHA-256 and SHA-512 on lengths around their blocks and the limits of their padding; HMAC with both, with keys up to past a block; PBKDF2-HMAC-SHA256; HKDF-SHA256 with no salt, empty salts and others, outputs up to past its limit of 255 blocks; ChaCha20-Poly1305 sealing, and opening what was sealed, with a bit changed or not, and data that was never sealed; X25519 with random points, points of small order, and values from p − 1 to 2^255 − 1, each with and without the top bit; scrypt with N up to 2^10, r up to 8 and p up to 3, and N = 1, which both refuse. What takes data in pieces gets it in pieces of random sizes. 4,400 requests are compared with Go where the oracle is built (Linux and macOS in CI, which install the Go that its `go.mod` names), and `testdata/oracle/crypto-go.txt` replays 1,100 everywhere else.

## Speed

The crates choose the processor's instructions at run time, on x86-64 and arm64, with nothing to turn on. The formats' READMEs have the numbers: `hivepack-zip`, `hivepack-7z`, `hivepack-rar` and `hivepack-age`.

## Following new releases

Versions are pinned by `Cargo.lock`. `cargo deny` in CI reports advisories on them. A new version is taken when the tests above still pass.

## Licenses

This crate is under the MIT license. The crates it calls are under MIT or Apache-2.0, `blake2s_simd` under MIT, `curve25519-dalek` and `subtle` under BSD-3-Clause; `cargo deny` checks them. nettle is under the LGPL-3.0-or-later or GPL-2.0-or-later, and only the test oracle is built with it; `golang.org/x/crypto` is under the BSD-3-Clause license, and only `tools/age-oracle` is built with it. The known answers in `tests/data` are the BLAKE2 reference implementation's, under CC0 1.0.
