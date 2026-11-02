# Porting BearSSL's cryptography

`hivepack-crypto` has the cryptography of hivepack's formats, in safe Rust.

- **ZIP's encryption**: AES, SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1. WinZip AES, step 4 of [zip.md](zip.md), derives its keys with PBKDF2, encrypts with AES in counter mode and authenticates with HMAC-SHA1; ZipCrypto needs only CRC-32, which `hivepack-deflate` has. libzip takes these from OpenSSL, GnuTLS, CommonCrypto or Windows (`zip_crypto_*.c`); hivepack takes them from this crate.
- **age**, the encryption format that `hivepack-age` will read: SHA-256, HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305, X25519 and scrypt, and SHA-512 for the keys of SSH's Ed25519. age's reference implementation, in Go, takes these from Go's standard library and `golang.org/x/crypto`; hivepack takes them from this crate.
- **RAR 5's file hashes**: BLAKE2sp, for `hivepack-rar` (see [rar.md](rar.md)).
- **XAR's checksums**: MD5, besides SHA-1, SHA-256 and SHA-512, for `hivepack-xar`. libarchive takes them from `archive_digest.c`, which calls the C library's, CommonCrypto, Windows', mbed TLS, nettle or OpenSSL.

## The source

The port follows [BearSSL](https://bearssl.org) **0.6** (August 2018, the latest release as of October 2026; `bearssl-0.6.tar.gz`, SHA-256 `6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14`). `hivepack_crypto::UPSTREAM_VERSION` names it. BearSSL is under the MIT license, small, and written so that its code runs in constant time; nettle, which the tests compare with, is under the LGPL, so its code is not ported.

| BearSSL | Port | What |
|---|---|---|
| `src/symcipher/aes_ct64.c` | `aes_ct64.rs` | the S-box, as Boyar and Peralta's circuit; the bitsliced representation; the key schedule |
| `src/symcipher/aes_ct64_enc.c` | `aes_ct64_enc.rs` | the rounds |
| `src/symcipher/aes_ct64_ctr.c` | `aes_ct64_ctr.rs` (`Aes`) | four blocks encrypted at once, without the counter |
| `src/symcipher/aes_ct64_dec.c` | `aes_ct64_dec.rs` | the rounds of decryption, and the inverse S-box |
| `src/symcipher/aes_ct64_cbcdec.c` | `aes_ct64_ctr.rs` (`Aes::decrypt4`, `Aes::cbc_decrypt`) | four blocks decrypted at once, and CBC, for 7z |
| `src/hash/sha1.c` | `sha1.rs` (`Sha1`) | SHA-1 |
| `src/hash/sha2small.c` | `sha2small.rs` (`Sha256`) | SHA-256 |
| `src/hash/sha2big.c` | `sha2big.rs` (`Sha512`) | SHA-512 |
| `src/hash/md5.c` | `md5.rs` (`Md5`) | MD5 |
| `br_hash_class` (`inc/bearssl_hash.h`) | `digest.rs` (`Digest`) | what HMAC, HKDF and PBKDF2 need of a hash |
| `src/mac/hmac.c` | `hmac.rs` (`HmacKey`, `Hmac`) | HMAC, with any of the four hashes |
| `src/kdf/hkdf.c` | `hkdf.rs` (`Hkdf`, `HkdfExpand`) | HKDF (RFC 5869) |
| `src/symcipher/chacha20_ct.c` | `chacha20_ct.rs` (`chacha20`) | ChaCha20 (RFC 8439) |
| `src/symcipher/poly1305_ctmul.c` | `poly1305_ctmul.rs` (`chacha20_poly1305`) | ChaCha20-Poly1305 (RFC 8439, section 2.8) |
| `src/ec/ec_c25519_m31.c` | `ec_c25519_m31.rs` (`x25519`, `x25519_base`) | X25519 (RFC 7748), on 32-bit machines |
| `NOT`, `MUX`, `EQ`, `GT` (`src/inner.h`), `src/codec/ccopy.c` | `ct.rs` (`equal`) | constant-time selection and comparison |
| (none) | `pbkdf2.rs` (`pbkdf2`) | PBKDF2, from RFC 8018, section 5.2 |
| (none) | `scrypt.rs` (`scrypt`) | scrypt, from RFC 7914 |
| (none) | `blake2s.rs` (`Blake2s`), `blake2sp.rs` (`Blake2sp`) | BLAKE2s and BLAKE2sp, from the BLAKE2 reference implementation |

The rules are those of [porting.md](porting.md): a module for each C file, the C name in each doc comment, and `Differs from BearSSL:` comments where the port departs. The differences:

- **AES without its modes.** BearSSL offers AES with CBC, CTR, CCM and GCM. WinZip AES uses a counter of its own (libzip increments the first eight bytes, little-endian), so `Aes` encrypts blocks, one or four at a time, and the caller XORs them into the data: a counter mode decrypts by encrypting. 7z uses CBC, so `Aes` decrypts in that mode too; it does not encrypt in it, as nothing here writes 7z yet. Decryption is checked against NIST SP 800-38A's CBC vectors, and by undoing encryption, whose answers are compared with nettle.
- **The subkeys stay expanded.** BearSSL keeps them compressed and expands them at each call; `Aes` expands them once.
- **HMAC's whole output**; libzip cuts HMAC-SHA1 to 10 bytes itself. BearSSL's hashes are a vtable (`br_hash_class`) that HMAC takes at run time; here they are a trait, `Digest`, that HMAC, HKDF and PBKDF2 are generic over. SHA-1, SHA-256, SHA-512 and MD5, not SHA-224 or SHA-384, which nothing here uses.
- **HKDF's two steps are two types**: `Hkdf` takes the input key material, and `flip` turns it into `HkdfExpand`, which produces the output; BearSSL keeps a union of the two. Once 255 blocks are produced, later calls produce nothing, where BearSSL's counter would go on and start the block numbers again.
- **ChaCha20-Poly1305 with one ChaCha20**: BearSSL's `br_poly1305_ctmul_run` takes its ChaCha20 as a function pointer; `chacha20_poly1305` always uses `chacha20`. Whole 64-byte blocks of ChaCha20 are XORed with the key stream a word at a time, and Poly1305 reads whole 16-byte blocks where they are, without copying them first; the results are the same and it is faster (see Speed). After decrypting, BearSSL leaves it to the caller to compare the tags; `equal` does that in constant time.
- **X25519 on 64-bit machines** is not BearSSL's: `ec_c25519_m51.rs` has the usual field of five 51-bit words with 128-bit products, and the same ladder in constant time. It is more than twice as fast as 30-bit words here. A unit test compares it with the port of `m31`, on random input and at the edges, and the 32-bit build keeps `m31`, where 128-bit products would be calls into the compiler's runtime.
- **X25519 alone**: BearSSL's `br_ec_c25519_m31` is a `br_ec_impl`, with the curve's generator and order and a `muladd` that Curve25519 does not implement. The port has `mul` and `mulgen`, as `x25519` and `x25519_base`, on 32-byte arrays. Like BearSSL, it returns the all-zero result of a point of small order; age refuses it.
- **A key of the wrong length** is `None`, where BearSSL's key schedule returns 0 rounds.

`aes_ct64` is BearSSL's constant-time AES for 64-bit machines: four blocks at a time are spread over eight 64-bit words, so that the S-box is a circuit of logical operations. No table is indexed with secret data, and the time taken depends neither on the key nor on the data. The hashes, ChaCha20 and Poly1305 have no branches or indexing on their data either. X25519's Montgomery ladder swaps its points with masks (`cswap`), never with a branch, and its final reduction selects with `ccopy`; the last tag reduction of Poly1305 selects with `MUX`. Its multiplications are 32 × 32 → 64 bits, as Poly1305's are, which take the same time whatever their values on the 64-bit machines CI runs on; BearSSL's `BR_CT_MUL31`, for processors where they do not (some ARM Cortex-M cores, old PowerPC), is not ported.

scrypt is not in BearSSL. It is written from RFC 7914: the Salsa20/8 core of section 3, scryptBlockMix and scryptROMix, on 32-bit words, and PBKDF2-HMAC-SHA256 around them. scryptROMix reads its table at positions that depend on the data, as scrypt is defined to; that is what makes it costly in memory, and it is the same in every implementation. Its parameters are those RFC 7914 allows, except that N is not checked to be below 2^(16r), which matters only for r below 4: Go's `golang.org/x/crypto/scrypt`, which age uses, does not check it either. Its memory, 128 × r × N bytes, is allocated with `try_reserve_exact`, so that a cost too large for the machine is `ScryptError::Memory` rather than an abort; the limit on the cost is for the caller to set, as age does with its work factor.

BLAKE2 is not in BearSSL either. RAR 5 hashes files with BLAKE2sp, eight BLAKE2s leaves and a root, and [rar.md](rar.md) needs it: `blake2s.rs` and `blake2sp.rs` are ports of `ref/blake2s-ref.c` and `ref/blake2sp-ref.c` of the BLAKE2 reference implementation (github.com/BLAKE2/BLAKE2, commit `ed1974ea`), Samuel Neves's, which UnRAR's own BLAKE2 comes from, keys included, without the salt, personalization, other digest lengths and OpenMP threads, which nothing here uses.

## Ed25519 public keys as X25519

`ed25519_public_to_x25519` is what age needs to encrypt to an SSH key. It is not in BearSSL. It is written from RFC 8032, section 5.1.3, for whether the key is a point of the curve, and RFC 7748, section 4.1, for u = (1 + y) / (1 - y), on the field arithmetic of `ec_c25519_m31.rs`. Its input is public, so its time depends on the key. Where RFC 8032 refuses, it does what `filippo.io/edwards25519` does for age: a `y` of the modulus or more is reduced, the sign of an `x` of zero is not looked at, and `y` = 1 gives 0. RFC 7748's base point and RFC 8032's first key are in `tests/vectors.rs`; the rest is compared with age, by the files it writes, in `crates/age/tests/encrypt.rs`.

## Clearing secrets

libzip clears keys and contexts with `_zip_crypto_clear` when it frees them. The port overwrites keys, key schedules, HMAC keys and hash states when they are dropped, and the intermediate key material in the key schedule, HMAC, HKDF, PBKDF2, ChaCha20 (its copy of the key), Poly1305 (its one-time key), X25519 (its copy of the scalar) and scrypt (all of its memory); not the data or the per-block temporaries, which BearSSL does not clear either. It is best effort: safe Rust has no volatile write, so the zeroing is followed by `std::hint::black_box`, which asks the compiler to keep it but does not promise to.

## Random numbers

The crate makes none: `system_random` reads `/dev/urandom` with the standard library on Unix, in safe Rust, as libzip's `zip_random_unix.c` does, and fails elsewhere. WinZip AES needs a random salt for each entry, ZipCrypto eleven random bytes for its twelve-byte header, 7-Zip's AES a salt and IVs, and age its file keys, nonces and salts. Each takes a `RandomSource` from the caller; an application can use `getrandom` for that, which libraries here do not depend on (see [safety.md](safety.md)). A source that fails stops what encrypts.

## How it is shown

- **`tests/vectors.rs`**: the published vectors. AES from FIPS-197 (appendix C) and NIST SP 800-38A (F.1, ECB, four blocks with each key length); SHA-1, SHA-256 and SHA-512 from FIPS 180 (the empty message, `abc`, 448 or 896 bits, a million `a`); MD5 from RFC 1321 (appendix A.5, and a million `a`); HMAC-SHA1 and HMAC-MD5 from RFC 2202, HMAC-SHA256 and HMAC-SHA512 from RFC 4231 (all but the truncated test case 5); PBKDF2-HMAC-SHA1 from RFC 6070 (the 16,777,216-round vector is `#[ignore]`d) and PBKDF2-HMAC-SHA256 from RFC 7914, section 11; HKDF-SHA256 from RFC 5869 (test cases 1 to 3, the output taken in pieces); ChaCha20 (section 2.4.2) and ChaCha20-Poly1305 (section 2.8.2) from RFC 8439; X25519 from RFC 7748 (section 5.2, the iterated test to 1,000, its 1,000,000 `#[ignore]`d, and section 6.1); scrypt from RFC 7914, section 12 (the vector with N = 2^20, 1 GiB, `#[ignore]`d).
- **`tests/bearssl.rs`**: BearSSL's own tests from `test/test_crypto.c` for what the port has: the 387 AES known answers (FIPS-197 and NIST's `ECBVarTxt128`, `192` and `256` files), each block encrypted alone and as each of four, and the Monte Carlo test of AES encryption with each key length (100 keys of 1,000 encryptions).
- **`tests/oracle.rs`**: comparison with [nettle](https://www.lysator.liu.se/~nisse/nettle/) 3.10.2, the library libzip's GnuTLS backend takes AES and PBKDF2 from, through `tools/nettle-oracle`, a small C program built from nettle's release by `scripts/testdata.py` (its tarball is signed by nettle's author, Niels Möller). AES with every key length, some keys of other lengths, and up to nine blocks; SHA-1, MD5 and HMAC-SHA1 on lengths around their 64-byte blocks and the 55-byte limit of their padding, with keys up to past a block, and the port given its data in pieces of random sizes; PBKDF2 with 1 to 40 and 1,000 rounds, outputs of 1 to 100 bytes and the 34, 50 and 66 that WinZip AES derives, and salts of 8, 12 and 16 bytes among others. The inputs are random bytes, zeros, ones and single bits. 7,500 requests are compared with nettle where the oracle is built (Linux and macOS in CI), and `testdata/oracle/crypto.txt` replays 1,000 everywhere else, including Windows, 32-bit and big-endian machines.
- **`tests/blake2.rs`**: BLAKE2s and BLAKE2sp on the reference implementation's 1,024 known answers, keyed and not, on inputs up to 255 bytes, and RFC 7693's example. BLAKE2sp keeps 512 bytes back, so the known answers do not reach its main path: 16 more vectors, up to 1 MB, are made with Python's `hashlib.blake2s` and its tree parameters, which give the unkeyed known answers too. Each is hashed whole and in pieces of random sizes around the blocks, with digests taken on the way (`tests/data/blake2-kat.txt`).
- **`tests/go_oracle.rs`**: comparison with what age runs, through `tools/age-oracle`, a small Go program built by `scripts/testdata.py` with the Go toolchain; its `go.sum` pins `golang.org/x/crypto` v0.55.0, the release age v1.3.2 requires, and the go command checks it against Go's checksum database. SHA-256 and SHA-512 on lengths around their blocks and the limits of their padding; HMAC with both, with keys up to past a block; PBKDF2-HMAC-SHA256; HKDF-SHA256 with no salt, empty salts and others, outputs up to past its limit of 255 blocks, taken in pieces; ChaCha20 from any block, up to the last one before the counter wraps; ChaCha20-Poly1305 sealing, and opening what was sealed, with a bit changed or not, and data that was never sealed; X25519 with random points, points of small order, and values from p − 1 to 2^255 − 1, each with and without the top bit; scrypt with N up to 2^10, r up to 8 and p up to 3, and N = 1, which both refuse. The port gets its data in pieces of random sizes. 4,400 requests are compared with Go where the oracle is built (Linux and macOS in CI, which install the Go that its `go.mod` names), and `testdata/oracle/crypto-go.txt` replays 1,100 everywhere else.

## Speed

AMD Ryzen 9 9950X (x86-64, Linux), October 2026, 64 MiB at a time, release build:

| | Port | BearSSL (C, `gcc -O2`) | nettle (C, no assembly) |
|---|---|---|---|
| AES-128 | 351 MB/s | 326 MB/s (`aes_ct64`, CTR) | 672 MB/s |
| AES-256 | 246 MB/s | 235 MB/s | 442 MB/s |
| SHA-1, HMAC-SHA1 | 730 MB/s | 377 MB/s | 1,401 MB/s |
| PBKDF2, 1,000 rounds, 66 bytes (a WinZip AES-256 key) | 0.76 ms | | 0.45 ms |

The same machine, October 2026, for what age needs. Go is Go 1.27.2 with `golang.org/x/crypto` v0.55.0, as age v1.3.2 runs them:

| | Port | BearSSL (C, `gcc -O2`) | Go |
|---|---|---|---|
| SHA-256 | 484 MB/s | 477 MB/s | 2,770 MB/s (SHA instructions) |
| SHA-512 | 788 MB/s | 752 MB/s | 1,359 MB/s |
| ChaCha20 | 1,340 MB/s | 1,300 MB/s (`chacha20_ct`) | 1,265 MB/s |
| ChaCha20-Poly1305 | 998 MB/s | 964 MB/s (`poly1305_ctmul`) | 3,663 MB/s (AVX2 assembly) |
| X25519 | 22 µs | 79 µs (`m31`) | 47 µs |
| scrypt, N = 2^18, r = 8, p = 1 (age's default work factor, 256 MiB) | 0.30 s | | 0.33 s |
| scrypt, N = 2^20 (1 GiB) | 1.20 s | | 1.37 s |

age decrypts its payload with ChaCha20-Poly1305 in 64 KiB chunks, so at about 1 GB/s the port keeps up with a disk or a decompressor; Go's assembly would need `unsafe` code (see [safety.md](safety.md)). The rest runs once per file: X25519 once for each recipient tried, scrypt once for a passphrase.

nettle's AES looks bytes up in tables indexed with the key and the data, which is faster and whose time depends on them; the port keeps BearSSL's constant-time code. nettle's SHA-1 computes its message schedule as it goes, in 16 words, where BearSSL's computes all 80 first. Neither matters much for ZIP: decompression and the reads are the slower parts, and AES-NI or SHA instructions would need `unsafe` code (see [safety.md](safety.md)).

## Following new releases

BearSSL has had no release since 0.6. Changes to the ported files in its repository are ported when one comes.

## Licenses

The port is derived from BearSSL, under the MIT license (Copyright (c) 2016 Thomas Pornin). PBKDF2 and scrypt are written from their RFCs. BLAKE2s and BLAKE2sp are ported from the BLAKE2 reference implementation, Samuel Neves's, under CC0 1.0 (or the OpenSSL or Apache 2.0 licenses), and so are the known answers in `tests/data`. `hivepack-crypto` is under the MIT license, with BearSSL's notice in its [LICENSE](../crates/crypto/LICENSE). nettle is under the LGPL-3.0-or-later or GPL-2.0-or-later; only the test oracle is built with it, from its sources downloaded by `scripts/testdata.py`, and nothing in the repository is derived from it. `golang.org/x/crypto` is under the BSD-3-Clause license; only `tools/age-oracle` is built with it, and nothing in this crate is derived from it.
