# Porting age

`hivepack-age` decrypts and encrypts files of [age](https://age-encryption.org), the encryption tool and format by Filippo Valsorda, in safe Rust. age files are often archives: `tar | zstd | age > backup.tar.zst.age`. An application reads the decrypted stream as it would read the file underneath.

## The source

The port follows **age v1.3.2** (`filippo.io/age`, the reference implementation, in Go; tag `v1.3.2`, module sum `h1:r6RSZLFSMm6rzKepZ7ZAYkKCu14f3/Me8c7uKYh7C8c=`), the latest release as of October 2026. `hivepack_age::UPSTREAM_VERSION` names it. The format is specified by C2SP (`c2sp.org/age`); where the specification leaves a choice, such as the limits on a header, the port does what age does.

Each Go file ported is a module, its functions keep their names in snake case, and each doc comment names the Go original, as [porting.md](porting.md) asks of the other ports. Decrypting and encrypting are ported for the keys below.

| age | Port | What |
|---|---|---|
| `age.go` | `age.rs` (`decrypt`, `Decryptor`, `Identity`, `FileKey`, `FileKeyIdentity`, `encrypt`, `Encryptor`, `Recipient`) | the header's stanzas unwrapped by the identities, native ones first; the header's MAC; the payload's nonce; a file key known already (`NewInjectedFileKeyIdentity`); writing a file, with the labels that keep recipients from being mixed |
| `primitives.go` | `primitives.rs` | ChaCha20-Poly1305 with a zero nonce, the header's MAC, the payload's key |
| `internal/format/format.go` | `format.rs` (`Stanza`) | the header: intro, stanzas, closing line, with age's limits (2 MiB, 1,024 stanzas, 128 arguments); what the MAC is computed over |
| `internal/stream/stream.go` | `stream.rs` | the payload: STREAM over ChaCha20-Poly1305, 64 KiB chunks, the last marked in the nonce |
| `armor/armor.go` | `armor.rs` (`ArmoredReader`, `ArmoredWriter`) | the ASCII armor |
| `scrypt.go` | `scrypt.rs` (`ScryptIdentity`, `ScryptRecipient`) | passphrases, the limit on their work factor, and the work factor to encrypt with |
| `x25519.go` | `x25519.rs` (`X25519Identity`, `X25519Recipient`) | X25519 keys, `AGE-SECRET-KEY-1…` and `age1…` |
| `internal/bech32/bech32.go` | `bech32.rs` | the keys' encoding |
| `parse.go` | `parse.rs` (`parse_identities`) | files of keys, as `age-keygen` writes them |
| `agessh/agessh.go`, `agessh/encrypted_keys.go` | `agessh.rs` (`SshEd25519Identity`, `EncryptedSshIdentity`, `SshEd25519Recipient`) | SSH Ed25519 keys: the stanza's fingerprint, the key's X25519 form (the SHA-512 of its seed, or for a public key `ed25519_public_to_x25519`), the tweak; a key protected by a passphrase, asked for when a stanza's fingerprint is the key's |
| `parseRecipient`, `parseRecipientsFile` and `unsupportedSSHKey` in `cmd/age/parse.go`; `identitiesToRecipients` in `cmd/age/age.go` | `recipient_file.rs` (`parse_recipient`, `parse_recipients_file`), `age.rs` (`identities_to_recipients`) | what `age -r`, `-R` and `-i` take when encrypting; the keys left out are listed |
| `GenerateX25519Identity`; what `age-keygen` writes | `x25519.rs` (`X25519Identity::generate`, `to_key_file`) | new keys |
| `parseIdentitiesFile`, `parseIdentities`, `parseSSHIdentity` in `cmd/age/parse.go`; `cmd/age/encrypted_keys.go` | `identity_file.rs` (`parse_identities_file`, `LazyScryptIdentity`) | what `age -i` takes: a file of keys, an SSH key in PEM, or a file of keys encrypted with age and a passphrase, decrypted when one of its keys is first needed; and what `age --decrypt` uses without `-i`, a passphrase asked for only when the file is encrypted with one |
| `ssh/keys.go` of `golang.org/x/crypto` (`ParseRawPrivateKey`, `ParseRawPrivateKeyWithPassphrase`, `parseOpenSSHPrivateKey`, `ParsePublicKey`, `ParseAuthorizedKey`) | `ssh_keys.rs` | OpenSSH's private key format (`openssh-key-v1`), encrypted with bcrypt_pbkdf and AES-256 in counter mode or not; `authorized_keys` lines |
| `ssh/internal/bcrypt_pbkdf` of `golang.org/x/crypto` | `bcrypt_pbkdf.rs` | bcrypt_pbkdf, after OpenBSD's |
| `blowfish` of `golang.org/x/crypto` | `blowfish.rs` | Blowfish, as bcrypt needs it |
| Go's `encoding/pem` (`Decode`) | `pem.rs` | PEM blocks |
| `decrypt` in `cmd/age/age.go` | `lib.rs` (`decrypt_file`) | what `age --decrypt` does first: armor told apart from a binary file by its first line, after up to 1 KiB of white space; files whose intro PowerShell's redirection mangled refused |
| Go's `encoding/base64`, `Strict()` | `base64.rs` | strict base64, without padding in headers and with it in the armor |

The cryptography is `hivepack-crypto`'s ([crypto.md](crypto.md)): SHA-256, SHA-512, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, X25519, scrypt and AES, ported from BearSSL or written from their RFCs, in place of Go's standard library and `golang.org/x/crypto`. MACs and tags are compared in constant time. Blowfish and bcrypt_pbkdf, which only SSH keys need, are ported from `golang.org/x/crypto` into this crate. Blowfish looks its S-boxes up with the data, so its time depends on the passphrase, as bcrypt is defined; it runs once, when a key is decrypted. 16 rounds, `ssh-keygen`'s default, take 72 ms, as long as Go takes (Ryzen 9 9950X).

To decrypt, no Edwards arithmetic is needed: age turns an Ed25519 private key into an X25519 one with the SHA-512 of its seed, and the X25519 public key is computed from that. To encrypt to a public key, and to read one that protects a private key, `hivepack-crypto` checks that it is a point of the curve and maps it to X25519 ([crypto.md](crypto.md)).

## What differs

- **Errors are a type.** age's errors are Go values that its tests tell apart by type (`*format.ParseError`, `*age.NoIdentityMatchError`, `*armor.Error`) or by message (`bad header MAC`). Here they are `Error`'s variants, which match the outcomes C2SP's vectors name: `Header`, `NoMatch`, `HeaderMac`, `Armor` and `Payload`, plus `Io`. The messages are age's, near enough: Go's `%q` is Rust's `{:?}`, and base64's errors do not give the position. An identity's `unwrap` returns `UnwrapError::Incorrect` where age wraps `ErrIncorrectIdentity`, and `UnwrapError::Invalid` for its other errors, which end the decryption as a header failure.
- **Errors travel inside `io::Error`.** The armor's and the payload's errors are found while reading, through `io::Read`; they come as `io::Error`s of kind `InvalidData` that hold the `Error`, and `Error::from` takes it back out. A reader that failed returns its error again at every later read, as age's do.
- **Lines are read whole.** age peeks at three bytes for the header's closing line before reading a stanza; the port reads the next line and looks at its start, which cannot be confused, as a stanza starts with `->` and the closing line with `---`. The armor reader reads lines of at most 4 KiB, where age reads them whole whatever their length; a longer line fails as age would fail it, as too long or as not the first line.
- **No panics.** `SetMaxWorkFactor` and `SetWorkFactor` with a value out of 1 to 30 bring it into the range, where age panics; a chunk counter that wraps around, after 2^88 chunks, is an error.
- **Random bytes are given.** age calls `crypto/rand`, which cannot fail. `encrypt` takes a `RandomSource`, as `hivepack-zip` and `hivepack-7z` do, or reads `/dev/urandom` on Unix; Windows' own function would need `unsafe` code, so a program gives a source there. If the source fails, `encrypt` fails with `EncryptError::Random` before writing anything. The bytes are taken in age's order: the file key, each recipient's, the nonce.
- **A file is ended with `finish`.** age's writers end with `Close`. `Encryptor::finish` and `ArmoredWriter::finish` take the writer by value, flush the destination and give it back, so a closed writer cannot be written to. Dropped without it, a file lacks its last chunk and fails to decrypt. A failure of the destination is kept, and returned by every later write and by `finish`.
- **`RecipientWithLabels` is a method** of `Recipient`, `wrap_with_labels`, whose default gives no labels.
- **Post-quantum identities** (`AGE-SECRET-KEY-PQ-1…`, `mlkem768x25519` stanzas, age 1.3) are recognised in key files and refused as not supported yet; a file encrypted to one fails with `NoMatch`, whose `stanza_types` say so.
- **SSH keys: Ed25519 only.** `ssh-rsa` keys, ECDSA and DSA keys, and the PEM formats of PKCS#1, PKCS#8 and SEC 1 (`openssl`'s, and old `ssh-keygen`'s RSA keys) are recognised and refused as not supported yet; so are OpenSSH keys encrypted with `aes256-cbc` (`ssh-keygen -Z aes256-cbc`), which need AES decryption, where `ssh-keygen`'s default is `aes256-ctr`. Go reads all of these. A key whose public half is not in the file, which only the old PEM formats do, is refused rather than looked for in a `.pub` file next to it.
- **Passphrases come through a callback** (`PassphrasePrompt`), told whether it is for the file, an SSH key or a file of keys, where age prompts on the terminal; it is called as often as age would prompt, which the tests count. A wrong passphrase fails the decryption, as in age; asking again is the callback's to do. The warning age prints when an encrypted file of keys matches nothing is left to the application.
- **The file key is given out** (`Decryptor::file_key`), checked against the header's MAC, where age's `Decrypt` keeps it to itself and `DecryptHeader` gives it for a detached header. With `FileKeyIdentity`, the same file decrypts again without its identity: `hivepack-open` ([open.md](open.md)) reads a file more than once, and asks for its passphrase once. `cmd/age`'s `LazyScryptIdentity` is public here, for the same use.
- **`ssh-ed25519` stanzas wrap a file key of any length**, as agessh's own `aeadDecrypt` does not check it; `FileKey` holds what the stanza gives.
- **What cannot be encrypted to stops a recipients file.** age encrypts to `ssh-rsa` keys of 2048 bits or more, post-quantum and tagged recipients and plugins. The port does not, and a file that has one fails with the line's number, rather than encrypt without that person. Other SSH key types and shorter RSA keys are skipped, as age skips them with a warning; `Recipients::skipped` lists them for the program to show. Other SSH key types are not parsed past their type, so that a malformed one on a line counts as found where Go goes on looking.
- **A secret key is not `Display`.** age's `String` is `to_secret_string`, so that it is not printed by accident, and `to_key_file` takes the date, which `age-keygen` asks the clock for.
- **Not ported:** `EncryptReader` (nothing here needs a file encrypted as it is read, rather than as it is written), the library's `ParseRecipients` (`parse_recipients_file` takes more), `DecryptReaderAt` (random access), plugins (`age-plugin-*`, which age runs as programs, refused in key files), the hybrid post-quantum recipients, `ssh-rsa`, and `age-inspect`.

## Bounded resources

What the port allocates is bounded before it reads a file, as age bounds it: the header to 2 MiB, 1,024 stanzas and 128 arguments each; the payload to one chunk of 64 KiB at a time; a key file to 16 MiB and lines of 64 KiB. A passphrase's work factor is the exception that age sets for the caller to choose: 2^22 by default, which is 4 GiB of memory and about 5 seconds on a Ryzen 9 9950X. A file asking for more fails at once, without the work. An application that opens files from strangers, as an archiver does, should lower it with `ScryptIdentity::set_max_work_factor` (or `LazyScryptIdentity`'s): age's own default when encrypting is 2^18 (256 MiB, 0.3 s), and each step up doubles the time and the memory. scrypt's memory is allocated with `try_reserve_exact`, so a machine without it gets an error rather than an abort.

## The speed

`tools/age-bench` times the port against age v1.3.2, in a program of its own (`tools/age-bench/go`), on files age makes:

```sh
python3 scripts/testdata.py fetch --group bench
cargo run --release -p age-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
```

AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, Go 1.27.2 with age v1.3.2, October 2026, the Silesia corpus cut to 64 MiB, in memory. Each speed is the best of five rounds taken in turn. Both read the same bytes.

| Workload | The port | age | Port / age |
|---|---|---|---|
| **Finding the file key, in an empty file** | | | |
| X25519 | 35,903 files/s | 15,877 files/s | 2.26× |
| X25519, the last of ten recipients | 4,069 files/s | 1,827 files/s | 2.23× |
| ssh-ed25519 | 19,494 files/s | 8,306 files/s | 2.35× |
| Passphrase, scrypt at 2^14 | 71.2 files/s | 55.7 files/s | 1.28× |
| Passphrase, scrypt at 2^18, age's default | 3.3 files/s | 3.2 files/s | 1.02× |
| **Reading the payload** | | | |
| Big file | 905 MB/s | 2,279 MB/s | 0.40× |
| Big file, in ASCII armor | 668 MB/s | 519 MB/s | 1.29× |
| Files of 4 KiB | 30,981 files/s | 15,345 files/s | 2.02× |
| **Writing a file** (November 2026, the same machine) | | | |
| Empty, to X25519 | 20,892 files/s | 10,302 files/s | 2.03× |
| Empty, to ten X25519 keys | 2,247 files/s | 1,061 files/s | 2.12× |
| Empty, to ssh-ed25519 | 14,138 files/s | 6,922 files/s | 2.04× |
| Empty, scrypt at 2^14 | 76.5 files/s | 61.4 files/s | 1.25× |
| Empty, scrypt at 2^18, age's default | 3.5 files/s | 3.4 files/s | 1.02× |
| Big file | 990 MB/s | 3,380 MB/s | 0.29× |
| Big file, in ASCII armor | 750 MB/s | 1,167 MB/s | 0.64× |
| Files of 4 KiB | 19,221 files/s | 10,064 files/s | 1.91× |
| **Parsing keys and making them** | | | |
| A file of 1,000 age keys | 43 k keys/s | 20 k keys/s | 2.19× |
| A file of 1,000 recipients (November 2026) | 1,317 k keys/s | 694 k keys/s | 1.90× |
| Making a key (November 2026) | 46 k keys/s | 21 k keys/s | 2.16× |

With the `unsafe-fast` feature, a big file is written at 1,715 MB/s (0.51×), and in ASCII armor at 1,091 MB/s (0.95×), three rounds. Files written go to a writer that only counts, and the port's random bytes come from `getrandom`.

The big file's gap is ChaCha20-Poly1305, which Go runs in AVX2 assembly and the port in constant-time safe Rust ([crypto.md](crypto.md#speed)). ASCII armor went from 0.27× to 1.29×: a full line of 64 columns already in the reader's buffer is now decoded in place, with a table, where each line was two allocations and a `match` on each character. Anything else about a line goes the old way, with nothing consumed, so that errors stay as they were. The armor row was measured after that work, the others before it, which does not touch them. Parsing keys is X25519, for each key's public half. The rows with X25519 went from 0.72–0.92× to 2.02–2.35× with 51-bit words on 64-bit machines, measured after that work. Other work started on the machine towards the end of the run, though the best of the rounds should hide most of it.

## How it is shown

- **`tests/cctv.rs`**: C2SP's CCTV test vectors for age (`c2sp.org/CCTV/age` at commit 4448f2097b2d, the module age v1.3.2 tests with), fetched by `scripts/testdata.py` from Go's module proxy into the `cctv-age` set. Each vector is a file with the outcome it must have, and the SHA-256 of all the plaintext given out, even when the payload fails later. As age's `testkit_test.go` does, an armored vector goes through the armor reader; then the vector goes through `decrypt_file` too, which must agree, except that a file with garbage before its armor is not taken for armored and fails as a header. All 128 vectors with X25519 keys and passphrases pass; the 19 with post-quantum keys are skipped.
- **`tests/encrypt.rs`**: writing, compared with age itself through the same oracle, which replaces `crypto/rand.Reader` with the bytes it is given. Given the same random bytes, the port must write the file age writes, byte for byte, and take as many of them. 1,200 requests are compared where the oracle is built (Linux and macOS in CI), to one to four X25519 keys, SSH Ed25519 keys, a recipients file, a file of keys or a passphrase with a work factor of 2^1 to 2^4, armored or not, with payloads of 0 to 140,000 bytes around the 64 KiB chunks and the armor's lines, in pieces of random sizes; among them, what age refuses: passphrases mixed with keys or each other, empty passphrases, points of low order, what is no key. The SSH keys are RFC 8032's, random bytes, and encodings at the edge of the curve's modulus and sign bit, on lines with comments, options, quotes, CRLF, several lines, base64 without padding, a type that is not the key's, keys too short or with bytes after them. The recipients files have comments up to past 64 KiB, lines around 8 KiB, invalid UTF-8, secret keys, and SSH keys that are skipped or malformed: ECDSA, RSA below 2048 bits, RSA with a wrong exponent, base64 with stray bits. New keys come from `keygen` requests. SSH private keys and files of keys encrypted with age are compared where the oracle makes them, without the recorded file. `ssh-rsa` keys age takes, post-quantum recipients and plugins are not compared, as the port refuses them on purpose; that is tested by itself. `testdata/oracle/age-encrypt.txt` replays the SHA-256 of age's answers to the first 300 everywhere else. `X25519Recipient::parse` is compared with age's on keys with a character changed. A source of random bytes or a destination that fails, a file not finished, and the system's random bytes (two files differ, and age decrypts them) are tested too.
- **`tests/oracle.rs`**: comparison with age itself, through `tools/age-oracle`, the Go program of [crypto.md](crypto.md), now built with age v1.3.2 too, and with a copy of what `cmd/age` does with identity files (`tools/age-oracle/identities.go`), which is in package `main` there. age encrypts payloads of 0 to 200,000 bytes, around the 64 KiB chunks, to one to four X25519 keys, to one to three SSH Ed25519 keys (made by `ssh-keygen`'s rules: one without a passphrase, two with), or to a passphrase with a work factor of 2^1 to 2^4, armored or not. Three files in four are then damaged one of a dozen ways: a bit flipped anywhere or in the header, cut anywhere or at a chunk's end, bytes added, removed or inserted, CRLF line ends, a letter's case changed, a header line said twice or left out, the header of another file to the same recipients, white space or garbage before it. Both decrypt it with the right and wrong keys, the right and wrong passphrases, and work factors allowed or not; SSH keys and files of keys come as identity files read as `age -i` reads them, with comments, CRLF and stray public keys in the files of keys, some of those encrypted with age, armored or not, and one identity file in five damaged, a bit flipped or cut short. Passphrases are right, wrong or refused. The port reads in pieces of random sizes; the outcome (or the identity file's failure), the length and SHA-256 of the plaintext given out, and the number of passphrases asked for must be the same. 600 files are compared where the oracle is built (Linux and macOS in CI), all six outcomes among them, and `testdata/oracle/age.txt` replays 300 small ones everywhere else.
- **Fuzzing**: the `age_recipients` target reads any input as recipients (30 seconds in CI), and what it reads must give text that reads back. The `age_encrypt` target writes files (30 seconds in CI): to two X25519 keys or a passphrase, armored or not, whole and in pieces, which must give the same file, which must decrypt to the plaintext and, cut by a byte, must not read in full. The `age_keys` target reads any input as an identity file (30 seconds in CI, its corpus seeded with the recorded ones). The `age` target decrypts any input with CCTV's usual X25519 key and the passphrase `password` (work factors up to 2^4), which many of the recorded files use, so that its corpus, seeded with them in CI, gets past the header. It reads each file twice, in pieces of different sizes; both reads must give the same plaintext and end the same way, and a panic is a bug.
- **Unit tests**: base64 with RFC 4648's vectors and the strict cases, Bech32 with BIP 173's, PEM blocks as Go decodes them, and bcrypt_pbkdf with the vectors of `golang.org/x/crypto`'s tests, after OpenBSD's (its Blowfish setup among them).

## Following new releases

A new release of age is compared with the port's files, and its changes to them are ported; the CCTV module it tests with is the one the vectors come from.

## Next

`ssh-rsa`, with RSA-OAEP from BearSSL; `aes256-cbc` keys, with AES decryption; the post-quantum recipients, once ML-KEM is ported; encrypting.

## Licenses

The port is derived from age, under the BSD-3-Clause license (Copyright 2019 The age Authors, 2019 Google LLC, 2022 Filippo Valsorda), and its SSH and PEM parts from `golang.org/x/crypto` and Go, under the BSD-3-Clause license too (Copyright 2009 The Go Authors); `hivepack-age` is under the same license, with both notices in its [LICENSE](../crates/age/LICENSE). The CCTV vectors are under 0BSD, CC0-1.0 or the Unlicense, to the user's choice; they are fetched, not committed. `tools/age-oracle` is built with age and `golang.org/x/crypto`, both BSD-3-Clause, and only the tests run it.
