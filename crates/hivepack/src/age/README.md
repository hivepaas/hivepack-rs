# hivepack::age

Decrypting and encrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go (`filippo.io/age`).

> **Status:** decrypts files encrypted with a passphrase, to X25519 keys (`AGE-SECRET-KEY-1…`) or to SSH Ed25519 keys, with or without a passphrase, armored or not, with age's outcomes on C2SP's test vectors and on files age encrypts. Encrypts with a passphrase or to X25519 and SSH Ed25519 keys, armored or not, writing what age writes, byte for byte, given the same random bytes. Reads and writes post-quantum keys (`age1pq1…`), from crates that have not been independently audited: see [docs/crypto.md](../../../../docs/crypto.md). SSH RSA keys and plugins are not ported yet. This crate is not on crates.io.

```rust
use std::io::Read;
use hivepack::age::{Identity, ScryptIdentity, decrypt_file};

let file = std::fs::File::open("backup.tar.zst.age")?;
let passphrase = ScryptIdentity::new(b"correct horse battery staple")?;
let mut plaintext = decrypt_file(file, &[&passphrase as &dyn Identity])?;
let mut data = Vec::new();
plaintext.read_to_end(&mut data)?;
```

With keys from a file that `age-keygen` wrote:

```rust
let keys = hivepack::age::parse_identities(std::fs::File::open("keys.txt")?)?;
let identities: Vec<&dyn Identity> = keys.iter().map(|k| k.as_ref() as &dyn Identity).collect();
let plaintext = decrypt_file(file, &identities)?;
```

With what `age -i` takes: a file of keys, one encrypted with age, or an SSH private key. A passphrase is asked for only when one is needed: an SSH key's when a stanza is for that key, an encrypted file of keys' when one of its keys is first tried.

```rust
use std::sync::Arc;
use hivepack::age::{PassphraseFor, PassphrasePrompt, parse_identities_file};

let prompt: PassphrasePrompt = Arc::new(|what: PassphraseFor| ask_the_person(what));
let keys = parse_identities_file(std::fs::File::open("/home/me/.ssh/id_ed25519")?, prompt)?;
```

`decrypt_file` reads a file as `age --decrypt` does: armored (`-----BEGIN AGE ENCRYPTED FILE-----`) or binary, told apart by its first line. The header is checked before it returns; the payload is decrypted as it is read, 64 KiB at a time, each chunk authenticated before any of it is given out. A file cut short or changed fails when the damage is reached, with what was read before it authentic but incomplete.

`Error` says why a file did not decrypt: `Header` (malformed, or a stanza that asks for too much work), `NoMatch` (no identity fits; its `stanza_types` say what kind of key the file needs), `HeaderMac`, `Armor`, `Payload` or `Io`. A passphrase's work factor is limited to 2^22 by default (4 GiB of memory, as age); `ScryptIdentity::set_max_work_factor` lowers it.

To encrypt:

```rust
use std::io::Write;
use hivepack::age::{Recipient, X25519Recipient, encrypt};

let key = X25519Recipient::parse("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")?;
let file = std::fs::File::create("backup.tar.zst.age")?;
let mut w = encrypt(file, &[&key as &dyn Recipient], None)?;
w.write_all(b"the plaintext")?;
w.finish()?;
```

`SshEd25519Recipient::parse` takes an SSH public key, `parse_recipient` what `age -r` takes, `parse_recipients_file` what `age -R` takes, and `identities_to_recipients` what encrypts to the keys of `age -i`. A recipients file with a key the port cannot encrypt to, such as `ssh-rsa`, fails rather than leave that person out; the keys `age` skips with a warning are listed in `Recipients::skipped`. `X25519Identity::generate` makes a new key, and `to_key_file` what `age-keygen` writes for it.

`ScryptRecipient` is a passphrase, with a work factor of 2^18 unless `set_work_factor` says otherwise, and must be a file's only recipient. For an armored file, `encrypt` writes to an `ArmoredWriter`, finished after it. Without `finish` a file lacks its last chunk and fails to decrypt. The random bytes come from the third argument, a `RandomSource`, or with `None` from `/dev/urandom`: where the system is not Unix a program gives its own, such as the `getrandom` crate, or `encrypt` fails. It fails before writing anything, whenever the source does.

How the port follows age, and how it is checked, is in [docs/age.md](../../../../docs/age.md).

## Speed

Against age v1.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| X25519 and ssh-ed25519, an empty file | 1.86× (1.78–1.93×) | 1.96× (1.78–2.07×) | 2.20× (2.03–2.31×) |
| ML-KEM-768 with X25519, an empty file | 0.34× | 0.34× | 0.59× |
| Passphrase, scrypt | 1.15× (1.02–1.27×) | 1.17× (1.15–1.20×) | 0.99× (0.93–1.04×) |
| A big file's payload | 0.70× | 0.68× | 0.84× |
| A big file in ASCII armor | 2.40× | 2.42× | 1.50× |
| Files of 4 KiB | 1.85× | 1.98× | 2.11× |
| Writing: to X25519 and ssh-ed25519, an empty file | 2.51× (2.26–2.67×) | 2.40× (2.18–2.56×) | 2.76× (2.69–2.89×) |
| Writing: to ML-KEM-768 with X25519, an empty file | 0.70× | 0.64× | 0.96× |
| Writing: a passphrase, scrypt | 1.16× (1.03–1.28×) | 1.18× (1.18–1.18×) | 1.16× (1.15–1.17×) |
| Writing: a big file | 0.53× | 0.54× | 0.77× |
| Writing: a big file in ASCII armor | 0.99× | 1.02× | 1.08× |
| Writing: files of 4 KiB | 2.52× | 2.43× | 2.71× |
| Parsing age keys | 5.46× | 4.87× | 5.51× |
| Reading age recipients | 1.94× | 1.58× | 1.65× |
| Making a key | 5.73× | 5.25× | 6.24× |

**Measured on** `.github/workflows/bench.yml`, on November 10, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the formats are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

Go's ChaCha20-Poly1305 is assembly, which is the big file's gap, in writing as in reading; the rest of a file's work, its key and its header, is faster here. Writing gives the port's random bytes from `getrandom`, as a program does, to a writer that only counts. On one machine with more detail, an AMD Ryzen 9 9950X, the whole table is in [docs/age.md](../../../../docs/age.md#the-speed).

## License

BSD-3-Clause, as age is (see [LICENSE](LICENSE)).
