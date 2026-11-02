# hivepack-age

Decrypting and encrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go (`filippo.io/age`).

> **Status:** decrypts files encrypted with a passphrase, to X25519 keys (`AGE-SECRET-KEY-1…`) or to SSH Ed25519 keys, with or without a passphrase, armored or not, with age's outcomes on C2SP's test vectors and on files age encrypts. Encrypts with a passphrase or to X25519 and SSH Ed25519 keys, armored or not, writing what age writes, byte for byte, given the same random bytes. SSH RSA keys, post-quantum keys and plugins are not ported yet. This crate is not on crates.io.

```rust
use std::io::Read;
use hivepack_age::{Identity, ScryptIdentity, decrypt_file};

let file = std::fs::File::open("backup.tar.zst.age")?;
let passphrase = ScryptIdentity::new(b"correct horse battery staple")?;
let mut plaintext = decrypt_file(file, &[&passphrase as &dyn Identity])?;
let mut data = Vec::new();
plaintext.read_to_end(&mut data)?;
```

With keys from a file that `age-keygen` wrote:

```rust
let keys = hivepack_age::parse_identities(std::fs::File::open("keys.txt")?)?;
let identities: Vec<&dyn Identity> = keys.iter().map(|k| k.as_ref() as &dyn Identity).collect();
let plaintext = decrypt_file(file, &identities)?;
```

With what `age -i` takes: a file of keys, one encrypted with age, or an SSH private key. A passphrase is asked for only when one is needed: an SSH key's when a stanza is for that key, an encrypted file of keys' when one of its keys is first tried.

```rust
use std::sync::Arc;
use hivepack_age::{PassphraseFor, PassphrasePrompt, parse_identities_file};

let prompt: PassphrasePrompt = Arc::new(|what: PassphraseFor| ask_the_person(what));
let keys = parse_identities_file(std::fs::File::open("/home/me/.ssh/id_ed25519")?, prompt)?;
```

`decrypt_file` reads a file as `age --decrypt` does: armored (`-----BEGIN AGE ENCRYPTED FILE-----`) or binary, told apart by its first line. The header is checked before it returns; the payload is decrypted as it is read, 64 KiB at a time, each chunk authenticated before any of it is given out. A file cut short or changed fails when the damage is reached, with what was read before it authentic but incomplete.

`Error` says why a file did not decrypt: `Header` (malformed, or a stanza that asks for too much work), `NoMatch` (no identity fits; its `stanza_types` say what kind of key the file needs), `HeaderMac`, `Armor`, `Payload` or `Io`. A passphrase's work factor is limited to 2^22 by default (4 GiB of memory, as age); `ScryptIdentity::set_max_work_factor` lowers it.

To encrypt:

```rust
use std::io::Write;
use hivepack_age::{Recipient, X25519Recipient, encrypt};

let key = X25519Recipient::parse("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")?;
let file = std::fs::File::create("backup.tar.zst.age")?;
let mut w = encrypt(file, &[&key as &dyn Recipient], None)?;
w.write_all(b"the plaintext")?;
w.finish()?;
```

`SshEd25519Recipient::parse` takes an SSH public key, `parse_recipient` what `age -r` takes, `parse_recipients_file` what `age -R` takes, and `identities_to_recipients` what encrypts to the keys of `age -i`. A recipients file with a key the port cannot encrypt to, such as `ssh-rsa`, fails rather than leave that person out; the keys `age` skips with a warning are listed in `Recipients::skipped`. `X25519Identity::generate` makes a new key, and `to_key_file` what `age-keygen` writes for it.

`ScryptRecipient` is a passphrase, with a work factor of 2^18 unless `set_work_factor` says otherwise, and must be a file's only recipient. For an armored file, `encrypt` writes to an `ArmoredWriter`, finished after it. Without `finish` a file lacks its last chunk and fails to decrypt. The random bytes come from the third argument, a `RandomSource`, or with `None` from `/dev/urandom`: where the system is not Unix a program gives its own, such as the `getrandom` crate, or `encrypt` fails. It fails before writing anything, whenever the source does.

How the port follows age, and how it is checked, is in [docs/age.md](../../docs/age.md).

## Speed

Against age v1.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| X25519 and ssh-ed25519, an empty file | 2.15× (2.14–2.16×) | 2.56× (2.34–2.73×) | 2.43× (2.39–2.51×) |
| Passphrase, scrypt | 1.07× (0.96–1.19×) | 1.00× (0.96–1.05×) | 1.10× (1.10–1.11×) |
| A big file's payload | 0.24× | 0.34× | 0.56× |
| A big file in ASCII armor | 1.11× | 1.15× | 1.22× |
| Files of 4 KiB | 1.85× | 2.35× | 2.06× |
| Writing: to X25519 and ssh-ed25519, an empty file | 2.12× (2.07–2.19×) | 2.23× (2.15–2.33×) | 2.32× (2.11–2.59×) |
| Writing: a passphrase, scrypt | 1.07× (0.96–1.18×) | 1.00× (0.98–1.02×) | 1.03× (1.00–1.06×) |
| Writing: a big file | 0.17× | 0.26× | 0.50× |
| Writing: a big file in ASCII armor | 0.45× | 0.53× | 0.70× |
| Writing: files of 4 KiB | 1.92× | 2.04× | 2.15× |
| Parsing age keys | 2.24× | 2.36× | 2.64× |
| Reading age recipients | 1.97× | 1.54× | 1.84× |
| Making a key | 2.24× | 2.40× | 2.56× |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| X25519 and ssh-ed25519, an empty file | 2.31× (2.19–2.43×) | 2.60× (2.38–2.77×) | 2.65× (2.48–2.79×) |
| Passphrase, scrypt | 1.09× (0.95–1.23×) | 1.12× (1.10–1.14×) | 1.12× (1.01–1.23×) |
| A big file's payload | 0.58× | 0.42× | 0.88× |
| A big file in ASCII armor | 1.72× | 1.90× | 1.52× |
| Files of 4 KiB | 2.23× | 2.39× | 2.23× |
| Writing: to X25519 and ssh-ed25519, an empty file | 2.18× (2.16–2.20×) | 2.30× (2.28–2.31×) | 2.45× (2.33–2.56×) |
| Writing: a passphrase, scrypt | 1.04× (0.89–1.20×) | 1.11× (1.09–1.13×) | 1.13× (1.06–1.20×) |
| Writing: a big file | 0.50× | 0.33× | 0.67× |
| Writing: a big file in ASCII armor | 0.90× | 0.78× | 0.95× |
| Writing: files of 4 KiB | 2.11× | 2.22× | 2.63× |
| Parsing age keys | 2.18× | 2.29× | 2.41× |
| Reading age recipients | 1.96× | 1.55× | 1.72× |
| Making a key | 2.20× | 2.32× | 2.37× |

**Measured on** `.github/workflows/bench.yml`, on November 2, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on AMD EPYC 9V74 (4 threads); Windows x86-64 on Intel Family 6 Model 207 (4 threads); macOS arm64 on Apple M2 Pro (Virtual) (5 threads). With it: Linux x86-64 on AMD EPYC 9V45 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

Go's ChaCha20-Poly1305 is assembly, which is the big file's gap, in writing as in reading; the rest of a file's work, its key and its header, is faster here. Writing gives the port's random bytes from `getrandom`, as a program does, to a writer that only counts. On one machine with more detail, an AMD Ryzen 9 9950X, the whole table is in [docs/age.md](../../docs/age.md#the-speed).

## License

BSD-3-Clause, as age is (see [LICENSE](LICENSE)).
