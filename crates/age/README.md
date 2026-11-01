# hivepack-age

Decrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go (`filippo.io/age`).

> **Status:** decrypts files encrypted with a passphrase, to X25519 keys (`AGE-SECRET-KEY-1…`) or to SSH Ed25519 keys, with or without a passphrase, armored or not, with age's outcomes on C2SP's test vectors and on files age encrypts. SSH RSA keys, post-quantum keys, plugins and encrypting are not ported yet. This crate is not on crates.io.

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

How the port follows age, and how it is checked, is in [docs/age.md](../../docs/age.md).

## Speed

Against age v1.3.2, the reference implementation in Go, with `tools/age-bench`. Above 1× the port is faster.

| Port / age | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| X25519 and ssh-ed25519, an empty file | 2.20–2.24× | 2.08–2.22× | 2.12–2.36× |
| Parsing age keys | 2.27× | 2.13× | 2.38× |
| Files of 4 KiB | 1.94× | 1.95× | 1.96× |
| A big file in ASCII armor | 1.23× | 1.19× | 1.29× |
| Passphrase, scrypt | 0.99–1.25× | 1.10–1.15× | 0.99–1.23× |
| A big file's payload | 0.22× | 0.33× | 0.52× |

**Measured on** GitHub's runners with `.github/workflows/bench.yml`, on October 31, 2026, the best of five rounds taken in turn: Linux on an AMD EPYC 7763 (4 threads), Windows Server 2025 on an AMD processor (family 26, model 2, 4 threads), and macOS 26 on a virtual Apple M1 (3 threads). All with rustc 1.99.1 and Go 1.27.2. These are shared machines, so the ratios hold better than the speeds, and a runner's processor can differ from one run to the next.

Go's ChaCha20-Poly1305 is assembly, which is the big file's gap. On one machine with more detail, an AMD Ryzen 9 9950X, the whole table is in [docs/age.md](../../docs/age.md#the-speed).

**With the `unsafe-fast` feature**, off by default: a big file at 0.42–0.75×, and in armor at 1.40–1.94×, on GitHub's runners. See [docs/unsafe.md](../../docs/unsafe.md#the-processors-instructions).

## License

BSD-3-Clause, as age is (see [LICENSE](LICENSE)).
