# Signing files

`hivepack::sign` signs a file with an SSH Ed25519 key, or a hybrid key of Ed25519 and ML-DSA-65, and checks such a signature. A signature shows that a file is the one the holder of a key signed. It hides nothing: the file stays as readable as it was.

> **Status:** Ed25519 and hybrid keys, whole files, signatures kept beside them. Not yet in packwing.

## The format

The format is `ssh-keygen -Y sign`'s, from OpenSSH's description of it, [`PROTOCOL.sshsig`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig). It was chosen for what a user already has: an SSH key to sign with, and on most systems a program that checks the result without hivepack:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file backup.zip   # or hivepack::sign::sign
echo "me $(cat ~/.ssh/id_ed25519.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I me -n file -s backup.zip.sig < backup.zip
```

This is not a port: the format is short, and the code is written from its description. The signing itself is `ed25519-dalek`'s, through `hivepack::crypto`, and keys are read by `hivepack::age`'s port of Go's SSH key parser.

## Why beside the file

A signature in its own `<file>.sig` covers every byte of any file: ZIP, 7z, tar, RAR, an ISO image, an age file, or anything else. Nothing in the file changes, so every tool still opens it. ZIP has no signature that tools agree on, most formats have nowhere to put one, and one kept inside a file has to leave itself out of what it covers.

Changing the file in any way, even adding an entry, ends what the signature covers: it must be signed again.

## What checking shows, and what it does not

- **The key to trust comes from elsewhere.** `verify` takes it as an argument. The signature names a key too, which says only who claims to have signed: `Signature::public_key` is for showing that, or for finding a key the caller already trusts.
- **A file with no signature is the caller's to refuse.** Removing a `.sig` file removes the signature, so a program that expects one must treat its absence as a failure.
- **A signature has no trusted time.** It does not show when the file was signed, nor that the key was not revoked since.
- **Who the key belongs to is not known here.** `allowed_signers` files, with their principals, validity and revocation, are `ssh-keygen`'s; the caller decides what it trusts.
- **Check the bytes that are used.** Between checking a file and opening it the file can change. A program that cares reads it once, or holds it where others cannot write.

## Stricter than `ssh-keygen`

Every signature `ssh-keygen` writes passes here. `ssh-keygen` 10.2 also takes these, each made from a true signature without the key, and they are refused here (`oracle.rs`: `stricter_than_ssh_keygen`):

- **Version 0.** The version is not covered by what is signed.
- **Reserved bytes that are not empty**, which are not covered either.
- **An `S` past the group's order**, the same signature in another form: `ed25519-dalek`'s `verify_strict`.
- **Text after the armor.**

Also refused here: a public key of small order, whose signatures can be made without a private key, and Base64 with bits left over or anything but line ends inside.

So one signature has one form here, white space aside.

**A private key whose two public keys differ is refused** (`Error::KeyMismatch`). A key file holds the public key beside the private one. Ed25519 signing hashes the public key in, so signing with one that is not the private key's own gives the private key away to anyone who sees two such signatures. `hivepack::crypto` signs with the seed's own key in any case; this tells the user that the file is wrong.

## Hybrid keys

A file signed today may need to be checked when a quantum computer can forge Ed25519. A hybrid key signs with Ed25519 and with ML-DSA-65 (FIPS 204), and a signature holds only if both do: forging one takes breaking both, so a flaw in the young ML-DSA code, or a quantum computer, is not enough alone.

The price is that only this crate checks them, as `ssh-keygen` has no such key and refuses the type, and that a signature is about 7 KB in its armor, against 300 bytes.

They keep SSH's frame, with a type of their own, `mldsa65-ed25519@hivepaas.com`, of the `name@domain` form SSH has for that:

| | Ed25519 | Hybrid |
|---|---|---|
| Public key | `string type, string key` | `string type, string ed25519 (32), string ml-dsa (1,952)` |
| Signature | `string type, string bytes` | `string type, string ed25519 (64), string ml-dsa (3,309)` |
| Hash | SHA-512 written, SHA-256 read | SHA-512 only |
| Signed data | `SSHSIG`, namespace, reserved, hash, digest | `hivepack-hybrid-signature-v1`, `string public key`, namespace, reserved, hash, digest |
| ML-DSA's context | | the type's name |

**Neither half can be cut out and used.** The signed data does not start with `SSHSIG`, so the Ed25519 half is no `ssh-keygen` signature, and it names both public keys, so neither half can be moved under another key. This matters if one half's key is ever used on its own.

**Signing is deterministic in both halves**, FIPS 204's optional form for ML-DSA: a key signs a file in one way, with no random bytes to get wrong, which also lets the tests compare with OpenSSL byte for byte.

**A hybrid key's file is this crate's.** `PrivateKey::generate_hybrid` makes a key, from two seeds of 32 bytes kept rather than the expanded keys, and `PrivateKey::to_file` writes it: Base64 in armor, or with a passphrase that text in an armored age file under scrypt, so that `hivepack::age` does the encryption and `age --decrypt` can recover the seeds. The public key's line is written by `Display`, and read back by `PublicKey::parse`.

## Limits

- **Ed25519 and hybrid keys only.** RSA and ECDSA keys are refused (`Error::UnsupportedKey`), both to sign and to check. Hardware keys (`sk-ssh-ed25519`), certificates and SSH agents are not read.
- **SSH keys are not made here.** `ssh-keygen -t ed25519` makes one, with a passphrase if it is asked for one.
- **`ml-dsa` has not been independently audited**, as its README says: see [crypto.md](crypto.md). This is why it never signs alone.
- **`aes256-ctr` keys only among encrypted ones**, as in [age.md](age.md).

## Tests

- **`tests/oracle.rs`**, where there is an `ssh-keygen`: signatures equal to its own byte for byte, across sizes around the hash's block and this crate's buffer, for three namespaces; each checks the other's; SHA-256 signatures read; encrypted keys, fingerprints, and RSA keys refused. Of signatures and files damaged at random, `ssh-keygen` takes everything taken here, and what is taken here has the signature's own bytes, for the file's own bytes. `HIVEPACK_SIGN_DAMAGED` sets how many, 300 by default.
- **`tests/sign.rs`**, everywhere: signatures `ssh-keygen` made, kept in the test; another key's signature that names this one; a file that cannot be read; every cut of a signature; a private key whose halves do not match.
- **`tests/hybrid.rs`**: a hybrid signature rebuilt by hand, each half checked apart, ML-DSA's by OpenSSL where it has it; either half damaged fails; the Ed25519 half given to `ssh-keygen` as its own fails; key files with and without a passphrase, the former opened by `hivepack::age` too.
- **`hivepack::crypto`'s `tests/mldsa.rs`**: keys and deterministic signatures equal to OpenSSL 3.5's, byte for byte, each checking the other's, and what it gave, kept for where it has none.
- **The `sign` fuzz target**: what reads must write back as it came, and a signature made must pass, and fail on a changed file, with both kinds of key.

## What comes next

- **Signing and checking in packwing**, with the choice of keys and what the window shows.
- **A signed list of each entry's hash**, should checking one entry of a remote archive without reading it all be needed.
