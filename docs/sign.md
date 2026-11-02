# Signing files

`hivepack-sign` signs a file with an SSH Ed25519 key and checks such a signature. A signature shows that a file is the one the holder of a key signed. It hides nothing: the file stays as readable as it was.

> **Status:** Ed25519 keys, whole files, signatures kept beside them. Not yet in packwing.

## The format

The format is `ssh-keygen -Y sign`'s, from OpenSSH's description of it, [`PROTOCOL.sshsig`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig). It was chosen for what a user already has: an SSH key to sign with, and on most systems a program that checks the result without hivepack:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file backup.zip   # or hivepack_sign::sign
echo "me $(cat ~/.ssh/id_ed25519.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I me -n file -s backup.zip.sig < backup.zip
```

This is not a port: the format is short, and the code is written from its description. The signing itself is `ed25519-dalek`'s, through `hivepack-crypto`, and keys are read by `hivepack-age`'s port of Go's SSH key parser.

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

**A private key whose two public keys differ is refused** (`Error::KeyMismatch`). A key file holds the public key beside the private one. Ed25519 signing hashes the public key in, so signing with one that is not the private key's own gives the private key away to anyone who sees two such signatures. `hivepack-crypto` signs with the seed's own key in any case; this tells the user that the file is wrong.

## Limits

- **Ed25519 keys only.** RSA and ECDSA keys are refused (`Error::UnsupportedKey`), both to sign and to check. Hardware keys (`sk-ssh-ed25519`), certificates and SSH agents are not read.
- **No keys are made here.** `ssh-keygen -t ed25519` makes one, with a passphrase if it is asked for one.
- **`aes256-ctr` keys only among encrypted ones**, as in [age.md](age.md).

## Tests

- **`tests/oracle.rs`**, where there is an `ssh-keygen`: signatures equal to its own byte for byte, across sizes around the hash's block and this crate's buffer, for three namespaces; each checks the other's; SHA-256 signatures read; encrypted keys, fingerprints, and RSA keys refused. Of signatures and files damaged at random, `ssh-keygen` takes everything taken here, and what is taken here has the signature's own bytes, for the file's own bytes. `HIVEPACK_SIGN_DAMAGED` sets how many, 300 by default.
- **`tests/sign.rs`**, everywhere: signatures `ssh-keygen` made, kept in the test; another key's signature that names this one; a file that cannot be read; every cut of a signature; a private key whose halves do not match.
- **The `sign` fuzz target**: what reads must write back as it came, and a signature made must pass, and fail on a changed file.

## What comes next

- **Signing and checking in packwing**, with the choice of keys and what the window shows.
- **Ed25519 and ML-DSA-65 together**, once a crate for ML-DSA has been looked at. `ssh-keygen` has no such key, so it would be a format of hivepack's.
- **A signed list of each entry's hash**, should checking one entry of a remote archive without reading it all be needed.
