# hivepack::sign

Signing files with SSH Ed25519 keys, in the format of `ssh-keygen -Y sign`. Written from OpenSSH's description of the format, `PROTOCOL.sshsig`, and checked against `ssh-keygen`.

Hybrid keys of Ed25519 and ML-DSA-65 keep its frame, in a type of their own that only this crate checks.

See [docs/sign.md](../../../../docs/sign.md).
