//! Signing files with SSH Ed25519 keys, in the format of `ssh-keygen -Y sign`
//! (OpenSSH's `PROTOCOL.sshsig`), so that `ssh-keygen -Y verify` checks what this
//! crate signs and this crate checks what it signs; or with hybrid keys of
//! Ed25519 and ML-DSA-65 ([`PrivateKey::generate_hybrid`]), in the same frame, which
//! only this crate checks and which a quantum computer alone does not forge.
//!
//! A signature covers every byte of a file, whatever the file is, and is kept
//! beside it, as `<file>.sig`. The rules, and why each is there, are in the
//! repository: `docs/sign.md`.
//!
//! ```no_run
//! use hivepack::sign::{FILE_NAMESPACE, PrivateKey, PublicKey, Signature, sign, verify};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = PrivateKey::parse(&std::fs::read("id_ed25519")?, None)?;
//! let archive = std::fs::File::open("backup.zip")?;
//! let signature = sign(&key, FILE_NAMESPACE, archive)?;
//! std::fs::write("backup.zip.sig", signature.to_armored())?;
//!
//! // The key to trust comes from elsewhere, never from the signature.
//! let trusted = PublicKey::parse(&std::fs::read("id_ed25519.pub")?)?;
//! let signature = Signature::parse(&std::fs::read("backup.zip.sig")?)?;
//! let archive = std::fs::File::open("backup.zip")?;
//! verify(&signature, &trusted, FILE_NAMESPACE, archive)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod base64;
mod error;
mod key;
mod signature;

pub use error::Error;
pub use key::{PrivateKey, PublicKey};
pub use signature::{FILE_NAMESPACE, HashAlgorithm, Signature, sign, verify};
