//! OpenSSH private keys, as age reads them: port of the part of
//! `golang.org/x/crypto/ssh` that `agessh` calls (`keys.go`:
//! `ParseRawPrivateKey`, `ParseRawPrivateKeyWithPassphrase`,
//! `parseOpenSSHPrivateKey` and its decryption; `ParsePublicKey` and
//! `Marshal` for Ed25519; the wire format of `messages.go`).
//!
//! Differs from Go: only Ed25519 keys are read. RSA, ECDSA and DSA keys,
//! and the PKCS#1, PKCS#8 and SEC 1 PEM formats, are recognised and refused
//! as not supported; so are OpenSSH keys encrypted with `aes256-cbc`
//! (`ssh-keygen -Z aes256-cbc`), which Go reads. `ssh-keygen` encrypts with
//! `aes256-ctr` by default.

use hivepack_crypto::{AES_BLOCK_LENGTH, Aes};

use crate::armor::trim_space_start;
use crate::base64;
use crate::bcrypt_pbkdf;
use crate::pem;

/// `KeyAlgoED25519`.
pub(crate) const KEY_ALGO_ED25519: &str = "ssh-ed25519";

/// `privateKeyAuthMagic`.
const PRIVATE_KEY_AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// The largest bcrypt round count `passphraseProtectedOpenSSHKey` takes:
/// 128 times OpenSSH's default, a few seconds.
const MAX_ROUNDS: u32 = 1 << 11;

/// An Ed25519 private key: the seed, then the public key, as the key's file holds
/// them; nothing has checked that the one is the other's.
pub struct Ed25519PrivateKey(pub(crate) [u8; 64]);

impl Ed25519PrivateKey {
    /// The seed.
    pub fn seed(&self) -> &[u8] {
        &self.0[..32]
    }

    /// The public key the file gives.
    pub fn public(&self) -> &[u8] {
        &self.0[32..]
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// Why a private key did not parse.
#[derive(Debug)]
pub enum KeyError {
    /// `PassphraseMissingError`: the key is encrypted. The public key, in
    /// the wire format, when the file has it unencrypted.
    PassphraseMissing(Option<Vec<u8>>),
    /// `x509.IncorrectPasswordError`.
    IncorrectPassword,
    /// Anything else, with Go's message.
    Other(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::PassphraseMissing(_) => {
                f.write_str("ssh: this private key is passphrase protected")
            }
            KeyError::IncorrectPassword => f.write_str("x509: decryption password incorrect"),
            KeyError::Other(message) => f.write_str(message),
        }
    }
}

fn other(message: impl Into<String>) -> KeyError {
    KeyError::Other(message.into())
}

/// The SSH wire format: `uint32` and length-prefixed strings.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn u32(&mut self) -> Result<u32, KeyError> {
        let (head, rest) = self.0.split_first_chunk::<4>().ok_or_else(short_read)?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }

    /// `parseString`.
    fn string(&mut self) -> Result<&'a [u8], KeyError> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            return Err(short_read());
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(s)
    }

    /// The end of a struct with no `rest` field: nothing may follow.
    fn end(&self) -> Result<(), KeyError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(other("ssh: parse error in message type 0"))
        }
    }
}

/// `errShortRead`.
fn short_read() -> KeyError {
    other("ssh: short read")
}

/// `ed25519PublicKey.Marshal`.
pub(crate) fn marshal_ed25519(public: &[u8; 32]) -> Vec<u8> {
    let mut w = Vec::with_capacity(4 + KEY_ALGO_ED25519.len() + 4 + 32);
    w.extend_from_slice(&(KEY_ALGO_ED25519.len() as u32).to_be_bytes());
    w.extend_from_slice(KEY_ALGO_ED25519.as_bytes());
    w.extend_from_slice(&32u32.to_be_bytes());
    w.extend_from_slice(public);
    w
}

/// `parseRSA`: the bits in the modulus of an RSA key, after its type.
fn parse_rsa(w: &mut Wire<'_>) -> Result<usize, KeyError> {
    /// `parseInt`: the bits in a non-negative number.
    fn bits(s: &[u8]) -> Result<usize, KeyError> {
        if s.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(other("ssh: parse error in message type 0"));
        }
        let Some(at) = s.iter().position(|&b| b != 0) else {
            return Ok(0);
        };
        Ok((s.len() - at) * 8 - s[at].leading_zeros() as usize)
    }
    let e = w.string()?;
    let n = w.string()?;
    let n_bits = bits(n)?;
    if n_bits > 16384 {
        return Err(other("ssh: rsa modulus too large"));
    }
    let e_bits = bits(e)?;
    if e_bits > 24 {
        return Err(other("ssh: exponent too large"));
    }
    let value = e.iter().fold(0u64, |v, &b| v << 8 | u64::from(b));
    if value < 3 || value & 1 == 0 {
        return Err(other("ssh: incorrect exponent"));
    }
    Ok(n_bits)
}

/// The bits in the modulus, if `input` is an RSA key in the wire format.
pub(crate) fn rsa_modulus_bits(input: &[u8]) -> Option<usize> {
    let mut w = Wire(input);
    if w.string().ok()? != b"ssh-rsa" {
        return None;
    }
    parse_rsa(&mut w).ok()
}

/// Go's `bytes.TrimSpace`: Unicode's white space, on valid UTF-8; an invalid
/// byte is not space.
fn trim_space(b: &[u8]) -> &[u8] {
    let mut b = trim_space_start(b);
    'trim: while !b.is_empty() {
        for width in 1..=b.len().min(4) {
            if let Ok(s) = std::str::from_utf8(&b[b.len() - width..]) {
                if s.chars().next_back().is_some_and(char::is_whitespace) {
                    b = &b[..b.len() - width];
                    continue 'trim;
                }
                break 'trim;
            }
        }
        break;
    }
    b
}

/// An SSH public key as an `authorized_keys` line has it.
pub(crate) struct AuthorizedKey {
    /// Its type, which the line says too.
    pub(crate) kind: String,
    /// An Ed25519 key.
    pub(crate) ed25519: Option<[u8; 32]>,
}

/// `parseAuthorizedKey`: after a key's type, its base64 and perhaps a comment.
fn parse_authorized_key_body(input: &[u8]) -> Result<AuthorizedKey, KeyError> {
    let input = trim_space(input);
    let end = input
        .iter()
        .position(|&c| c == b' ' || c == b'\t')
        .unwrap_or(input.len());
    let key = base64::decode_lenient(&input[..end]).ok_or_else(|| other("illegal base64 data"))?;
    let (kind, ed25519) = parse_public_key(&key)?;
    Ok(AuthorizedKey { kind, ed25519 })
}

/// A key whose line says the same type as the key does, or why not.
fn typed_key(kind: &[u8], body: &[u8]) -> Result<AuthorizedKey, KeyError> {
    let key = parse_authorized_key_body(body)?;
    if kind != key.kind.as_bytes() {
        return Err(other(format!(
            "ssh: authorized keys key type mismatch: human-readable type {:?}, encoded type {:?}",
            String::from_utf8_lossy(kind),
            key.kind
        )));
    }
    Ok(key)
}

/// `ParseAuthorizedKey`: the first key of the lines in `input`, past empty lines,
/// comments and options, which are not kept.
///
/// Differs from Go as [`parse_public_key`] does: a key of another type than
/// Ed25519 or RSA is taken as it says it is, where Go goes on to the next line if
/// it finds it malformed.
pub(crate) fn parse_authorized_key(input: &[u8]) -> Result<AuthorizedKey, KeyError> {
    let mut last_err = None;
    for line in input.split(|&c| c == b'\n') {
        let line = line.split(|&c| c == b'\r').next().unwrap_or(line);
        let line = trim_space(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let is_blank = |c: &u8| *c == b' ' || *c == b'\t';
        let Some(at) = line.iter().position(is_blank) else {
            continue;
        };
        match typed_key(&line[..at], &line[at..]) {
            Ok(key) => return Ok(key),
            Err(e) => last_err = Some(e),
        }

        // No key type recognised. Maybe there's an options field at the
        // beginning.
        let mut in_quote = false;
        let mut i = line.len() - 1;
        for (at, &b) in line.iter().enumerate() {
            if !in_quote && is_blank(&b) {
                i = at;
                break;
            }
            if b == b'"' && (at == 0 || line[at - 1] != b'\\') {
                in_quote = !in_quote;
            }
        }
        while i < line.len() && is_blank(&line[i]) {
            i += 1;
        }
        if i == line.len() {
            continue;
        }
        let line = &line[i..];
        let Some(at) = line.iter().position(is_blank) else {
            continue;
        };
        match typed_key(&line[..at], &line[at..]) {
            Ok(key) => return Ok(key),
            Err(e) => last_err = Some(e),
        }
    }
    Err(match last_err {
        Some(e) => other(format!(
            "ssh: no key found; last parsing error for ignored line: {e}"
        )),
        None => other("ssh: no key found"),
    })
}

/// `ParsePublicKey`, for the keys agessh takes: its type, and for an
/// Ed25519 key the key itself. An RSA key is checked. Other types are only
/// checked to be strings.
pub(crate) fn parse_public_key(input: &[u8]) -> Result<(String, Option<[u8; 32]>), KeyError> {
    let mut w = Wire(input);
    let algo = String::from_utf8_lossy(w.string()?).into_owned();
    if algo == "ssh-rsa" {
        parse_rsa(&mut w)?;
        if !w.0.is_empty() {
            return Err(other("ssh: trailing junk in public key"));
        }
        return Ok((algo, None));
    }
    if algo != KEY_ALGO_ED25519 {
        // Differs from Go, which parses every type it knows: agessh only
        // takes Ed25519 and RSA keys, and the port reads Ed25519 only.
        return Ok((algo, None));
    }
    let key = w.string()?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| other(format!("invalid size {} for Ed25519 public key", key.len())))?;
    if !w.0.is_empty() {
        return Err(other("ssh: trailing junk in public key"));
    }
    Ok((algo, Some(key)))
}

/// `encryptedBlock`: a PEM block with `Proc-Type: 4,ENCRYPTED`.
fn encrypted_block(block: &pem::Block) -> bool {
    block
        .headers
        .get("Proc-Type")
        .is_some_and(|v| v.contains("ENCRYPTED"))
}

/// What `ParseRawPrivateKey` would read but the port does not.
fn unsupported_pem(kind: &str) -> KeyError {
    match kind {
        "RSA PRIVATE KEY" | "PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" => {
            other(format!("ssh: {kind:?} keys are not supported yet"))
        }
        _ => other(format!("ssh: unsupported key type {kind:?}")),
    }
}

/// An Ed25519 key from an SSH private key file, as `hivepack-sign` takes one:
/// `passphrase` is used only if the key is encrypted, and is asked for with
/// [`KeyError::PassphraseMissing`] if it is and there is none.
pub fn parse_ssh_private_key(
    pem_bytes: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Ed25519PrivateKey, KeyError> {
    match (parse_raw_private_key(pem_bytes), passphrase) {
        (Err(KeyError::PassphraseMissing(_)), Some(passphrase)) => {
            parse_raw_private_key_with_passphrase(pem_bytes, passphrase)
        }
        (read, _) => read,
    }
}

/// An SSH public key's line, `ssh-ed25519 AAAA… comment`: its type, and for an
/// Ed25519 key the key itself.
pub fn parse_ssh_public_key(line: &[u8]) -> Result<(String, Option<[u8; 32]>), KeyError> {
    let key = parse_authorized_key(line)?;
    Ok((key.kind, key.ed25519))
}

/// `ParseRawPrivateKey`: an unencrypted key, or `PassphraseMissing`.
pub(crate) fn parse_raw_private_key(pem_bytes: &[u8]) -> Result<Ed25519PrivateKey, KeyError> {
    let block = pem::decode(pem_bytes).ok_or_else(|| other("ssh: no key found"))?;
    if encrypted_block(&block) {
        return Err(KeyError::PassphraseMissing(None));
    }
    if block.kind != "OPENSSH PRIVATE KEY" {
        return Err(unsupported_pem(&block.kind));
    }
    parse_openssh_private_key(&block.bytes, None)
}

/// `ParseRawPrivateKeyWithPassphrase`.
pub(crate) fn parse_raw_private_key_with_passphrase(
    pem_bytes: &[u8],
    passphrase: &[u8],
) -> Result<Ed25519PrivateKey, KeyError> {
    let block = pem::decode(pem_bytes).ok_or_else(|| other("ssh: no key found"))?;
    if block.kind == "OPENSSH PRIVATE KEY" {
        return parse_openssh_private_key(&block.bytes, Some(passphrase));
    }
    if !encrypted_block(&block) {
        return Err(other("ssh: not an encrypted key"));
    }
    Err(unsupported_pem(&block.kind))
}

/// `passphraseProtectedOpenSSHKey`'s function: the private key block
/// decrypted in place.
fn decrypt_with_passphrase(
    passphrase: &[u8],
    cipher_name: &[u8],
    kdf_name: &[u8],
    kdf_opts: &[u8],
    priv_key_block: &mut [u8],
) -> Result<(), KeyError> {
    if kdf_name == b"none" || cipher_name == b"none" {
        return Err(other("ssh: key is not password protected"));
    }
    if kdf_name != b"bcrypt" {
        return Err(other(format!(
            "ssh: unknown KDF {:?}, only supports \"bcrypt\"",
            String::from_utf8_lossy(kdf_name)
        )));
    }
    let mut opts = Wire(kdf_opts);
    let salt = opts.string()?;
    let rounds = opts.u32()?;
    opts.end()?;
    if rounds > MAX_ROUNDS {
        return Err(other(format!(
            "ssh: bcrypt KDF rounds {rounds} exceed maximum {MAX_ROUNDS}"
        )));
    }
    let mut k = bcrypt_pbkdf::key(passphrase, salt, rounds, 32 + 16).map_err(other)?;
    let (key, iv) = k.split_at(32);
    let aes = Aes::new(key).ok_or_else(|| other("crypto/aes: invalid key size"))?;
    let mut counter = [0u8; AES_BLOCK_LENGTH];
    counter.copy_from_slice(iv);
    k.fill(0);
    match cipher_name {
        b"aes256-ctr" => {
            // `cipher.NewCTR`: the IV is a 128-bit big-endian counter.
            let mut ctr = u128::from_be_bytes(counter);
            for chunk in priv_key_block.chunks_mut(AES_BLOCK_LENGTH) {
                let mut stream = ctr.to_be_bytes();
                aes.encrypt_block(&mut stream);
                for (byte, s) in chunk.iter_mut().zip(stream) {
                    *byte ^= s;
                }
                ctr = ctr.wrapping_add(1);
            }
            Ok(())
        }
        b"aes256-cbc" => Err(other("ssh: aes256-cbc keys are not supported yet")),
        _ => Err(other(format!(
            "ssh: unknown cipher {:?}, only supports \"aes256-ctr\" or \"aes256-cbc\"",
            String::from_utf8_lossy(cipher_name)
        ))),
    }
}

/// `checkOpenSSHKeyPadding`: 1, 2, 3, … to the end.
fn check_openssh_key_padding(pad: &[u8]) -> Result<(), KeyError> {
    if pad
        .iter()
        .enumerate()
        .all(|(i, &b)| usize::from(b) == i + 1)
    {
        Ok(())
    } else {
        Err(other("ssh: padding not as expected"))
    }
}

/// `parseOpenSSHPrivateKey`, decrypting with `passphrase` if there is one
/// (`passphraseProtectedOpenSSHKey`) and refusing an encrypted key
/// otherwise (`unencryptedOpenSSHKey`).
fn parse_openssh_private_key(
    key: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Ed25519PrivateKey, KeyError> {
    let Some(remaining) = key.strip_prefix(PRIVATE_KEY_AUTH_MAGIC) else {
        return Err(other("ssh: invalid openssh private key format"));
    };
    // `openSSHEncryptedPrivateKey`.
    let mut w = Wire(remaining);
    let cipher_name = w.string()?;
    let kdf_name = w.string()?;
    let kdf_opts = w.string()?;
    let num_keys = w.u32()?;
    let pub_key = w.string()?;
    let priv_key_block = w.string()?;
    if num_keys != 1 {
        return Err(other("ssh: multi-key files are not supported"));
    }

    let mut block = priv_key_block.to_vec();
    let decrypted = match passphrase {
        None => {
            if kdf_name != b"none" || cipher_name != b"none" {
                // The public key, for the caller to know which key it is.
                parse_public_key(pub_key)
                    .map_err(|e| other(format!("ssh: failed to parse embedded public key: {e}")))?;
                Err(KeyError::PassphraseMissing(Some(pub_key.to_vec())))
            } else if !kdf_opts.is_empty() {
                Err(other("ssh: invalid openssh private key"))
            } else {
                Ok(())
            }
        }
        Some(passphrase) => {
            decrypt_with_passphrase(passphrase, cipher_name, kdf_name, kdf_opts, &mut block)
        }
    };
    let result = decrypted.and_then(|()| parse_private_key_block(&block, cipher_name != b"none"));
    block.fill(0);
    result
}

/// The decrypted block: `openSSHPrivateKey`, then the key of its type.
fn parse_private_key_block(block: &[u8], encrypted: bool) -> Result<Ed25519PrivateKey, KeyError> {
    let mut w = Wire(block);
    let check =
        (|| -> Result<(u32, u32, &[u8]), KeyError> { Ok((w.u32()?, w.u32()?, w.string()?)) })();
    let keytype = match check {
        Ok((check1, check2, keytype)) if check1 == check2 => keytype,
        _ if encrypted => return Err(KeyError::IncorrectPassword),
        _ => return Err(other("ssh: malformed OpenSSH key")),
    };
    match keytype {
        b"ssh-ed25519" => {
            // `openSSHEd25519PrivateKey`.
            let _public = w.string()?;
            let private = w.string()?;
            let _comment = w.string()?;
            let pad = w.0;
            let private: [u8; 64] = private
                .try_into()
                .map_err(|_| other("ssh: private key unexpected length"))?;
            let private = Ed25519PrivateKey(private);
            check_openssh_key_padding(pad)?;
            Ok(private)
        }
        b"ssh-rsa" | b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            Err(other(format!(
                "ssh: {} keys are not supported yet",
                String::from_utf8_lossy(keytype)
            )))
        }
        _ => Err(other("ssh: unhandled key type")),
    }
}
