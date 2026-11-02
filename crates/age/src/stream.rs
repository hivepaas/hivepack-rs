//! The payload: port of `internal/stream/stream.go`.
//!
//! The payload is the STREAM construction over ChaCha20-Poly1305: chunks of
//! 64 KiB of plaintext, each sealed with a nonce that counts the chunks in
//! its first 11 bytes and marks the last chunk in its 12th. Each chunk is
//! authenticated before any of it is given out, and a payload cut at a
//! chunk boundary fails, as its last chunk lacks the mark.

use std::io::{self, Read, Write};

use hivepack_crypto::{
    CHACHA20_NONCE_LENGTH, POLY1305_TAG_LENGTH, chacha20, chacha20_poly1305, equal,
};

use crate::error::Error;

/// `ChunkSize`: the plaintext in each chunk but the last.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

/// `encChunkSize`: a chunk with its tag.
const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + POLY1305_TAG_LENGTH;

/// `lastChunkFlag`.
const LAST_CHUNK_FLAG: u8 = 0x01;

/// What stopped the stream, kept to be returned again: `io::Error` cannot
/// be cloned.
#[derive(Clone, Debug)]
enum Stop {
    End,
    Payload(String),
    /// The armor around the file failed, under the payload.
    Armor(String),
    Io(io::ErrorKind, String),
}

impl Stop {
    fn message(&self) -> &str {
        match self {
            Stop::End => "EOF",
            Stop::Payload(message) | Stop::Armor(message) | Stop::Io(_, message) => message,
        }
    }

    fn to_result(&self) -> io::Result<usize> {
        match self {
            Stop::End => Ok(0),
            Stop::Payload(message) => Err(Error::Payload(message.clone()).into()),
            Stop::Armor(message) => Err(Error::Armor(message.clone()).into()),
            Stop::Io(kind, message) => Err(io::Error::new(*kind, message.clone())),
        }
    }
}

/// `DecryptReader`: the plaintext of a payload, read from `src`.
///
/// Errors come as `io::Error`s of kind `InvalidData` that hold an
/// [`Error::Payload`], which `Error::from` takes back out. Once one is
/// returned, every later read returns it again. Plaintext that was given
/// out before it is authentic.
pub struct DecryptReader<R> {
    key: [u8; 32],
    src: R,
    /// The chunk being read: decrypted from `buf[start..end]` in place.
    buf: Box<[u8; ENC_CHUNK_SIZE]>,
    start: usize,
    end: usize,
    err: Option<Stop>,
    nonce: [u8; CHACHA20_NONCE_LENGTH],
}

impl<R: Read> DecryptReader<R> {
    /// `NewDecryptReader`: the payload of `src`, decrypted with `key`.
    pub(crate) fn new(key: [u8; 32], src: R) -> DecryptReader<R> {
        DecryptReader {
            key,
            src,
            buf: Box::new([0; ENC_CHUNK_SIZE]),
            start: 0,
            end: 0,
            err: None,
            nonce: [0; CHACHA20_NONCE_LENGTH],
        }
    }

    /// `io.ReadFull` into `buf`: how many bytes were read before the end.
    fn read_full(&mut self, len: usize) -> Result<usize, Stop> {
        let mut n = 0;
        while n < len {
            match self.src.read(&mut self.buf[n..len]) {
                Ok(0) => break,
                Ok(read) => n += read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(stop_for(e)),
            }
        }
        Ok(n)
    }

    /// `readChunk`: the next chunk, decrypted into `buf[..end]`; whether it
    /// was the last.
    fn read_chunk(&mut self) -> Result<bool, Stop> {
        let n = self.read_full(ENC_CHUNK_SIZE)?;
        let mut last = false;
        if n == 0 {
            return Err(Stop::Payload("unexpected EOF".into()));
        }
        if n < ENC_CHUNK_SIZE {
            // A short chunk can only be the last one. It cannot be empty,
            // unless it is the only one: the payload is empty.
            if self.nonce != [0; CHACHA20_NONCE_LENGTH] && n == POLY1305_TAG_LENGTH {
                return Err(Stop::Payload(
                    "last chunk is empty, try age v1.0.0, and please consider reporting this"
                        .into(),
                ));
            }
            last = true;
            self.nonce[CHACHA20_NONCE_LENGTH - 1] = LAST_CHUNK_FLAG;
        }

        let mut opened = self.open(n);
        if !opened && !last {
            // A full chunk can be the last one too.
            last = true;
            self.nonce[CHACHA20_NONCE_LENGTH - 1] = LAST_CHUNK_FLAG;
            opened = self.open(n);
        }
        if !opened {
            return Err(Stop::Payload(
                "failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with"
                    .into(),
            ));
        }
        inc_nonce(&mut self.nonce)?;
        self.start = 0;
        self.end = n - POLY1305_TAG_LENGTH;
        Ok(last)
    }

    /// `Open` of `buf[..n]` with the current nonce, in place. If the tag
    /// does not match, the ciphertext is put back and nothing is given
    /// out.
    fn open(&mut self, n: usize) -> bool {
        let Some(len) = n.checked_sub(POLY1305_TAG_LENGTH) else {
            return false;
        };
        let (data, tag) = self.buf[..n].split_at_mut(len);
        let computed = chacha20_poly1305(&self.key, &self.nonce, data, &[], false);
        if equal(&computed, tag) {
            return true;
        }
        // Encrypted again: ChaCha20 is its own inverse.
        chacha20(&self.key, &self.nonce, 1, data);
        false
    }

    /// After the last chunk: the end of `src`, or trailing data.
    fn check_end(&mut self) -> Stop {
        let mut byte = [0u8; 1];
        loop {
            match self.src.read(&mut byte) {
                Ok(0) => return Stop::End,
                Ok(_) => return Stop::Payload("trailing data after end of encrypted file".into()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // The armor's error stays one, as age's wrapping keeps it
                // for errors.As.
                Err(e) => {
                    return match stop_for(e) {
                        Stop::Armor(message) => Stop::Armor(message),
                        stop => Stop::Payload(format!(
                            "non-EOF error reading after end of encrypted file: {}",
                            stop.message()
                        )),
                    };
                }
            }
        }
    }
}

/// What a read error of the source stops the stream with: the error, or
/// the armor's error inside it.
fn stop_for(e: io::Error) -> Stop {
    match Error::from(e) {
        Error::Io(e) => Stop::Io(e.kind(), e.to_string()),
        Error::Payload(message) => Stop::Payload(message),
        Error::Armor(message) => Stop::Armor(message),
        other => Stop::Io(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// `incNonce`: the chunk counter, big-endian in the first 11 bytes.
fn inc_nonce(nonce: &mut [u8; CHACHA20_NONCE_LENGTH]) -> Result<(), Stop> {
    for i in (0..CHACHA20_NONCE_LENGTH - 1).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            return Ok(());
        }
    }
    // Differs from age, which panics: 2^88 chunks cannot be read anyway.
    Err(Stop::Payload("stream: chunk counter wrapped around".into()))
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.start < self.end {
            let n = p.len().min(self.end - self.start);
            p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
            self.start += n;
            return Ok(n);
        }
        if let Some(stop) = &self.err {
            return stop.to_result();
        }
        if p.is_empty() {
            return Ok(0);
        }
        let last = match self.read_chunk() {
            Ok(last) => last,
            Err(stop) => {
                let result = stop.to_result();
                self.err = Some(stop);
                return result;
            }
        };
        let n = p.len().min(self.end - self.start);
        p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        if last {
            self.err = Some(self.check_end());
        }
        Ok(n)
    }
}

impl<R> Drop for DecryptReader<R> {
    fn drop(&mut self) {
        self.key.fill(0);
        std::hint::black_box(&mut self.key);
    }
}

impl<R> std::fmt::Debug for DecryptReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptReader")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

/// What [`EncryptWriter`] must overwrite when it is dropped (best effort): the
/// key, and the plaintext of a chunk not sealed yet. Apart from the writer, so
/// that the writer can give its destination back.
struct Sealer {
    key: [u8; 32],
    nonce: [u8; CHACHA20_NONCE_LENGTH],
    /// The chunk being written, plaintext in `buf[..len]`, then sealed in place
    /// with its tag after it.
    buf: Box<[u8; ENC_CHUNK_SIZE]>,
    len: usize,
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.key.fill(0);
        self.buf.fill(0);
        std::hint::black_box((&mut self.key, &mut self.buf));
    }
}

/// `EncryptWriter`: seals what is written to it into `dst`, a chunk at a time.
///
/// A failure of `dst` is kept, and returned again by every later write and by
/// `finish`. `io::Error` cannot be cloned, so those are its kind and message.
pub(crate) struct EncryptWriter<W> {
    sealer: Sealer,
    dst: W,
    err: Option<(io::ErrorKind, String)>,
}

impl<W: Write> EncryptWriter<W> {
    /// `NewEncryptWriter`.
    pub(crate) fn new(key: [u8; 32], dst: W) -> EncryptWriter<W> {
        EncryptWriter {
            sealer: Sealer {
                key,
                nonce: [0; CHACHA20_NONCE_LENGTH],
                buf: Box::new([0; ENC_CHUNK_SIZE]),
                len: 0,
            },
            dst,
            err: None,
        }
    }

    /// `flushChunk`.
    fn flush_chunk(&mut self, last: bool) -> io::Result<()> {
        let s = &mut self.sealer;
        if last {
            s.nonce[CHACHA20_NONCE_LENGTH - 1] = LAST_CHUNK_FLAG;
        }
        let (plaintext, rest) = s.buf.split_at_mut(s.len);
        let tag = chacha20_poly1305(&s.key, &s.nonce, plaintext, &[], true);
        rest[..POLY1305_TAG_LENGTH].copy_from_slice(&tag);
        self.dst.write_all(&s.buf[..s.len + POLY1305_TAG_LENGTH])?;
        s.len = 0;
        inc_nonce(&mut s.nonce).map_err(|stop| io::Error::other(stop.message()))
    }

    /// The failure kept, if there is one.
    fn check(&self) -> io::Result<()> {
        match &self.err {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    /// Keeps a failure, and returns it.
    fn fail(&mut self, e: io::Error) -> io::Error {
        self.err = Some((e.kind(), e.to_string()));
        e
    }

    /// `Close`: seals the last chunk, flushes `dst` and gives it back.
    pub(crate) fn finish(mut self) -> io::Result<W> {
        self.check()?;
        self.flush_chunk(true)?;
        self.dst.flush()?;
        Ok(self.dst)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    /// `Write`.
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.check()?;
        let total = p.len();
        let mut p = p;
        while !p.is_empty() {
            let len = self.sealer.len;
            let n = p.len().min(CHUNK_SIZE - len);
            self.sealer.buf[len..len + n].copy_from_slice(&p[..n]);
            self.sealer.len += n;
            p = &p[n..];
            // Only flush if there's a full chunk with bytes still to write, or
            // we can't know if this is the last chunk yet.
            if self.sealer.len == CHUNK_SIZE
                && !p.is_empty()
                && let Err(e) = self.flush_chunk(false)
            {
                return Err(self.fail(e));
            }
        }
        Ok(total)
    }

    /// Flushes `dst`. What is in the chunk being written stays there, as a
    /// chunk is sealed only when it is full or the last.
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.dst.flush()
    }
}

impl<W> std::fmt::Debug for EncryptWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptWriter")
            .field("nonce", &self.sealer.nonce)
            .finish_non_exhaustive()
    }
}
