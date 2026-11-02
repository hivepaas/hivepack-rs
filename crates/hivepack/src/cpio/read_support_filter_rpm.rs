//! Port of libarchive's `archive_read_support_filter_rpm.c`: the filter
//! that takes an RPM package's lead and headers off, and gives what follows
//! them, the payload.
//!
//! An RPM package is a lead of 96 bytes, then headers, each 16 bytes, an
//! index of 16-byte entries and their data; the first is the signature,
//! padded to 8 bytes with zeros. The filter skips the lead, then each
//! header and the zeros after it, and gives the rest as it is.

use std::io::{self, Read};

use crate::cpio::error::Error;
use crate::cpio::read::Input;

/// `RPM_LEAD_SIZE`: the size of the lead.
const RPM_LEAD_SIZE: u64 = 96;
/// `RPM_MIN_HEAD_SIZE`: the fixed part of a header.
const RPM_MIN_HEAD_SIZE: usize = 16;

/// How many first bytes [`bid`] looks at.
pub const BID_SIZE: usize = 8;

/// `rpm_bidder_bid` on the first bytes of a file: how many bits of them
/// say this is an RPM package (the lead's magic, a major version of 3 or
/// 4, and a binary or source package), 56; or 0 if not, or if there are
/// fewer than [`BID_SIZE`] bytes.
pub fn bid(p: &[u8]) -> i32 {
    if p.len() < BID_SIZE {
        return 0;
    }
    let mut bits_checked = 0;
    // The lead's magic.
    if p[..4] != [0xED, 0xAB, 0xEE, 0xDB] {
        return 0;
    }
    bits_checked += 32;
    // The major version.
    if p[4] != 3 && p[4] != 4 {
        return 0;
    }
    bits_checked += 8;
    // The package's type: binary or source.
    if p[6] != 0 {
        return 0;
    }
    bits_checked += 8;
    if p[7] != 0 && p[7] != 1 {
        return 0;
    }
    bits_checked += 8;
    bits_checked
}

/// An RPM package's payload: what follows the lead and the headers, read
/// as libarchive's RPM filter gives it, from a file whose [`bid`] says it
/// is a package. The zeros that pad the last header are taken off with
/// it, and so are any the payload starts with.
///
/// The first read fails if the package ends before its payload, or has no
/// header after its lead, with libarchive's message; a failure stays, and
/// every later read returns it again.
#[derive(Debug)]
pub struct Reader<R> {
    input: Input<R>,
    /// `data_reached`: the lead and headers are behind.
    data_reached: bool,
    failed: Option<Error>,
}

impl<R: Read> Reader<R> {
    /// `rpm_bidder_init`: the payload of the package `r`.
    pub fn new(r: R) -> Reader<R> {
        Reader {
            input: Input::new(r),
            data_reached: false,
            failed: None,
        }
    }

    /// The package, as far as it was read.
    pub fn into_inner(self) -> R {
        self.input.into_inner()
    }

    /// `skip_padding`: the zeros after a header.
    fn skip_padding(&mut self) -> Result<(), Error> {
        loop {
            let Some(h) = self.input.ahead(1)? else {
                return Err(Error::Unspecified(None));
            };
            let avail = h.len();
            let count = h.iter().take_while(|&&b| b == 0).count();
            self.input.consume(count as u64)?;
            if count != avail {
                return Ok(());
            }
        }
    }

    /// `skip_prologue`: the lead, and the headers.
    fn skip_prologue(&mut self) -> Result<(), Error> {
        // The lead.
        self.input.consume(RPM_LEAD_SIZE)?;

        let mut seen_header = false;
        loop {
            // A header's fixed part.
            let Some(h) = self.input.ahead(RPM_MIN_HEAD_SIZE)? else {
                return Err(Error::Unspecified(None));
            };
            if h[..4] != [0x8E, 0xAD, 0xE8, 0x01] {
                break;
            }
            seen_header = true;

            // The header's length: the fixed part, 16 bytes for each entry
            // of the index, and the bytes of their data.
            let section = u64::from(u32::from_be_bytes([h[8], h[9], h[10], h[11]]));
            let bytes = u64::from(u32::from_be_bytes([h[12], h[13], h[14], h[15]]));
            let length = RPM_MIN_HEAD_SIZE as u64 + section * 16 + bytes;
            self.input.consume(length)?;

            self.skip_padding()?;
        }

        // At least one header must have been there.
        if !seen_header {
            return Err(Error::RpmHeader);
        }
        Ok(())
    }

    /// `rpm_filter_read`, into `buf`.
    fn filter_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.data_reached {
            self.skip_prologue()?;
            self.data_reached = true;
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let Some(h) = self.input.ahead(1)? else {
            return Ok(0);
        };
        let n = h.len().min(buf.len());
        buf[..n].copy_from_slice(&h[..n]);
        self.input.consume(n as u64)?;
        Ok(n)
    }
}

impl<R: Read> Read for Reader<R> {
    /// The payload.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.again().into());
        }
        match self.filter_read(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.failed = Some(e.again());
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lead, a signature of `signature` bytes padded to 8, a header of
    /// `header` bytes, and `payload`.
    fn package(signature: u32, header: u32, payload: &[u8]) -> Vec<u8> {
        let mut rpm = vec![0xED, 0xAB, 0xEE, 0xDB, 3, 0, 0, 0];
        rpm.resize(96, 0);
        for (bytes, pad) in [(signature, true), (header, false)] {
            rpm.extend_from_slice(&[0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0]);
            rpm.extend_from_slice(&1u32.to_be_bytes());
            rpm.extend_from_slice(&bytes.to_be_bytes());
            rpm.extend(std::iter::repeat_n(7, 16 + bytes as usize));
            while pad && rpm.len() % 8 != 0 {
                rpm.push(0);
            }
        }
        rpm.extend_from_slice(payload);
        rpm
    }

    fn payload(rpm: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        Reader::new(rpm).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn bids() {
        let rpm = package(5, 9, b"070701");
        assert_eq!(bid(&rpm), 56);
        assert_eq!(bid(&rpm[..7]), 0);
        for (at, value) in [(0, 0xEE), (4, 2), (4, 5), (6, 1), (7, 2)] {
            let mut other = rpm.clone();
            other[at] = value;
            assert_eq!(bid(&other), 0, "byte {at} = {value}");
        }
        let mut source = rpm.clone();
        source[7] = 1;
        source[4] = 4;
        assert_eq!(bid(&source), 56);
    }

    #[test]
    fn payloads_come_after_the_headers_and_their_zeros() {
        let gzip = b"\x1f\x8b\x08 and the rest of it";
        assert_eq!(payload(&package(5, 9, gzip)).unwrap(), gzip);
        // The zeros a payload starts with go with the padding.
        assert_eq!(
            payload(&package(8, 3, b"\0\0\0BZh91AY&SY and more")).unwrap(),
            b"BZh91AY&SY and more"
        );
    }

    #[test]
    fn packages_cut_short() {
        let rpm = package(5, 9, &[1; 40]);
        let message = |e: Error| String::from_utf8(e.message().unwrap_or_default()).unwrap();
        assert_eq!(
            message(payload(&rpm[..50]).unwrap_err()),
            "Truncated input file (needed 96 bytes, only 50 available)"
        );
        assert!(matches!(
            payload(&rpm[..100]),
            Err(Error::Unspecified(None))
        ));
        let mut header = rpm.clone();
        header[96] = 0;
        assert!(matches!(payload(&header), Err(Error::RpmHeader)));
        // No payload: the zeros after the last header go on to the end.
        assert!(matches!(
            payload(&package(5, 9, &[0; 30])),
            Err(Error::Unspecified(None))
        ));
        // A payload too short for a header to be looked for.
        assert!(matches!(
            payload(&package(5, 9, b"short")),
            Err(Error::Unspecified(None))
        ));
    }
}
