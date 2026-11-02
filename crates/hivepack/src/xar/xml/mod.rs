//! What stands for libxml2 2.15.4's xmlTextReader as libarchive's
//! `xml2_read_toc` uses it: a reader of XML 1.0 in safe Rust, ported from
//! libxml2's reader (`xmlreader.c`), push parser (`parser.c`,
//! `parserInternals.c`), tree builder (`SAX2.c`), input buffer (`xmlIO.c`)
//! and URI parser (`uri.c`).
//!
//! libarchive reads a XAR archive's table of contents with whichever XML
//! parser it was built with; libxml2 is its default on Linux and macOS.
//! The parsers do not give the same: with expat, libarchive keeps only the
//! first piece of a name broken by a reference (`a&amp;b` reads as `a`).
//! This gives what libxml2's reader gives: the same nodes, in the same
//! order, with the same names, attributes and text, read from the same
//! callback in the same pieces, and the same errors at the same places,
//! though with messages of its own.
//!
//! What it does not do as libxml2 does, `docs/xar.md` lists: encodings
//! other than UTF-8 and US-ASCII, and the internal subset of a DOCTYPE,
//! fail.

mod parser;
mod parser_internals;
mod sax2;
mod tree;
mod uri;
mod xml_io;
mod xmlreader;

#[cfg(test)]
mod tests;

pub(crate) use parser::Severity;
pub(crate) use xmlreader::{
    TextReader, XML_READER_TYPE_ELEMENT, XML_READER_TYPE_END_ELEMENT, XML_READER_TYPE_TEXT,
};

/// What the reader is given: `xml2_read_cb` and `xml2_error_hdr`.
pub(crate) trait XmlIo {
    /// The read callback (`xmlInputReadCallback`): up to `buf.len()` bytes
    /// into `buf`, and how many; 0 at the end, negative on an error.
    fn read(&mut self, buf: &mut [u8]) -> i32;

    /// The error handler (`xmlTextReaderErrorFunc`): a warning or an
    /// error, with libxml2's severity and a message of the port's.
    fn error(&mut self, severity: Severity, msg: &str);
}
