//! The XML an archive carries: what each image is called, and what it
//! holds.
//!
//! It is UTF-16, little-endian, with a byte order mark in front of it, and
//! it is written by whatever made the archive — Windows' own tools, DISM,
//! wimlib, 7-Zip — so it is read for the few things it is relied on for
//! and nothing else: an image's name, and the counts it gives. **The tree
//! is what says what an image holds**; the XML is what says what it is
//! called, and a reader that needed it to find anything would be at the
//! mercy of whatever wrote it.
//!
//! So this is not an XML parser. It walks the text for the elements it
//! wants, takes their contents as they are, and gives nothing where the
//! text is not what it expects. A name is at most 1024 characters, and
//! what it holds is not unescaped beyond the five entities XML fixes.

use std::io::{Read, Seek};

use super::error::Error;
use super::{Compression, Resource, read_resource};

/// How much of the XML is read: a `.wim` of many editions has a few tens
/// of kilobytes of it, and nothing in it is needed to read a tree.
const MOST_XML: u64 = 4 << 20;

/// How long a name may be, in characters.
const MOST_NAME: usize = 1024;

/// What the XML says about one image.
pub(crate) struct Said {
    pub(crate) index: u32,
    pub(crate) name: Option<String>,
    pub(crate) files: Option<u64>,
    pub(crate) directories: Option<u64>,
    pub(crate) bytes: Option<u64>,
}

/// What the XML at `xml` says about each image, in the order it gives
/// them.
pub(crate) fn read<R: Read + Seek>(
    reader: &mut R,
    xml: &Resource,
    compression: Compression,
) -> Result<Vec<Said>, Error> {
    if xml.size == 0 {
        return Ok(Vec::new());
    }
    let raw = read_resource(reader, xml, u64::MAX, compression, MOST_XML)?;
    Ok(said(&text(&raw)))
}

/// The XML as text: UTF-16 little-endian, its byte order mark taken off.
///
/// What is not UTF-16 is read as far as it goes and the rest replaced: the
/// XML is a label, and a name with a replacement character in it is better
/// than refusing to open an archive whose tree is sound.
fn text(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let units = units.strip_prefix(&[0xFEFF]).unwrap_or(&units);
    String::from_utf16_lossy(units)
}

/// What each `<IMAGE>` element says.
fn said(text: &str) -> Vec<Said> {
    let mut found = Vec::new();
    for image in text.split("<IMAGE").skip(1) {
        // The index is an attribute of the element; everything else is an
        // element inside it.
        let Some(index) = attribute(image, "INDEX").and_then(|v| v.parse().ok()) else {
            continue;
        };
        // Only as far as this element ends, so that the next image's
        // numbers are not read as this one's.
        let inside = image.split("</IMAGE>").next().unwrap_or(image);
        found.push(Said {
            index,
            name: element(inside, "NAME").map(|name| {
                let name = unescape(name);
                name.chars().take(MOST_NAME).collect()
            }),
            files: element(inside, "FILECOUNT").and_then(|v| v.trim().parse().ok()),
            directories: element(inside, "DIRCOUNT").and_then(|v| v.trim().parse().ok()),
            bytes: element(inside, "TOTALBYTES").and_then(|v| v.trim().parse().ok()),
        });
    }
    found
}

/// What `name="…"` holds, where the element's own tag has one.
fn attribute<'a>(image: &'a str, name: &str) -> Option<&'a str> {
    let tag = image.split('>').next()?;
    let at = tag.find(name)?;
    let rest = &tag[at + name.len()..];
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    rest[1..].split(quote).next()
}

/// What `<name>…</name>` holds, the first one of them.
fn element<'a>(inside: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let at = inside.find(&open)? + open.len();
    let end = inside[at..].find(&close)? + at;
    Some(&inside[at..end])
}

/// The five entities XML fixes, and nothing else: what a name holding `&`
/// is written as.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The XML 7-Zip wrote for the archive the tests read, and the one
    /// Windows writes for a disc's `install.wim`, as far as the few things
    /// read from it go.
    #[test]
    fn what_the_xml_says_about_each_image() {
        let xml = "<WIM><TOTALBYTES>201176</TOTALBYTES>\
             <IMAGE INDEX=\"1\"><NAME>Windows 11 Pro</NAME><DIRCOUNT>2</DIRCOUNT>\
             <FILECOUNT>3</FILECOUNT><TOTALBYTES>200024</TOTALBYTES></IMAGE>\
             <IMAGE INDEX=\"2\"><NAME>Windows 11 Home &amp; more</NAME></IMAGE></WIM>";
        let said = said(xml);
        assert_eq!(said.len(), 2);
        assert_eq!(said[0].index, 1);
        assert_eq!(said[0].name.as_deref(), Some("Windows 11 Pro"));
        assert_eq!(said[0].files, Some(3));
        assert_eq!(said[0].directories, Some(2));
        assert_eq!(said[0].bytes, Some(200_024));
        assert_eq!(said[1].index, 2);
        assert_eq!(said[1].name.as_deref(), Some("Windows 11 Home & more"));
        // The second image says none of the counts, and the first image's
        // are not read as its own.
        assert_eq!(
            (said[1].files, said[1].directories, said[1].bytes),
            (None, None, None)
        );
    }

    #[test]
    fn what_is_not_the_xml_it_expects_says_nothing() {
        assert!(said("").is_empty());
        assert!(said("<WIM></WIM>").is_empty());
        // An image with no index is no image: nothing points at it.
        assert!(said("<IMAGE><NAME>x</NAME></IMAGE>").is_empty());
        // An index that is not a number, and one that is not in quotes.
        assert!(said("<IMAGE INDEX=\"x\"><NAME>x</NAME></IMAGE>").is_empty());
        assert!(said("<IMAGE INDEX=1><NAME>x</NAME></IMAGE>").is_empty());
        // An element that never ends gives nothing, and does not hang.
        let said = said("<IMAGE INDEX=\"1\"><NAME>x");
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].name, None);
    }

    /// The text is UTF-16 with a byte order mark, which is taken off.
    #[test]
    fn the_text_is_utf16_with_a_mark_in_front() {
        let mut raw = Vec::new();
        for unit in std::iter::once(0xFEFFu16).chain("<WIM/>".encode_utf16()) {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(text(&raw), "<WIM/>");
        // An odd byte at the end is not half a character.
        raw.push(0);
        assert_eq!(text(&raw), "<WIM/>");
    }

    /// A name of 1024 characters and more is cut, so that a crafted XML
    /// cannot hand back a megabyte as a name.
    #[test]
    fn a_name_is_as_long_as_it_may_be_and_no_longer() {
        let long = "x".repeat(4000);
        let xml = format!("<IMAGE INDEX=\"1\"><NAME>{long}</NAME></IMAGE>");
        assert_eq!(said(&xml)[0].name.as_deref().map(str::len), Some(MOST_NAME));
    }
}
