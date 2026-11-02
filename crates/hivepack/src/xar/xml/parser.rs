//! Port of libxml2's push parser (`parser.c`): `xmlParseChunk` and
//! `xmlParseTryOrFinish`, which parse what has been pushed as far as it
//! lets them, and the parsing functions they call, as xmlTextReader drives
//! them (SAX2, no options but `XML_PARSE_COMPACT`).
//!
//! The parser stops at its first fatal error, as libxml2's does in effect:
//! there it disables the SAX callbacks, and the reader fails at its next
//! push. The port returns from the parsing functions at that point where
//! libxml2 goes on to the end of the construct, reporting more errors to a
//! handler that keeps only the last; nothing else differs.
//!
//! Differs from libxml2: a DOCTYPE with an internal subset fails
//! ([`Code::InternalSubset`]); without one, it is read as libxml2 reads it.
//! Not ported: the dictionary's size limit (`XML_MAX_DICTIONARY_LIMIT`,
//! 100 MB of distinct names).

use super::parser_internals::{
    char_len, copy_char, is_blank_ch, is_byte_char, is_char, is_pubid_char,
};
use super::tree::{NodeId, Tree};
use super::uri::parse_uri_safe;

/// `XML_MAX_TEXT_LENGTH`: the longest text node, comment, PI, CDATA
/// section or attribute value, without `XML_PARSE_HUGE`.
pub(crate) const XML_MAX_TEXT_LENGTH: usize = 10_000_000;
/// `XML_MAX_NAME_LENGTH`: the longest name.
pub(crate) const XML_MAX_NAME_LENGTH: usize = 50_000;
/// `XML_MAX_LOOKUP_LIMIT`: how far the parser may get from the start of
/// its buffer in one push.
const XML_MAX_LOOKUP_LIMIT: usize = 10_000_000;
/// `XML_PARSER_BIG_BUFFER_SIZE`.
const XML_PARSER_BIG_BUFFER_SIZE: usize = 300;
/// `XML_PARSER_BUFFER_SIZE`.
const XML_PARSER_BUFFER_SIZE: usize = 100;
/// `LINE_LEN`: what shrinking keeps before the position.
const LINE_LEN: usize = 80;
/// The deepest nesting of elements: where `nodePush` cannot grow its table
/// (`xmlGrowCapacity` up to 256) without `XML_PARSE_HUGE`.
const MAX_DEPTH: usize = 256;

/// The namespace of the `xml` prefix.
pub(crate) const XML_XML_NAMESPACE: &[u8] = b"http://www.w3.org/XML/1998/namespace";
/// The namespace of `xmlns`, which cannot be declared.
const XMLNS_NAMESPACE: &[u8] = b"http://www.w3.org/2000/xmlns/";

/// How grave a report is: `xmlErrorLevel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Warning,
    Error,
    Fatal,
}

/// What the error handler is told (`xmlParserSeverities`, as
/// xml2_error_hdr tells them apart).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Severity {
    Warning,
    Error,
}

/// The `xmlParserErrors` codes whose handling differs; the others are
/// [`Code::Other`] and [`Code::InvalidChar`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    /// `XML_ERR_RESOURCE_LIMIT`: stops the parser.
    ResourceLimit,
    /// `XML_ERR_INVALID_ENCODING`.
    InvalidEncoding,
    /// `XML_ERR_UNSUPPORTED_ENCODING`.
    UnsupportedEncoding,
    /// `XML_ERR_INVALID_CHAR`.
    InvalidChar,
    /// A read callback's failure: its result, negated (`in->error`).
    Io,
    /// A DOCTYPE with an internal subset, which the port does not read.
    InternalSubset,
    /// Any other.
    Other,
}

/// `xmlParserInputState`, for the push parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InState {
    Start,
    XmlDecl,
    Misc,
    Prolog,
    Epilog,
    StartTag,
    Content,
    EndTag,
    Eof,
}

/// `xmlStartTag` of the push parser's name stack.
#[derive(Clone, Debug)]
struct StartTag {
    name: Vec<u8>,
    prefix: Option<Vec<u8>>,
    ns_nr: usize,
}

/// A namespace binding (`nsTab` and `xmlParserNsExtra`).
#[derive(Clone, Debug)]
struct NsBinding {
    prefix: Option<Vec<u8>>,
    uri: Vec<u8>,
    element_id: u64,
}

/// An attribute of a start tag, before the SAX callback.
#[derive(Clone, Debug)]
pub(crate) struct ParsedAttr {
    pub(crate) name: Vec<u8>,
    pub(crate) prefix: Option<Vec<u8>>,
    /// The namespace URI: `None` for none or an undeclared prefix.
    pub(crate) uri: Option<Vec<u8>>,
    pub(crate) value: Vec<u8>,
}

/// `xmlSBuf`, by its size only: whether it holds anything, how much, and
/// whether it went past its limit.
#[derive(Clone, Copy, Debug)]
struct SBuf {
    used: bool,
    size: usize,
    over: bool,
}

impl SBuf {
    fn new() -> SBuf {
        SBuf {
            used: false,
            size: 0,
            over: false,
        }
    }

    /// `xmlSBufAddString` of `len` bytes, kept in `value` too.
    fn add(&mut self, value: &mut Vec<u8>, bytes: &[u8]) {
        if XML_MAX_TEXT_LENGTH - self.size < bytes.len() {
            self.over = true;
            return;
        }
        self.used = true;
        self.size += bytes.len();
        value.extend_from_slice(bytes);
    }

    /// `xmlSBufAddChar`.
    fn add_char(&mut self, value: &mut Vec<u8>, c: i32) {
        if XML_MAX_TEXT_LENGTH - self.size < 4 {
            self.over = true;
            return;
        }
        self.used = true;
        self.size += char_len(c);
        copy_char(value, c);
    }
}

/// `xmlGrowCapacity`: the next size of a buffer of `capacity` bytes that
/// may not pass `max`, or `None` once it is there.
fn grow_capacity(capacity: usize, max: usize) -> Option<usize> {
    if capacity >= max {
        return None;
    }
    let extra = capacity.div_ceil(2);
    if capacity > max - extra {
        Some(max)
    } else {
        Some(capacity + extra)
    }
}

/// `xmlIsNameStartCharNew` (XML 1.0 fifth edition).
fn is_name_start_char(c: i32) -> bool {
    c != i32::from(b' ')
        && c != i32::from(b'>')
        && c != i32::from(b'/')
        && ((i32::from(b'a')..=i32::from(b'z')).contains(&c)
            || (i32::from(b'A')..=i32::from(b'Z')).contains(&c)
            || c == i32::from(b'_')
            || c == i32::from(b':')
            || (0xc0..=0xd6).contains(&c)
            || (0xd8..=0xf6).contains(&c)
            || (0xf8..=0x2ff).contains(&c)
            || (0x370..=0x37d).contains(&c)
            || (0x37f..=0x1fff).contains(&c)
            || (0x200c..=0x200d).contains(&c)
            || (0x2070..=0x218f).contains(&c)
            || (0x2c00..=0x2fef).contains(&c)
            || (0x3001..=0xd7ff).contains(&c)
            || (0xf900..=0xfdcf).contains(&c)
            || (0xfdf0..=0xfffd).contains(&c)
            || (0x10000..=0xeffff).contains(&c))
}

/// `xmlIsNameCharNew`.
fn is_name_char(c: i32) -> bool {
    c != i32::from(b' ')
        && c != i32::from(b'>')
        && c != i32::from(b'/')
        && (is_name_start_char(c)
            || (i32::from(b'0')..=i32::from(b'9')).contains(&c)
            || c == i32::from(b'-')
            || c == i32::from(b'.')
            || c == 0xb7
            || (0x300..=0x36f).contains(&c)
            || (0x203f..=0x2040).contains(&c))
}

/// `test_char_data`: the bytes of character data that need no care.
fn test_char_data(c: u8) -> bool {
    c == 0x09 || ((0x20..=0x7f).contains(&c) && c != b'&' && c != b'<' && c != b']')
}

/// What `xmlParseStartTag2` gives the push parser.
struct StartTagResult {
    localname: Vec<u8>,
    prefix: Option<Vec<u8>>,
    nb_ns: usize,
}

/// `xmlParserCtxt` of the push parser, with its input (`xmlParserInput`).
#[derive(Debug)]
pub(crate) struct ParserCtxt {
    /// The input from its base: what was pushed and not shrunk away.
    pub(crate) buf: Vec<u8>,
    /// The position in `buf`.
    pub(crate) cur: usize,
    /// `XML_INPUT_HAS_ENCODING`.
    pub(crate) has_encoding: bool,
    /// `XML_INPUT_AUTO_UTF8`: UTF-8's byte order mark was seen.
    pub(crate) auto_utf8: bool,
    /// `XML_INPUT_ENCODING_ERROR`: one was reported.
    pub(crate) encoding_error_seen: bool,
    /// The input is converted from US-ASCII.
    pub(crate) ascii: bool,
    /// `in->error`: the conversion failed.
    pub(crate) buf_error: bool,
    pub(crate) encoding: Option<Vec<u8>>,
    pub(crate) instate: InState,
    check_index: usize,
    end_check_state: u8,
    pub(crate) disable_sax: u8,
    pub(crate) well_formed: bool,
    /// `errNo`: the last error's code, if any.
    pub(crate) err_no: Option<Code>,
    pub(crate) nb_errors: u32,
    pub(crate) nb_warnings: u32,
    standalone: i32,
    has_external_subset: bool,
    /// What the error handler is to be told, in order.
    pub(crate) messages: Vec<(Severity, String)>,
    pub(crate) tree: Tree,
    /// `myDoc`.
    pub(crate) my_doc: Option<NodeId>,
    /// `nodeTab`: the elements being built; the last is `ctxt->node`.
    pub(crate) node_tab: Vec<NodeId>,
    name_tab: Vec<StartTag>,
    space_tab: Vec<i32>,
    ns_tab: Vec<NsBinding>,
    element_id: u64,
    /// `nodelen`: the length of the text node being added to.
    pub(crate) nodelen: usize,
    /// The reader's startElement wrapper ran (`XML_TEXTREADER_ELEMENT`).
    pub(crate) element_started: bool,
    /// `doc->ids`.
    pub(crate) ids: super::sax2::Ids,
}

impl ParserCtxt {
    /// `xmlCreatePushParserCtxt` with the first bytes of the input.
    pub(crate) fn new(chunk: &[u8]) -> ParserCtxt {
        ParserCtxt {
            buf: chunk.to_vec(),
            cur: 0,
            has_encoding: false,
            auto_utf8: false,
            encoding_error_seen: false,
            ascii: false,
            buf_error: false,
            encoding: None,
            instate: InState::Start,
            check_index: 0,
            end_check_state: 0,
            disable_sax: 0,
            well_formed: true,
            err_no: None,
            nb_errors: 0,
            nb_warnings: 0,
            standalone: -1,
            has_external_subset: false,
            messages: Vec::new(),
            tree: Tree::default(),
            my_doc: None,
            node_tab: Vec::new(),
            name_tab: Vec::new(),
            space_tab: Vec::new(),
            ns_tab: Vec::new(),
            element_id: 0,
            nodelen: 0,
            element_started: false,
            ids: super::sax2::Ids::default(),
        }
    }

    /// `ctxt->node`.
    pub(crate) fn node(&self) -> Option<NodeId> {
        self.node_tab.last().copied()
    }

    /// `ctxt->nodeNr`.
    pub(crate) fn node_nr(&self) -> usize {
        self.node_tab.len()
    }

    /// `xmlParserInputBufferPush`: `chunk` to the input, through the
    /// US-ASCII conversion if there is one; `false` if it fails.
    fn push_input(&mut self, chunk: &[u8]) -> bool {
        if self.buf_error {
            return false;
        }
        if self.ascii
            && let Some(at) = chunk.iter().position(|&b| b >= 0x80)
        {
            self.buf.extend_from_slice(&chunk[..at]);
            self.buf_error = true;
            return false;
        }
        self.buf.extend_from_slice(chunk);
        true
    }

    /// `xmlParserShrink`: the input before the position, but `LINE_LEN`
    /// bytes, is dropped.
    fn shrink(&mut self) {
        if self.cur > LINE_LEN {
            let n = self.cur - LINE_LEN;
            self.buf.drain(..n);
            self.cur -= n;
        }
    }

    /// `xmlParseChunk`: `chunk` pushed and parsed as far as can be; with
    /// `terminate`, to the end. 0, or (non-zero) the error that stopped the
    /// parse.
    pub(crate) fn parse_chunk(&mut self, chunk: &[u8], terminate: bool) -> i32 {
        if self.disable_sax != 0 {
            return 1;
        }
        let mut chunk = chunk;
        let mut end_in_lf = false;
        if !chunk.is_empty() && !terminate && chunk[chunk.len() - 1] == b'\r' {
            end_in_lf = true;
            chunk = &chunk[..chunk.len() - 1];
        }
        if !self.push_input(chunk) {
            self.err_io(Code::InvalidEncoding);
            return 1;
        }
        self.try_or_finish(terminate);
        // How far the parse got from the buffer's base.
        if self.cur > XML_MAX_LOOKUP_LIMIT {
            self.fatal(
                Code::ResourceLimit,
                "Buffer size limit exceeded, try XML_PARSE_HUGE",
            );
        }
        if self.err_no.is_some() && self.disable_sax != 0 {
            return 1;
        }
        if end_in_lf && !self.push_input(b"\r") {
            self.err_io(Code::InvalidEncoding);
            return 1;
        }
        if terminate {
            if self.instate != InState::Eof && self.instate != InState::Epilog {
                if !self.name_tab.is_empty() {
                    self.fatal(Code::Other, "Premature end of data in tag");
                } else if self.instate == InState::Start {
                    self.fatal(Code::Other, "Document is empty");
                } else {
                    self.fatal(Code::Other, "Start tag expected, '<' not found");
                }
            } else if self.err_no.is_none() && self.cur < self.buf.len() {
                // xmlParserCheckEOF.
                self.fatal(Code::Other, "Extra content at the end of the document");
            }
            self.instate = InState::Eof;
        }
        if self.well_formed { 0 } else { 1 }
    }

    /// `xmlParseLookupChar`: whether `c` is in the input after the
    /// position.
    fn lookup_char(&mut self, c: u8) -> bool {
        let start = if self.check_index == 0 {
            self.cur + 1
        } else {
            self.cur + self.check_index
        };
        if self.buf.get(start..).is_some_and(|s| s.contains(&c)) {
            self.check_index = 0;
            true
        } else {
            self.check_index = self.buf.len() - self.cur;
            false
        }
    }

    /// `xmlParseLookupString`: whether `s` is in the input from the
    /// position plus `start_delta`, as `strstr` finds it: not past a NUL.
    fn lookup_string(&mut self, start_delta: usize, s: &[u8]) -> bool {
        let start = if self.check_index == 0 {
            self.cur + start_delta
        } else {
            self.cur + self.check_index
        };
        let hay = self.buf.get(start..).unwrap_or(&[]);
        let hay = &hay[..hay.iter().position(|&b| b == 0).unwrap_or(hay.len())];
        if hay.windows(s.len()).any(|w| w == s) {
            self.check_index = 0;
            return true;
        }
        // Rescan the last (strLen - 1) characters.
        let end = self.buf.len();
        let end = if end.saturating_sub(start) < s.len() {
            start
        } else {
            end - (s.len() - 1)
        };
        self.check_index = end - self.cur;
        false
    }

    /// `xmlParseLookupCharData`: whether character data is ended by `<`
    /// or `&` in the input.
    fn lookup_char_data(&mut self) -> bool {
        let start = self.cur + self.check_index;
        match self.buf[start.min(self.buf.len())..]
            .iter()
            .position(|&b| b == b'<' || b == b'&')
        {
            Some(_) => {
                self.check_index = 0;
                true
            }
            None => {
                self.check_index = self.buf.len() - self.cur;
                false
            }
        }
    }

    /// `xmlParseLookupGt`: whether the input holds the end of the start
    /// tag at the position, out of quotes.
    fn lookup_gt(&mut self) -> bool {
        let mut i = if self.check_index == 0 {
            self.cur + 1
        } else {
            self.cur + self.check_index
        };
        let mut state = self.end_check_state;
        while i < self.buf.len() {
            let c = self.buf[i];
            if state != 0 {
                if c == state {
                    state = 0;
                }
            } else if c == b'\'' || c == b'"' {
                state = c;
            } else if c == b'>' {
                self.check_index = 0;
                self.end_check_state = 0;
                return true;
            }
            i += 1;
        }
        self.check_index = i - self.cur;
        self.end_check_state = state;
        false
    }

    /// `xmlParseTryOrFinish`: as far as the input lets it, or to the end
    /// with `terminate`.
    fn try_or_finish(&mut self, terminate: bool) {
        if self.cur > 4096 {
            self.shrink();
        }
        while self.disable_sax == 0 {
            let avail = self.avail();
            if avail < 1 {
                return;
            }
            match self.instate {
                InState::Eof => return,
                InState::Start => {
                    if !terminate && avail < 4 {
                        return;
                    }
                    // More bytes are needed to tell EBCDIC code pages.
                    if self.cmp(&[0x4c, 0x6f, 0xa7, 0x94]) && !terminate && avail < 200 {
                        return;
                    }
                    self.detect_encoding();
                    self.instate = InState::XmlDecl;
                }
                InState::XmlDecl => {
                    if !terminate && avail < 2 {
                        return;
                    }
                    if self.raw() == b'<' && self.nxt(1) == b'?' {
                        if !terminate && !self.lookup_string(2, b"?>") {
                            return;
                        }
                        if self.nxt(2) == b'x'
                            && self.nxt(3) == b'm'
                            && self.nxt(4) == b'l'
                            && is_blank_ch(self.nxt(5))
                        {
                            self.parse_xml_decl();
                        }
                    }
                    if self.disable_sax == 0 {
                        self.sax2_start_document();
                    }
                    self.instate = InState::Misc;
                }
                InState::StartTag => {
                    if !terminate && avail < 2 {
                        return;
                    }
                    if self.raw() != b'<' {
                        self.fatal(Code::Other, "Start tag expected, '<' not found");
                        self.instate = InState::Eof;
                        return;
                    }
                    if !terminate && !self.lookup_gt() {
                        return;
                    }
                    let space = match self.space_tab.last() {
                        None | Some(-2) => -1,
                        Some(&s) => s,
                    };
                    self.space_tab.push(space);
                    let Some(tag) = self.parse_start_tag2() else {
                        self.space_tab.pop();
                        self.instate = InState::Eof;
                        return;
                    };
                    if self.stopped() {
                        return;
                    }
                    if self.raw() == b'/' && self.nxt(1) == b'>' {
                        self.skip(2);
                        self.sax2_end_element_ns();
                        self.ns_pop(tag.nb_ns);
                        self.space_tab.pop();
                    } else if self.raw() == b'>' {
                        self.skip(1);
                        self.name_tab.push(StartTag {
                            name: tag.localname,
                            prefix: tag.prefix,
                            ns_nr: tag.nb_ns,
                        });
                    } else {
                        self.fatal(Code::Other, "Couldn't find end of Start Tag");
                        return;
                    }
                    self.instate = if self.name_tab.is_empty() {
                        InState::Epilog
                    } else {
                        InState::Content
                    };
                }
                InState::Content => {
                    let cur = self.raw();
                    if cur == b'<' {
                        if !terminate && avail < 2 {
                            return;
                        }
                        let next = self.nxt(1);
                        if next == b'/' {
                            self.instate = InState::EndTag;
                            continue;
                        } else if next == b'?' {
                            if !terminate && !self.lookup_string(2, b"?>") {
                                return;
                            }
                            self.parse_pi();
                            continue;
                        } else if next == b'!' {
                            if !terminate && avail < 3 {
                                return;
                            }
                            let next = self.nxt(2);
                            if next == b'-' {
                                if !terminate && avail < 4 {
                                    return;
                                }
                                if self.nxt(3) == b'-' {
                                    if !terminate && !self.lookup_string(4, b"-->") {
                                        return;
                                    }
                                    self.parse_comment();
                                    continue;
                                }
                            } else if next == b'[' {
                                if !terminate && avail < 9 {
                                    return;
                                }
                                if self.cmp(b"<![CDATA[") {
                                    if !terminate && !self.lookup_string(9, b"]]>") {
                                        return;
                                    }
                                    self.parse_cdsect();
                                    continue;
                                }
                            }
                        }
                    } else if cur == b'&' {
                        if !terminate && !self.lookup_char(b';') {
                            return;
                        }
                        self.parse_reference();
                        continue;
                    } else {
                        // Character data: in pieces as large as can be, so
                        // that the SAX calls are few.
                        if avail < XML_PARSER_BIG_BUFFER_SIZE
                            && !terminate
                            && !self.lookup_char_data()
                        {
                            return;
                        }
                        self.check_index = 0;
                        self.parse_char_data_internal(!terminate);
                        continue;
                    }
                    self.instate = InState::StartTag;
                }
                InState::EndTag => {
                    if !terminate && !self.lookup_char(b'>') {
                        return;
                    }
                    self.parse_end_tag2();
                    if self.stopped() {
                        return;
                    }
                    if let Some(tag) = self.name_tab.pop() {
                        self.ns_pop(tag.ns_nr);
                    }
                    self.instate = if self.name_tab.is_empty() {
                        InState::Epilog
                    } else {
                        InState::Content
                    };
                }
                InState::Misc | InState::Prolog | InState::Epilog => {
                    self.skip_blanks();
                    let avail = self.avail();
                    if avail < 1 {
                        return;
                    }
                    if self.raw() == b'<' {
                        if !terminate && avail < 2 {
                            return;
                        }
                        let next = self.nxt(1);
                        if next == b'?' {
                            if !terminate && !self.lookup_string(2, b"?>") {
                                return;
                            }
                            self.parse_pi();
                            continue;
                        } else if next == b'!' {
                            if !terminate && avail < 3 {
                                return;
                            }
                            if self.nxt(2) == b'-' {
                                if !terminate && avail < 4 {
                                    return;
                                }
                                if self.nxt(3) == b'-' {
                                    if !terminate && !self.lookup_string(4, b"-->") {
                                        return;
                                    }
                                    self.parse_comment();
                                    continue;
                                }
                            } else if self.instate == InState::Misc {
                                if !terminate && avail < 9 {
                                    return;
                                }
                                if self.cmp(b"<!DOCTYPE") {
                                    if !terminate && !self.lookup_gt() {
                                        return;
                                    }
                                    self.parse_doctype_decl();
                                    if self.stopped() {
                                        return;
                                    }
                                    if self.raw() == b'[' {
                                        // Differs from libxml2: the internal
                                        // subset is not read.
                                        self.fatal(
                                            Code::InternalSubset,
                                            "DOCTYPE internal subset not supported",
                                        );
                                        return;
                                    }
                                    if self.raw() == b'>' {
                                        self.next_char();
                                    }
                                    self.instate = InState::Prolog;
                                    continue;
                                }
                            }
                        }
                    }
                    if self.instate == InState::Epilog {
                        if self.err_no.is_none() {
                            self.fatal(Code::Other, "Extra content at the end of the document");
                        }
                        self.instate = InState::Eof;
                    } else {
                        self.instate = InState::StartTag;
                    }
                }
            }
        }
    }

    // --- The XML declaration -------------------------------------------

    /// `xmlParseXMLDecl`.
    fn parse_xml_decl(&mut self) {
        self.standalone = -2;
        // '<?xml' is here.
        self.skip(5);
        if !is_blank_ch(self.raw()) {
            self.fatal(Code::Other, "Blank needed after '<?xml'");
            return;
        }
        self.skip_blanks();
        match self.parse_version_info() {
            None => {
                if self.stopped() {
                    return;
                }
                self.fatal(Code::Other, "Malformed declaration expecting version");
                return;
            }
            Some(version) => {
                if version != b"1.0" {
                    if version.starts_with(b"1.") {
                        self.warning(
                            Code::Other,
                            format!(
                                "Unsupported version '{}'\n",
                                String::from_utf8_lossy(&version)
                            ),
                        );
                    } else {
                        self.fatal(Code::Other, "Unsupported version");
                        return;
                    }
                }
            }
        }
        // The encoding declaration, maybe.
        if !is_blank_ch(self.raw()) {
            if self.raw() == b'?' && self.nxt(1) == b'>' {
                self.skip(2);
                return;
            }
            self.fatal(Code::Other, "Blank needed here");
            return;
        }
        self.parse_encoding_decl();
        if self.stopped() {
            return;
        }
        // The standalone status, maybe.
        if self.encoding.is_some() && !is_blank_ch(self.raw()) {
            if self.raw() == b'?' && self.nxt(1) == b'>' {
                self.skip(2);
                return;
            }
            self.fatal(Code::Other, "Blank needed here");
            return;
        }
        self.skip_blanks();
        self.standalone = self.parse_sd_decl();
        if self.stopped() {
            return;
        }
        self.skip_blanks();
        if self.raw() == b'?' && self.nxt(1) == b'>' {
            self.skip(2);
        } else {
            self.fatal(Code::Other, "parsing XML declaration: '?>' expected");
        }
    }

    /// `xmlParseVersionInfo` and `xmlParseVersionNum`.
    fn parse_version_info(&mut self) -> Option<Vec<u8>> {
        if !self.cmp(b"version") {
            return None;
        }
        self.skip(7);
        self.skip_blanks();
        if self.raw() != b'=' {
            self.fatal(Code::Other, "AttValue: = expected");
            return None;
        }
        self.next_char();
        self.skip_blanks();
        let quote = self.raw();
        if quote != b'"' && quote != b'\'' {
            self.fatal(Code::Other, "String not started expecting ' or \"");
            return None;
        }
        self.next_char();
        let version = self.parse_version_num();
        if self.stopped() {
            return None;
        }
        if self.raw() != quote {
            self.fatal(Code::Other, "String not closed expecting \" or '");
            return None;
        }
        self.next_char();
        version
    }

    /// `xmlParseVersionNum`: `[0-9] '.' [0-9]*`.
    fn parse_version_num(&mut self) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut size = 10;
        if !self.raw().is_ascii_digit() {
            return None;
        }
        buf.push(self.raw());
        self.next_char();
        if self.raw() != b'.' {
            return None;
        }
        buf.push(b'.');
        self.next_char();
        while self.raw().is_ascii_digit() {
            if buf.len() + 1 >= size {
                match grow_capacity(size, XML_MAX_NAME_LENGTH) {
                    Some(s) => size = s,
                    None => {
                        self.fatal(Code::Other, "VersionNum: name too long");
                        return None;
                    }
                }
            }
            buf.push(self.raw());
            self.next_char();
        }
        Some(buf)
    }

    /// `xmlParseEncodingDecl` and `xmlParseEncName`.
    fn parse_encoding_decl(&mut self) {
        self.skip_blanks();
        if !self.cmp(b"encoding") {
            return;
        }
        self.skip(8);
        self.skip_blanks();
        if self.raw() != b'=' {
            self.fatal(Code::Other, "AttValue: = expected");
            return;
        }
        self.next_char();
        self.skip_blanks();
        let quote = self.raw();
        if quote != b'"' && quote != b'\'' {
            self.fatal(Code::Other, "String not started expecting ' or \"");
            return;
        }
        self.next_char();
        // xmlParseEncName: [A-Za-z] ([A-Za-z0-9._] | '-')*
        let mut name = Vec::new();
        let mut size = 10;
        if self.raw().is_ascii_alphabetic() {
            name.push(self.raw());
            self.next_char();
            while {
                let c = self.raw();
                c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-'
            } {
                if name.len() + 1 >= size {
                    match grow_capacity(size, XML_MAX_NAME_LENGTH) {
                        Some(s) => size = s,
                        None => {
                            self.fatal(Code::Other, "EncName: name too long");
                            return;
                        }
                    }
                }
                name.push(self.raw());
                self.next_char();
            }
        } else {
            self.fatal(Code::Other, "Invalid XML encoding name");
            return;
        }
        if self.raw() != quote {
            self.fatal(Code::Other, "String not closed expecting \" or '");
            return;
        }
        self.next_char();
        self.set_declared_encoding(name);
    }

    /// `xmlParseSDDecl`.
    fn parse_sd_decl(&mut self) -> i32 {
        let mut standalone = -2;
        self.skip_blanks();
        if !self.cmp(b"standalone") {
            return standalone;
        }
        self.skip(10);
        self.skip_blanks();
        if self.raw() != b'=' {
            self.fatal(Code::Other, "AttValue: = expected");
            return standalone;
        }
        self.next_char();
        self.skip_blanks();
        let quote = self.raw();
        if quote != b'\'' && quote != b'"' {
            self.fatal(Code::Other, "String not started expecting ' or \"");
            return standalone;
        }
        self.next_char();
        if self.raw() == b'n' && self.nxt(1) == b'o' {
            standalone = 0;
            self.skip(2);
        } else if self.raw() == b'y' && self.nxt(1) == b'e' && self.nxt(2) == b's' {
            standalone = 1;
            self.skip(3);
        } else {
            self.fatal(Code::Other, "standalone accepts only 'yes' or 'no'");
            return standalone;
        }
        if self.raw() != quote {
            self.fatal(Code::Other, "String not closed expecting \" or '");
            return standalone;
        }
        self.next_char();
        standalone
    }

    // --- Names ---------------------------------------------------------

    /// `xmlParseName`: a Name, or `None` (after an error if it is too
    /// long).
    fn parse_name(&mut self) -> Option<Vec<u8>> {
        // The accelerator for simple ASCII names.
        let start = self.cur;
        let c = self.raw();
        if c.is_ascii_alphabetic() || c == b'_' || c == b':' {
            let mut i = start + 1;
            while {
                let c = self.at(i);
                c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b':' || c == b'.'
            } {
                i += 1;
            }
            let c = self.at(i);
            if c > 0 && c < 0x80 {
                let count = i - start;
                if count > XML_MAX_NAME_LENGTH {
                    self.fatal(Code::Other, "Name: name too long");
                    return None;
                }
                self.cur = i;
                return Some(self.buf[start..i].to_vec());
            }
        }
        // xmlParseNameComplex.
        let (c, l) = self.current_char();
        if !is_name_start_char(c) {
            return None;
        }
        let mut len = l;
        self.skip(l);
        loop {
            let (c, l) = self.current_char();
            if !is_name_char(c) {
                break;
            }
            len += l;
            self.skip(l);
        }
        if len > XML_MAX_NAME_LENGTH {
            self.fatal(Code::Other, "Name: name too long");
            return None;
        }
        if self.stopped() {
            return None;
        }
        Some(self.buf[self.cur - len..self.cur].to_vec())
    }

    /// `xmlParseNCName`: an NCName (a Name without colons), or `None`.
    fn parse_ncname(&mut self) -> Option<Vec<u8>> {
        let start = self.cur;
        let end = self.buf.len();
        let c = self.raw();
        if (c.is_ascii_alphabetic() || c == b'_') && start < end {
            let mut i = start + 1;
            while {
                let c = self.at(i);
                (c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.') && i < end
            } {
                i += 1;
            }
            if i < end {
                let c = self.at(i);
                if c > 0 && c < 0x80 {
                    if i - start > XML_MAX_NAME_LENGTH {
                        self.fatal(Code::Other, "NCName: name too long");
                        return None;
                    }
                    self.cur = i;
                    return Some(self.buf[start..i].to_vec());
                }
            }
        }
        // xmlParseNCNameComplex.
        let (c, mut l) = self.current_char();
        if c == i32::from(b' ')
            || c == i32::from(b'>')
            || c == i32::from(b'/')
            || !is_name_start_char(c)
            || c == i32::from(b':')
        {
            return None;
        }
        let mut c = c;
        let mut len = 0;
        while c != i32::from(b' ')
            && c != i32::from(b'>')
            && c != i32::from(b'/')
            && is_name_char(c)
            && c != i32::from(b':')
        {
            len += l;
            self.skip(l);
            (c, l) = self.current_char();
        }
        if len > XML_MAX_NAME_LENGTH {
            self.fatal(Code::Other, "NCName: name too long");
            return None;
        }
        if self.stopped() {
            return None;
        }
        Some(self.buf[start..start + len].to_vec())
    }

    /// `xmlParseNmtoken`, for what it consumes and whether the token is
    /// too long.
    fn parse_nmtoken(&mut self) {
        let mut len = 0usize;
        let (mut c, mut l) = self.current_char();
        let mut max: Option<usize> = None;
        while is_name_char(c) {
            if let Some(m) = max
                && len + 10 > m
            {
                match grow_capacity(m, XML_MAX_NAME_LENGTH) {
                    Some(s) => max = Some(s),
                    None => {
                        self.fatal(Code::Other, "NmToken: name too long");
                        return;
                    }
                }
            }
            len += char_len(c);
            self.skip(l);
            (c, l) = self.current_char();
            if max.is_none() && len >= 100 {
                max = Some(len * 2);
            }
        }
        if max.is_none() && len > XML_MAX_NAME_LENGTH {
            self.fatal(Code::Other, "NmToken: name too long");
        }
    }

    /// `xmlParseQNameHashed`: a QName as `(local name, prefix)`; one that is
    /// not well formed is taken whole, after a namespace error.
    fn parse_qname(&mut self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let start = self.cur;
        let mut prefix = None;
        let mut is_ncname = false;
        let mut l = self.parse_ncname();
        if self.stopped() {
            return None;
        }
        if l.is_some() {
            is_ncname = true;
            if self.raw() == b':' {
                self.next_char();
                prefix = l;
                l = self.parse_ncname();
                if self.stopped() {
                    return None;
                }
            }
        }
        if l.is_none() || self.raw() == b':' {
            if !is_ncname && self.raw() != b':' {
                return None;
            }
            self.parse_nmtoken();
            if self.stopped() {
                return None;
            }
            let name = self.buf[start..self.cur].to_vec();
            self.ns_err(
                Code::Other,
                format!(
                    "Failed to parse QName '{}'\n",
                    String::from_utf8_lossy(&name)
                ),
            );
            return Some((name, None));
        }
        l.map(|l| (l, prefix))
    }

    // --- Start tags --------------------------------------------------

    /// `xmlParseAttValueInternal`: the value, with references replaced
    /// (`&amp;` and `&#38;` as `&`, as SAX2 makes them in the end) and
    /// whitespace characters as spaces; `None` after an error.
    fn parse_att_value_internal(&mut self) -> Option<Vec<u8>> {
        let quote = self.raw();
        if quote != b'"' && quote != b'\'' {
            self.fatal(Code::Other, "AttValue: \" or ' expected");
            return None;
        }
        self.skip(1);
        let mut value = Vec::new();
        let mut buf = SBuf::new();
        let mut chunk_start = self.cur;
        let mut chunk_size = 0usize;
        loop {
            if self.cur >= self.buf.len() {
                self.fatal(Code::Other, "AttValue: ' expected");
                return None;
            }
            let c = self.raw();
            if c >= 0x80 {
                let l = self.utf8_multibyte_len(self.cur, "invalid character in attribute value");
                if self.stopped() {
                    return None;
                }
                if l == 0 {
                    unreachable_after_error();
                    return None;
                }
                chunk_size += l;
                self.skip(l);
            } else if c != b'&' {
                if c > 0x20 {
                    if c == quote {
                        break;
                    }
                    if c == b'<' {
                        self.fatal(
                            Code::Other,
                            "Unescaped '<' not allowed in attributes values",
                        );
                        return None;
                    }
                    chunk_size += 1;
                } else if !is_byte_char(c) {
                    self.fatal(Code::InvalidChar, "invalid character in attribute value");
                    return None;
                } else {
                    // Whitespace: a space, or a character turned into one.
                    if c < 0x20 {
                        if chunk_size > 0 {
                            let bytes = self.buf[chunk_start..chunk_start + chunk_size].to_vec();
                            buf.add(&mut value, &bytes);
                            chunk_size = 0;
                        }
                        buf.add(&mut value, b" ");
                    } else {
                        chunk_size += 1;
                    }
                    if c == 0x0d && self.nxt(1) == 0x0a {
                        self.skip(1);
                    }
                }
                self.skip(1);
                if chunk_size == 0 {
                    chunk_start = self.cur;
                }
            } else if self.nxt(1) == b'#' {
                if chunk_size > 0 {
                    let bytes = self.buf[chunk_start..chunk_start + chunk_size].to_vec();
                    buf.add(&mut value, &bytes);
                    chunk_size = 0;
                }
                let val = self.parse_char_ref();
                if self.stopped() || val == 0 {
                    return None;
                }
                if val == i32::from(b'&') {
                    // "&#38;", which SAX2 parses back into '&'.
                    if XML_MAX_TEXT_LENGTH - buf.size < 5 {
                        buf.over = true;
                    } else {
                        buf.used = true;
                        buf.size += 5;
                        value.push(b'&');
                    }
                } else if val == i32::from(b' ') {
                    buf.add(&mut value, b" ");
                } else {
                    buf.add_char(&mut value, val);
                }
                chunk_start = self.cur;
            } else {
                if chunk_size > 0 {
                    let bytes = self.buf[chunk_start..chunk_start + chunk_size].to_vec();
                    buf.add(&mut value, &bytes);
                    chunk_size = 0;
                }
                let name = self.parse_entity_ref_internal();
                if self.stopped() {
                    return None;
                }
                chunk_start = self.cur;
                let Some(name) = name else {
                    continue;
                };
                match predefined_entity(&name) {
                    Some(b'&') => {
                        // "&#38;", which SAX2 parses back.
                        if XML_MAX_TEXT_LENGTH - buf.size < 5 {
                            buf.over = true;
                        } else {
                            buf.used = true;
                            buf.size += 5;
                            value.push(b'&');
                        }
                    }
                    Some(c) => buf.add(&mut value, &[c]),
                    None => {
                        self.handle_undeclared_entity(&name);
                        if self.stopped() {
                            return None;
                        }
                    }
                }
            }
        }
        if !buf.used {
            // The value as it is in the input.
            value = self.buf[chunk_start..chunk_start + chunk_size].to_vec();
        } else if chunk_size > 0 {
            let bytes = self.buf[chunk_start..chunk_start + chunk_size].to_vec();
            buf.add(&mut value, &bytes);
        }
        if buf.over {
            self.fatal(Code::ResourceLimit, "AttValue length too long");
            return None;
        }
        self.skip(1);
        Some(value)
    }

    /// `xmlParseAttribute2`: an attribute's name, prefix and value (`None`
    /// after an error that lets the start tag go on).
    #[allow(clippy::type_complexity)]
    fn parse_attribute2(&mut self) -> Option<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let Some((name, prefix)) = self.parse_qname() else {
            if !self.stopped() {
                self.fatal(Code::Other, "error parsing attribute name");
            }
            return None;
        };
        self.skip_blanks();
        if self.raw() != b'=' {
            self.fatal(Code::Other, "Specification mandates value for attribute");
            return None;
        }
        self.next_char();
        self.skip_blanks();
        let value = self.parse_att_value_internal();
        if self.stopped() {
            return None;
        }
        let Some(value) = value else {
            return Some((name, prefix, None));
        };
        if prefix.as_deref() == Some(b"xml") && name == b"space" {
            if value == b"default" {
                if let Some(s) = self.space_tab.last_mut() {
                    *s = 0;
                }
            } else if value == b"preserve" {
                if let Some(s) = self.space_tab.last_mut() {
                    *s = 1;
                }
            } else {
                self.warning(
                    Code::Other,
                    format!(
                        "Invalid value \"{}\" for xml:space : \"default\" or \"preserve\" expected\n",
                        String::from_utf8_lossy(&value)
                    ),
                );
            }
        }
        Some((name, prefix, Some(value)))
    }

    /// `xmlParserNsLookup` and `xmlParserNsLookupUri`: the URI bound to
    /// `prefix` (the default namespace for `None`), and whether there is a
    /// binding at all.
    fn ns_lookup(&self, prefix: Option<&[u8]>) -> Option<&NsBinding> {
        self.ns_tab
            .iter()
            .rev()
            .find(|b| b.prefix.as_deref() == prefix)
    }

    /// `xmlParserNsPush`: `false` (after an error) if the element already
    /// declares the prefix.
    fn ns_push(&mut self, prefix: Option<&[u8]>, uri: &[u8]) -> bool {
        if let Some(old) = self.ns_lookup(prefix)
            && old.element_id == self.element_id
        {
            match prefix {
                None => self.fatal(Code::Other, "Attribute xmlns redefined"),
                Some(p) => {
                    let msg = format!("Attribute xmlns:{} redefined", String::from_utf8_lossy(p));
                    self.fatal(Code::Other, &msg);
                }
            }
            return false;
        }
        self.ns_tab.push(NsBinding {
            prefix: prefix.map(<[u8]>::to_vec),
            uri: uri.to_vec(),
            element_id: self.element_id,
        });
        true
    }

    /// `xmlParserNsPop`.
    fn ns_pop(&mut self, nr: usize) {
        let n = self.ns_tab.len().saturating_sub(nr);
        self.ns_tab.truncate(n);
    }

    /// `xmlParseStartTag2`: a start tag, through the SAX callback; `None`
    /// when it has no name.
    fn parse_start_tag2(&mut self) -> Option<StartTagResult> {
        if self.raw() != b'<' {
            return None;
        }
        self.skip(1);
        self.element_id += 1;
        let Some((localname, prefix)) = self.parse_qname() else {
            if !self.stopped() {
                self.fatal(Code::Other, "StartTag: invalid element name");
            }
            return None;
        };
        self.skip_blanks();
        let mut atts: Vec<ParsedAttr> = Vec::new();
        let mut nb_ns = 0;
        while self.raw() != b'>'
            && (self.raw() != b'/' || self.nxt(1) != b'>')
            && is_byte_char(self.raw())
        {
            let Some((attname, aprefix, value)) = self.parse_attribute2() else {
                break;
            };
            if let Some(value) = value {
                if attname == b"xmlns" && aprefix.is_none() {
                    // The default namespace.
                    let mut keep = true;
                    if !value.is_empty() {
                        match parse_uri_safe(&value) {
                            None => self.ns_err(
                                Code::Other,
                                format!(
                                    "xmlns: '{}' is not a valid URI\n",
                                    String::from_utf8_lossy(&value)
                                ),
                            ),
                            Some(false) => self.warning(
                                Code::Other,
                                format!(
                                    "xmlns: URI {} is not absolute\n",
                                    String::from_utf8_lossy(&value)
                                ),
                            ),
                            Some(true) => {}
                        }
                        if value == XML_XML_NAMESPACE {
                            self.ns_err(
                                Code::Other,
                                "xml namespace URI cannot be the default namespace\n".into(),
                            );
                            keep = false;
                        } else if value == XMLNS_NAMESPACE {
                            self.ns_err(
                                Code::Other,
                                "reuse of the xmlns namespace name is forbidden\n".into(),
                            );
                            keep = false;
                        }
                    }
                    if keep && self.ns_push(None, &value) {
                        nb_ns += 1;
                    }
                    if self.stopped() {
                        return None;
                    }
                } else if aprefix.as_deref() == Some(b"xmlns") {
                    let mut keep = true;
                    if attname == b"xml" {
                        if value != XML_XML_NAMESPACE {
                            self.ns_err(
                                Code::Other,
                                "xml namespace prefix mapped to wrong URI\n".into(),
                            );
                        }
                        keep = false;
                    } else if value == XML_XML_NAMESPACE {
                        self.ns_err(
                            Code::Other,
                            "xml namespace URI mapped to wrong prefix\n".into(),
                        );
                        keep = false;
                    } else if attname == b"xmlns" {
                        self.ns_err(
                            Code::Other,
                            "redefinition of the xmlns prefix is forbidden\n".into(),
                        );
                        keep = false;
                    } else if value == XMLNS_NAMESPACE {
                        self.ns_err(
                            Code::Other,
                            "reuse of the xmlns namespace name is forbidden\n".into(),
                        );
                        keep = false;
                    } else if value.is_empty() {
                        self.ns_err(
                            Code::Other,
                            format!(
                                "xmlns:{}: Empty XML namespace is not allowed\n",
                                String::from_utf8_lossy(&attname)
                            ),
                        );
                        keep = false;
                    } else if parse_uri_safe(&value).is_none() {
                        self.ns_err(
                            Code::Other,
                            format!(
                                "xmlns:{}: '{}' is not a valid URI\n",
                                String::from_utf8_lossy(&attname),
                                String::from_utf8_lossy(&value)
                            ),
                        );
                    }
                    if keep && self.ns_push(Some(&attname), &value) {
                        nb_ns += 1;
                    }
                    if self.stopped() {
                        return None;
                    }
                } else {
                    atts.push(ParsedAttr {
                        name: attname,
                        prefix: aprefix,
                        uri: None,
                        value,
                    });
                }
            }
            if self.raw() == b'>' || (self.raw() == b'/' && self.nxt(1) == b'>') {
                break;
            }
            if self.skip_blanks() == 0 {
                self.fatal(Code::Other, "attributes construct error");
                return None;
            }
        }
        if self.stopped() {
            return None;
        }

        // The attributes' namespaces.
        let mut undeclared = vec![false; atts.len()];
        for i in 0..atts.len() {
            let uri = match atts[i].prefix.as_deref() {
                None => None,
                Some(b"xml") => Some(XML_XML_NAMESPACE.to_vec()),
                Some(p) => match self.ns_lookup(Some(p)) {
                    Some(b) => Some(b.uri.clone()),
                    None => {
                        self.ns_err(
                            Code::Other,
                            format!(
                                "Namespace prefix {} for {} on {} is not defined\n",
                                String::from_utf8_lossy(p),
                                String::from_utf8_lossy(&atts[i].name),
                                String::from_utf8_lossy(&localname)
                            ),
                        );
                        undeclared[i] = true;
                        None
                    }
                },
            };
            atts[i].uri = uri;
        }

        // Attribute names are unique, with their namespaces.
        let mut num_ns_err = 0;
        if atts.len() > 1 {
            let mut seen: Vec<usize> = Vec::new();
            for j in 0..atts.len() {
                if undeclared[j] {
                    continue;
                }
                let found = seen
                    .iter()
                    .copied()
                    .find(|&i| atts[i].name == atts[j].name && atts[i].uri == atts[j].uri);
                match found {
                    None => seen.push(j),
                    Some(i) => {
                        if atts[i].prefix == atts[j].prefix {
                            self.attribute_dup(atts[j].prefix.as_deref(), &atts[j].name);
                            return None;
                        }
                        self.ns_err(
                            Code::Other,
                            format!(
                                "Namespaced Attribute {} in '{}' redefined\n",
                                String::from_utf8_lossy(&atts[j].name),
                                String::from_utf8_lossy(atts[j].uri.as_deref().unwrap_or(b""))
                            ),
                        );
                        num_ns_err += 1;
                    }
                }
            }
        }
        // One hash table cannot tell every duplicate QName: they are looked
        // for again after more than one namespace error.
        if num_ns_err > 1 {
            for j in 0..atts.len() {
                if atts[j].prefix.is_none() {
                    continue;
                }
                if (0..j).any(|i| {
                    atts[i].prefix.is_some()
                        && atts[i].name == atts[j].name
                        && atts[i].prefix == atts[j].prefix
                }) {
                    self.attribute_dup(atts[j].prefix.as_deref(), &atts[j].name);
                    return None;
                }
            }
        }

        // The element's namespace.
        let uri = match prefix.as_deref() {
            Some(b"xml") => Some(XML_XML_NAMESPACE.to_vec()),
            p => self
                .ns_lookup(p)
                .map(|b| b.uri.clone())
                .filter(|u| !u.is_empty()),
        };
        if let (Some(p), None) = (&prefix, &uri) {
            self.ns_err(
                Code::Other,
                format!(
                    "Namespace prefix {} on {} is not defined\n",
                    String::from_utf8_lossy(p),
                    String::from_utf8_lossy(&localname)
                ),
            );
        }

        if self.disable_sax == 0 {
            let ns_defs: Vec<(Option<Vec<u8>>, Vec<u8>)> = self.ns_tab[self.ns_tab.len() - nb_ns..]
                .iter()
                .map(|b| (b.prefix.clone(), b.uri.clone()))
                .collect();
            self.sax2_start_element_ns(
                &localname,
                prefix.as_deref(),
                uri.is_some(),
                &ns_defs,
                &atts,
            );
        }
        Some(StartTagResult {
            localname,
            prefix,
            nb_ns,
        })
    }

    /// `xmlErrAttributeDup`.
    fn attribute_dup(&mut self, prefix: Option<&[u8]>, name: &[u8]) {
        let msg = match prefix {
            None => format!("Attribute {} redefined", String::from_utf8_lossy(name)),
            Some(p) => format!(
                "Attribute {}:{} redefined",
                String::from_utf8_lossy(p),
                String::from_utf8_lossy(name)
            ),
        };
        self.fatal(Code::Other, &msg);
    }

    // --- End tags ----------------------------------------------------

    /// `xmlParseEndTag2`, for the element at the top of the name stack.
    fn parse_end_tag2(&mut self) {
        let Some(tag) = self.name_tab.last().cloned() else {
            return;
        };
        if self.raw() != b'<' || self.nxt(1) != b'/' {
            self.fatal(Code::Other, "expected '</'");
            return;
        }
        self.skip(2);
        let matched = match &tag.prefix {
            None => self.parse_name_and_compare(&tag.name),
            Some(p) => self.parse_qname_and_compare(&tag.name, p),
        };
        if self.stopped() {
            return;
        }
        self.skip_blanks();
        if !is_byte_char(self.raw()) || self.raw() != b'>' {
            self.fatal(Code::Other, "expected '>'");
            return;
        }
        self.skip(1);
        if !matched {
            let msg = format!(
                "Opening and ending tag mismatch: {}",
                String::from_utf8_lossy(&tag.name)
            );
            self.fatal(Code::Other, &msg);
            return;
        }
        self.sax2_end_element_ns();
        self.space_tab.pop();
    }

    /// `xmlParseNameAndCompare`: whether the name at the position is
    /// `other`.
    fn parse_name_and_compare(&mut self, other: &[u8]) -> bool {
        let mut i = self.cur;
        let mut k = 0;
        while self.at(i) != 0 && k < other.len() && self.at(i) == other[k] {
            i += 1;
            k += 1;
        }
        if k == other.len() && (self.at(i) == b'>' || is_blank_ch(self.at(i))) {
            self.cur = i;
            return true;
        }
        // Failure, or the end of the buffer: the full function.
        match self.parse_name() {
            Some(name) => name == other,
            None => false,
        }
    }

    /// `xmlParseQNameAndCompare`.
    fn parse_qname_and_compare(&mut self, name: &[u8], prefix: &[u8]) -> bool {
        let mut i = self.cur;
        let mut k = 0;
        while self.at(i) != 0 && k < prefix.len() && self.at(i) == prefix[k] {
            i += 1;
            k += 1;
        }
        if k == prefix.len() && self.at(i) == b':' {
            i += 1;
            let mut k = 0;
            while self.at(i) != 0 && k < name.len() && self.at(i) == name[k] {
                i += 1;
                k += 1;
            }
            if k == name.len() && (self.at(i) == b'>' || is_blank_ch(self.at(i))) {
                self.cur = i;
                return true;
            }
        }
        match self.parse_qname() {
            Some((n, p)) => n == name && p.as_deref() == Some(prefix),
            None => false,
        }
    }

    // --- Character data and references -------------------------------

    /// `xmlParseCharDataInternal`: character data up to markup, a reference
    /// or (when `partial`) the end of what was pushed.
    fn parse_char_data_internal(&mut self, partial: bool) {
        let mut inp = self.cur;
        loop {
            // get_more_space: spaces and newlines.
            loop {
                while self.at(inp) == 0x20 {
                    inp += 1;
                }
                if self.at(inp) == 0x0a {
                    while self.at(inp) == 0x0a {
                        inp += 1;
                    }
                    continue;
                }
                break;
            }
            if self.at(inp) == b'<' {
                if inp > self.cur {
                    let start = self.cur;
                    self.cur = inp;
                    self.characters_range(start, inp);
                }
                return;
            }
            // get_more.
            let mut terminate = false;
            loop {
                while test_char_data(self.at(inp)) {
                    inp += 1;
                }
                if self.at(inp) == 0x0a {
                    while self.at(inp) == 0x0a {
                        inp += 1;
                    }
                    continue;
                }
                if self.at(inp) == b']' {
                    let avail = self.buf.len().saturating_sub(inp);
                    if partial && avail < 2 {
                        terminate = true;
                        break;
                    }
                    if self.at(inp + 1) == b']' {
                        if partial && avail < 3 {
                            terminate = true;
                            break;
                        }
                        if self.at(inp + 2) == b'>' {
                            self.fatal(Code::Other, "Sequence ']]>' not allowed in content");
                            return;
                        }
                    }
                    inp += 1;
                    continue;
                }
                break;
            }
            // invoke_callback.
            if inp > self.cur {
                let start = self.cur;
                self.cur = inp;
                self.characters_range(start, inp);
                if self.stopped() {
                    return;
                }
            }
            self.cur = inp;
            let mut at_lf = false;
            if self.at(inp) == 0x0d && self.at(inp + 1) == 0x0a {
                self.cur = inp + 1;
                inp += 2;
                at_lf = true;
            }
            if !at_lf {
                let c = self.at(inp);
                if c == b'<' || c == b'&' || terminate {
                    return;
                }
                inp = self.cur;
            }
            let c = self.at(inp);
            if !((0x20..=0x7f).contains(&c) || c == 0x09 || c == 0x0a) {
                break;
            }
        }
        self.parse_char_data_complex(partial);
    }

    /// `xmlParseCharDataComplex`: character data with non-ASCII characters
    /// or carriage returns, in pieces of `XML_PARSER_BIG_BUFFER_SIZE`.
    fn parse_char_data_complex(&mut self, partial: bool) {
        let mut buf = Vec::with_capacity(XML_PARSER_BIG_BUFFER_SIZE + 5);
        let (mut cur, mut l) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        while cur != i32::from(b'<') && cur != i32::from(b'&') && is_char(cur) {
            if cur == i32::from(b']') {
                let avail = self.avail();
                if partial && avail < 2 {
                    break;
                }
                if self.nxt(1) == b']' {
                    if partial && avail < 3 {
                        break;
                    }
                    if self.nxt(2) == b'>' {
                        self.fatal(Code::Other, "Sequence ']]>' not allowed in content");
                        return;
                    }
                }
            }
            copy_char(&mut buf, cur);
            self.skip(l);
            if buf.len() >= XML_PARSER_BIG_BUFFER_SIZE {
                self.characters(&buf);
                buf.clear();
                if self.stopped() {
                    return;
                }
            }
            (cur, l) = self.current_char_recover();
            if self.stopped() {
                return;
            }
        }
        if !buf.is_empty() {
            self.characters(&buf);
            if self.stopped() {
                return;
            }
        }
        // At the end of the buffer, at an actual 0, or before a truncated
        // UTF-8 sequence (allowed when partial).
        if self.cur < self.buf.len() {
            if cur == 0 && self.raw() != 0 {
                if !partial {
                    self.fatal(Code::InvalidChar, "Incomplete UTF-8 sequence");
                }
            } else if cur != i32::from(b'<') && cur != i32::from(b'&') && cur != i32::from(b']') {
                self.fatal(Code::InvalidChar, "PCDATA invalid Char value");
            }
        }
    }

    /// The characters of `buf[start..end]` to SAX.
    fn characters_range(&mut self, start: usize, end: usize) {
        let bytes = self.buf[start..end].to_vec();
        self.characters(&bytes);
    }

    /// `xmlCharacters`, through the reader's wrapper to `xmlSAX2Characters`.
    fn characters(&mut self, bytes: &[u8]) {
        if self.disable_sax != 0 {
            return;
        }
        self.sax2_text(bytes, false);
    }

    /// `xmlParseCharRef`: the value of `&#...;`, or 0 after an error.
    fn parse_char_ref(&mut self) -> i32 {
        let mut val: i32 = 0;
        let mut count: i32 = 0;
        if self.raw() == b'&' && self.nxt(1) == b'#' && self.nxt(2) == b'x' {
            self.skip(3);
            while self.raw() != b';' {
                if count > 20 {
                    count = 0;
                } else {
                    count += 1;
                }
                let c = self.raw();
                if c.is_ascii_digit() {
                    val = val * 16 + i32::from(c - b'0');
                } else if (b'a'..=b'f').contains(&c) && count < 20 {
                    val = val * 16 + i32::from(c - b'a') + 10;
                } else if (b'A'..=b'F').contains(&c) && count < 20 {
                    val = val * 16 + i32::from(c - b'A') + 10;
                } else {
                    self.fatal(Code::Other, "xmlParseCharRef: invalid hexadecimal value");
                    return 0;
                }
                if val > 0x11_0000 {
                    val = 0x11_0000;
                }
                self.next_char();
                count += 1;
            }
            if self.raw() == b';' {
                self.skip(1);
            }
        } else if self.raw() == b'&' && self.nxt(1) == b'#' {
            self.skip(2);
            while self.raw() != b';' {
                let c = self.raw();
                if c.is_ascii_digit() {
                    val = val * 10 + i32::from(c - b'0');
                } else {
                    self.fatal(Code::Other, "xmlParseCharRef: invalid decimal value");
                    return 0;
                }
                if val > 0x11_0000 {
                    val = 0x11_0000;
                }
                self.next_char();
            }
            if self.raw() == b';' {
                self.skip(1);
            }
        } else {
            if self.raw() == b'&' {
                self.skip(1);
            }
            self.fatal(Code::Other, "xmlParseCharRef: invalid xmlChar value");
            return 0;
        }
        // Characters referred to must be Chars.
        if val >= 0x11_0000 {
            self.fatal(
                Code::InvalidChar,
                "xmlParseCharRef: character reference out of bounds",
            );
            return 0;
        } else if !is_char(val) {
            self.fatal(Code::InvalidChar, "xmlParseCharRef: invalid xmlChar value");
            return 0;
        }
        val
    }

    /// `xmlParseEntityRefInternal`: the name of `&name;`, or `None` (after
    /// an error).
    fn parse_entity_ref_internal(&mut self) -> Option<Vec<u8>> {
        if self.raw() != b'&' {
            return None;
        }
        self.next_char();
        let Some(name) = self.parse_name() else {
            if !self.stopped() {
                self.fatal(Code::Other, "xmlParseEntityRef: no name");
            }
            return None;
        };
        if self.raw() != b';' {
            self.fatal(Code::Other, "EntityRef: expecting ';'");
            return None;
        }
        self.next_char();
        Some(name)
    }

    /// `xmlHandleUndeclaredEntity`: fatal without a DTD or with
    /// `standalone="yes"`, a warning with an external subset (which is not
    /// read).
    fn handle_undeclared_entity(&mut self, name: &[u8]) {
        let msg = format!("Entity '{}' not defined", String::from_utf8_lossy(name));
        if self.standalone == 1 || !self.has_external_subset {
            self.fatal(Code::Other, &msg);
        } else {
            self.warning(Code::Other, format!("{msg}\n"));
        }
    }

    /// `xmlParseReference`: a character or entity reference in content.
    fn parse_reference(&mut self) {
        if self.raw() != b'&' {
            return;
        }
        if self.nxt(1) == b'#' {
            let value = self.parse_char_ref();
            if value == 0 || self.stopped() {
                return;
            }
            let mut out = Vec::new();
            copy_char(&mut out, value);
            self.characters(&out);
            return;
        }
        let Some(name) = self.parse_entity_ref_internal() else {
            return;
        };
        match predefined_entity(&name) {
            Some(c) => self.characters(&[c]),
            None => {
                self.handle_undeclared_entity(&name);
                // A reference node for an undeclared entity.
                if self.disable_sax == 0 {
                    self.sax2_reference(&name);
                }
            }
        }
    }

    // --- Comments, PIs, CDATA, DOCTYPE -----------------------------------

    /// `xmlParseComment` and `xmlParseCommentComplex`: the comment's node,
    /// once its end is found. Only its length matters here, for the
    /// limit, so the content is not kept.
    fn parse_comment(&mut self) {
        if self.raw() != b'<' || self.nxt(1) != b'!' || self.nxt(2) != b'-' || self.nxt(3) != b'-' {
            return;
        }
        self.skip(4);
        // The accelerated path, for ASCII.
        let mut len = 0usize;
        let mut size: Option<usize> = None;
        let mut inp = self.cur;
        loop {
            loop {
                if self.at(inp) == 0x0a {
                    while self.at(inp) == 0x0a {
                        inp += 1;
                    }
                }
                while {
                    let c = self.at(inp);
                    (c > b'-' && c <= 0x7f) || (0x20..b'-').contains(&c) || c == 0x09
                } {
                    inp += 1;
                }
                if self.at(inp) == 0x0a {
                    continue;
                }
                break;
            }
            let nbchar = inp - self.cur;
            if nbchar > 0 {
                if nbchar > XML_MAX_TEXT_LENGTH - len {
                    self.fatal(Code::Other, "Comment too big found");
                    return;
                }
                size = Some(match size {
                    None => {
                        if self.at(inp) == b'-' && self.at(inp + 1) == b'-' {
                            nbchar + 1
                        } else {
                            XML_PARSER_BUFFER_SIZE + nbchar
                        }
                    }
                    Some(s) if len + nbchar + 1 >= s => s + len + nbchar + XML_PARSER_BUFFER_SIZE,
                    Some(s) => s,
                });
                len += nbchar;
            }
            self.cur = inp;
            if self.at(inp) == 0x0a {
                inp += 1;
            }
            if self.at(inp) == 0x0d && self.at(inp + 1) == 0x0a {
                self.cur = inp + 1;
                inp += 2;
                continue;
            }
            inp = self.cur;
            if self.at(inp) == b'-' {
                if self.at(inp + 1) == b'-' {
                    if self.at(inp + 2) == b'>' {
                        self.skip(3);
                        if self.disable_sax == 0 {
                            self.sax2_add_leaf(super::tree::NodeKind::Comment, b"");
                        }
                        return;
                    }
                    self.fatal(Code::Other, "Double hyphen within comment");
                    return;
                }
                inp += 1;
                continue;
            }
            let c = self.at(inp);
            if !((0x20..=0x7f).contains(&c) || c == 0x09 || c == 0x0a) {
                break;
            }
        }
        self.parse_comment_complex(len, size.unwrap_or(XML_PARSER_BUFFER_SIZE));
    }

    /// `xmlParseCommentComplex`, from `len` bytes in a buffer of `size`.
    fn parse_comment_complex(&mut self, mut len: usize, mut size: usize) {
        let (q, ql) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        if q == 0 {
            self.fatal(Code::Other, "Comment not terminated");
            return;
        }
        if !is_char(q) {
            self.fatal(Code::InvalidChar, "xmlParseComment: invalid xmlChar value");
            return;
        }
        self.skip(ql);
        let (r, rl) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        if r == 0 {
            self.fatal(Code::Other, "Comment not terminated");
            return;
        }
        if !is_char(r) {
            self.fatal(Code::InvalidChar, "xmlParseComment: invalid xmlChar value");
            return;
        }
        self.skip(rl);
        let (mut q, mut r) = (q, r);
        let (mut cur, mut l) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        if cur == 0 {
            self.fatal(Code::Other, "Comment not terminated");
            return;
        }
        while is_char(cur)
            && (cur != i32::from(b'>') || r != i32::from(b'-') || q != i32::from(b'-'))
        {
            if r == i32::from(b'-') && q == i32::from(b'-') {
                self.fatal(Code::Other, "Double hyphen within comment");
                return;
            }
            if len + 5 >= size {
                match grow_capacity(size, XML_MAX_TEXT_LENGTH) {
                    Some(s) => size = s,
                    None => {
                        self.fatal(Code::Other, "Comment too big found");
                        return;
                    }
                }
            }
            len += char_len(q);
            q = r;
            r = cur;
            self.skip(l);
            (cur, l) = self.current_char_recover();
            if self.stopped() {
                return;
            }
        }
        if cur == 0 {
            self.fatal(Code::Other, "Comment not terminated");
        } else if !is_char(cur) {
            self.fatal(Code::InvalidChar, "xmlParseComment: invalid xmlChar value");
        } else {
            self.next_char();
            if self.disable_sax == 0 {
                self.sax2_add_leaf(super::tree::NodeKind::Comment, b"");
            }
        }
    }

    /// `xmlParsePITarget`.
    fn parse_pi_target(&mut self) -> Option<Vec<u8>> {
        let name = self.parse_name()?;
        if name.len() >= 3 && name[..3].eq_ignore_ascii_case(b"xml") {
            if name == b"xml" {
                self.fatal(
                    Code::Other,
                    "XML declaration allowed only at the start of the document",
                );
                return Some(name);
            } else if name.len() == 3 {
                self.fatal(Code::Other, "xmlParsePITarget: invalid name prefix 'xml'");
                return Some(name);
            }
            if name != b"xml-stylesheet" && name != b"xml-model" {
                self.warning(
                    Code::Other,
                    "xmlParsePITarget: invalid name prefix 'xml'\n".into(),
                );
            }
        }
        if name.contains(&b':') {
            self.ns_err(
                Code::Other,
                format!(
                    "colons are forbidden from PI names '{}'\n",
                    String::from_utf8_lossy(&name)
                ),
            );
        }
        Some(name)
    }

    /// `xmlParsePI`: a processing instruction, whose node is made once its
    /// end is found.
    fn parse_pi(&mut self) {
        if self.raw() != b'<' || self.nxt(1) != b'?' {
            return;
        }
        self.skip(2);
        let target = self.parse_pi_target();
        if self.stopped() {
            return;
        }
        let Some(target) = target else {
            self.fatal(Code::Other, "xmlParsePI : no target name");
            return;
        };
        if self.raw() == b'?' && self.nxt(1) == b'>' {
            self.skip(2);
            if self.disable_sax == 0 {
                self.sax2_add_leaf(super::tree::NodeKind::Pi, &target);
            }
            return;
        }
        if self.skip_blanks() == 0 {
            self.fatal(Code::Other, "ParsePI: PI space expected");
            return;
        }
        let mut len = 0usize;
        let mut size = XML_PARSER_BUFFER_SIZE;
        let (mut cur, mut l) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        while is_char(cur) && (cur != i32::from(b'?') || self.nxt(1) != b'>') {
            if len + 5 >= size {
                match grow_capacity(size, XML_MAX_TEXT_LENGTH) {
                    Some(s) => size = s,
                    None => {
                        self.fatal(Code::Other, "PI too big found");
                        return;
                    }
                }
            }
            len += char_len(cur);
            self.skip(l);
            (cur, l) = self.current_char_recover();
            if self.stopped() {
                return;
            }
        }
        if cur != i32::from(b'?') {
            self.fatal(Code::Other, "ParsePI: PI never end ...");
            return;
        }
        self.skip(2);
        if self.disable_sax == 0 {
            self.sax2_add_leaf(super::tree::NodeKind::Pi, &target);
        }
    }

    /// `xmlParseCDSect`: a CDATA section's node, once its end is found.
    fn parse_cdsect(&mut self) {
        if !self.cmp(b"<![CDATA[") {
            return;
        }
        self.skip(9);
        let (r, rl) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        if !is_char(r) {
            self.fatal(Code::Other, "CData section not finished");
            return;
        }
        self.skip(rl);
        let (s, sl) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        if !is_char(s) {
            self.fatal(Code::Other, "CData section not finished");
            return;
        }
        self.skip(sl);
        let (mut r, mut s) = (r, s);
        let mut content = Vec::new();
        let mut size = XML_PARSER_BUFFER_SIZE;
        let (mut cur, mut l) = self.current_char_recover();
        if self.stopped() {
            return;
        }
        while is_char(cur)
            && (r != i32::from(b']') || s != i32::from(b']') || cur != i32::from(b'>'))
        {
            if content.len() + 5 >= size {
                match grow_capacity(size, XML_MAX_TEXT_LENGTH) {
                    Some(n) => size = n,
                    None => {
                        self.fatal(Code::Other, "CData section too big found");
                        return;
                    }
                }
            }
            copy_char(&mut content, r);
            r = s;
            s = cur;
            self.skip(l);
            (cur, l) = self.current_char_recover();
            if self.stopped() {
                return;
            }
        }
        if cur != i32::from(b'>') {
            self.fatal(Code::Other, "CData section not finished");
            return;
        }
        self.skip(l);
        if self.disable_sax == 0 {
            self.sax2_cdata(&content);
        }
    }

    /// `xmlParseSystemLiteral`, for where it ends: `None` after an error.
    fn parse_system_literal(&mut self) -> Option<()> {
        let stop = self.raw();
        if stop != b'"' && stop != b'\'' {
            self.fatal(Code::Other, "SystemLiteral \" or ' expected");
            return None;
        }
        self.next_char();
        let mut len = 0usize;
        let mut size = XML_PARSER_BUFFER_SIZE;
        let (mut cur, mut l) = self.current_char_recover();
        if self.stopped() {
            return None;
        }
        while is_char(cur) && cur != i32::from(stop) {
            if len + 5 >= size {
                match grow_capacity(size, XML_MAX_NAME_LENGTH) {
                    Some(s) => size = s,
                    None => {
                        self.fatal(Code::Other, "SystemLiteral: name too long");
                        return None;
                    }
                }
            }
            len += char_len(cur);
            self.skip(l);
            (cur, l) = self.current_char_recover();
            if self.stopped() {
                return None;
            }
        }
        if !is_char(cur) {
            self.fatal(
                Code::Other,
                "Unfinished System or Public ID \" or ' expected",
            );
            return None;
        }
        self.next_char();
        Some(())
    }

    /// `xmlParsePubidLiteral`, for where it ends.
    fn parse_pubid_literal(&mut self) -> Option<()> {
        let stop = self.raw();
        if stop != b'"' && stop != b'\'' {
            self.fatal(Code::Other, "PubidLiteral \" or ' expected");
            return None;
        }
        self.next_char();
        let mut len = 0usize;
        let mut size = XML_PARSER_BUFFER_SIZE;
        let mut cur = self.raw();
        while is_pubid_char(cur) && cur != stop {
            if len + 1 >= size {
                match grow_capacity(size, XML_MAX_NAME_LENGTH) {
                    Some(s) => size = s,
                    None => {
                        self.fatal(Code::Other, "Public ID: name too long");
                        return None;
                    }
                }
            }
            len += 1;
            self.next_char();
            cur = self.raw();
        }
        if cur != stop {
            self.fatal(Code::Other, "Unfinished PubidLiteral");
            return None;
        }
        self.skip(1);
        Some(())
    }

    /// `xmlParseExternalID` (strict): whether a system or public ID was
    /// found.
    fn parse_external_id(&mut self) -> bool {
        if self.cmp(b"SYSTEM") {
            self.skip(6);
            if self.skip_blanks() == 0 {
                self.fatal(Code::Other, "Space required after 'SYSTEM'");
                return false;
            }
            if self.parse_system_literal().is_none() {
                if !self.stopped() {
                    self.fatal(Code::Other, "SYSTEM or PUBLIC, the URI is missing");
                }
                return false;
            }
            return true;
        }
        if self.cmp(b"PUBLIC") {
            self.skip(6);
            if self.skip_blanks() == 0 {
                self.fatal(Code::Other, "Space required after 'PUBLIC'");
                return false;
            }
            if self.parse_pubid_literal().is_none() {
                if !self.stopped() {
                    self.fatal(Code::Other, "PUBLIC, the Public Identifier is missing");
                }
                return false;
            }
            if self.skip_blanks() == 0 {
                self.fatal(Code::Other, "Space required after the Public Identifier");
                return false;
            }
            if self.parse_system_literal().is_none() {
                if !self.stopped() {
                    self.fatal(Code::Other, "SYSTEM or PUBLIC, the URI is missing");
                }
                return false;
            }
            return true;
        }
        false
    }

    /// `xmlParseDocTypeDecl`: the DOCTYPE, up to its internal subset or
    /// end.
    fn parse_doctype_decl(&mut self) {
        // '<!DOCTYPE' is here.
        self.skip(9);
        if self.skip_blanks() == 0 {
            self.fatal(Code::Other, "Space required after 'DOCTYPE'");
            return;
        }
        let name = self.parse_name();
        if self.stopped() {
            return;
        }
        if name.is_none() {
            self.fatal(Code::Other, "xmlParseDocTypeDecl : no DOCTYPE name !");
            return;
        }
        self.skip_blanks();
        if self.parse_external_id() {
            self.has_external_subset = true;
        }
        if self.stopped() {
            return;
        }
        self.skip_blanks();
        if self.disable_sax == 0 {
            self.sax2_internal_subset();
        }
        if self.raw() != b'[' && self.raw() != b'>' {
            self.fatal(Code::Other, "DOCTYPE improperly terminated");
        }
    }
}

/// `xmlGetPredefinedEntity`: the character of `lt`, `gt`, `amp`, `apos`
/// and `quot`.
fn predefined_entity(name: &[u8]) -> Option<u8> {
    match name {
        b"lt" => Some(b'<'),
        b"gt" => Some(b'>'),
        b"amp" => Some(b'&'),
        b"apos" => Some(b'\''),
        b"quot" => Some(b'"'),
        _ => None,
    }
}

/// Where the C goes on after an error the port stops at.
fn unreachable_after_error() {}

/// The depth past which elements cannot be pushed.
pub(crate) const fn max_depth() -> usize {
    MAX_DEPTH
}
