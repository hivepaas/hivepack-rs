//! Port of libxml2's `xmlreader.c`, the streaming reader, as
//! `xml2_read_toc` uses it: `xmlReaderForIO` (with no options),
//! `xmlTextReaderRead`, `xmlTextReaderNodeType`,
//! `xmlTextReaderConstLocalName`, `xmlTextReaderConstValue`,
//! `xmlTextReaderIsEmptyElement`, `xmlTextReaderMoveToFirstAttribute` and
//! `xmlTextReaderMoveToNextAttribute`.
//!
//! The reader reads its input through the callback 4,096 bytes at a time
//! (4,000 the first time), pushes it to the parser in chunks of 512 bytes
//! until an element starts, and walks the tree the parser builds, freeing
//! what it has passed. When the reader pushes, and so how much it reads,
//! depends on that walk: the port takes the same steps.

use super::XmlIo;
use super::parser::{Code, Level, ParserCtxt};
use super::tree::{NodeId, NodeKind};
use super::xml_io::InputBuffer;

/// `CHUNK_SIZE`: what is pushed to the parser at a time.
const CHUNK_SIZE: usize = 512;

/// `xmlReaderTypes`: what [`TextReader::node_type`] gives.
pub(crate) const XML_READER_TYPE_NONE: i32 = 0;
pub(crate) const XML_READER_TYPE_ELEMENT: i32 = 1;
pub(crate) const XML_READER_TYPE_TEXT: i32 = 3;
pub(crate) const XML_READER_TYPE_CDATA: i32 = 4;
pub(crate) const XML_READER_TYPE_ENTITY_REFERENCE: i32 = 5;
pub(crate) const XML_READER_TYPE_PROCESSING_INSTRUCTION: i32 = 7;
pub(crate) const XML_READER_TYPE_COMMENT: i32 = 8;
pub(crate) const XML_READER_TYPE_DOCUMENT: i32 = 9;
pub(crate) const XML_READER_TYPE_DOCUMENT_TYPE: i32 = 10;
pub(crate) const XML_READER_TYPE_SIGNIFICANT_WHITESPACE: i32 = 14;
pub(crate) const XML_READER_TYPE_END_ELEMENT: i32 = 15;
pub(crate) const XML_READER_TYPE_ATTRIBUTE: i32 = 2;

/// `xmlTextReaderMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Initial,
    Interactive,
    Error,
    Eof,
}

/// `xmlTextReaderState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Start,
    Element,
    End,
    Backtrack,
    Done,
    Error,
}

/// `curnode`: an attribute or namespace declaration of the current node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CurNode {
    NsDef(usize),
    Attr(usize),
}

/// `xmlTextReader`.
#[derive(Debug)]
pub(crate) struct TextReader {
    input: InputBuffer,
    /// `cur`: how much of `input` was pushed.
    cur: usize,
    ctxt: ParserCtxt,
    mode: Mode,
    state: State,
    node: Option<NodeId>,
    curnode: Option<CurNode>,
    depth: i64,
}

impl TextReader {
    /// `xmlReaderForIO`, and `xmlNewTextReader`'s first read: up to 4,000
    /// bytes, the first 4 of which go to the parser.
    pub(crate) fn for_io(io: &mut dyn XmlIo) -> TextReader {
        let mut input = InputBuffer::default();
        input.grow(4, io);
        let (ctxt, cur) = if input.buffer.len() >= 4 {
            (ParserCtxt::new(&input.buffer[..4]), 4)
        } else {
            (ParserCtxt::new(&[]), 0)
        };
        TextReader {
            input,
            cur,
            ctxt,
            mode: Mode::Initial,
            state: State::Start,
            node: None,
            curnode: None,
            depth: 0,
        }
    }

    /// The parser's reports, to the error handler.
    fn flush_messages(&mut self, io: &mut dyn XmlIo) {
        for (severity, msg) in self.ctxt.messages.drain(..) {
            io.error(severity, &msg);
        }
    }

    /// `xmlParseChunk` of `input[from..to]`.
    fn parse(&mut self, from: usize, to: usize, terminate: bool, io: &mut dyn XmlIo) -> i32 {
        let val = self
            .ctxt
            .parse_chunk(&self.input.buffer[from..to], terminate);
        self.flush_messages(io);
        val
    }

    /// `xmlTextReaderPushData`: more input to the parser, in chunks, until
    /// an element starts; -1 on an error.
    fn push_data(&mut self, io: &mut dyn XmlIo) -> i32 {
        let oldstate = self.state;
        self.ctxt.element_started = false;
        loop {
            if self.input.buffer.len() < self.cur + CHUNK_SIZE {
                // Refill the buffer unless at the end of the stream.
                if self.mode != Mode::Eof {
                    let val = self.input.grow(4096, io);
                    if val == 0 {
                        if self.input.buffer.len() == self.cur {
                            self.mode = Mode::Eof;
                            break;
                        }
                    } else if val < 0 {
                        let level = if self.input.error == Some(-1) {
                            // XML_IO_UNKNOWN is only a warning.
                            Level::Warning
                        } else {
                            Level::Fatal
                        };
                        self.ctxt.err(level, Code::Io, "I/O error\n".into());
                        self.flush_messages(io);
                        self.mode = Mode::Error;
                        self.state = State::Error;
                        return -1;
                    }
                } else {
                    break;
                }
            }
            if self.input.buffer.len() >= self.cur + CHUNK_SIZE {
                let val = self.parse(self.cur, self.cur + CHUNK_SIZE, false, io);
                self.cur += CHUNK_SIZE;
                if val != 0 {
                    self.ctxt.well_formed = false;
                }
                if !self.ctxt.well_formed {
                    break;
                }
            } else {
                let to = self.input.buffer.len();
                let val = self.parse(self.cur, to, false, io);
                self.cur = to;
                if val != 0 {
                    self.ctxt.well_formed = false;
                }
                break;
            }
            if self.ctxt.element_started {
                break;
            }
        }
        self.state = oldstate;
        if self.mode == Mode::Interactive {
            // Discard the consumed input.
            if self.cur > 80 {
                let n = self.cur - 80;
                self.input.shrink(n);
                self.cur -= n;
            }
        } else if self.mode == Mode::Eof && self.state != State::Done {
            // The end of the stream, to the parser.
            let to = self.input.buffer.len();
            let val = self.parse(self.cur, to, true, io);
            self.cur = to;
            self.state = State::Done;
            if val != 0 {
                if self.ctxt.well_formed {
                    self.ctxt.well_formed = false;
                } else {
                    return -1;
                }
            }
        }
        if !self.ctxt.well_formed {
            self.mode = Mode::Eof;
            return -1;
        }
        0
    }

    /// `xmlTextReaderGetSuccessor`: the next node after `cur` and its
    /// descendants.
    fn get_successor(&self, mut cur: NodeId) -> Option<NodeId> {
        let tree = &self.ctxt.tree;
        if let Some(next) = tree.get(cur).next {
            return Some(next);
        }
        loop {
            cur = tree.get(cur).parent?;
            if let Some(next) = tree.get(cur).next {
                return Some(next);
            }
        }
    }

    /// `xmlTextReaderDoExpand`: the current node's subtree, read whole.
    fn do_expand(&mut self, io: &mut dyn XmlIo) -> i32 {
        let Some(node) = self.node else {
            return -1;
        };
        loop {
            if self.ctxt.disable_sax > 1 {
                return 1;
            }
            if self.get_successor(node).is_some() {
                return 1;
            }
            if (self.ctxt.node_nr() as i64) < self.depth {
                return 1;
            }
            if self.mode == Mode::Eof {
                return 1;
            }
            if self.push_data(io) < 0 {
                self.mode = Mode::Error;
                self.state = State::Error;
                return -1;
            }
            if self.mode == Mode::Eof {
                return 1;
            }
        }
    }

    /// `xmlTextReaderRead`: on to the next node; 1, 0 at the end, -1 on an
    /// error.
    pub(crate) fn read(&mut self, io: &mut dyn XmlIo) -> i32 {
        if self.state == State::Error {
            return -1;
        }
        self.curnode = None;
        if self.mode == Mode::Initial {
            self.mode = Mode::Interactive;
            // The initial state: until the root element starts.
            loop {
                if self.push_data(io) < 0 {
                    self.mode = Mode::Error;
                    self.state = State::Error;
                    return -1;
                }
                if !(self.ctxt.node().is_none()
                    && self.mode != Mode::Eof
                    && self.state != State::Done)
                {
                    break;
                }
            }
            if let Some(doc) = self.ctxt.my_doc {
                self.node = self.ctxt.tree.get(doc).children;
            }
            if self.ctxt.node().is_none() {
                if self.node.is_none() {
                    self.mode = Mode::Error;
                    self.state = State::Error;
                    return -1;
                }
            } else if self.node.is_none() {
                self.node = self.ctxt.node_tab.first().copied();
            }
            self.state = State::Element;
            self.depth = 0;
            return self.node_found(io);
        }
        let oldstate = self.state;
        let olddepth = self.ctxt.node_nr();
        let mut oldnode = self.node;

        // get_next_node.
        let Some(mut node) = self.node else {
            if self.mode == Mode::Eof {
                return 0;
            }
            self.mode = Mode::Error;
            self.state = State::Error;
            return -1;
        };
        // Not backtracking on ancestors or examined nodes, the parser not
        // done and not at the end of the stream: on with the parse.
        while self.must_push(node, oldstate, olddepth) {
            if self.push_data(io) < 0 {
                self.mode = Mode::Error;
                self.state = State::Error;
                return -1;
            }
        }
        let tree = &self.ctxt.tree;
        let n = tree.get(node);
        if oldstate != State::Backtrack
            && n.children.is_some()
            && n.kind != NodeKind::EntityRef
            && n.kind != NodeKind::Dtd
        {
            self.node = n.children;
            self.depth += 1;
            self.state = State::Element;
            return self.node_found(io);
        }
        if let Some(next) = n.next {
            if oldstate == State::Element
                && n.kind == NodeKind::Element
                && n.children.is_none()
                && !n.empty
            {
                self.state = State::End;
                return self.node_found(io);
            }
            node = next;
            self.node = Some(node);
            self.state = State::Element;
            // The old node goes.
            if let Some(prev) = self.ctxt.tree.get(node).prev
                && self.ctxt.tree.get(prev).kind != NodeKind::Dtd
            {
                if oldnode == Some(prev) {
                    oldnode = None;
                }
                let _ = oldnode;
                self.ctxt.tree.unlink_and_free(prev);
            }
            return self.node_found(io);
        }
        if oldstate == State::Element
            && n.kind == NodeKind::Element
            && n.children.is_none()
            && !n.empty
        {
            self.state = State::End;
            return self.node_found(io);
        }
        let parent = n.parent;
        let parent_is_doc = parent.is_none_or(|p| tree.get(p).kind == NodeKind::Document);
        if parent_is_doc {
            if self.mode != Mode::Eof {
                let to = self.cur;
                let val = self.parse(to, to, true, io);
                self.state = State::Done;
                if val != 0 {
                    self.mode = Mode::Error;
                    self.state = State::Error;
                    return -1;
                }
            }
            self.node = None;
            self.depth = -1;
            if let Some(old) = oldnode
                && self.ctxt.tree.get(old).kind != NodeKind::Dtd
            {
                self.ctxt.tree.unlink_and_free(old);
            }
            // node_end.
            self.state = State::Done;
            return 0;
        }
        let Some(parent) = parent else {
            return -1;
        };
        self.node = Some(parent);
        if let Some(last) = self.ctxt.tree.get(parent).last {
            self.ctxt.tree.unlink_and_free(last);
        }
        self.depth -= 1;
        self.state = State::Backtrack;
        self.node_found(io)
    }

    /// The condition of the loop of `xmlTextReaderRead` that pushes more
    /// input before moving from `node`.
    fn must_push(&self, node: NodeId, oldstate: State, olddepth: usize) -> bool {
        let tree = &self.ctxt.tree;
        let n = tree.get(node);
        let children_text_only = n
            .children
            .is_some_and(|c| tree.get(c).kind == NodeKind::Text && tree.get(c).next.is_none());
        let ctxt_node = self.ctxt.node();
        n.next.is_none()
            && self.ctxt.node_nr() == olddepth
            && (oldstate == State::Backtrack
                || n.children.is_none()
                || n.kind == NodeKind::EntityRef
                || children_text_only
                || n.kind == NodeKind::Dtd
                || n.kind == NodeKind::Document)
            && (ctxt_node.is_none() || ctxt_node == Some(node) || ctxt_node == n.parent)
            && self.ctxt.instate != super::parser::InState::Eof
            && self.ctxt.disable_sax <= 1
    }

    /// `node_found`: a text or CDATA node is made whole before it is given.
    fn node_found(&mut self, io: &mut dyn XmlIo) -> i32 {
        if let Some(node) = self.node {
            let n = self.ctxt.tree.get(node);
            if n.next.is_none()
                && (n.kind == NodeKind::Text || n.kind == NodeKind::CData)
                && self.do_expand(io) < 0
            {
                return -1;
            }
        }
        1
    }

    /// `xmlTextReaderNodeType`.
    pub(crate) fn node_type(&self) -> i32 {
        let Some(node) = self.node else {
            return XML_READER_TYPE_NONE;
        };
        if self.curnode.is_some() {
            return XML_READER_TYPE_ATTRIBUTE;
        }
        let tree = &self.ctxt.tree;
        match tree.get(node).kind {
            NodeKind::Element => {
                if self.state == State::End || self.state == State::Backtrack {
                    XML_READER_TYPE_END_ELEMENT
                } else {
                    XML_READER_TYPE_ELEMENT
                }
            }
            // A blank node is significant whitespace: xmlNodeGetSpacePreserve
            // of a text node is -1.
            NodeKind::Text => {
                if tree.is_blank_node(node) {
                    XML_READER_TYPE_SIGNIFICANT_WHITESPACE
                } else {
                    XML_READER_TYPE_TEXT
                }
            }
            NodeKind::CData => XML_READER_TYPE_CDATA,
            NodeKind::EntityRef => XML_READER_TYPE_ENTITY_REFERENCE,
            NodeKind::Pi => XML_READER_TYPE_PROCESSING_INSTRUCTION,
            NodeKind::Comment => XML_READER_TYPE_COMMENT,
            NodeKind::Document => XML_READER_TYPE_DOCUMENT,
            NodeKind::Dtd => XML_READER_TYPE_DOCUMENT_TYPE,
        }
    }

    /// `xmlTextReaderIsEmptyElement`: an element written `<a/>`.
    pub(crate) fn is_empty_element(&self) -> bool {
        let Some(node) = self.node else {
            return false;
        };
        let n = self.ctxt.tree.get(node);
        n.kind == NodeKind::Element
            && self.curnode.is_none()
            && n.children.is_none()
            && self.state != State::End
            && n.empty
    }

    /// `xmlTextReaderConstLocalName`, for elements and their attributes:
    /// the local name (with its prefix if that is not declared), a
    /// namespace declaration's prefix, or `xmlns`.
    pub(crate) fn const_local_name(&self) -> &[u8] {
        let Some(node) = self.node else {
            return b"";
        };
        let n = self.ctxt.tree.get(node);
        match self.curnode {
            Some(CurNode::NsDef(i)) => n.ns_def[i].prefix.as_deref().unwrap_or(b"xmlns"),
            Some(CurNode::Attr(i)) => &n.properties[i].name,
            None => match n.kind {
                NodeKind::Element | NodeKind::Pi | NodeKind::EntityRef => &n.name,
                NodeKind::Text => b"#text",
                NodeKind::CData => b"#cdata-section",
                NodeKind::Comment => b"#comment",
                NodeKind::Document => b"#document",
                NodeKind::Dtd => b"",
            },
        }
    }

    /// `xmlTextReaderConstValue`: a text node's content, an attribute's
    /// value, a namespace declaration's URI.
    pub(crate) fn const_value(&self) -> Option<&[u8]> {
        let node = self.node?;
        let n = self.ctxt.tree.get(node);
        match self.curnode {
            Some(CurNode::NsDef(i)) => Some(&n.ns_def[i].href),
            Some(CurNode::Attr(i)) => Some(&n.properties[i].value),
            None => match n.kind {
                NodeKind::Text | NodeKind::CData | NodeKind::Pi | NodeKind::Comment => {
                    Some(&n.content)
                }
                _ => None,
            },
        }
    }

    /// `xmlTextReaderMoveToFirstAttribute`: the namespace declarations
    /// come first, then the attributes.
    pub(crate) fn move_to_first_attribute(&mut self) -> i32 {
        let Some(node) = self.node else {
            return -1;
        };
        let n = self.ctxt.tree.get(node);
        if n.kind != NodeKind::Element {
            return 0;
        }
        if !n.ns_def.is_empty() {
            self.curnode = Some(CurNode::NsDef(0));
            return 1;
        }
        if !n.properties.is_empty() {
            self.curnode = Some(CurNode::Attr(0));
            return 1;
        }
        0
    }

    /// `xmlTextReaderMoveToNextAttribute`.
    pub(crate) fn move_to_next_attribute(&mut self) -> i32 {
        let Some(node) = self.node else {
            return -1;
        };
        let n = self.ctxt.tree.get(node);
        if n.kind != NodeKind::Element {
            return 0;
        }
        match self.curnode {
            None => self.move_to_first_attribute(),
            Some(CurNode::NsDef(i)) => {
                if i + 1 < n.ns_def.len() {
                    self.curnode = Some(CurNode::NsDef(i + 1));
                    1
                } else if !n.properties.is_empty() {
                    self.curnode = Some(CurNode::Attr(0));
                    1
                } else {
                    0
                }
            }
            Some(CurNode::Attr(i)) => {
                if i + 1 < n.properties.len() {
                    self.curnode = Some(CurNode::Attr(i + 1));
                    1
                } else {
                    0
                }
            }
        }
    }
}
