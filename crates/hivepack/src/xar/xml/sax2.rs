//! Port of libxml2's tree builder (`SAX2.c`), the SAX2 handlers the reader
//! wraps: `xmlSAX2StartDocument`, `xmlSAX2StartElementNs` and
//! `xmlSAX2AttributeNs`, `xmlSAX2EndElementNs`, `xmlSAX2Characters` (merged
//! into the text node before, as `xmlSAX2Text` does), `xmlSAX2CDataBlock`,
//! `xmlSAX2Comment`, `xmlSAX2ProcessingInstruction`, `xmlSAX2Reference`
//! and `xmlSAX2InternalSubset`; with what the reader's `startElementNs`
//! wrapper adds (`NODE_IS_EMPTY`).

use std::collections::HashSet;

use super::parser::{
    Code, Level, ParsedAttr, ParserCtxt, XML_MAX_TEXT_LENGTH, XML_XML_NAMESPACE, max_depth,
};
use super::parser_internals::is_blank_ch;
use super::tree::{Attr, NodeKind, Ns};

/// `xmlValidateNCName` with spaces allowed around: whether `value` is an
/// NCName.
fn validate_ncname(value: &[u8]) -> bool {
    let s = String::from_utf8_lossy(value);
    let t = s.trim_matches(|c: char| c.is_ascii() && is_blank_ch(c as u8));
    let mut chars = t.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let ok_start = first != ':' && is_name_start(first as i32);
    if !ok_start {
        return false;
    }
    let rest: String = chars.collect();
    // xmlScanName stops at a colon; what follows must be blanks only,
    // which the trim took.
    rest.chars().all(|c| c != ':' && is_name(c as i32))
}

fn is_name_start(c: i32) -> bool {
    (i32::from(b'a')..=i32::from(b'z')).contains(&c)
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
        || (0x10000..=0xeffff).contains(&c)
}

fn is_name(c: i32) -> bool {
    is_name_start(c)
        || (i32::from(b'0')..=i32::from(b'9')).contains(&c)
        || c == i32::from(b'-')
        || c == i32::from(b'.')
        || c == 0xb7
        || (0x300..=0x36f).contains(&c)
        || (0x203f..=0x2040).contains(&c)
}

/// The `xml:id` values seen (`doc->ids`), which outlive their elements in
/// the reader's streaming mode.
#[derive(Debug, Default)]
pub(crate) struct Ids(HashSet<Vec<u8>>);

impl ParserCtxt {
    /// `xmlSAX2StartDocument`: the document node.
    pub(crate) fn sax2_start_document(&mut self) {
        let doc = self.tree.add(NodeKind::Document);
        self.my_doc = Some(doc);
    }

    /// `xmlSAX2AppendChild`: to the element being built, or the document.
    fn sax2_append_child(&mut self, node: usize) {
        let parent = match self.node() {
            Some(n) => n,
            None => match self.my_doc {
                Some(d) => d,
                None => return,
            },
        };
        self.tree.append_child(parent, node);
    }

    /// `xmlSAX2StartElementNs`, then the reader's wrapper: the element,
    /// its namespace declarations and attributes, pushed on the node
    /// stack.
    pub(crate) fn sax2_start_element_ns(
        &mut self,
        localname: &[u8],
        prefix: Option<&[u8]>,
        has_uri: bool,
        ns_defs: &[(Option<Vec<u8>>, Vec<u8>)],
        atts: &[ParsedAttr],
    ) {
        // The rare case of an undefined namespace prefix: the QName.
        let name = match (prefix, has_uri) {
            (Some(p), false) => [p, b":", localname].concat(),
            _ => localname.to_vec(),
        };
        let node = self.tree.add(NodeKind::Element);
        {
            let n = self.tree.get_mut(node);
            n.name = name;
            n.ns_def = ns_defs
                .iter()
                .map(|(prefix, href)| Ns {
                    prefix: prefix.clone(),
                    href: href.clone(),
                })
                .collect();
        }
        self.sax2_append_child(node);
        // nodePush.
        if self.node_tab.len() >= max_depth() {
            let msg = format!(
                "Excessive depth in document: {}, use XML_PARSE_HUGE option",
                self.node_tab.len()
            );
            self.fatal(Code::ResourceLimit, &msg);
            self.tree.unlink_and_free(node);
            return;
        }
        self.node_tab.push(node);
        for att in atts {
            // The rare case of an undefined attribute prefix.
            let (name, xml_ns) = match (&att.prefix, &att.uri) {
                (Some(p), None) => ([p.as_slice(), b":", att.name.as_slice()].concat(), false),
                (Some(p), Some(_)) => (att.name.clone(), p == b"xml"),
                (None, _) => (att.name.clone(), false),
            };
            // xml:id is registered, its value checked.
            if xml_ns && att.name == b"id" && !att.value.is_empty() {
                if !validate_ncname(&att.value) {
                    self.err(
                        Level::Error,
                        Code::Other,
                        format!(
                            "xml:id : attribute value {} is not an NCName\n",
                            String::from_utf8_lossy(&att.value)
                        ),
                    );
                }
                if !self.ids.0.insert(att.value.clone()) {
                    self.err(
                        Level::Error,
                        Code::Other,
                        format!(
                            "ID {} already defined\n",
                            String::from_utf8_lossy(&att.value)
                        ),
                    );
                }
            }
            self.tree.get_mut(node).properties.push(Attr {
                name,
                value: att.value.clone(),
            });
        }
        let _ = XML_XML_NAMESPACE;
        // The reader's wrapper: "<a/>" is marked, and the push stops.
        if self.raw() == b'/' && self.nxt(1) == b'>' {
            self.tree.get_mut(node).empty = true;
        }
        self.element_started = true;
    }

    /// `xmlSAX2EndElementNs`: off the node stack.
    pub(crate) fn sax2_end_element_ns(&mut self) {
        if self.disable_sax != 0 {
            return;
        }
        self.node_tab.pop();
    }

    /// `xmlSAX2Text` of text (`xmlSAX2Characters`): to the last child if it
    /// is a text node, as one node, else in a new one.
    pub(crate) fn sax2_text(&mut self, bytes: &[u8], _cdata: bool) {
        let Some(parent) = self.node() else {
            return;
        };
        let last = self.tree.get(parent).last;
        match last {
            Some(last) if self.tree.get(last).kind == NodeKind::Text => {
                let old = self.nodelen;
                if bytes.len() > XML_MAX_TEXT_LENGTH || old > XML_MAX_TEXT_LENGTH - bytes.len() {
                    self.fatal(
                        Code::ResourceLimit,
                        "Text node too long, try XML_PARSE_HUGE",
                    );
                    return;
                }
                self.tree.get_mut(last).content.extend_from_slice(bytes);
                self.nodelen = old + bytes.len();
            }
            _ => {
                let node = self.tree.add(NodeKind::Text);
                self.tree.get_mut(node).content = bytes.to_vec();
                self.tree.append_child(parent, node);
                self.nodelen = bytes.len();
            }
        }
    }

    /// `xmlSAX2CDataBlock`: a CDATA section, never merged.
    pub(crate) fn sax2_cdata(&mut self, content: &[u8]) {
        let Some(parent) = self.node() else {
            return;
        };
        let node = self.tree.add(NodeKind::CData);
        self.tree.get_mut(node).content = content.to_vec();
        self.tree.append_child(parent, node);
        self.nodelen = content.len();
    }

    /// `xmlSAX2Comment` and `xmlSAX2ProcessingInstruction`: a leaf, whose
    /// content is not needed here.
    pub(crate) fn sax2_add_leaf(&mut self, kind: NodeKind, name: &[u8]) {
        let node = self.tree.add(kind);
        self.tree.get_mut(node).name = name.to_vec();
        self.sax2_append_child(node);
    }

    /// `xmlSAX2Reference`: an entity reference node (of an undeclared
    /// entity: there are no others here).
    pub(crate) fn sax2_reference(&mut self, name: &[u8]) {
        let node = self.tree.add(NodeKind::EntityRef);
        self.tree.get_mut(node).name = name.to_vec();
        self.sax2_append_child(node);
    }

    /// `xmlSAX2InternalSubset`: the DTD node, before the first element.
    pub(crate) fn sax2_internal_subset(&mut self) {
        let Some(doc) = self.my_doc else {
            return;
        };
        let dtd = self.tree.add(NodeKind::Dtd);
        self.tree.insert_dtd(doc, dtd);
    }
}
