//! The nodes libxml2's tree builder (`SAX2.c`) makes and its reader
//! (`xmlreader.c`) walks: the parts of `xmlNode`, `xmlAttr` and `xmlNs`
//! (`tree.h`) they use.
//!
//! The C links nodes through pointers; here they live in an arena and point
//! at each other by index, with the same links. Nodes the reader is done
//! with are freed, as `xmlTextReaderFreeNode` frees them, and their slots
//! used again.

/// A node's index in [`Tree`].
pub(crate) type NodeId = usize;

/// `xmlElementType`, for the nodes the parser makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeKind {
    /// `XML_DOCUMENT_NODE`.
    Document,
    /// `XML_ELEMENT_NODE`.
    Element,
    /// `XML_TEXT_NODE`.
    Text,
    /// `XML_CDATA_SECTION_NODE`.
    CData,
    /// `XML_ENTITY_REF_NODE`.
    EntityRef,
    /// `XML_PI_NODE`.
    Pi,
    /// `XML_COMMENT_NODE`.
    Comment,
    /// `XML_DTD_NODE`.
    Dtd,
}

/// `xmlAttr`, with its value as `xmlTextReaderConstValue` gives it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Attr {
    /// `name`: the local name, or `prefix:name` when the prefix is not
    /// declared.
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

/// `xmlNs`: a namespace declaration on an element (`nsDef`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Ns {
    /// `prefix`: `None` for the default namespace (`xmlns="..."`).
    pub(crate) prefix: Option<Vec<u8>>,
    pub(crate) href: Vec<u8>,
}

/// `xmlNode`, with what the reader looks at.
#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub(crate) kind: NodeKind,
    /// An element's name, a PI's target, an entity reference's name.
    pub(crate) name: Vec<u8>,
    /// A text, CDATA section, comment or PI's content.
    pub(crate) content: Vec<u8>,
    pub(crate) parent: Option<NodeId>,
    pub(crate) children: Option<NodeId>,
    pub(crate) last: Option<NodeId>,
    pub(crate) next: Option<NodeId>,
    pub(crate) prev: Option<NodeId>,
    /// `nsDef`, in the order of the start tag.
    pub(crate) ns_def: Vec<Ns>,
    /// `properties`, in the order of the start tag.
    pub(crate) properties: Vec<Attr>,
    /// `extra & NODE_IS_EMPTY`: written `<a/>`.
    pub(crate) empty: bool,
}

impl Node {
    fn new(kind: NodeKind) -> Node {
        Node {
            kind,
            name: Vec::new(),
            content: Vec::new(),
            parent: None,
            children: None,
            last: None,
            next: None,
            prev: None,
            ns_def: Vec::new(),
            properties: Vec::new(),
            empty: false,
        }
    }
}

/// The nodes, by index.
#[derive(Debug, Default)]
pub(crate) struct Tree {
    nodes: Vec<Node>,
    /// The slots of freed nodes.
    free: Vec<NodeId>,
}

impl Tree {
    /// A new node, unlinked.
    pub(crate) fn add(&mut self, kind: NodeKind) -> NodeId {
        match self.free.pop() {
            Some(id) => {
                self.nodes[id] = Node::new(kind);
                id
            }
            None => {
                self.nodes.push(Node::new(kind));
                self.nodes.len() - 1
            }
        }
    }

    pub(crate) fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    pub(crate) fn get_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id]
    }

    /// `xmlSAX2AppendChild`'s linking: `node` after `parent`'s last child.
    pub(crate) fn append_child(&mut self, parent: NodeId, node: NodeId) {
        match self.nodes[parent].last {
            None => self.nodes[parent].children = Some(node),
            Some(last) => {
                self.nodes[last].next = Some(node);
                self.nodes[node].prev = Some(last);
            }
        }
        self.nodes[parent].last = Some(node);
        self.nodes[node].parent = Some(parent);
    }

    /// `xmlCreateIntSubset`'s linking of the DTD into the document: before
    /// its first element, else at its end.
    pub(crate) fn insert_dtd(&mut self, doc: NodeId, dtd: NodeId) {
        self.nodes[dtd].parent = Some(doc);
        let mut next = self.nodes[doc].children;
        if next.is_none() {
            self.nodes[doc].children = Some(dtd);
            self.nodes[doc].last = Some(dtd);
            return;
        }
        while let Some(n) = next {
            if self.nodes[n].kind == NodeKind::Element {
                break;
            }
            next = self.nodes[n].next;
        }
        match next {
            None => {
                let last = self.nodes[doc].last;
                self.nodes[dtd].prev = last;
                if let Some(last) = last {
                    self.nodes[last].next = Some(dtd);
                }
                self.nodes[doc].last = Some(dtd);
            }
            Some(next) => {
                let prev = self.nodes[next].prev;
                self.nodes[dtd].next = Some(next);
                self.nodes[dtd].prev = prev;
                match prev {
                    None => self.nodes[doc].children = Some(dtd),
                    Some(prev) => self.nodes[prev].next = Some(dtd),
                }
                self.nodes[next].prev = Some(dtd);
            }
        }
    }

    /// `xmlUnlinkNode` then `xmlTextReaderFreeNode`: the node and what it
    /// holds go.
    pub(crate) fn unlink_and_free(&mut self, id: NodeId) {
        let (parent, prev, next) = {
            let n = &self.nodes[id];
            (n.parent, n.prev, n.next)
        };
        if let Some(parent) = parent {
            if self.nodes[parent].children == Some(id) {
                self.nodes[parent].children = next;
            }
            if self.nodes[parent].last == Some(id) {
                self.nodes[parent].last = prev;
            }
        }
        if let Some(prev) = prev {
            self.nodes[prev].next = next;
        }
        if let Some(next) = next {
            self.nodes[next].prev = prev;
        }
        self.free_subtree(id);
    }

    fn free_subtree(&mut self, id: NodeId) {
        let mut stack = vec![id];
        while let Some(id) = stack.pop() {
            let mut child = self.nodes[id].children;
            while let Some(c) = child {
                child = self.nodes[c].next;
                stack.push(c);
            }
            self.nodes[id] = Node::new(NodeKind::Comment);
            self.free.push(id);
        }
    }

    /// `xmlIsBlankNode`: a text or CDATA node of blanks only.
    pub(crate) fn is_blank_node(&self, id: NodeId) -> bool {
        let n = &self.nodes[id];
        if n.kind != NodeKind::Text && n.kind != NodeKind::CData {
            return false;
        }
        n.content
            .iter()
            .all(|&c| c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d)
    }
}
