//! Port of the input buffer of libxml2's `xmlIO.c` that the reader fills
//! through its read callback: `xmlParserInputBufferGrow`.

use super::XmlIo;

/// `MINLEN`: the least a read asks for.
const MINLEN: usize = 4000;

/// `xmlParserInputBuffer` without an encoder: what the read callback gave.
#[derive(Debug, Default)]
pub(crate) struct InputBuffer {
    /// The bytes read and not shrunk away.
    pub(crate) buffer: Vec<u8>,
    /// The callback ended (`endOfInput` in its place).
    eof: bool,
    /// `in->error`: what the callback's failure was, negated.
    pub(crate) error: Option<i32>,
}

impl InputBuffer {
    /// `xmlParserInputBufferGrow`: one call of the read callback for at
    /// least `MINLEN` bytes; what it gave, 0 at the end, or -1.
    pub(crate) fn grow(&mut self, len: usize, io: &mut dyn XmlIo) -> i32 {
        if self.error.is_some() {
            return -1;
        }
        if self.eof {
            return 0;
        }
        let len = len.max(MINLEN);
        let start = self.buffer.len();
        self.buffer.resize(start + len, 0);
        let res = io.read(&mut self.buffer[start..]);
        let got = if res > 0 { (res as usize).min(len) } else { 0 };
        self.buffer.truncate(start + got);
        if res <= 0 {
            self.eof = true;
        }
        if res < 0 {
            self.error = Some(if res == -1 { -1 } else { -res });
            return -1;
        }
        got as i32
    }

    /// `xmlBufShrink`: the first `n` bytes dropped.
    pub(crate) fn shrink(&mut self, n: usize) {
        let n = n.min(self.buffer.len());
        self.buffer.drain(..n);
    }
}
