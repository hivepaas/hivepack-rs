//! The reader against libxml2 2.15.4's, through `tools/xar-oracle`'s `xml`
//! request: the nodes `xml2_read_toc` goes through, what xmlTextReaderRead
//! last returned, how many bytes the read callback gave, and the severity
//! of each report. Documents made at random, with what TOCs have and the
//! XML around it, as they are and damaged; `testdata/oracle/xar.txt`
//! replays answers where the oracle is not built.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use super::{
    Severity, TextReader, XML_READER_TYPE_ELEMENT, XML_READER_TYPE_END_ELEMENT,
    XML_READER_TYPE_TEXT, XmlIo,
};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The source of the oracle's `xml` request: what it is asked for, then
/// ARCHIVE_FATAL at `failat`.
struct Source<'a> {
    data: &'a [u8],
    pos: usize,
    failat: Option<usize>,
    /// The reports: their severity, and how many nodes came before.
    severities: Vec<String>,
    nodes: usize,
}

impl XmlIo for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> i32 {
        if self.failat.is_some_and(|f| self.pos >= f) {
            return -30;
        }
        let mut n = (self.data.len() - self.pos).min(buf.len());
        if let Some(f) = self.failat {
            n = n.min(f - self.pos);
        }
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        n as i32
    }

    fn error(&mut self, severity: Severity, _msg: &str) {
        let c = match severity {
            Severity::Warning => 'w',
            Severity::Error => 'e',
        };
        let entry = format!("{c}{}", self.nodes);
        // As much as the oracle keeps: the text so far, with its commas.
        let used = self.severities.iter().map(String::len).sum::<usize>()
            + self.severities.len().saturating_sub(1);
        if used + 32 < 4096 {
            self.severities.push(entry);
        }
    }
}

/// The port's answer to `xml <failat> <document>`.
pub(crate) fn answer(document: &[u8], failat: Option<usize>) -> String {
    let mut src = Source {
        data: document,
        pos: 0,
        failat,
        severities: Vec::new(),
        nodes: 0,
    };
    let mut reader = TextReader::for_io(&mut src);
    let mut parts = Vec::new();
    let r = loop {
        let r = reader.read(&mut src);
        if r != 1 {
            break r;
        }
        src.nodes += 1;
        let name = reader.const_local_name().to_vec();
        parts.push(match reader.node_type() {
            XML_READER_TYPE_ELEMENT => {
                let empty = reader.is_empty_element();
                let mut attrs = Vec::new();
                let mut more = reader.move_to_first_attribute();
                while more == 1 {
                    attrs.push(format!(
                        "{}={}",
                        hex(reader.const_local_name()),
                        hex(reader.const_value().unwrap_or(b""))
                    ));
                    more = reader.move_to_next_attribute();
                }
                let attrs = if attrs.is_empty() {
                    "-".to_string()
                } else {
                    attrs.join(".")
                };
                format!("s{}:{}:{attrs}", u8::from(empty), hex(&name))
            }
            XML_READER_TYPE_END_ELEMENT => format!("e:{}", hex(&name)),
            XML_READER_TYPE_TEXT => format!("t:{}", hex(reader.const_value().unwrap_or(b""))),
            t => format!("n{t}"),
        });
    };
    parts.push(format!("r{r}"));
    parts.push(format!("@{}", src.pos));
    parts.push(format!("m:{}", src.severities.join(",")));
    parts.join("|")
}

/// Whether the port's answer is libxml2's. After a fatal error the port
/// stops where libxml2 goes on to the end of the construct, reporting more
/// to a handler that keeps only the last report: when the reading failed,
/// the port's reports are the first of libxml2's.
pub(crate) fn same(got: &str, want: &str) -> bool {
    if got == want {
        return true;
    }
    let (Some((g, gm)), Some((w, wm))) = (got.rsplit_once("|m:"), want.rsplit_once("|m:")) else {
        return false;
    };
    let failed = g.starts_with("r-1|") || g.contains("|r-1|");
    let (gm, wm): (Vec<&str>, Vec<&str>) = (
        gm.split(',').filter(|e| !e.is_empty()).collect(),
        wm.split(',').filter(|e| !e.is_empty()).collect(),
    );
    failed && g == w && wm.starts_with(&gm)
}

/// The oracle, if `scripts/testdata.py` built it.
struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    fn spawn() -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata")
            });
        let folder = cache.join("xar-oracle");
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            return None;
        }
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        line.trim_end().to_string()
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// xorshift64*.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub(crate) fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

/// A name: an element's or attribute's, with prefixes and characters past
/// ASCII now and then.
fn name(rng: &mut Rng) -> String {
    let base = rng.pick(&[
        "xar", "toc", "file", "name", "data", "a", "b", "ea", "x-y.z", "_q", "é", "名前", "n1",
    ]);
    match rng.below(10) {
        0 => format!(
            "{}:{base}",
            rng.pick(&["p", "q", "xml", "xmlns", "undeclared"])
        ),
        1 => format!("{base}{}", "long".repeat(rng.below(40) as usize)),
        _ => base.to_string(),
    }
}

/// Text with what XML escapes, references and characters of every width.
fn text(rng: &mut Rng) -> String {
    let mut s = String::new();
    let n = match rng.below(10) {
        0 => rng.below(5000),
        1 => rng.below(700) + 300,
        _ => rng.below(30),
    };
    for _ in 0..n {
        s.push_str(rng.pick(&[
            "a",
            "b",
            "0",
            " ",
            "\n",
            "\t",
            "\r\n",
            "\r",
            "&amp;",
            "&lt;",
            "&gt;",
            "&quot;",
            "&apos;",
            "&#65;",
            "&#x42;",
            "&#x10FFFF;",
            "é",
            "€",
            "😀",
            "]",
            "]]",
            "x",
            "&#xa;",
            "&#32;",
        ]));
    }
    s
}

/// Attributes, namespace declarations among them.
fn attrs(rng: &mut Rng) -> String {
    let mut s = String::new();
    for _ in 0..rng.below(4) {
        let value = match rng.below(8) {
            0 => "http://example.com/ns".to_string(),
            1 => "relative".to_string(),
            2 => String::new(),
            3 => "a b\tc\nd\r\ne&amp;f&#38;g&lt;".to_string(),
            _ => text(rng).replace(['<', '"'], "x").replace('&', "&amp;"),
        };
        let quote = rng.pick(&["\"", "'"]);
        let value = value.replace(quote, "");
        let name = match rng.below(6) {
            0 => format!("xmlns:{}", rng.pick(&["p", "q", "r"])),
            1 => "xmlns".to_string(),
            2 => "xml:space".to_string(),
            _ => name(rng),
        };
        let _ = write!(
            s,
            " {name}{}={quote}{value}{quote}",
            rng.pick(&["", " ", "\n"])
        );
    }
    s
}

/// An element and its content, `depth` deep at most.
fn element(rng: &mut Rng, depth: u32, out: &mut String) {
    let n = name(rng);
    let a = attrs(rng);
    if rng.below(5) == 0 {
        let _ = write!(out, "<{n}{a}{}/>", rng.pick(&["", " "]));
        return;
    }
    let _ = write!(out, "<{n}{a}>");
    for _ in 0..rng.below(5) {
        match rng.below(9) {
            0 | 1 => out.push_str(&text(rng).replace('<', "&lt;").replace("]]>", "]]&gt;")),
            2 if depth > 0 => element(rng, depth - 1, out),
            3 if depth > 0 => element(rng, depth - 1, out),
            4 => out.push_str("<!-- a comment - with - dashes -->"),
            5 => out.push_str("<?pi data?>"),
            6 => {
                let _ = write!(out, "<![CDATA[{}]]>", text(rng).replace("]]>", ""));
            }
            7 => out.push_str(rng.pick(&["\n  ", " ", "\r\n", "\t"])),
            _ => out.push_str(rng.pick(&["&amp;", "&#x41;", "&undeclared;"])),
        }
    }
    let _ = write!(out, "</{n}{}>", rng.pick(&["", " ", "\n"]));
}

/// A document: a declaration, a prolog, the root, an epilog.
pub(crate) fn document(rng: &mut Rng) -> Vec<u8> {
    let mut s = String::new();
    match rng.below(8) {
        0 => {}
        1 => s.push_str("<?xml version=\"1.0\"?>"),
        2 => s.push_str("<?xml version='1.1' encoding='utf-8' standalone='no'?>\n"),
        3 => s.push_str("<?xml version=\"1.0\" encoding=\"US-ASCII\"?>"),
        4 => s.push_str("\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        _ => s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
    }
    for _ in 0..rng.below(3) {
        s.push_str(rng.pick(&[
            "<!-- prolog -->",
            "\n",
            "<?pi?>",
            "<!DOCTYPE xar SYSTEM \"x.dtd\">",
        ]));
    }
    let mut body = String::new();
    let depth = rng.pick(&[1, 3, 6]);
    element(rng, depth, &mut body);
    s.push_str(&body);
    for _ in 0..rng.below(3) {
        s.push_str(rng.pick(&["\n", "<!-- epilog -->", "  ", "<?end?>"]));
    }
    let mut d = s.into_bytes();
    if rng.below(8) == 0 {
        // Padding past the first reads.
        let pad = rng.below(9000) as usize;
        d.extend(std::iter::repeat_n(b' ', pad));
    }
    d
}

/// A long document shaped like a table of contents: many files, some text
/// long enough to cross the reader's reads and chunks.
fn long_document(rng: &mut Rng) -> Vec<u8> {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n");
    let files = rng.below(400);
    for i in 0..files {
        let _ = write!(
            s,
            "  <file id=\"{i}\">\n   <name>{}</name>\n   <type>file</type>\n   <mode>0644</mode>\n",
            text(rng).replace('<', "&lt;").replace("]]>", "]]&gt;")
        );
        if rng.below(4) == 0 {
            let _ = writeln!(
                s,
                "   <data><length>{}</length><encoding style=\"application/x-gzip\"/></data>",
                rng.below(1 << 20)
            );
        }
        if rng.below(10) == 0 {
            element(rng, 3, &mut s);
        }
        s.push_str("  </file>\n");
    }
    s.push_str(" </toc>\n</xar>\n");
    s.into_bytes()
}

/// The document with something wrong in it./// The document with something wrong in it.
pub(crate) fn damage(rng: &mut Rng, mut d: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(3) {
        if d.is_empty() {
            break;
        }
        let at = rng.below(d.len() as u64) as usize;
        match rng.below(7) {
            0 => d[at] ^= 1 << rng.below(8),
            1 => d[at] = rng.pick(&[0, b'<', b'>', b'&', b'"', b'\'', b'/', 0x80, 0xff, b'\r']),
            2 => d.truncate(at),
            3 => {
                let what = rng.pick(&[
                    &b"<!--"[..],
                    b"]]>",
                    b"&",
                    b"<x>",
                    b"</x>",
                    b"\xc3",
                    b"<?xml?>",
                    b"<![CDATA[",
                ]);
                d.splice(at..at, what.iter().copied());
            }
            4 => {
                let n = rng.below(20) as usize;
                let end = (at + n).min(d.len());
                d.drain(at..end);
            }
            5 => d.extend((0..rng.below(50)).map(|_| rng.next() as u8)),
            _ => {
                let end = (at + 1 + rng.below(8) as usize).min(d.len());
                let copy = d[at..end].to_vec();
                d.splice(at..at, copy);
            }
        }
    }
    d
}

/// Documents for the edge cases one by one.
fn edge_cases() -> Vec<Vec<u8>> {
    let mut docs: Vec<Vec<u8>> = [
        &b""[..],
        b" ",
        b"<a/>",
        b"<a></a>",
        b"<a>x<b/>y</a>",
        b"<a> </a>",
        b"<a>&#32;z </a>",
        b"<a><![CDATA[x]]>y</a>",
        b"<a>a<?p x?>b</a>",
        b"<a",
        b"<a></b>",
        b"<a>&foo;</a>",
        b"<a/>junk",
        b"<p:a/>junk",
        b"<a/><!--x-->  ",
        b"<p:a/>",
        b"<a p:x=\"1\"/>",
        b"<a xmlns=\"rel\"/>",
        b"<a xmlns:p=\"\"/>",
        b"<a b='1' b='2'/>",
        b"<a xmlns:p='u' xmlns:q='u' p:b='1' q:b='2'/>",
        b"<a xmlns='u' xmlns='v'/>",
        b"<a xml:space='bad'/>",
        b"<a xml:id='1'/>",
        b"<a><b xml:id='x'/><c xml:id='x'/></a>",
        b"<?xml version=\"1.0\" encoding=\"Shift_JIS\"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"US-ASCII\"?><a>\xc3\xa9</a>",
        b"\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"latin1\"?><a/>",
        b"<!DOCTYPE a SYSTEM \"x\"><a>b&foo;c</a>",
        b"<!DOCTYPE a><a>b&foo;c</a>",
        b"<a b=\"&foo;\"/>",
        b"<a>\x00</a>",
        b"<a>\xff</a>",
        b"<a>x]]>y</a>",
        b"<a>&#0;</a>",
        b"<a>&#x0000000000a;</a>",
        b"<a>&#x00000000041;</a>",
        b"<a b='<'/>",
        b"<a b=\"\x01\"/>",
        b"<a>\r\n\r</a>",
        b"<a:b:c/>",
        b"<:a/>",
        b"<a><!-- a -- b --></a>",
        b"<a><?xml x?></a>",
        b"<a><?xml-stylesheet x?><?xmlfoo?><?p:q?></a>",
        b"<?xml version=\"2.0\"?><a/>",
        b"<?xml  version = '1.0' ?><a/>",
        b"<?xml version=\"1.0\" standalone=\"yes\"?><a>&x;</a>",
        b"<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>",
        b"<a xmlns:p='http://www.w3.org/XML/1998/namespace'/>",
        b"<a xmlns:xmlns='u'/>",
        b"<a xmlns='http://www.w3.org/2000/xmlns/'/>",
        b"<a xmlns=':bad'/>",
        b"<xmlns:a/>",
    ]
    .iter()
    .map(|d| d.to_vec())
    .collect();
    // Depth around the limit.
    for depth in [255, 256, 257] {
        let mut d = Vec::new();
        for _ in 0..depth {
            d.extend_from_slice(b"<a>");
        }
        for _ in 0..depth {
            d.extend_from_slice(b"</a>");
        }
        docs.push(d);
    }
    // Text across the reads, a name near the limit, long attribute values.
    for len in [500, 511, 512, 513, 3990, 4000, 4096, 8200, 50_000] {
        let mut d = b"<a><name>".to_vec();
        d.extend(std::iter::repeat_n(b'n', len));
        d.extend_from_slice(b"</name><b x='");
        d.extend(std::iter::repeat_n(b'v', len));
        d.extend_from_slice(b"'/></a>");
        docs.push(d);
    }
    for len in [49_999, 50_000, 50_001] {
        let mut d = b"<".to_vec();
        d.extend(std::iter::repeat_n(b'n', len));
        d.extend_from_slice(b"/>");
        docs.push(d);
    }
    docs
}

#[test]
fn reader_matches_libxml2_on_edge_cases() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    for d in edge_cases() {
        for failat in [None, Some(0), Some(3), Some(4000), Some(4100)] {
            let f = failat.map_or("-".to_string(), |f| f.to_string());
            let want = oracle.ask(&format!("xml {f} {}", hex(&d)));
            let got = answer(&d, failat);
            assert!(
                same(&got, &want),
                "{:?} failing at {f}:\n  port: {got}\n  libxml2: {want}",
                String::from_utf8_lossy(&d)
            );
        }
    }
}

#[test]
fn reader_matches_libxml2_on_documents() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let count: u64 = std::env::var("XAR_XML_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let mut rng = Rng(0x0786_d1c0);
    for i in 0..count {
        let mut d = if i % 10 == 9 {
            long_document(&mut rng)
        } else {
            document(&mut rng)
        };
        if i % 2 == 1 {
            d = damage(&mut rng, d);
        }
        let failat = if rng.below(10) == 0 {
            Some(rng.below(d.len() as u64 + 1) as usize)
        } else {
            None
        };
        let f = failat.map_or("-".to_string(), |f| f.to_string());
        let want = oracle.ask(&format!("xml {f} {}", hex(&d)));
        let got = answer(&d, failat);
        assert!(
            same(&got, &want),
            "document {i} failing at {f}: {:?}\n  port: {got}\n  libxml2: {want}",
            String::from_utf8_lossy(&d)
        );
    }
}

/// The recorded answers of `xml` requests in `testdata/oracle/xar.txt`.
#[test]
fn reader_matches_recorded_answers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/oracle/xar.txt");
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let mut checked = 0;
    for line in text.lines().filter(|l| l.starts_with("xml ")) {
        let (request, want) = line.split_once('\t').unwrap();
        let words: Vec<&str> = request.split(' ').collect();
        let failat = (words[1] != "-").then(|| words[1].parse().unwrap());
        let got = answer(&unhex(words[2]), failat);
        assert!(
            same(&got, want),
            "{request:.200}:\n  port: {got}\n  libxml2: {want}"
        );
        checked += 1;
    }
    let _ = checked;
}

/// Documents at libxml2's limits: text nodes, comments, PIs, CDATA
/// sections and attribute values around 10,000,000 bytes, and a start tag
/// longer than the parser may get from its buffer's start in one push.
fn limit_documents() -> Vec<Vec<u8>> {
    let mut docs = Vec::new();
    let around = [9_999_990usize, 9_999_999, 10_000_000, 10_000_001];
    for &n in &around {
        let mut d = b"<a>".to_vec();
        d.extend(std::iter::repeat_n(b'x', n));
        d.extend_from_slice(b"</a>");
        docs.push(d);
        let mut d = b"<a><!--".to_vec();
        d.extend(std::iter::repeat_n(b'x', n));
        d.extend_from_slice(b"--></a>");
        docs.push(d);
        let mut d = b"<a><![CDATA[".to_vec();
        d.extend(std::iter::repeat_n(b'x', n));
        d.extend_from_slice(b"]]></a>");
        docs.push(d);
        let mut d = b"<a><?p ".to_vec();
        d.extend(std::iter::repeat_n(b'x', n));
        d.extend_from_slice(b"?></a>");
        docs.push(d);
        let mut d = b"<a b='&#65;".to_vec();
        d.extend(std::iter::repeat_n(b'x', n));
        d.extend_from_slice(b"'/>");
        docs.push(d);
    }
    let mut d = b"<a b='".to_vec();
    d.extend(std::iter::repeat_n(b'x', 10_000_100));
    d.extend_from_slice(b"'/>");
    docs.push(d);
    // A comment past the limit, and one with a character past ASCII, which
    // takes the slow path with the accelerated path's buffer.
    let mut d = b"<a><!--".to_vec();
    d.extend(std::iter::repeat_n(b'x', 6_000_000));
    d.extend_from_slice("é".as_bytes());
    d.extend(std::iter::repeat_n(b'x', 4_000_000));
    d.extend_from_slice(b"--></a>");
    docs.push(d);
    docs
}

#[test]
#[ignore = "large: XAR_XML_LIMITS=1 cargo test --release -p hivepack-xar --lib limits -- --ignored"]
fn reader_matches_libxml2_at_limits() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    for (i, d) in limit_documents().into_iter().enumerate() {
        let want = oracle.ask(&format!("xml - {}", hex(&d)));
        let got = answer(&d, None);
        assert!(
            same(&got, &want),
            "limit document {i}:\n  port: {got}\n  libxml2: {want}"
        );
    }
}
