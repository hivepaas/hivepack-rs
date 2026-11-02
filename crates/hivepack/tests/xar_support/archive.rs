//! XAR archives made here: the table of contents (TOC) and its checksum
//! put together, archives with TOCs that use every element and attribute
//! libarchive's reader knows (and many it does not), and damaged copies.

use std::fmt::Write as _;

use hivepack::crypto::{Md5, Sha1, Sha256, Sha512};

use super::Rng;

thread_local! {
    /// Whether the crafted archive being made has numbers too large,
    /// checksums wrong and the like.
    static NOISY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn noisy() -> bool {
    NOISY.with(std::cell::Cell::get)
}

/// One time in `n`, in a noisy archive.
fn wild(rng: &mut Rng, n: u64) -> bool {
    let hit = rng.below(n) == 0;
    hit && noisy()
}

/// `rng.below(n)` in a noisy archive, `n` (out of range) in a clean one.
fn wild_below(rng: &mut Rng, n: u64) -> u64 {
    let r = rng.below(n);
    if noisy() { r } else { n }
}

/// The checksum algorithms of the header and of the TOC's `style`s.
pub const NONE: u32 = 0;
pub const SHA1: u32 = 1;
pub const MD5: u32 = 2;
pub const SHA256: u32 = 3;
pub const SHA512: u32 = 4;

fn be16(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}

fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn be64(p: &[u8]) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&p[..8]);
    u64::from_be_bytes(b)
}

/// The digest of `data` with algorithm `alg` (empty for none).
pub fn digest(alg: u32, data: &[u8]) -> Vec<u8> {
    match alg {
        SHA1 => {
            let mut h = Sha1::new();
            h.update(data);
            h.out().to_vec()
        }
        MD5 => {
            let mut h = Md5::new();
            h.update(data);
            h.out().to_vec()
        }
        SHA256 => {
            let mut h = Sha256::new();
            h.update(data);
            h.out().to_vec()
        }
        SHA512 => {
            let mut h = Sha512::new();
            h.update(data);
            h.out().to_vec()
        }
        _ => Vec::new(),
    }
}

/// The name of algorithm `alg` in a `style` attribute.
pub fn style(alg: u32) -> &'static str {
    match alg {
        SHA1 => "sha1",
        MD5 => "md5",
        SHA256 => "sha256",
        SHA512 => "sha512",
        _ => "none",
    }
}

/// zlib's format at `level`, which XAR calls "application/x-gzip".
pub fn zlib(data: &[u8], level: i32) -> Vec<u8> {
    use hivepack::deflate::{Deflate, Flush, InBuffer, OutBuffer, Status};
    let mut z = Deflate::new_default(level).unwrap();
    let mut out = vec![0; data.len() + data.len() / 8 + 64];
    let mut input = InBuffer::new(data);
    let mut pos = 0;
    loop {
        let mut output = OutBuffer::new(&mut out[pos..]);
        let status = z.deflate(&mut output, &mut input, Flush::Finish).unwrap();
        pos += output.pos;
        if status == Status::StreamEnd {
            out.truncate(pos);
            return out;
        }
        out.resize(out.len() * 2, 0);
    }
}

/// zlib's inflate of a whole stream, or `None` if it is not one.
pub fn unzlib(data: &[u8]) -> Option<Vec<u8>> {
    use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
    let mut z = Inflate::new_default();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = z.inflate(&mut output, &mut input, Flush::NoFlush).ok()?;
        let n = output.pos;
        out.extend_from_slice(&piece[..n]);
        if status == Status::StreamEnd {
            return Some(out);
        }
        if n == 0 && input.pos == data.len() {
            return None;
        }
    }
}

pub fn bzip2(data: &[u8]) -> Vec<u8> {
    use hivepack::bzip2::{Action, Compress, InBuffer, OutBuffer, Status};
    let mut z = Compress::new(9, 0).unwrap();
    let mut out = vec![0; data.len() + data.len() / 4 + 1024];
    let mut input = InBuffer::new(data);
    let mut pos = 0;
    loop {
        let mut output = OutBuffer::new(&mut out[pos..]);
        let status = z.compress(&mut output, &mut input, Action::Finish).unwrap();
        pos += output.pos;
        if status == Status::StreamEnd {
            out.truncate(pos);
            return out;
        }
        out.resize(out.len() * 2, 0);
    }
}

pub fn xz(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Check, easy_buffer_encode, stream_buffer_bound};
    let mut out = vec![0; stream_buffer_bound(data.len())];
    let mut pos = 0;
    easy_buffer_encode(1, Check::CRC64, data, &mut out, &mut pos).unwrap();
    out.truncate(pos);
    out
}

pub fn lzma(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Action, InBuffer, LzmaOptions, OutBuffer, Status, Stream};
    let mut z = Stream::alone_encoder(&LzmaOptions::preset(1).unwrap()).unwrap();
    let mut out = vec![0; data.len() + data.len() / 4 + 1024];
    let mut input = InBuffer::new(data);
    let mut pos = 0;
    loop {
        let mut output = OutBuffer::new(&mut out[pos..]);
        let status = z.code(&mut output, &mut input, Action::Finish).unwrap();
        pos += output.pos;
        if status == Status::StreamEnd {
            out.truncate(pos);
            return out;
        }
        out.resize(out.len() * 2, 0);
    }
}

/// The parts of an archive: its header's fields, the compressed TOC, and
/// the heap; `None` if it is too short for its header.
pub struct Parts {
    pub header: Vec<u8>,
    pub ctoc: Vec<u8>,
    pub heap: Vec<u8>,
}

pub fn parts(archive: &[u8]) -> Option<Parts> {
    if archive.len() < 28 || be16(&archive[4..]) < 28 {
        return None;
    }
    let size = usize::from(be16(&archive[4..]));
    let csize = usize::try_from(be64(&archive[8..])).ok()?;
    let toc_end = size.checked_add(csize)?;
    if toc_end > archive.len() {
        return None;
    }
    Some(Parts {
        header: archive[..size].to_vec(),
        ctoc: archive[size..toc_end].to_vec(),
        heap: archive[toc_end..].to_vec(),
    })
}

/// The archive's TOC, uncompressed.
pub fn toc(archive: &[u8]) -> Option<Vec<u8>> {
    unzlib(&parts(archive)?.ctoc)
}

/// As much of the archive's TOC as inflates, from where the header says
/// it starts to the end of the archive.
pub fn toc_start(archive: &[u8]) -> Vec<u8> {
    use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer};
    if archive.len() < 28 {
        return Vec::new();
    }
    // libarchive reads it after the 28 bytes it knows, whatever the header
    // says its size is.
    let data = &archive[28..];
    let mut z = Inflate::new_default();
    let mut out = Vec::new();
    let mut piece = vec![0; 1 << 16];
    // A little input at a time, to keep what comes before an error.
    for chunk in data.chunks(16) {
        let mut input = InBuffer::new(chunk);
        while input.pos < chunk.len() {
            let mut output = OutBuffer::new(&mut piece);
            let status = z.inflate(&mut output, &mut input, Flush::NoFlush);
            let n = output.pos;
            out.extend_from_slice(&piece[..n]);
            match status {
                Ok(hivepack::deflate::Status::Ok) => {}
                _ => return out,
            }
        }
    }
    out
}

/// The number in the first `<tag>` after `<checksum` in `toc`.
fn checksum_field(toc: &[u8], tag: &str) -> Option<u64> {
    let text = String::from_utf8_lossy(toc);
    let at = text.find("<checksum")?;
    let rest = &text[at..];
    let end = rest.find("</checksum>").unwrap_or(rest.len());
    let rest = &rest[..end];
    let open = format!("<{tag}>");
    let from = rest.find(&open)? + open.len();
    let digits: String = rest[from..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// An archive of `toc`, compressed at `level`, and `heap`, with the header
/// saying checksum `alg`; the TOC's checksum is written where the TOC says
/// it is, when that is in the heap and as long as the digest.
pub fn assemble(toc: &[u8], level: i32, alg: u32, heap: &[u8]) -> Vec<u8> {
    let ctoc = zlib(toc, level);
    let mut out = Vec::with_capacity(28 + ctoc.len() + heap.len());
    out.extend_from_slice(&0x7861_7221u32.to_be_bytes());
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(ctoc.len() as u64).to_be_bytes());
    out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    out.extend_from_slice(&alg.to_be_bytes());
    out.extend_from_slice(&ctoc);
    let base = out.len();
    out.extend_from_slice(heap);
    let sum = digest(alg, &ctoc);
    if let (Some(offset), Some(size)) = (checksum_field(toc, "offset"), checksum_field(toc, "size"))
    {
        let at = usize::try_from(offset)
            .ok()
            .and_then(|o| o.checked_add(base));
        if let Some(at) = at
            && size as usize == sum.len()
            && at + sum.len() <= out.len()
        {
            out[at..at + sum.len()].copy_from_slice(&sum);
        }
    }
    out
}

/// The archive with its TOC changed by `f`, and the header and the TOC's
/// checksum made right again; `None` if it has no TOC to change.
pub fn retoc(archive: &[u8], f: impl FnOnce(Vec<u8>) -> Vec<u8>) -> Option<Vec<u8>> {
    let p = parts(archive)?;
    if p.header.len() != 28 {
        return None;
    }
    let toc = unzlib(&p.ctoc)?;
    let alg = be32(&p.header[24..]);
    let toc = f(toc);
    let mut out = assemble(&toc, 6, alg, &p.heap);
    // The header's other fields as they were.
    out[..8].copy_from_slice(&p.header[..8]);
    Some(out)
}

/// A random number for a field: small, around the archive, or extreme.
pub fn field(rng: &mut Rng, len: usize) -> String {
    match rng.below(10) {
        0 => "0".into(),
        1 => rng.below(64).to_string(),
        2 => rng.below(len as u64 + 64).to_string(),
        3 => rng.below(1 << 20).to_string(),
        4 => u64::MAX.to_string(),
        5 => "18446744073709551616".into(),
        6 => (1u64 << 63).to_string(),
        7 => ((1u64 << 63) - 1).to_string(),
        8 => rng
            .pick(&[
                "4294967295",
                "4294967296",
                "2147483648",
                "65535",
                "65536",
                "-1",
                "",
                "x",
                "12x",
            ])
            .into(),
        _ => rng.next().to_string(),
    }
}

/// `toc` with a number between tags replaced.
fn renumber(rng: &mut Rng, toc: Vec<u8>, len: usize) -> Vec<u8> {
    let text = String::from_utf8_lossy(&toc).into_owned();
    let starts: Vec<usize> = text
        .match_indices('>')
        .map(|(i, _)| i + 1)
        .filter(|&i| text[i..].starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    if starts.is_empty() {
        return toc;
    }
    let at = rng.pick(&starts);
    let end = at
        + text[at..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(0);
    let mut out = text[..at].to_string();
    out.push_str(&field(rng, len));
    out.push_str(&text[end..]);
    out.into_bytes()
}

/// Bits of XML to put into a TOC.
const SNIPPETS: &[&str] = &[
    "<file id=\"99\"><name>x</name></file>",
    "<file>",
    "</file>",
    "<data><offset>0</offset><length>1</length><size>1</size></data>",
    "<ea id=\"1\"><name>n</name><offset>0</offset><length>1</length><size>1</size></ea>",
    "<type link=\"original\">file</type>",
    "<type link=\"1\">hardlink</type>",
    "<type link=\"2\">hardlink</type>",
    "<link>target</link>",
    "<unknown><deeper>t</deeper></unknown>",
    "<name enctype=\"base64\">AAEC/w==</name>",
    "<!-- comment -->",
    "<?pi data?>",
    "<![CDATA[cdata <&>]]>",
    "&amp;&lt;&#65;&#x42;",
    "&undefined;",
    "&#0;",
    "<a:b xmlns:a=\"urn:a\"/>",
    "<p:q/>",
    "\u{e9}\u{4e2d}",
    "\u{0}",
    "<",
    ">",
    "&",
    "]]>",
    "\"",
    "<x a=\"1\" a=\"2\"/>",
    "<x xml:id=\"1bad\"/>",
    "<mode>4777777</mode>",
    "<flags><UserNoDump/><SystemImmutable/></flags>",
    "<ext2><Compress/><TopDir/></ext2>",
    "<encoding style=\"application/x-bzip2\"/>",
    "<archived-checksum style=\"MD5\">00</archived-checksum>",
    "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>",
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE x>",
    "\r\n",
];

/// The archive with one to three things wrong in it, in its header, its
/// bytes, or (with the checksums made right again) its TOC.
pub fn damage(rng: &mut Rng, archive: &[u8]) -> Vec<u8> {
    let mut archive = archive.to_vec();
    for _ in 0..1 + rng.below(3) {
        let len = archive.len();
        if len == 0 {
            break;
        }
        match rng.below(20) {
            // A bit or byte anywhere.
            0 | 1 => {
                let at = rng.below(len as u64) as usize;
                if rng.below(2) == 0 {
                    archive[at] ^= 1 << rng.below(8);
                } else {
                    let any = rng.next() as u8;
                    archive[at] = rng.pick(&[0, 1, 0x7f, 0x80, 0xff, any]);
                }
            }
            // A header field.
            2 | 3 => {
                if len < 28 {
                    continue;
                }
                match rng.below(7) {
                    0 => archive[..4].copy_from_slice(&rng.next().to_be_bytes()[..4]),
                    1 => {
                        let v = rng.pick(&[0u16, 27, 28, 29, 64, 0xffff]);
                        archive[4..6].copy_from_slice(&v.to_be_bytes());
                    }
                    2 => {
                        let v = rng.pick(&[0u16, 2, 0xffff]);
                        archive[6..8].copy_from_slice(&v.to_be_bytes());
                    }
                    3 | 4 => {
                        let at = if rng.below(2) == 0 { 8 } else { 16 };
                        let old = be64(&archive[at..]);
                        let v = match rng.below(5) {
                            0 => old.wrapping_add(1),
                            1 => old.wrapping_sub(1),
                            2 => rng.below(len as u64 * 2),
                            3 => rng.pick(&[0, u64::MAX, 1 << 63, 1 << 32]),
                            _ => rng.next(),
                        };
                        archive[at..at + 8].copy_from_slice(&v.to_be_bytes());
                    }
                    _ => {
                        let v = rng.pick(&[0u32, 1, 2, 3, 4, 5, 0xffff_ffff]);
                        archive[24..28].copy_from_slice(&v.to_be_bytes());
                    }
                }
            }
            // Cut short.
            4 => {
                let at = rng.below(len as u64 + 1) as usize;
                archive.truncate(at);
            }
            // Bytes after the end.
            5 => {
                let more = rng.below(3000) as usize;
                archive.extend((0..more).map(|_| rng.next() as u8));
            }
            // A byte in the heap.
            6 | 7 => {
                let Some(p) = parts(&archive) else { continue };
                if p.heap.is_empty() {
                    continue;
                }
                let at = len - p.heap.len() + rng.below(p.heap.len() as u64) as usize;
                archive[at] ^= 1 << rng.below(8);
            }
            // The TOC's text.
            _ => {
                // Mostly ways that keep the XML well-formed.
                let kind = rng.pick(&[0, 1, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 7, 8]);
                let seed = rng.next();
                let changed = retoc(&archive, |toc| {
                    let mut rng = Rng(seed | 1);
                    xml_damage(&mut rng, kind, toc, len)
                });
                if let Some(changed) = changed {
                    archive = changed;
                }
            }
        }
    }
    archive
}

/// A TOC damaged in way `kind`.
fn xml_damage(rng: &mut Rng, kind: u64, mut toc: Vec<u8>, len: usize) -> Vec<u8> {
    if toc.is_empty() {
        return toc;
    }
    let n = toc.len() as u64;
    match kind {
        0 => {
            let at = rng.below(n) as usize;
            toc[at] = rng.pick(b"<>&/\"'= \0\x80\xffxa1;!?-]");
        }
        1 => {
            let at = rng.below(n) as usize;
            let end = (at + 1 + rng.below(40) as usize).min(toc.len());
            toc.drain(at..end);
        }
        2 => {
            let at = rng.below(n) as usize;
            let end = (at + 1 + rng.below(200) as usize).min(toc.len());
            let copy = toc[at..end].to_vec();
            let to = rng.below(n) as usize;
            toc.splice(to..to, copy);
        }
        3 | 4 => toc = renumber(rng, toc, len),
        5 => {
            let at = rng.below(n + 1) as usize;
            let snippet = rng.pick(SNIPPETS).as_bytes().to_vec();
            toc.splice(at..at, snippet);
        }
        6 => {
            // Inside a tag: another place for a snippet, between tags.
            let text = String::from_utf8_lossy(&toc).into_owned();
            let gaps: Vec<usize> = text.match_indices('>').map(|(i, _)| i + 1).collect();
            if let Some(&at) = gaps.get(rng.below(gaps.len().max(1) as u64) as usize) {
                let mut out = text[..at].to_string();
                out.push_str(rng.pick(SNIPPETS));
                out.push_str(&text[at..]);
                toc = out.into_bytes();
            }
        }
        7 => {
            let styles = [
                "application/octet-stream",
                "application/x-gzip",
                "application/x-bzip2",
                "application/x-lzma",
                "application/x-xz",
                "sha1",
                "md5",
                "SHA256",
                "Sha512",
                "none",
            ];
            let text = String::from_utf8_lossy(&toc).into_owned();
            let at: Vec<usize> = text.match_indices("style=\"").map(|(i, _)| i + 7).collect();
            if let Some(&at) = at.get(rng.below(at.len().max(1) as u64) as usize) {
                let end = at + text[at..].find('"').unwrap_or(0);
                let mut out = text[..at].to_string();
                out.push_str(rng.pick(&styles));
                out.push_str(&text[end..]);
                toc = out.into_bytes();
            }
        }
        _ => {
            let at = rng.below(n) as usize;
            toc.truncate(at);
        }
    }
    toc
}

/// What a crafted archive's data is: its bytes as stored, its size, and
/// the TOC's `<data>` or `<ea>` fields for it.
struct Blob {
    stored: Vec<u8>,
    size: u64,
    style: &'static str,
    a_alg: u32,
    e_alg: u32,
    a_sum: Vec<u8>,
    e_sum: Vec<u8>,
}

/// Data of a random kind: text, repeated bytes, or noise.
fn content(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(8) {
        0 => 0,
        1 => 1 + rng.below(10),
        2 => 60_000 + rng.below(20_000),
        3 => 200_000 + rng.below(100_000),
        _ => rng.below(3000),
    } as usize;
    match rng.below(3) {
        0 => (0..len).map(|i| b"hello xar "[i % 10]).collect(),
        1 => (0..len).map(|i| (i * 7 % 251) as u8).collect(),
        _ => (0..len).map(|_| rng.next() as u8).collect(),
    }
}

/// `data` encoded one of XAR's ways, with checksums (sometimes wrong).
fn blob(rng: &mut Rng, data: &[u8]) -> Blob {
    let kinds = if rng.below(5) == 0 { 7 } else { 6 };
    let (style, stored) = match rng.below(kinds) {
        0 => ("application/octet-stream", data.to_vec()),
        1 | 2 => ("application/x-gzip", zlib(data, rng.pick(&[0, 1, 6, 9]))),
        3 => ("application/x-bzip2", bzip2(data)),
        4 => ("application/x-lzma", lzma(data)),
        5 => ("application/x-xz", xz(data)),
        // Not what it says it is.
        _ => {
            let style = rng.pick(&[
                "application/x-gzip",
                "application/x-bzip2",
                "application/x-lzma",
                "application/x-xz",
            ]);
            let mut bad = zlib(data, 6);
            if !bad.is_empty() {
                let at = rng.below(bad.len() as u64) as usize;
                bad[at] ^= 0x55;
            }
            (style, bad)
        }
    };
    let algs = [NONE, SHA1, MD5, SHA256, SHA512];
    let a_alg = rng.pick(&algs);
    let e_alg = rng.pick(&algs);
    let mut a_sum = digest(a_alg, &stored);
    let mut e_sum = digest(e_alg, data);
    if wild(rng, 40) && !a_sum.is_empty() {
        a_sum[0] ^= 1;
    }
    if wild(rng, 40) && !e_sum.is_empty() {
        let at = e_sum.len() - 1;
        e_sum[at] ^= 0x80;
    }
    let mut size = data.len() as u64;
    if wild(rng, 40) {
        size = size.wrapping_add(rng.pick(&[1, u64::MAX, 100]));
    }
    Blob {
        stored,
        size,
        style,
        a_alg,
        e_alg,
        a_sum,
        e_sum,
    }
}

/// A checksum element: the style in some case, and the hex, sometimes
/// cut or not hex.
fn sum_element(rng: &mut Rng, tag: &str, alg: u32, sum: &[u8]) -> String {
    let mut style = style(alg).to_string();
    if rng.below(4) == 0 {
        style = style.to_uppercase();
    }
    let mut text: String = sum.iter().map(|b| format!("{b:02x}")).collect();
    match wild_below(rng, 80) {
        0 => text.truncate(text.len() / 2),
        1 => text.push('g'),
        2 => text = text.to_uppercase(),
        3 => text.push_str("00"),
        _ => {}
    }
    if alg == NONE && rng.below(2) == 0 {
        return String::new();
    }
    format!("<{tag} style=\"{style}\">{text}</{tag}>")
}

/// A name: ASCII, long, UTF-8, with what XML must escape, or bytes that
/// are not UTF-8 (in base64).
fn name(rng: &mut Rng) -> (String, Vec<u8>) {
    let len = match rng.below(8) {
        0 => 1 + rng.below(3),
        1 => 100 + rng.below(300),
        _ => 3 + rng.below(12),
    } as usize;
    let alphabets: [&[char]; 4] = [
        &['a', 'b', 'z', '.', '-', ' ', '_', '0'],
        &['&', '<', '>', '"', '\'', 'x', '/'],
        &['é', 'ü', 'ñ', 'Ø', 'ß', 'Ä'],
        &['中', '文', 'カ', '한', '😀', '𝄞'],
    ];
    let pick = rng.below(4) as usize;
    let text: String = (0..len)
        .map(|_| {
            let alphabet = alphabets[if rng.below(4) == 0 {
                rng.below(4) as usize
            } else {
                pick
            }];
            alphabet[rng.below(alphabet.len() as u64) as usize]
        })
        .collect();
    let raw = text.as_bytes().to_vec();
    (text, raw)
}

/// `text` escaped for XML, in one of the ways XML allows.
fn escape(rng: &mut Rng, text: &str) -> String {
    if rng.below(6) == 0 && !text.contains("]]>") {
        return format!("<![CDATA[{text}]]>");
    }
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' if rng.below(2) == 0 => out.push_str("&gt;"),
            '"' if rng.below(2) == 0 => out.push_str("&quot;"),
            c if rng.below(30) == 0 => {
                let _ = write!(out, "&#{};", c as u32);
            }
            c if rng.below(30) == 0 => {
                let _ = write!(out, "&#x{:X};", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A time as XAR writes it, or not quite.
fn time(rng: &mut Rng) -> String {
    let year = match rng.below(8) {
        0 => 1800 + rng.below(170),
        1 => 2100 + rng.below(7000),
        2 => 1900,
        _ => 1970 + rng.below(80),
    };
    let (mut mon, mut day) = (1 + rng.below(12), 1 + rng.below(31));
    let (mut h, mut m, mut s) = (rng.below(24), rng.below(60), rng.below(61));
    match rng.below(20) {
        0 => mon = rng.pick(&[0, 13, 99]),
        1 => day = rng.pick(&[0, 32]),
        2 => h = 24,
        3 => m = 60,
        4 => s = 61,
        5 => {
            return rng
                .pick(&[
                    "",
                    "2020-01-01",
                    "2020-01-01T00:00:00",
                    "2020-01-01T00:00:00Z0",
                    "2020/01/01T00:00:00Z",
                    "abcd-01-01T00:00:00Z",
                    "2020-01-01 00:00:00Z",
                    "2020-01-01T00:00:00+",
                ])
                .to_string();
        }
        _ => {}
    }
    format!("{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// What the files of a crafted archive refer to.
struct Tree {
    heap: Vec<u8>,
    next_id: u64,
    ids: Vec<u64>,
    files: usize,
}

impl Tree {
    /// `blob` put in the heap, mostly at its end, sometimes over earlier
    /// data or out of it.
    fn put(&mut self, rng: &mut Rng, blob: &Blob) -> u64 {
        match wild_below(rng, 60) {
            0 => rng.below(self.heap.len() as u64 + 1),
            1 => self.heap.len() as u64 + rng.below(100_000),
            _ => {
                let at = self.heap.len() as u64;
                self.heap.extend_from_slice(&blob.stored);
                at
            }
        }
    }
}

/// The elements of a `<data>` or `<ea>` for `blob`.
fn data_fields(rng: &mut Rng, tree: &mut Tree, blob: &Blob) -> String {
    let offset = tree.put(rng, blob);
    let mut length = blob.stored.len() as u64;
    if wild(rng, 60) {
        length = rng.pick(&[0, length + 1, length.saturating_sub(1), 1 << 40]);
    }
    let mut parts = vec![
        format!("<length>{length}</length>"),
        format!("<offset>{offset}</offset>"),
        format!("<size>{}</size>", blob.size),
        format!("<encoding style=\"{}\"/>", blob.style),
        sum_element(rng, "archived-checksum", blob.a_alg, &blob.a_sum),
        sum_element(rng, "extracted-checksum", blob.e_alg, &blob.e_sum),
    ];
    if rng.below(5) == 0 {
        parts.push("<content style=\"application/xml\"><x>y</x></content>".into());
    }
    if rng.below(6) == 0 {
        parts.push("<unknown-field>1</unknown-field>".into());
    }
    if rng.below(3) == 0 {
        let i = rng.below(parts.len() as u64) as usize;
        let j = rng.below(parts.len() as u64) as usize;
        parts.swap(i, j);
    }
    if wild(rng, 40) {
        parts.remove(rng.below(parts.len() as u64) as usize);
    }
    parts.join(if rng.below(2) == 0 { "" } else { "\n" })
}

/// A `<file>` element, with its children when it is a directory.
fn file(rng: &mut Rng, tree: &mut Tree, depth: usize, out: &mut String) {
    tree.files += 1;
    let id = match wild_below(rng, 60) {
        0 => tree.ids.first().copied().unwrap_or(1),
        1 => rng.below(1 << 40),
        _ => {
            tree.next_id += 1 + rng.below(3);
            tree.next_id
        }
    };
    tree.ids.push(id);
    match wild_below(rng, 80) {
        0 => out.push_str("<file>"),
        1 => {
            let _ = write!(out, "<file id=\"{}\">", field(rng, 100));
        }
        2 => {
            let _ = write!(out, "<file xmlns:x=\"urn:x\" x:id=\"5\" id=\"{id}\">");
        }
        _ => {
            let _ = write!(out, "<file id=\"{id}\">");
        }
    }
    let kinds = [
        "file",
        "directory",
        "symlink",
        "hardlink",
        "character special",
        "block special",
        "socket",
        "fifo",
        "whiteout",
    ];
    let kind = if depth < 6 && rng.below(4) == 0 {
        "directory"
    } else {
        rng.pick(&kinds)
    };
    let mut parts: Vec<String> = Vec::new();
    // The name.
    let (text, raw) = name(rng);
    match rng.below(12) {
        0 => parts.push(format!("<name enctype=\"base64\">{}</name>", base64(&raw))),
        1 => {
            // Bytes that are not UTF-8, or with a NUL.
            let mut bytes = raw.clone();
            bytes.push(rng.pick(&[0xff, 0x80, 0xc3, 0, 0xed]));
            bytes.extend_from_slice(b"tail");
            parts.push(format!(
                "<name enctype=\"base64\">{}</name>",
                base64(&bytes)
            ));
        }
        2 => parts.push(format!(
            "<name enctype=\"base64\">{}</name>",
            "QUJD".repeat(rng.below(200) as usize)
        )),
        3 => {} // None.
        4 => parts.push(format!(
            "<name>{}</name><name>second</name>",
            escape(rng, &text)
        )),
        5 => parts.push("<name/>".into()),
        _ => parts.push(format!("<name>{}</name>", escape(rng, &text))),
    }
    // The type, and links.
    let link_attr = match (kind, rng.below(10)) {
        ("hardlink", 0..=8) if !tree.ids.is_empty() => {
            format!(" link=\"{}\"", rng.pick(&tree.ids))
        }
        ("hardlink", _) if noisy() => format!(" link=\"{}\"", field(rng, 100)),
        ("hardlink", _) => format!(" link=\"{}\"", rng.below(100)),
        ("file", 0..=1) => " link=\"original\"".into(),
        _ => String::new(),
    };
    if rng.below(15) != 0 {
        parts.push(format!("<type{link_attr}>{kind}</type>"));
    }
    if kind == "symlink" || rng.below(20) == 0 {
        let (target, _) = name(rng);
        parts.push(format!(
            "<link type=\"file\">{}</link>",
            escape(rng, &target)
        ));
    }
    // Who and when.
    let numbers: [(&str, u64); 6] = [
        ("mode", 8),
        ("uid", 10),
        ("gid", 10),
        ("inode", 10),
        ("deviceno", 10),
        ("ignored", 10),
    ];
    for (tag, base) in numbers {
        if tag == "ignored" || rng.below(4) == 0 {
            continue;
        }
        let value = match (tag, wild_below(rng, 60)) {
            (_, 0) => field(rng, 100),
            ("mode", _) => format!("{:04o}", rng.below(0o10000)),
            (_, _) if base == 10 => rng.below(100_000).to_string(),
            _ => String::new(),
        };
        parts.push(format!("<{tag}>{value}</{tag}>"));
    }
    if rng.below(3) == 0 {
        let (u, _) = name(rng);
        parts.push(format!("<user>{}</user>", escape(rng, &u)));
    }
    if rng.below(3) == 0 {
        let (g, _) = name(rng);
        parts.push(format!("<group>{}</group>", escape(rng, &g)));
    }
    if rng.below(12) == 0 {
        parts.push(format!(
            "<group enctype=\"base64\">{}</group>",
            base64(b"\xff\xfe")
        ));
        parts.push("<user>\u{fffd}ok</user>".into());
    }
    for tag in ["ctime", "mtime", "atime"] {
        if rng.below(3) != 0 {
            parts.push(format!("<{tag}>{}</{tag}>", time(rng)));
        }
    }
    if matches!(kind, "character special" | "block special") || rng.below(15) == 0 {
        let mut device = String::from("<device>");
        if rng.below(5) != 0 {
            let _ = write!(
                device,
                "<major>{}</major>",
                if wild(rng, 12) {
                    field(rng, 10)
                } else {
                    rng.below(300).to_string()
                }
            );
        }
        if rng.below(5) != 0 {
            let _ = write!(
                device,
                "<minor>{}</minor>",
                if wild(rng, 12) {
                    field(rng, 10)
                } else {
                    rng.below(70000).to_string()
                }
            );
        }
        if rng.below(8) == 0 {
            device.push_str("<other>1</other>");
        }
        device.push_str("</device>");
        parts.push(device);
    }
    if rng.below(5) == 0 {
        let flags = [
            "UserNoDump",
            "UserImmutable",
            "UserAppend",
            "UserOpaque",
            "UserNoUnlink",
            "SystemArchived",
            "SystemImmutable",
            "SystemAppend",
            "SystemNoUnlink",
            "SystemSnapshot",
            "UserBogus",
        ];
        let mut f = String::from("<flags>");
        for _ in 0..1 + rng.below(4) {
            let _ = write!(f, "<{}/>", rng.pick(&flags));
        }
        f.push_str("</flags>");
        parts.push(f);
    }
    if rng.below(6) == 0 {
        let flags = [
            "SecureDeletion",
            "Undelete",
            "Compress",
            "Synchronous",
            "Immutable",
            "AppendOnly",
            "NoDump",
            "NoAtime",
            "CompDirty",
            "CompBlock",
            "NoCompBlock",
            "CompError",
            "BTree",
            "HashIndexed",
            "iMagic",
            "Journaled",
            "NoTail",
            "DirSync",
            "TopDir",
            "Reserved",
            "Other",
        ];
        let mut f = String::from("<ext2>");
        for _ in 0..1 + rng.below(4) {
            let flag = rng.pick(&flags);
            if rng.below(3) == 0 {
                let _ = write!(f, "<{flag}>x</{flag}>");
            } else {
                let _ = write!(f, "<{flag}/>");
            }
        }
        f.push_str("</ext2>");
        parts.push(f);
    }
    if rng.below(8) == 0 {
        parts.push(
            "<acl><access>user::rw-</access><default>u::r</default><appleextended>!#acl</appleextended><x/></acl>"
                .into(),
        );
    }
    // Extended attributes.
    let eas = if rng.below(3) == 0 { rng.below(4) } else { 0 };
    for _ in 0..eas {
        let data = match rng.below(3) {
            0 => Vec::new(),
            _ => {
                let mut d = content(rng);
                d.truncate(rng.pick(&[10, 100, 70_000, 200_000]));
                d
            }
        };
        let blob = blob(rng, &data);
        let ea_id = rng.below(5);
        let mut ea = format!("<ea id=\"{ea_id}\">");
        if rng.below(10) != 0 {
            let (n, _) = name(rng);
            let _ = write!(ea, "<name>{}</name>", escape(rng, &n));
        }
        if rng.below(4) == 0 {
            ea.push_str("<fstype>hfs</fstype>");
        }
        ea.push_str(&data_fields(rng, tree, &blob));
        ea.push_str("</ea>");
        parts.push(ea);
    }
    // Data.
    if (kind == "file" || kind == "hardlink" || rng.below(10) == 0) && rng.below(8) != 0 {
        let data = content(rng);
        let blob = blob(rng, &data);
        parts.push(format!("<data>{}</data>", data_fields(rng, tree, &blob)));
    }
    if rng.below(10) == 0 {
        parts.push(format!(
            "<unknown attr=\"1\"><file id=\"{}\"><name>hidden</name></file></unknown>",
            rng.below(100)
        ));
    }
    if rng.below(30) == 0 {
        parts.push("<!-- a comment --><?pi x?>".into());
    }
    if rng.below(3) == 0 && !parts.is_empty() {
        let i = rng.below(parts.len() as u64) as usize;
        let j = rng.below(parts.len() as u64) as usize;
        parts.swap(i, j);
    }
    let sep = rng.pick(&["", "\n", "\n  ", " \t"]);
    for p in &parts {
        out.push_str(sep);
        out.push_str(p);
    }
    // Children.
    if kind == "directory" && tree.files < 400 {
        let children = match rng.below(10) {
            0 => 0,
            1 => 5 + rng.below(30),
            _ => rng.below(5),
        };
        for _ in 0..children {
            file(rng, tree, depth + 1, out);
        }
    }
    out.push_str(sep);
    out.push_str("</file>");
}

/// A crafted archive: its TOC's text, and the archive made of it.
pub fn crafted(rng: &mut Rng) -> Vec<u8> {
    let noisy = rng.below(2) == 0;
    NOISY.with(|c| c.set(noisy));
    let alg = rng.pick(&[SHA1, SHA1, MD5, SHA256, SHA512, NONE]);
    let sum_len = digest(alg, b"").len();
    let mut tree = Tree {
        heap: vec![0; sum_len],
        next_id: 0,
        ids: Vec::new(),
        files: 0,
    };
    let mut toc = String::new();
    match rng.below(6) {
        0 => {}
        1 => toc.push_str("<?xml version=\"1.0\"?>\n"),
        2 => toc.push_str("<?xml version=\"1.0\" encoding=\"US-ASCII\" standalone=\"yes\"?>"),
        3 => {
            toc.push_str("\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- made here -->\n")
        }
        _ => toc.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
    }
    let root = if rng.below(30) == 0 { "xarx" } else { "xar" };
    let _ = write!(toc, "<{root}");
    if rng.below(5) == 0 {
        toc.push_str(" xmlns=\"http://www.apple.com/xar\"");
    }
    toc.push_str(">\n <toc>\n");
    if rng.below(4) != 0 {
        let _ = writeln!(toc, "  <creation-time>{}</creation-time>", time(rng));
    }
    let style_alg = if rng.below(10) == 0 {
        rng.pick(&[SHA1, MD5, SHA256])
    } else {
        alg
    };
    let (offset, size) = match wild_below(rng, 20) {
        0 => (field(rng, 100), sum_len.to_string()),
        1 => ("0".to_string(), field(rng, 100)),
        _ => ("0".to_string(), sum_len.to_string()),
    };
    if alg != NONE || rng.below(3) == 0 {
        let _ = writeln!(
            toc,
            "  <checksum style=\"{}\">\n   <offset>{offset}</offset>\n   <size>{size}</size>\n  </checksum>",
            style(style_alg)
        );
    }
    if rng.below(6) == 0 {
        toc.push_str("  <signature style=\"RSA\"><offset>0</offset><size>256</size><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIB</X509Certificate></X509Data></KeyInfo></signature>\n");
    }
    // Deep nesting, near libxml2's limit of 256.
    if rng.below(25) == 0 {
        let depth = rng.pick(&[100, 250, 252, 253, 254, 255, 256, 300]);
        for _ in 0..depth {
            toc.push_str("<u>");
        }
        for _ in 0..depth {
            toc.push_str("</u>");
        }
    }
    let files = match rng.below(10) {
        0 => 0,
        1 => 100 + rng.below(300),
        _ => 1 + rng.below(8),
    };
    for _ in 0..files {
        if tree.files >= 400 {
            break;
        }
        file(rng, &mut tree, 0, &mut toc);
        toc.push('\n');
    }
    if rng.below(10) == 0 {
        toc.push_str("<unknown/>");
    }
    toc.push_str(" </toc>\n");
    let _ = write!(toc, "</{root}>");
    match rng.below(15) {
        0 => toc.push_str("\n<!-- after -->\n"),
        1 => toc.push_str("<extra/>"),
        _ => toc.push('\n'),
    }
    let level = rng.pick(&[0, 1, 6, 9]);
    assemble(toc.as_bytes(), level, alg, &tree.heap)
}
