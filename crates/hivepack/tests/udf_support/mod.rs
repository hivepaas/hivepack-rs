//! What the tests share: the repository, images kept compressed, and the
//! transcript of a volume that tools/udf-images/answer.py writes of what
//! Linux mounts.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod image;

use std::io::{Cursor, Read};
use std::path::PathBuf;

use hivepack::udf::{Error, Node, Options, Udf, VType};

/// The repository's root.
pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `data` decompressed with xz.
pub fn xz_decode(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Action, InBuffer, OutBuffer, Status, Stream};
    let mut stream = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = stream
            .code(&mut output, &mut input, Action::Finish)
            .unwrap();
        let written = output.pos;
        out.extend_from_slice(&piece[..written]);
        if status == Status::StreamEnd {
            return out;
        }
    }
}

/// The hexadecimal of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(data: &[u8]) -> String {
    let mut h = hivepack::crypto::Sha256::new();
    h.update(data);
    hex(&h.out())
}

fn letter(kind: VType) -> &'static str {
    match kind {
        VType::VDIR => "d",
        VType::VREG => "f",
        VType::VLNK => "l",
        VType::VCHR => "c",
        VType::VBLK => "b",
        VType::VFIFO => "p",
        VType::VSOCK => "s",
        VType::VNON => "?",
    }
}

fn ns(t: hivepack::udf::Timespec) -> i128 {
    i128::from(t.sec) * 1_000_000_000 + i128::from(t.nsec)
}

/// The line of a node, as answer.py words Linux's.
fn line(udf: &mut Udf<Cursor<Vec<u8>>>, path: &[u8], node: &Node) -> Result<String, Error> {
    let stat = udf.stat(node);
    let mut extra = "-".to_string();
    let mut digest = "-".to_string();
    match stat.kind {
        VType::VLNK => {
            let target = udf.read_link(node)?;
            if !target.is_empty() {
                extra = hex(&target);
            }
        }
        VType::VCHR | VType::VBLK => {
            if let Some((major, minor)) = stat.rdev {
                extra = format!("{major},{minor}");
            }
        }
        VType::VREG => {
            let mut data = Vec::new();
            udf.file(node)
                .read_to_end(&mut data)
                .map_err(|e| match e.downcast::<Error>() {
                    Ok(e) => e,
                    Err(e) => Error::Io(e),
                })?;
            digest = sha256(&data);
        }
        _ => {}
    }
    Ok([
        if path.is_empty() {
            ".".to_string()
        } else {
            hex(path)
        },
        letter(stat.kind).to_string(),
        format!("{:o}", stat.mode & 0o7777),
        stat.uid.to_string(),
        stat.gid.to_string(),
        stat.nlink.to_string(),
        stat.size.to_string(),
        ns(stat.mtime).to_string(),
        ns(stat.atime).to_string(),
        ns(stat.ctime).to_string(),
        extra,
        digest,
    ]
    .join("\t"))
}

/// The options that read as Linux mounts: the owner of nodes without one
/// is nobody.
pub fn linux_options() -> Options {
    Options {
        anon_uid: 65534,
        anon_gid: 65534,
        ..Options::default()
    }
}

/// Every node of the volume, one line each, sorted by path: what
/// answer.py writes.
pub fn transcript(image: Vec<u8>, options: &Options) -> Result<String, Error> {
    let mut udf = Udf::with_options(Cursor::new(image), options)?;
    let root = udf.root().clone();
    let mut lines = vec![(Vec::new(), line(&mut udf, b"", &root)?)];
    let mut dirs = vec![(Vec::new(), root)];
    while let Some((path, dir)) = dirs.pop() {
        let entries: Vec<_> = udf.read_dir(&dir)?.collect::<Result<_, _>>()?;
        for entry in entries {
            if entry.is_parent() {
                continue;
            }
            let mut child = path.clone();
            if !child.is_empty() {
                child.push(b'/');
            }
            child.extend_from_slice(&entry.name);
            let node = udf.node(entry.icb)?;
            lines.push((child.clone(), line(&mut udf, &child, &node)?));
            if node.kind() == VType::VDIR {
                dirs.push((child, node));
            }
        }
    }
    lines.sort();
    Ok(lines.into_iter().map(|(_, l)| l + "\n").collect())
}
