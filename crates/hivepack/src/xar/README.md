# hivepack::xar

Reading XAR archives (macOS's `.pkg` installers, `.xip` files) in safe Rust, ported from libarchive 3.8.10's reader, with the parts of libxml2 2.15.4 it reads the table of contents with.

> **Status:** reads every file of an archive: paths (base64 names too), types, permissions, owners, times, inodes, devices, hard and symbolic links, BSD and Linux file flags, extended attributes, and data stored, or compressed with gzip, bzip2, lzma or xz, with its MD5, SHA-1, SHA-256 or SHA-512 checksums checked, as the table of contents's own. Every header, warning, byte of data and error is the same as libarchive's, on libarchive's test archives, archives its writer makes, archives of macOS's `xar` and `pkgbuild`, archives the tests make with what neither does, and tens of thousands of damaged ones. Writing is not ported. This crate is not on crates.io.

```rust
use std::io::Read;

let mut xar = hivepack::xar::Reader::seekable(std::fs::File::open("Install.pkg")?);
while let Some(header) = xar.next()? {
    let mut data = Vec::new();
    xar.read_to_end(&mut data)?;
    let path = header.path.unwrap_or_default();
    println!("{} {} bytes", String::from_utf8_lossy(&path), data.len());
}
```

Entries come in the order of their `id` in the table of contents. `Reader::seekable` goes back for data that is before the place read to, as libarchive does with a file; `Reader::new` reads any `io::Read`, and fails such an entry with `Error::CannotSeek`, after which the next one comes. An entry libarchive gives with `ARCHIVE_WARN` comes with a `Warning`. A failure stays: every later call returns it. The `Payload` of a `.pkg` is itself an archive (cpio, compressed), which this crate gives as data.

How the port follows libarchive and libxml2, and how it is checked, is in [docs/xar.md](../../../../docs/xar.md).

## License

BSD-2-Clause, as libarchive is, and MIT for the parts ported from libxml2 (see [LICENSE](LICENSE)).
