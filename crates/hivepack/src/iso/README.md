# hivepack::iso

Reading ISO 9660 images (`.iso`) in safe Rust, ported from libarchive 3.8.10's reader.

> **Status:** reads ISO 9660 at every level, with Rock Ridge (POSIX names, permissions, owners, times, symbolic and hard links, devices, deep directories moved to `rr_moved`, continuation areas), Joliet (Unicode names, when there is no Rock Ridge), files in several extents, and files compressed with zisofs. Every header, warning, byte of data and error is the same as libarchive's, on libarchive's own test images, images libarchive's writer makes, images the tests make with what it does not, and tens of thousands of damaged ones. UDF and writing are not ported.

```rust
use std::io::Read;

let mut iso = hivepack::iso::Reader::seekable(std::fs::File::open("disc.iso")?);
while let Some(header) = iso.next()? {
    let mut data = Vec::new();
    iso.read_to_end(&mut data)?;
    let path = header.path.unwrap_or_default();
    println!("{} {} bytes", String::from_utf8_lossy(&path), data.len());
}
```

Entries come in the order their data is in the image, which is how libarchive reads an image in one pass. `Reader::seekable` goes back for a file whose data is before its directory, as libarchive does with a file; `Reader::new` reads any `io::Read`, a compressed layer for one, and gives such a file with a warning and no data. An entry libarchive gives with `ARCHIVE_WARN` comes with a `Warning`. A failure stays: every later call returns it. Extracting to disk, with its checks on names and links, belongs to hivepack::extract.

How the port follows libarchive, and how it is checked, is in [docs/iso.md](../../../../docs/iso.md).

## License

BSD-2-Clause, as libarchive is (see [LICENSE](LICENSE)).
