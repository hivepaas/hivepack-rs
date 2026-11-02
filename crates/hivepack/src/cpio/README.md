# hivepack::cpio

Reading cpio archives in safe Rust, ported from libarchive 3.8.10's reader, and the payload of RPM packages, from its RPM filter.

> **Status:** reads every cpio format libarchive reads: odc (POSIX.1), newc and crc (SVR4, as Linux's initramfs and RPM packages have it), afio's large ASCII headers, and the old binary format in either byte order, with symbolic and hard links, devices, and the search for the next header after garbage. Every header, warning, byte of data and error is the same as libarchive's, on libarchive's own test archives, archives its writers make, archives the tests make with what they do not, and tens of thousands of damaged ones. Takes the lead and headers off RPM packages as libarchive's filter does. Writing is not ported. This crate is not on crates.io.

```rust
use std::io::Read;

let mut cpio = hivepack::cpio::Reader::new(std::fs::File::open("initrd.cpio")?);
while let Some(header) = cpio.next()? {
    let mut data = Vec::new();
    cpio.read_to_end(&mut data)?;
    println!("{} {} bytes", String::from_utf8_lossy(&header.path), data.len());
}
```

Entries come in the order of the archive, up to its `TRAILER!!!`; data not read is skipped by the next `next`. `Reader::new` reads any `io::Read`, a decompressing reader for one, and never seeks. An entry libarchive gives with `ARCHIVE_WARN` (bytes skipped to find its header) comes with a `Warning`. A failure stays: every later call returns it. `rpm::Reader` gives an RPM package's payload, which is a cpio archive most often compressed; `rpm::bid` tells a package by its first eight bytes. Decompressing, and extracting to disk with its checks on names and links, belong to hivepack::open and hivepack::extract.

How the port follows libarchive, and how it is checked, is in [docs/cpio.md](../../../../docs/cpio.md).

## License

BSD-2-Clause, as libarchive is (see [LICENSE](LICENSE)).
