# hivepack::ar

Reading ar archives in safe Rust, ported from libarchive 3.8.10's reader: Debian packages (`.deb`), and static libraries.

> **Status:** reads what libarchive's ar reader reads: GNU and SVR4's archives, with their symbol tables passed over and long names in a filename table, and BSD's, with long names before the data. Every header, byte of data and error is the same as libarchive's, on its test archive, archives its writers make, and thousands of archives the tests make with what they do not, as they are and damaged. Writing is not ported. This crate is not on crates.io.

```rust
use std::io::Read;

let mut ar = hivepack::ar::Reader::new(std::fs::File::open("hello.deb")?);
while let Some(header) = ar.next()? {
    let mut data = Vec::new();
    ar.read_to_end(&mut data)?;
    println!("{} {} bytes", String::from_utf8_lossy(&header.path), data.len());
}
```

Entries come in the order of the archive, until no whole header is left; data not read is skipped by the next `next`. `Reader::new` reads any `io::Read` and never seeks. Every entry is a regular file. A failure stays: every later call returns it. `hivepack::open` takes a Debian package off as a layer, down to its `data.tar`, the files it installs; extracting them, with their checks on names and links, belongs to hivepack::extract.

How the port follows libarchive, and how it is checked, is in [docs/ar.md](../../../../docs/ar.md).

## License

BSD-2-Clause, as libarchive is (see [LICENSE](LICENSE)).
