# hivepack-tar

Reading and writing tar archives in safe Rust, ported from Go's `archive/tar` (Go 1.27.2).

> **Status:** reads V7, USTAR, PAX, GNU and STAR archives: PAX records and GNU long names merged into their entries, global PAX headers, and sparse files in GNU's formats 0.0, 0.1, 1.0 and the old one, their holes read as zeros. Every header, byte of data and error is the same as Go's, on Go's own test archives, archives Go's writer makes, and thousands of damaged ones. Writes USTAR, PAX and GNU, choosing the first that can hold each header unless it names one: every byte and error the same as Go's, over thousands of scripts of calls, with wrong headers and failing outputs among them. It writes no sparse files, as Go does not. This crate is not on crates.io.

```rust
use std::io::Read;

let mut tar = hivepack_tar::Reader::new(std::fs::File::open("backup.tar")?);
while let Some(header) = tar.next()? {
    let mut data = Vec::new();
    tar.read_to_end(&mut data)?;
    println!("{} {} bytes", String::from_utf8_lossy(&header.name), data.len());
}
```

```rust
use std::io::Write;

let file = std::io::BufWriter::new(std::fs::File::create("backup.tar")?);
let mut tar = hivepack_tar::Writer::new(file);
let data = b"hello\n";
tar.write_header(&hivepack_tar::Header {
    typeflag: hivepack_tar::TYPE_REG,
    name: b"hello.txt".to_vec(),
    mode: 0o644,
    size: data.len() as i64,
    ..Default::default()
})?;
tar.write_all(data)?;
tar.close()?;
```

Names are bytes, as tar keeps them. Data not read is skipped by the next `next`. An error stays: every later call returns it, except, when writing, a header no format can hold and a write past an entry's size, which fail alone. `close` is what ends an archive: dropping the writer leaves it without its end. Extracting to disk, with its checks on names and links, belongs to hivepack-extract.

How the port follows Go, and how it is checked, is in [docs/tar.md](../../docs/tar.md).

## Speed

Against Go 1.27.2's `archive/tar`, with `tools/tar-bench`. Above 1× the port is faster.

| Port / Go | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Going through entries, USTAR and PAX, from memory | 2.88–3.03× | 2.20–2.28× | 2.52× |
| Going through entries, GNU long names, from memory | 1.81× | 1.43× | 1.75× |
| Going through entries, from a file | 1.89–2.47× | 1.48–2.01× | 1.49–2.08× |
| Going through sparse entries, from memory | 2.38–2.47× | no GNU tar | no holes |
| Reading data, from memory | 0.96–2.00× | 2.12–2.16× | 1.61–2.46× |
| Reading data, from a file | 1.05–1.09× | 1.12–1.15× | 0.99–1.08× |
| Skipping data, through a buffer | 1.04× | 0.96× | 1.26× |
| Skipping data, seeking in a file | 1.78–1.92× | 1.41–1.49× | 1.51–1.53× |

**Measured on** GitHub's runners with `.github/workflows/bench.yml`, on October 31, 2026, the best of five rounds taken in turn: Linux on an AMD EPYC 9V45 (4 threads), Windows Server 2025 on an Intel processor (family 6, model 173) (4 threads), and macOS 26 on a virtual Apple M1 (3 threads). All with rustc 1.99.1 and Go 1.27.2. These are shared machines, so the ratios hold better than the speeds, and a runner's processor can differ from one run to the next.

The sparse rows are missing on macOS because GNU tar writes those files whole there, so the archives have no holes to read, and on Windows because the runners have no GNU tar. On one machine with more detail, an AMD Ryzen 9 9950X, the whole table and the reasons are in [docs/tar.md](../../docs/tar.md#the-speed).

## License

BSD-3-Clause, as Go is (see [LICENSE](LICENSE)).
