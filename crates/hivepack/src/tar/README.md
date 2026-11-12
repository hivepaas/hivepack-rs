# hivepack::tar

Reading and writing tar archives in safe Rust, ported from Go's `archive/tar` (Go 1.27.2).

> **Status:** reads V7, USTAR, PAX, GNU and STAR archives: PAX records and GNU long names merged into their entries, global PAX headers, and sparse files in GNU's formats 0.0, 0.1, 1.0 and the old one, their holes read as zeros. Every header, byte of data and error is the same as Go's, on Go's own test archives, archives Go's writer makes, and thousands of damaged ones. Writes USTAR, PAX and GNU, choosing the first that can hold each header unless it names one: every byte and error the same as Go's, over thousands of scripts of calls, with wrong headers and failing outputs among them. It writes no sparse files, as Go does not.

```rust
use std::io::Read;

let mut tar = hivepack::tar::Reader::new(std::fs::File::open("backup.tar")?);
while let Some(header) = tar.next()? {
    let mut data = Vec::new();
    tar.read_to_end(&mut data)?;
    println!("{} {} bytes", String::from_utf8_lossy(&header.name), data.len());
}
```

```rust
use std::io::Write;

let file = std::io::BufWriter::new(std::fs::File::create("backup.tar")?);
let mut tar = hivepack::tar::Writer::new(file);
let data = b"hello\n";
tar.write_header(&hivepack::tar::Header {
    typeflag: hivepack::tar::TYPE_REG,
    name: b"hello.txt".to_vec(),
    mode: 0o644,
    size: data.len() as i64,
    ..Default::default()
})?;
tar.write_all(data)?;
tar.close()?;
```

Names are bytes, as tar keeps them. Data not read is skipped by the next `next`. An error stays: every later call returns it, except, when writing, a header no format can hold and a write past an entry's size, which fail alone. `close` is what ends an archive: dropping the writer leaves it without its end. Extracting to disk, with its checks on names and links, belongs to hivepack::extract.

How the port follows Go, and how it is checked, is in [docs/tar.md](../../../../docs/tar.md).

## Speed

Against Go 1.27.2's `archive/tar`, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Going through entries, USTAR and PAX, from memory | 2.75× (2.75–2.76×) | 2.05× (2.03–2.07×) | 2.54× (2.30–2.79×) |
| Going through entries, GNU long names, from memory | 1.56× | 1.34× | 1.76× |
| Going through sparse entries, from memory | 2.71× (2.68–2.75×) | – | – |
| Going through entries, from a file | 1.97× (1.73–2.20×) | 1.73× (1.54–1.91×) | 1.84× (1.52–2.17×) |
| Reading data, from memory | 1.46× (0.90–2.03×) | 1.40× (1.03–1.76×) | 1.88× (1.52–2.23×) |
| Reading sparse data, from memory | 1.11× (1.10–1.12×) | – | – |
| Reading data, from a file | 1.04× (1.02–1.07×) | 1.06× (1.05–1.06×) | 0.97× (0.94–1.01×) |
| Skipping data, through a buffer | 1.02× | 1.02× | 0.99× |
| Skipping data, seeking in a file | 1.78× (1.71–1.85×) | 1.46× (1.46–1.47×) | 1.54× (1.45–1.63×) |
| Writing entries, to nowhere | 2.99× (2.82–3.45×) | 2.80× (2.11–3.23×) | 2.87× (2.44–3.32×) |
| Writing to a file | 1.49× (1.02–1.96×) | 1.48× (1.03–1.94×) | 1.54× (1.05–2.03×) |

**Measured on** `.github/workflows/bench.yml`, on November 10, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 9V45 (4 threads); Windows x86-64 on Intel64 Family 6 Model 106 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

The sparse rows are missing on macOS because GNU tar writes those files whole there, so the archives have no holes to read, and on Windows because the runners have no GNU tar. On one machine with more detail, an AMD Ryzen 9 9950X, the whole table and the reasons are in [docs/tar.md](../../../../docs/tar.md#the-speed).

## License

BSD-3-Clause, as Go is (see [LICENSE](LICENSE)).
