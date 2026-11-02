# hivepack::rar

Reading RAR archives in safe Rust: a port of [UnRAR](https://www.rarlab.com/rar_add.htm) 7.3.2, RARLAB's source, under UnRAR's license. It reads RAR and never writes it.

> **Status:** reads what UnRAR reads, as UnRAR does, broken archives included: the headers of RAR 1.4 to 7, entries stored or compressed by any RAR, encrypted with a password, split across volumes, comments and QuickOpen records, checked against CRC-32, BLAKE2sp or RAR 1.4's checksum. Compared with UnRAR on the archives of four other projects and damaged copies of them. `hivepack::extract` writes it to disk with its feature `rar`. This crate is not on crates.io.

```rust
use hivepack::rar::{Archive, HEAD_FILE, name};

let mut archive = Archive::open(std::fs::File::open("archive.rar")?, false)?;
while archive.read_header()? != 0 {
    if archive.cur_header_type == HEAD_FILE {
        println!("{}", name::to_string_lossy(&archive.file_head.file_name));
    }
    archive.seek_to_next();
}
```

An `Extract` goes through the entries, giving out each one's data and checking its hash; see the crate's documentation.

The plan, the license and how the port is checked are in [docs/rar.md](../../../../docs/rar.md).

## Speed

Against UnRAR 7.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| RAR 4, each file apart | 0.97× (0.95–0.99×) | 1.31× (1.27–1.34×) | 0.99× (0.99–1.00×) |
| RAR 4, with a password | 0.82× | 1.08× | 0.93× |
| RAR 4, PPMd | 0.73× | 0.75× | 0.98× |
| RAR 4, solid | 1.11× | 1.52× | 0.96× |
| RAR 5, each file apart | 1.00× (1.00–1.00×) | 1.51× (1.50–1.52×) | 0.92× (0.91–0.93×) |
| RAR 5, with a password | 1.22× | 1.76× | 1.34× |
| RAR 5, solid | 1.03× | 1.44× | 0.77× |

**Measured on** `.github/workflows/bench.yml`, on November 2, 2026, with rustc 1.99.1: Linux x86-64 on Intel Xeon Platinum 8370C (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the formats are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

The archives are `testdata/rar`, each 8.3 MB unpacked: this repository's files and some bytes a script makes, not the Silesia corpus of the other formats. `tools/rar-bench` runs both sides on one thread. The first table's PPMd row is from a later run, after its model's reads were made faster.

## License

UnRAR's license; see [LICENSE](LICENSE). In its words:

> UnRAR source code may be used in any software to handle RAR archives without limitations free of charge, but cannot be used to develop RAR (WinRAR) compatible archiver and to re-create RAR compression algorithm, which is proprietary. Distribution of modified UnRAR source code in separate form or as a part of other software is permitted, provided that full text of this paragraph, starting from "UnRAR source code" words, is included in license, or in documentation if license is not available, and in source code comments of resulting package.

All copyrights to RAR and to UnRAR are Alexander Roshal's.
