# hivepack-rar

Reading RAR archives in safe Rust: a port of [UnRAR](https://www.rarlab.com/rar_add.htm) 7.3.2, RARLAB's source, under UnRAR's license. It reads RAR and never writes it.

> **Status:** reads what UnRAR reads, as UnRAR does, broken archives included: the headers of RAR 1.4 to 7, entries stored or compressed by any RAR, encrypted with a password, split across volumes, comments and QuickOpen records, checked against CRC-32, BLAKE2sp or RAR 1.4's checksum. Compared with UnRAR on the archives of four other projects and damaged copies of them. `hivepack-extract` writes it to disk with its feature `rar`. This crate is not on crates.io.

```rust
use hivepack_rar::{Archive, HEAD_FILE, name};

let mut archive = Archive::open(std::fs::File::open("archive.rar")?, false)?;
while archive.read_header()? != 0 {
    if archive.cur_header_type == HEAD_FILE {
        println!("{}", name::to_string_lossy(&archive.file_head.file_name));
    }
    archive.seek_to_next();
}
```

An `Extract` goes through the entries, giving out each one's data and checking its hash; see the crate's documentation.

The plan, the license and how the port is checked are in [docs/rar.md](../../docs/rar.md).

## Speed

Against UnRAR 7.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| RAR 4, each file apart | 1.13× (1.10–1.16×) | 1.25× (1.22–1.27×) | 0.98× (0.97–1.00×) |
| RAR 4, with a password | 0.91× | 0.99× | 0.84× |
| RAR 4, PPMd | 0.75× | 0.82× | 0.93× |
| RAR 4, solid | 1.35× | 1.45× | 1.05× |
| RAR 5, each file apart | 1.08× (1.07–1.09×) | 1.46× (1.44–1.49×) | 0.87× (0.85–0.91×) |
| RAR 5, with a password | 1.34× | 1.60× | 1.38× |
| RAR 5, solid | 1.17× | 1.31× | 0.82× |

**Measured on** `.github/workflows/bench.yml`, on November 2, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 26 Model 2 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the formats are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

The archives are `testdata/rar`, each 8.3 MB unpacked: this repository's files and some bytes a script makes, not the Silesia corpus of the other formats. `tools/rar-bench` runs both sides on one thread. The first table's PPMd row is from a later run, after its model's reads were made faster.

## License

UnRAR's license; see [LICENSE](LICENSE). In its words:

> UnRAR source code may be used in any software to handle RAR archives without limitations free of charge, but cannot be used to develop RAR (WinRAR) compatible archiver and to re-create RAR compression algorithm, which is proprietary. Distribution of modified UnRAR source code in separate form or as a part of other software is permitted, provided that full text of this paragraph, starting from "UnRAR source code" words, is included in license, or in documentation if license is not available, and in source code comments of resulting package.

All copyrights to RAR and to UnRAR are Alexander Roshal's.
