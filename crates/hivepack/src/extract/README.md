# hivepack::extract

Extracting archives to disk, safe by default: nothing is written outside the destination, through a link, over what is there, or past limits set against archive bombs.

> **Status:** extracts ZIP archives that `hivepack::zip` opened, refusing unportable names, the same path twice (ignoring case and how accents are written), links and overlapping data, writing by handle, and counting what is written against its limits, with named options to relax each rule, a time limit, cancelling and progress, and carrying the archive's mark of origin (Windows' Mark of the Web, macOS's quarantine) to every file. tar, cpio and XAR archives (`extract_tar`, `extract_cpio`: an RPM package's payload too, `extract_xar`: a macOS package with its payloads expanded) and ISO 9660 images (`extract_iso`) are read twice, to check everything before writing, and UDF volumes (`extract_udf`) and 7z archives (`extract_7z`, each folder decoded once, solid blocks too) checked first, as ZIP archives are. RAR comes later. With the feature `rar`, off by default as it takes UnRAR's license, `extract_rar` extracts RAR archives the same way.

```rust
use hivepack::extract::{Options, Origin, extract_zip};
use hivepack::zip::{Archive, OpenFlags};

let path = std::path::Path::new("archive.zip");
let archive = Archive::open(std::fs::File::open(path)?, OpenFlags::CHECKCONS)?;
let mut options = Options::default();
options.origin = Origin::of(path)?;
let summary = extract_zip(&archive, "out".as_ref(), &options)?;
println!("{} files, {} bytes", summary.files, summary.bytes);
```

The rules, and why each is there, are in [docs/extract.md](../../../../docs/extract.md). Writing by handle takes cap-std, a dependency with `unsafe` code, until the standard library's directory handles are stable, and macOS's quarantine attribute takes rustix, which cap-std already uses (see [docs/safety.md](../../../../docs/safety.md)).

## License

MIT. See [LICENSE](../../../../LICENSE). Copyright (c) 2026 HivePaaS.

The tables names are compared with (`src/unicode/tables.rs`) are made by `scripts/unicode.py` from the Unicode Character Database, under the Unicode License v3: see [LICENSE-UNICODE](LICENSE-UNICODE).
