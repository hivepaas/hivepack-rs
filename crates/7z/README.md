# hivepack-7z

Reading 7z archives in safe Rust, ported from the 7z decoder of the [LZMA SDK](https://7-zip.org/sdk.html) (7-Zip 26.05), which is in the public domain, and writing them, from the description of the format.

> **Status:** opens what the SDK opens, encoded headers included, and decodes what it decodes (Copy, LZMA, LZMA2 and PPMd, after a branch converter, the delta filter or BCJ2), with the SDK's answers, its error numbers included, on archives 7-Zip makes and on damaged copies of them. Past the SDK, it reads what 7-Zip's program reads: any graph of coders, with Deflate, Deflate64, BZip2 and the swap filters, Zstandard as 7-Zip's forks write it, and AES with a password. This crate is not on crates.io.

```rust,no_run
use std::io::Read;

let mut archive = hivepack_7z::Archive::open(std::fs::File::open("backup.7z")?)?;
let mut files = archive.files();
while let Some(entry) = files.next()? {
    let mut data = Vec::new();
    files.read_to_end(&mut data)?;
    println!("{} {} bytes", entry.name, data.len());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Two ways to read a file's data:

- **`Archive::files`** reads the files one after another, each folder decoded once, in pieces, so that a solid block of any size takes little memory: what its coders need.
- **`Archive::extract`** decodes a file's whole folder into memory, as `SzArEx_Extract` does, and keeps it for the folder's next file.

An encrypted archive takes its password in `Options::password`, or later in `Archive::set_password` when its names can be read without it. 7z has nothing to check a password with but the data, so `Error::WrongPassword` may also be damaged data.

An archive says how much memory it needs, so `Options` limits it: the description of the archive, 1 GiB by default, and a folder's dictionaries and models, 4 GiB by default. An application that opens archives from strangers lowers them.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same answers as the SDK**, error numbers included.
- **The same speed**: LZMA and LZMA2 go through [`hivepack-xz`](../xz), which is faster than the SDK's C decoder without its assembly; PPMd takes 0.92× the SDK's speed.

How the port follows the SDK, how it is checked, and what is left are in [docs/7z.md](../../docs/7z.md).

## Writing

```rust,no_run
use std::io::Write;

let file = std::io::BufWriter::new(std::fs::File::create("backup.7z")?);
let mut archive = hivepack_7z::Writer::new(file)?;
archive.add_directory(hivepack_7z::NewEntry::new("notes"))?;
archive.start_file(hivepack_7z::NewEntry::new("notes/hello.txt"))?;
archive.write_all(b"hello\n")?;
archive.finish()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`WriteOptions` picks Copy, LZMA, LZMA2 (the default), Deflate or BZip2, a branch converter or the delta filter before LZMA and LZMA2, how large a solid block may grow, and AES-256 with a password, for the data alone or the names too. Files take any size, not known beforehand. It writes what `7zz` and the LZMA SDK read; PPMd, BCJ2 and Zstandard are read and not written. An archive is no archive until `finish`.

## Speed

Against the LZMA SDK 26.05's C decoder and, for what that does not read, `7zz t -mmt=1` from the same release, with `tools/7z-bench`. Above 1× the port is faster.

| | hivepack-7z / the reference |
|---|---|
| LZMA, LZMA2 and their filters, against the SDK | 1.10–1.24× |
| PPMd, against the SDK | 0.88–0.92× |
| LZMA with `lc + lp` above 4, against the SDK | 0.77× |
| Copy, against the SDK | 0.59× |
| Opening 100,000 files, against the SDK | 0.66–0.81× |
| Deflate and Deflate64, against `7zz` | 1.00–1.39× |
| BZip2 and Swap4, against `7zz` | 0.62–0.64× |
| AES-256 behind a compressor, against `7zz` | 1.17–1.21× |
| AES-256 with Copy, against `7zz` | 0.62× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, in October 2026. The SDK and `7zz` are built with GCC 15.2 and their makefile's flags, without the assembly decoders that 7-Zip's releases use. The data is the Silesia corpus cut to 64 MiB, the best of five rounds taken in turn.

The LZMA figures are against C only. AES has the processor's instructions on both sides now, and the two rows of it were measured in November 2026. The whole table and the reasons are in [docs/7z.md](../../docs/7z.md#the-speed).

### On GitHub's runners

Against the LZMA SDK 26.05 and `7zz`, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many files, against the SDK | 0.66× (0.58–0.73×) | 0.77× (0.74–0.79×) | 0.75× (0.62–0.88×) |
| Copy, against the SDK | 0.43× | 0.69× | 0.49× |
| LZMA, LZMA2 and their filters, against the SDK | 1.01× (0.84–1.07×) | 0.99× (0.87–1.02×) | 0.89× (0.81–0.96×) |
| LZMA with `lc + lp` above 4, against the SDK | 0.71× | 0.72× | 0.61× |
| PPMd, against the SDK | 0.86× (0.81–0.91×) | 0.90× (0.83–0.96×) | 0.89× (0.75–1.02×) |
| Deflate and Deflate64, against `7zz` | 1.10× (0.88–1.32×) | 1.19× (0.95–1.44×) | 0.98× (0.79–1.18×) |
| BZip2 and Swap4, against `7zz` | 0.53× (0.45–0.61×) | 0.66× (0.63–0.68×) | 0.52× (0.39–0.64×) |
| AES-256 with Copy, against `7zz` | 0.64× | 0.79× | 0.63× |
| AES-256 behind a compressor, against `7zz` | 1.05× (1.03–1.07×) | 1.09× (0.99–1.19×) | 0.77× (0.72–0.83×) |
| Writing, Copy | 1.06× (0.54–1.59×) | 1.40× (0.99–1.80×) | 1.02× (0.78–1.25×) |
| Writing, LZMA and LZMA2 | 0.69× (0.67–0.72×) | 0.78× (0.70–0.83×) | 0.79× (0.77–0.83×) |
| Writing, Deflate | 2.24× | 2.12× | 2.70× |
| Writing, BZip2 | 1.25× | 1.39× | 1.20× |
| Writing, AES-256 with LZMA2 | 0.70× | 0.80× | 0.73× |
| Writing, LZMA2, not solid, small files | 0.68× | 0.80× | 0.81× |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many files, against the SDK | 0.78× (0.70–0.86×) | 0.77× (0.74–0.79×) | 0.76× (0.65–0.86×) |
| Copy, against the SDK | 0.54× | 0.41× | 0.51× |
| LZMA, LZMA2 and their filters, against the SDK | 1.19× (1.06–1.28×) | 1.00× (0.84–1.04×) | 0.90× (0.86–0.99×) |
| LZMA with `lc + lp` above 4, against the SDK | 0.78× | 0.69× | 0.62× |
| PPMd, against the SDK | 0.89× (0.88–0.89×) | 0.85× (0.81–0.89×) | 0.83× (0.74–0.93×) |
| Deflate and Deflate64, against `7zz` | 1.21× (1.01–1.40×) | 1.11× (0.80–1.42×) | 0.99× (0.81–1.17×) |
| BZip2 and Swap4, against `7zz` | 0.60× (0.60–0.60×) | 0.59× (0.50–0.68×) | 0.54× (0.43–0.64×) |
| AES-256 with Copy, against `7zz` | 0.60× | 0.78× | 0.68× |
| AES-256 behind a compressor, against `7zz` | 1.25× (1.18–1.32×) | 1.13× (1.02–1.24×) | 0.77× (0.73–0.82×) |
| Writing, Copy | 0.98× (0.17–1.79×) | 1.43× (0.99–1.87×) | 1.15× (0.90–1.39×) |
| Writing, LZMA and LZMA2 | 0.74× (0.68–0.78×) | 0.74× (0.73–0.76×) | 0.83× (0.77–0.94×) |
| Writing, Deflate | 2.21× | 2.17× | 2.51× |
| Writing, BZip2 | 1.44× | 1.31× | 1.19× |
| Writing, AES-256 with LZMA2 | 0.70× | 0.78× | 0.85× |
| Writing, LZMA2, not solid, small files | 0.64× | 0.81× | 0.78× |

**Measured on** `.github/workflows/bench.yml`, on November 2, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 25 Model 17 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). With it: Linux x86-64 on AMD EPYC 9V45 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). `unsafe-fast` here is now only CRC-32 on arm64: AES has the processor's instructions in both, and differences between the tables on x86-64 are the machines. Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

The rows of writing are against `7zz`, which has its own compressors.

## License

MIT, as hivepack is. The code it is ported from, the LZMA SDK's C files, is in the public domain, by Igor Pavlov, and PPMd var.H by Dmitry Shkarin. See [LICENSE](../../LICENSE). Copyright (c) 2026 HivePaaS.
