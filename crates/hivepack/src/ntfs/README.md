# hivepack::ntfs

Reading NTFS file systems in safe Rust, read-only.

> **Status:** reads the directories, the files, the times and the alternate data streams of an NTFS file system on a [`Disk`](../image) — a partition of a disk image, or a file that holds one as it is. Compressed and encrypted data are **refused**, not read. Checked against file systems `mkntfs` writes and `ntfs-3g` fills, including a compressed file, a sparse file, a file in a hundred pieces, a second name for one file, and a directory too long for its own record. Extracted to a folder or a sink by [`hivepack::extract`](../extract)'s `extract_ntfs`, with every rule it holds an archive to. Writing is not here and is not planned. This is the last file system of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225), after [`hivepack::fat`](../fat) and [`hivepack::ext`](../ext).

```rust
use std::io::Read;

use hivepack::ntfs::Ntfs;

let fs = Ntfs::open(std::fs::File::open("windows.img")?)?;
println!("{:?}", fs.label());
let mut walk = fs.walk()?;
while let Some((path, entry)) = walk.next(&fs)? {
    println!("{path} {} bytes", entry.size);
    if entry.readable().is_ok() {
        let mut data = Vec::new();
        fs.file(&entry)?.read_to_end(&mut data)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

A partition of a disk is read by giving it the partition: `Ntfs::open(Part::new(&disk, part.at, part.size))`, where `part` came from [`hivepack::image::partitions`](../image).

## What it gives

- **`Ntfs::open(disk)`** — the file system, or why it is not one. It reads the whole boot sector and checks the name in it, which the library underneath does not; `Ntfs::label`, `Ntfs::cluster_size` and `Ntfs::size` say what it is.
- **`Ntfs::read_root`** and **`Ntfs::read_dir(&entry)`** — the entries of a directory. The records the file system keeps for itself are left out, and so is the 8.3 name Windows keeps beside a long one, as the long name is the file's.
- **`Ntfs::lookup_path("sub/file.txt")`** — what is at a path. The name has to be the name: NTFS compares names by a table the volume carries, and this module does not keep that table's rules.
- **`Ntfs::file(&entry)`** — the data, as `io::Read` and `io::Seek`, read straight from the disk at the runs the file system named. A hole of a sparse file reads as the zeroes it stands for.
- **`Ntfs::stream(&entry, "name")`** and **`Ntfs::streams`** — the alternate data streams, the second stretch of bytes a file may hold under the same name.
- **`Ntfs::walk`** — every file and directory, each with the path to it, depth first.
- **`Entry`** — the name, the length, the three times, the flags, how many names the file has, and which record it is: two entries of one record are one file under two names. **`Entry::readable`** says whether the data can be read before anything goes to the disk.
- **`Time`** is an instant, counted in UTC, unlike [`hivepack::fat`](../fat)'s.

## This one *is* a dependency, and that is the whole story

Every other format in this crate is read by code that is here. NTFS has no published specification, and the two complete readers — ntfs-3g and the kernel's ntfs3 — are GPL-2.0, which this crate cannot take. So the structures are read by [Colin Finck's `ntfs`](https://crates.io/crates/ntfs), which is MIT or Apache-2.0 and forbids `unsafe` code, and what is here is the layer around it: it gives the library a `Disk` to read, holds it to this crate's limits, and turns what it answers into entries and byte streams.

Two things that library does not do are refused here rather than passed on:

- **Compressed data** it hands back *still compressed, with no error at all*. A reader that did not stop would write files that are not the ones in the image. `Error::Compressed`.
- **Encrypted data** it cannot decrypt; the key is a Windows user's and is not in the image. `Error::Encrypted`.

The feature is off by default, as `rar` is, for reasons measured rather than assumed. What those are — both panics found in the library, the compressed-data measurement, the licence result over the whole dependency tree, and the dependency of its own that a future Rust will refuse to compile — is in [docs/ntfs.md](../../../../docs/ntfs.md).
