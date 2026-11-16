# hivepack::fat

Reading FAT file systems in safe Rust, read-only: FAT12, FAT16 and FAT32, with the long names VFAT added.

> **Status:** reads the directories and files of a FAT file system on a [`Disk`](../image) — a partition of a card or of a disk image, or a file that holds one as it is — with the 8.3 names MS-DOS had, the long names Windows writes in front of them, the times each record carries, and the chain of clusters a file's data lies in. Checked against the file systems `qemu-img`'s `vvfat` writes out of a folder and those `mkfs.fat` writes, and against file systems built byte by byte, each of which `fsck.fat` is run over. Writing is not here and is not planned. [`hivepack::ext`](../ext) reads ext2, ext3 and ext4, and NTFS is what is left of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225).

```rust
use std::io::Read;

use hivepack::fat::Fat;

let fat = Fat::open(std::fs::File::open("boot.img")?)?;
println!("{} {:?}", fat.kind().says(), fat.label());
let mut walk = fat.walk()?;
while let Some((path, entry)) = walk.next(&fat)? {
    println!("{path} {} bytes", entry.size);
    if entry.is_file() {
        let mut data = Vec::new();
        fat.file(&entry)?.read_to_end(&mut data)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

A partition of a card is read by giving it the partition: `Fat::open(Part::new(&disk, part.at, part.size))`, where `part` came from [`hivepack::image::partitions`](../image). That is the layering the two modules are for — a container holds a disk, the disk's table names partitions, and a partition holds a file system.

## What it gives

- **`Fat::open(disk)`** — the file system, or why it is not one. `Fat::kind`, `Fat::label`, `Fat::cluster_size` and `Fat::clusters` say what it is.
- **`Fat::read_root`** and **`Fat::read_dir(&entry)`** — the entries of a directory, in the order its records hold them. `.` and `..` are left out: they are what the file system finds its way about with, not files.
- **`Fat::lookup_path("sub/file.txt")`** — what is at a path, by either of a file's names and without regard to case, as every system that reads a FAT file system does.
- **`Fat::file(&entry)`** — the data, as `io::Read` and `io::Seek`. Clusters that follow one another are read in one go.
- **`Fat::walk`** — every file and directory, each with the path to it, depth first.
- **`Entry`** — the names, the length, the three times, and the four flags a record carries. **`Time`** has no time zone, because a FAT file system holds none: see its own note.

## Nothing here is a port

The layout is Microsoft's published *FAT32 File System Specification*, which gives FAT12 and FAT16 with it, and the long names are what that specification and VFAT's own published description say. So the repository's own MIT license covers this module and it has no `LICENSE` of its own, as `image` has none. The rules it follows, what it refuses, and how it is checked are in [docs/fat.md](../../../../docs/fat.md).
