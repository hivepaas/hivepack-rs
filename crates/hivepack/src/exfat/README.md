# hivepack::exfat

Reading exFAT file systems in safe Rust, read-only.

> **Status:** reads the directories and files of an exFAT volume on a [`Disk`](../image) — a partition of a card or of a disk image, or a file that holds one as it is. This is what a memory card larger than 32 GB holds: the size where Windows stops offering FAT32, so every large SD card, camera card and stick sold formatted is this. Checked against volumes `mkfs.exfat` wrote with files put in them and `fsck.exfat` run over the result, and against volumes built byte by byte. Writing is not here and is not planned. The file systems beside it are [`fat`](../fat), [`ext`](../ext) and [`ntfs`](../ntfs).

```rust
use std::io::Read;

use hivepack::exfat::Exfat;

let exfat = Exfat::open(std::fs::File::open("card.img")?)?;
println!("{:?}", exfat.label());
let mut walk = exfat.walk()?;
while let Some((path, entry)) = walk.next(&exfat)? {
    println!("{path} {} bytes", entry.size);
    if entry.is_file() {
        let mut data = Vec::new();
        exfat.file(&entry)?.read_to_end(&mut data)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

A partition of a card is read by giving it the partition: `Exfat::open(Part::new(&disk, part.at, part.size))`, where `part` came from [`hivepack::image::partitions`](../image). That is the layering the modules are for — a container holds a disk, the disk's table names partitions, and a partition holds a file system.

## It is not FAT with larger numbers

A file is a **set** of entries rather than one record, and the set carries a checksum of itself. Names are UTF-16 with no 8.3 name beside them. A file written in one piece says so and keeps nothing in the table at all. A file knows how much of it has ever been written, and past that it reads as zeroes — the clusters hold whatever was in them before. Each time says what the offset from UTC was where it was written. There are no `.` and `..` entries. And the volume's start carries a checksum, with a backup region behind it that is read where the first one fails.

## What it gives

- **`Exfat::open(disk)`** — the file system, or why it is not one. `label`, `cluster_size`, `sector_size`, `clusters` and `serial` say what it is; `dirty`, `media_failure` and `from_backup` say what state it was found in.
- **`Exfat::read_root`** and **`Exfat::read_dir(&entry)`** — the entries of a directory, in the order it holds them. The bitmap, the upcase table and the label are not files and are not among them.
- **`Exfat::lookup_path("sub/file.txt")`** — what is at a path, without regard to case. The volume's own upcase table is not read: see [docs/exfat.md](../../../../docs/exfat.md).
- **`Exfat::file(&entry)`** — the data, as `io::Read` and `io::Seek`. Clusters that follow one another are read in one go, which is what a file written in one piece is made of; past what has been written, the file reads as zeroes.
- **`Exfat::walk`** — every file and directory, each with the path to it, depth first.
- **`Entry`** — the name, the length, how much of it was written, the three times and the four flags. **`Time`** carries the offset from UTC where the entry has one, which a FAT time never does.

## Nothing here is a port

The layout is Microsoft's *exFAT file system specification*, published in 2019 under its Open Specification Promise — the one file system here whose owner published it. Linux's own driver is GPL-2.0 and nothing here needed it, so the repository's own MIT license covers this module and it has no `LICENSE` of its own, as `fat` and `image` have none. The rules it follows, what it refuses, and how it is checked are in [docs/exfat.md](../../../../docs/exfat.md).
