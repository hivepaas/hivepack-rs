# FAT: the file system in the partition

`hivepack::fat` reads FAT12, FAT16 and FAT32, with the long names VFAT added, read-only. It is the second layer of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225): a container holds a disk, the disk's table names partitions ([`hivepack::image`](../crates/hivepack/src/image)), and a partition holds a file system. This is the smallest file system with real reach — the boot partition of a Raspberry Pi's card, an EFI system partition, a camera's card, a USB stick anything will mount.

**It is not a port.** The layout is Microsoft's published *FAT32 File System Specification*, which gives FAT12 and FAT16 with it, and the long names are what that specification and VFAT's own published description say. There is no library to port anyway: Linux's own reader is GPL-2.0, and nothing here needed it. The repository's MIT license covers the module.

It reads a [`Disk`](image.md), so a partition of a card is read by handing it `Part::new(&disk, part.at, part.size)`, and a file holding a file system as it is — what `mkfs.fat` writes into one — by handing it the file.

## What it gives

- **`Fat::open(disk)`**, and then `kind`, `label`, `cluster_size` and `clusters`.
- **`read_root`** and **`read_dir(&entry)`**: the entries of a directory in the order its records hold them.
- **`lookup_path`**: by either name, without regard to case.
- **`file(&entry)`**: `io::Read` and `io::Seek` over the data.
- **`walk`**: every file and directory with the path to it, depth first.

## The rules it follows

- **Which of the three it is, is not written anywhere.** The boot sector's `FAT12 `/`FAT16 `/`FAT32 ` string is a label for a human and nothing reads it, and Microsoft's specification says the number of data clusters decides: fewer than 4085 is FAT12, fewer than 65525 is FAT16, the rest is FAT32.

  **That rule is wrong for FAT32, and tools write file systems it gets wrong.** `mkfs.fat -F 32` on a 32 MiB image writes 64496 clusters — fewer than 65525 — with a table of four bytes to an entry, `fs_type` of `FAT32 `, no root directory of its own and no 16-bit table length. Read by the rule, its table is read two bytes at a time and every chain leads somewhere else. `fsck.fat` warns about such a file system and reads it. So **the shape of the boot sector decides FAT32** — no 16-bit table length and no root directory area — which is what Linux's own reader goes by, and the cluster count decides only between FAT12 and FAT16.
- **A file system may say more clusters than its own table reaches**, and is then read as far as the table does, as Linux reads one: the count is clamped to what a table of that many sectors can hold.
- **The root directory is two different things.** FAT12 and FAT16 keep it in an area between the tables and the data, as many 32-byte records as the boot sector says. FAT32 keeps it in a chain of clusters like any other directory, starting at the cluster the boot sector names.
- **A table entry of 0 is a cluster nothing was written to, and the highest values say a chain ends** (`0xFF8`, `0xFFF8`, `0x0FFFFFF8` and above). The one below those is a cluster the file system marks as not to be used, and a chain going through it is refused rather than read as what happens to lie there.
- **A chain cannot be longer than there are clusters**, which is how one that leads back into itself is told: by its length, not by keeping every cluster it has been through, which for a file of millions of clusters would cost more than the data.
- **Where the copies of the table are not kept alike, the one the file system names is read.** FAT32's flags say whether the copies are mirrored and, where they are not, which single copy is the live one.
- **A long name belongs to a file only where its checksum says so.** The records of a long name lie in front of the file's own record, in reverse order, each carrying a checksum of the 8.3 name. Where a record is missing, out of order, or carries another name's checksum, the long name is dropped and the 8.3 name is the name — which is what a tool left behind when it wrote over the record after a long name.
- **`.` and `..` are not entries.** They are what a file system finds its way about with; giving them out would walk a directory into its own parent for ever.
- **A name's bytes above ASCII are code page 437**: the one every IBM PC had, and the one Linux reads a FAT file system in unless it is told another (`CONFIG_FAT_DEFAULT_CODEPAGE=437`). Nothing in the file system says which code page was meant, and a name of anything but ASCII carries a long name beside it in every file system written since VFAT, so this only shows in an 8.3 name from before them.
- **A name written in one case is shown in it.** The byte Windows NT took for itself says whether the base and the kind were written in lower case, which is what makes `readme.txt` read as it was written rather than as `README.TXT`.
- **A time has no time zone.** MS-DOS wrote the clock as the computer read it, and nothing in the file system says where that was. `Time` gives the parts; `Time::unix` reads them as UTC, which is what Linux does with `tz=UTC`, and says so.
- **A file longer than its chain fails.** What the record says and what the file system holds can disagree; the bytes that are not there are not answered as zeroes.
- **Nothing is cached.** A table entry is four bytes, read when it is wanted, and a chain is read once before the data it names. The `Disk` underneath may cache as it likes.
- **exFAT is told apart and named.** It carries the same signature and the same jump, says its name where the one that made the file system goes, and leaves every field FAT's numbers are in zero; a reader that went on would make a file system up out of zeroes.

## What it refuses

Each of these would otherwise be read as a tree that is not on the disk:

- A boot sector with no signature, or no jump where one has to be: `Unrecognized`. NTFS has both, and says a layout no FAT has, so it comes out as `Says`.
- exFAT: `ExFat`.
- A sector size the format has not got (not 512, 1024, 2048 or 4096), a cluster of no sectors or of a number that is not a power of two, no room before the table, no table, a table of no sectors, no root directory where one is needed, a file system longer than the disk it is on, or one with no data clusters: `Says`.
- A chain that leads out of the file system, back into itself, or through a cluster marked as not to be used: `Chain { at }`.
- A directory of more entries than are read, or more bytes than are read: `TooMany`. Directories inside directories past 1024 deep: `TooDeep`.

## How it is checked

`crates/hivepack/tests/fat.rs`, in two halves.

- **Against `vvfat`, which is QEMU's own way of making a FAT file system out of a folder.** A folder of short names and long, a name of more than ASCII, a file of several clusters, one of none and a folder inside a folder, converted by `qemu-img convert -f vvfat -O raw` and read back: every path and every file's bytes compared with what went in, read in pieces of 3571 bytes so that no read lines up with a cluster. As a floppy, which is a bare FAT12 file system, and as a disk, which is a master boot record with FAT16 in its one partition — the layering of the two modules, end to end.

  **`fat:32:` is no oracle.** QEMU says as much when it writes one ("FAT32 has not been tested. You are welcome to do so!"): what it writes is a FAT16 boot sector whose root directory names cluster 1, which no file system has, and `fsck.fat` finds long names of nothing in it. So FAT32 is checked by `mkfs.fat` and by hand instead, and a record naming cluster 1 is one of the things refused.
- **Against `mkfs.fat`**, which is what every Linux tool makes: each of the three kinds, with sector sizes of 512, 1024 and 4096 and clusters of 1 to 8 sectors, each read for its kind, its label, its cluster size and its empty root. And the small FAT32 above, where the specification's own rule gets the kind wrong.
- **File systems built byte by byte**, which is what CI checks the reader against where no tool is installed — and **`fsck.fat` is run over each one that is meant to be sound**, so that a test passing is not the reader agreeing with its own mistake. It caught two mistakes in the test's own builder: a table written four bytes to an entry in a file system of 64 clusters, which is FAT12 however it was written (the builder now refuses to build a kind its cluster count is not), and a `..` record naming the root's cluster where the format says it names cluster 0.

  A FAT32 whose root directory is longer than the start of it that the label is looked for in is built too, which is what found a defect of the reader's own: finding the label read the directory through its chain with a limit, so a root of more than 32 KiB — a few hundred files — made **opening the file system fail altogether**. Only the start of the root is read for the label now, and the boot sector's own copy answers where a file system keeps it further in.

  Each of FAT12, FAT16 and FAT32 is built with one of everything: a short name, a name written in one case, a long name over a chain whose clusters do not follow one another, a name of more than ASCII, a file of no bytes, a record whose file was deleted, a folder with the two records a file system needs and a file in it, and the label as a record of the root. Then: a long name whose checksum is another file's; bytes above ASCII; a chain that leads back into itself; a cluster marked as not to be used; a record naming cluster 1; a folder that leads back into itself; exFAT; files that are not file systems; ten layouts the format has not got; a file longer than its chain; reads in pieces of 1, 7, 511, 512, 513, 1024, 5000 and 8192 bytes with seeks from the start, from where it is and from the end; and the whole of it again inside a partition of a card.
