# exFAT: the file system every large card is formatted with

`hivepack::exfat` reads exFAT, read-only. It is the file system of a memory card larger than 32 GB — the size where Windows stops offering FAT32 — so every large SD card, camera card and USB stick sold formatted holds one, and a `card.img` of one is what reading it is for. The layers under it are [`hivepack::image`](image.md) for the disk and its partitions; the file systems beside it are [`fat`](fat.md), [`ext`](ext.md) and [`ntfs`](ntfs.md).

**It is not a port.** The layout is Microsoft's *exFAT file system specification*, published in 2019 under its Open Specification Promise — the one file system here whose owner published it. Linux's own driver is GPL-2.0 and nothing here needed it; the repository's MIT license covers the module.

It reads a [`Disk`](image.md), so a partition of a card is read by handing it `Part::new(&disk, part.at, part.size)`, and a file holding a volume as it is — what `mkfs.exfat` writes into one — by handing it the file.

## It is not FAT with larger numbers

The name says otherwise, and so does the boot sector's signature, but almost nothing inside is the same:

| | FAT | exFAT |
|---|---|---|
| A file is | one 32-byte record, with records of a long name in front of it | a **set** of entries: a file entry, a stream entry, and one entry per 15 characters of the name |
| Is the set checked | a long name is tied to its record by a checksum of the 8.3 name | the whole set carries a 16-bit checksum of itself |
| Names | 8.3 in a code page, with UTF-16 long names beside them | UTF-16 only, up to 255 characters, no second name |
| A file written in one piece | is still a chain in the table | **says so, and the table holds nothing for it at all** |
| How much of a file is written | not kept: the length is the length | kept beside it (`ValidDataLength`), and the rest is room |
| Times | a local time of nowhere in particular | each carries the offset from UTC where it was written |
| `.` and `..` | records of every directory | **not kept at all** |
| Where the label is | a record of the root, and a copy in the boot sector | a record of the root, and nowhere else |
| What checks the volume's start | nothing | a checksum over the first eleven sectors, with a backup region behind it |

## What it gives

- **`Exfat::open(disk)`**, and then `label`, `cluster_size`, `sector_size`, `clusters`, `serial`, `dirty`, `media_failure` and `from_backup`.
- **`read_root`** and **`read_dir(&entry)`**: the entries of a directory in the order it holds them.
- **`lookup_path`**: by name, without regard to case.
- **`file(&entry)`**: `io::Read` and `io::Seek` over the data.
- **`walk`**: every file and directory with the path to it, depth first.

## The rules it follows

- **The boot region carries a checksum, and the backup region is read where it fails.** The checksum is over every byte of the first eleven sectors but the three that change while a volume is mounted — the volume flags and how full it is — and the twelfth sector holds it over and over. A volume whose first region fails it has had its start overwritten, most often by a partition table written over the volume, and the copy at sector 12 is what a tool repairs it from: hivepack reads that copy and says so (`from_backup`). Where neither passes, the answer is `Error::Checksum` and no layout is guessed at.

  The backup is looked for at sector 12 of **each sector size the format allows, largest first**, because the number saying what a sector is was in the region that just failed. A region found there is taken only where it says the same size it was found at; a smaller guess would otherwise find the backup of a volume of larger sectors somewhere inside its own boot code.
- **What tells exFAT from FAT is the 53 bytes FAT keeps its numbers in.** Both end with `0x55AA`, both begin with a jump, and exFAT writes `EXFAT   ` where the tool that made a FAT file system writes its own name. The specification says those 53 bytes are zero in an exFAT volume — and a FAT file system cannot have them all zero, since it would have no sector size, no sectors per cluster and no reserved sectors. A boot sector that says `EXFAT   ` **and** keeps FAT's numbers is neither, and is read as neither.
- **A set of entries that fails its own checksum is not read.** The name, the length and the first cluster would all come out of bytes that cannot be trusted, so the directory holding it fails rather than handing back a file built from them. This is the one integrity check the format has for a file, and `fsck.exfat` checks the same thing.
- **A name is one name, not a path.** exFAT's own rules leave out every character a path is made of; a name holding `/`, `\` or a NUL did not come from anything that writes file systems, and extraction refuses it (`NameError::Separator`).
- **A file written in one piece says so, and the table is not asked.** The stream entry's second flag (`NoFatChain`) means the clusters are the run that begins where the file begins — one of the two reasons exFAT is faster than FAT on a large card. The reader follows the run, and the table only where that flag is clear.
- **Past what has ever been written, a file reads as zeroes.** exFAT keeps a file's length and, beside it, how much of it has been written. The clusters past the second hold whatever was in them before — somebody else's deleted data, as the file system never cleared them — so the file is as long as it says and the rest of it is zeroes. This is what every driver does, and the one place where reading the disk honestly would be wrong.
- **A chain cannot be longer than there are clusters**, which is how one that leads back into itself is told: by its length, not by keeping every cluster it has been through, which for a file of millions of clusters would cost more than the data. `0xFFFFFFF7` is a cluster the volume marks as not to be used, and a chain through it is refused rather than read as what happens to lie there.
- **The active table is the one the volume names.** A volume written for TexFAT keeps two; the first volume flag says which is live, and that is the one read.
- **There are no `.` and `..` entries to leave out**, so a directory holds what is in it and nothing that leads back out.
- **A directory in one run has no length of its own**, so it is read until its first unused entry, bounded by the 16 MiB a directory is read to at all.
- **The entries that are not files are passed by**: the allocation bitmap, the upcase table, the volume's GUID, and whatever a later version adds. Each is one entry and says nothing about a file.
- **The upcase table is not read, and case folding is Rust's own.** The table matters to a writer, which has to fold a name the volume's way before hashing it; nothing hivepack reads depends on it, and the two differ only for characters whose case changed between Unicode versions. The name hash in each stream entry is not checked for the same reason — checking it would mean reading the table.
- **A volume left dirty, or marked as having a sector that cannot be used, is read as it is** (`dirty`, `media_failure`). What was being written when the volume was lost may be a length without the bytes; where the damage is, reading fails and says so. Refusing the whole volume would refuse the files that are there.

## What a reader should know

- **The timestamps are MS-DOS's, with a zone bolted on.** The date and time fields are FAT's, to two seconds; a tenths field carries the odd second and hundredths; and an offset field holds minutes from UTC in 15-minute steps, as a seven-bit two's complement count, with its top bit saying whether it holds an offset at all. So `+05:45` (Nepal) comes out, and a volume written by a tool that left the field alone reads with no offset, which is then read as UTC as FAT's times are.
- **The cluster heap is numbered from 2.** Clusters 0 and 1 are not clusters; their numbers are kept for the table's own first two entries.
- **A cluster is at most 32 MiB**, which is what the two shifts together allow (`BytesPerSectorShift` 9 to 12, and their sum no more than 25).
- **An entry's in-use bit is in its type byte.** A deleted file keeps its entries with that bit cleared, and the set is still as long as it was: it is stepped over whole, so the name entries of a deleted file are not read as entries of their own.

## How it is checked

`crates/hivepack/tests/exfat.rs` reads volumes, `crates/hivepack/tests/extract_exfat.rs` extracts them, and `crates/hivepack/tests/exfat_support/mod.rs` builds them — two ways, because neither is enough on its own.

- **Volumes `mkfs.exfat` wrote, with files put in by hand, and `fsck.exfat` run over the result.** Nothing can mount exFAT without root, so the files are written by the test: entry sets with their checksums, the name hashes folded through **the volume's own upcase table**, the allocation bitmap marked, and the table chained where a file is not one run. `fsck.exfat` is then run, and what hivepack reads is a volume the format's own tool calls clean — a better check than anything the test could assert for itself. What is read back: the names, the lengths, every byte, a file over more than one cluster, a file whose clusters are not a run, a directory inside the volume, a name of more than ASCII, lookups without regard to case, the whole tree walked, and the times with their offset from UTC.
- **That the oracle would notice.** The same volume with one byte of a set's checksum turned over: `fsck.exfat` refuses it, and so does hivepack (`Error::SetChecksum`). Without this test, a `fsck.exfat` that rubber-stamped anything would make every test above say nothing.
- **The label `mkfs.exfat -L` wrote**, read back by hivepack and by `exfatlabel`, which is where exFAT keeps it and FAT does not.
- **Volumes built byte by byte**, so the reader is checked where no tool is installed, and because no tool writes a volume that says something impossible: a file cut over two clusters that are not next to each other; the backup boot region read where the first is overwritten; both regions failing; a boot sector that says `EXFAT   ` and keeps FAT's numbers; sector sizes no disk has; a cluster past 32 MiB; two tables where there is room for one; a table over the boot regions; a table too short for the clusters; no clusters at all; a root directory that is not a cluster of the volume; a chain that leads back into itself; and reading a file as a directory and a directory as a file.
- **Extraction**, out of a real volume and out of built ones: the tree as it went in; the room a file never filled coming out as zeroes rather than as what the clusters hold; a name with `/` or `\` landing nowhere; a folder whose entries name a folder already walked into refused (`DirectoryAgain`); a set whose checksum is wrong stopping its directory with nothing written; and the bitmap, upcase and label entries of a real volume coming out as nothing at all.
- **Where `HIVEPACK_EXFAT_REQUIRED` holds a value, a missing tool fails the test** rather than printing why it skipped. CI gives it one on the job that installs exfatprogs: without it a test that found no tools and a test that read a volume both pass, and `cargo test` hides the printed reason for a test that passes, so the suite could say nothing and look exactly the same.
- **A fuzz target, `exfat`**, which opens any input as a volume, walks it whole, reads every file and looks up every path, twice in pieces of different sizes, and compares: what a file holds does not depend on how it was asked for. Seeded with a real volume, it ran here for 241 seconds and 476,856 inputs with no crash.

## What is not read

- **Writing**, of any kind.
- **TexFAT's second table** beyond knowing which one is live, and the transaction state a TexFAT volume keeps.
- **The allocation bitmap**, which says which clusters are free: only writing needs it. A file's own clusters are where its entry says, and whether the bitmap agrees is `fsck.exfat`'s business.
- **The upcase table**, as above.
- **Extended attributes, permissions, owners and links**, none of which exFAT has. What extraction gives a file is `Options::permissions`.
