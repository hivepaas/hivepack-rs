# Disk images: the disk, and its partitions

`hivepack::image` reads what a disk image holds: the block device in it, and the partitions the table at its start names. It is the layer every other part of a disk image stands on, and it is **not a port** — there is no library behind a partition table. A master boot record's layout is the one every system has agreed on since MS-DOS, and a GUID partition table's is the UEFI specification's (version 2.10, §5.3, "GPT Disk Layout"). The repository's own MIT license covers the module, which is why it has no `LICENSE` of its own, unlike the ports beside it.

What is **not** here yet, and the order it comes in, is in [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225): the containers that keep a disk in less room than it is long (VHD, QCOW2, VHDX, VMDK, each ported from QEMU's block driver for it), and then the file systems a partition holds (FAT, ext2/3/4, NTFS). On its own, this module reads a raw image — an `.img`, a `.bin`, a `dd` of a card — and says where each partition is.

## What it gives

- **A `Disk`** is a size and reads at offsets, never a position, so one disk can be read from several threads, as the file systems inside it will be. `std::fs::File`, `[u8]` and `Vec<u8>` are disks; a container will be one over another.
- **`partitions(&disk)`** answers with the table, the sector size its numbers are counted in, and the partitions in the order the table holds them — or with **none**, for a disk that has no table at all. A file system written straight to a disk has none, and so has a file that is not a disk image: that is not an error.
- **`partitions_in(&disk, sector)`** is the same, in sectors the caller gives: 512 or more, a power of two.
- **`Part`** is one partition as a disk of its own. What reads the file system in it sees nothing of the disk before it and nothing past its end.

## The rules it follows

- **A GUID partition table is read before a master boot record**, because a disk that has one keeps a master boot record in front of it that says so (one partition of type `0xEE` over the whole disk). A table is looked for at the second sector for both sector sizes a disk has, 512 bytes and 4096.
- **Both of a GUID partition table's copies carry a CRC-32**, over the header and over the array of entries, and both are checked. Where the one at the disk's start fails, the copy at its end is read instead; where both fail, the answer says so and no partitions are made up. The check is what tells a table from bytes that happen to start with `EFI PART`.
- **A disk that says it has a GUID partition table and has none fails.** Reading its protective master boot record as a table of its own would answer with one partition over the whole disk, which is not what is on it.
- **The last sector of a GUID partition table's entry is its own**, not the one after it, so a partition of sectors 2048 to 6143 is 4096 sectors long.
- **An entry of all zeroes is no partition**, and the numbers count over it: a GUID partition table's partitions are numbered as the systems that name them do, 1 upwards by the entry's place in the array, and a master boot record's are 1 to 4 for its own entries and from 5 for the logical ones.
- **An extended partition is not a partition anything is in.** Its entry starts a chain of extended boot records, each of which says where its own partition's data is, counted from that record, and where the next record is, counted from the extended partition. The chain is followed at most 128 steps, and a record already seen ends it with an error, so a chain that leads back into itself cannot be read for ever.
- **A partition that reaches past the end of the disk fails**, with its number, rather than being given to something that would then read nothing.
- **A GUID partition table says what a sector is; a master boot record cannot.** The table's header is looked for in the second sector of each size a disk has, 512 bytes and 4096, so where it was found says which the disk's are. A master boot record holds nothing that says it, and its own numbers cannot tell: counted in a smaller sector they come out smaller, so they fit the disk either way and only point at the wrong place. It is read in 512-byte sectors, which is what every tool reading an image file does and what every disk sold with one counts in.

  A disk whose sectors are its own is read by `partitions_in(&disk, sector)`, for a caller that knows the size from somewhere else. That somewhere is the container: VHDX records the logical sector size, VHD's geometry is in 512-byte sectors, and QCOW2 says nothing — so this is the hook the containers will hang on when they arrive.
- **What a partition holds is what the table says it holds, which is not what is in it.** `Kind::says` names the types met on a disk anyone opens, and answers nothing for the rest; what is in a partition is told by reading it.

## How it is checked

`crates/hivepack/tests/image_partitions.rs`.

- **Tables built byte by byte**, with their CRC-32s computed as a tool computes them: a master boot record of two partitions; an extended partition holding two logical ones, numbered 5 and 6; a chain that leads back into itself; a GUID partition table whose names are UTF-16 and not all ASCII; a damaged primary header, where the copy at the end gives the same answer; both copies damaged; entries that fail their check; a partition past the end of the disk; a protective record with no table behind it; a GUID partition table counted in 4096-byte sectors; a master boot record read both as every tool reads one and in the sectors `partitions_in` is told, with the sector sizes no disk has refused; and files that have no table at all.
- **Tables util-linux wrote**, where `sfdisk` is installed: the same two layouts, in a 16 MiB image, read back and compared with what was asked for — the partitions' places, sizes, types, names and bootable flags. Where it is not installed, the test says so and passes; the tables built by hand are what CI checks.

## What a reader should know

- A GUID partition table's entry size is not always 128 bytes: the specification allows more, and the array is read in entries of the size the header gives.
- A name is UTF-16, little-endian, to the first NUL. An empty name is none, not an empty string.
- `Partition::id` is a GUID partition table's unique GUID for the partition, written as every system writes one (the first three fields with their bytes the other way about, as they are on the disk). A master boot record has none.
- `bootable` is an entry's active flag in a master boot record, and the legacy BIOS bootable attribute (bit 2) in a GUID partition table. Neither says anything about what boots on a system that uses the other.
