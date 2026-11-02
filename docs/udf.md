# Porting NetBSD's UDF file system

`hivepack::udf` reads UDF volumes in safe Rust: DVD and Blu-ray images, Windows' installation images, packet-written CDs and DVDs, and disks formatted with UDF. It is a port of the reading half of NetBSD's UDF file system (`sys/fs/udf`), by Reinoud Zandijk, under the BSD-2-Clause license. NetBSD's is the most complete UDF reader under a permissive license: UDF 1.02 to 2.60, on physical, sparable, virtual (VAT) and metadata partitions.

[hivepack::iso](iso.md) reads the ISO 9660 side of an image that has both ("UDF bridge").

## The source

The port follows `sys/fs/udf` of NetBSD's netbsd-11 branch at commit `83fb854bf81a` (2026-10-29), which `hivepack::udf::UPSTREAM_COMMIT` names, and `clock_ymdhms_to_secs` of `sys/dev/clock_subr.c`. As in the other ports ([porting.md](porting.md)), each C file is a module, functions keep their names, and each doc comment names its C original. Only what reads is ported: NetBSD's UDF also writes.

| NetBSD | Port | What |
|---|---|---|
| `ecma167-udf.h` | `ecma167_udf.rs` | the descriptors' fields, as offsets |
| `udf.h` | `udf.rs` (`UdfMount`, `UdfNode`, `Device`) | the mount, the node, and the image read in sectors |
| `udf_vfsops.c` | `udf_vfsops.rs` | `udf_mountfs`: the order the volume is read in |
| `udf_subr.c` | `udf_subr.rs` | tags, anchors, the volume descriptor sequence, the logical volume integrity, the VAT, sparing tables, the metadata files, the file set, nodes (`udf_loadvnode`), FIDs, names, times, permissions, extended attributes, reading a file's blocks |
| `udf_allocation.c` | `udf_allocation.rs` | logical blocks to sectors through the partition maps (`udf_translate_vtop`), a file's extents (`udf_translate_file_extent`), allocation descriptors and their extents (`udf_get_adslot`) |
| `udf_readwrite.c`, `udf_strat_direct.c`, `udf_strat_rmw.c` | `udf_readwrite.rs` | descriptors from sectors, and nodes' descriptors as the disc strategies read them |
| `udf_vnops.c` | `udf_vnops.rs` | `udf_readdir`, `udf_lookup_name_in_dir`, `udf_getattr`, `udf_do_readlink` |
| `udf_osta.c` | `udf_osta.rs` | the OSTA specification's routines: CS0, the descriptors' CRC, `UDFTransName` for UNIX |
| `clock_subr.c` | `clock_subr.rs` | dates to seconds |

The API is the kernel's, as a library: `Udf::open` mounts (`udf_mountfs`), `node` gets a node from a directory entry's ICB (`udf_get_node`), `read_dir` lists a directory (`udf_readdir`), `lookup`, `stat` (`udf_getattr`), `read_link` and `read_at` (`udf_read`). `Options` holds the mount arguments NetBSD takes (`gmtoff`, `anon_uid`, `anon_gid`) and what is not in NetBSD. `check_data`, not in NetBSD either, tells whether all of a file's data reads without reading it, for [extract.md](extract.md)'s `extract_udf`, which checks every file before writing; [open.md](open.md) tells a UDF volume by its volume recognition sequence.

The image is read as NetBSD reads a disc partition or a file through vnd(4): one track, from sector 0 to the last whole sector, with the anchors at 256, at the end less 256, at the end, and at 512. The disc information of an optical drive (sessions, tracks, write-once state) is not there, so sessions other than the last are not read.

## What differs

Where NetBSD would loop for good, crash, or read past its buffers, the port has a bound or an error, and where NetBSD's reading is wrong by the UDF specification and Linux reads the right thing, the port reads it as Linux does:

- **The sector size is found.** NetBSD takes the device's, which must be the volume's block size. The port tries 2048, 512, 1024 and 4096 bytes (`SECTOR_SIZES`), or the size `Options::sector_size` gives.
- **A volume that was not closed is read.** NetBSD refuses one whose logical volume integrity is open (EPERM, "please fsck"); the port reads it, `Volume::closed` says so, and `Options::strict` refuses it.
- **A strategy 4096 chain ends at a terminator.** NetBSD says the chain of a node recorded with strategy 4096 ends at a blank block or a terminator, but only ends it at a blank block; mkudffs ends it with a terminal entry, and NetBSD then fails. The port ends it at a terminal entry or a terminating descriptor too, as Linux does.
- **Other strategies than 4 and 4096 are an error**, as in Linux, where NetBSD reads the same block again for good.
- **A file entry longer than a block is an error.** NetBSD only asserts that it is not, then reads its first block.
- **A blank block where a node should be** is read as NetBSD's read-modify-write strategy reads it (no node); its direct strategy copies from a null pointer.
- **Data recorded in a node is bounded** by the node: NetBSD copies `inf_len` bytes after `l_ea` whatever they are.
- **The VAT's allocation descriptors are on the physical partition.** NetBSD reads the VAT's node from the raw device, and its short allocation descriptors then as sectors, not as blocks of the partition the virtual one is on, as NetBSD records them: a VAT too long for its node, on a partition not at sector 0, reads wrong. The port reads them on the physical partition, as Linux does.
- **A sparing table's entries are the first block of their packet** [UDF 2.01, 2.2.11]. NetBSD compares them with the packet's number (the block divided by the packet's length), and so reads the remapped packets from where they were. The port compares them with the packet's first block, as Linux does.
- **A device's numbers are read where they are.** NetBSD adds the offset of the device specification to a pointer to that attribute, which moves it by as many attributes.
- **Times have 64 bits, and go before 1970.** NetBSD keeps seconds in 32 bits and gives -1 for a year before 1970; the port's seconds are an `i64`, and dates before 1970 are what they are, as in Linux.
- **A surrogate pair in a name is one character**, of four bytes in UTF-8, as Linux writes it. NetBSD writes each half on its own (CESU-8). A lone half is written on its own, as NetBSD does.
- **Bounds where NetBSD has none:** a volume descriptor, integrity or file set sequence of at most 1,024 descriptors (NetBSD loops on a length that is not a multiple of theirs); a descriptor of at most 1 MiB; the VAT searched for back to the start of the track, once (NetBSD's sector numbers wrap there, and it goes on); a translation through the metadata partition at most 4 times over (its metadata file can map on itself); an extent of no blocks at the end of its partition, and a sparable partition of packets of no blocks, are errors (NetBSD loops, or divides by zero); a symbolic link of at most 64 KiB (NetBSD's buffer); and what the C reads past a buffer reads as zeros.
- **Extended allocation descriptors** (an ICB's allocation type 2), which NetBSD does not read, give no extents: NetBSD goes on with a descriptor it never set.
- **Reading does not change the access time.** NetBSD notes the access on a volume mounted read-only too.
- **Not in NetBSD:** `Options::unhide` lists hidden entries, as Linux's `unhide` option does; `Options::mount_point` is the mount point NetBSD puts in front of a symbolic link that starts at it.
- **`lookup` compares the name as given** with the entries' names, and finds the first entry of the directory with it. NetBSD first takes the name to UCS-2, CS0 and back, and takes the hits of its hash table in their order.

What NetBSD does that a reader may not expect is kept: the tags' locations and the volume recognition sequence are not checked; the last descriptor of each kind in the volume descriptor sequence is the one, whatever its sequence number; the integrity sequence's next extent is not followed (NetBSD only follows it when it still has the descriptor it has just let go of); a partition reference past the partition maps reads the raw device (its type, 0, is also the raw one's); the metadata file is read with the physical partition's index as a logical partition; `..` is an entry; names are translated by the OSTA specification's `UDFTransName` for UNIX (a slash, NUL or an unprintable character becomes `_`, and the name then ends with `#` and its CRC, before an extension of up to five characters), at most 255 characters, at most 511 bytes of UTF-8; names in a character set other than OSTA's are their bytes; a device without its device specification has no permissions; a directory has one link more than it records.

## Where Linux reads otherwise

The tests compare with Linux, which reads some things otherwise:

- Linux checks the tags' locations, the volume recognition sequence, and more of the descriptors' fields.
- Linux keeps control characters in names, which `UDFTransName` replaces, and takes the CRC of an 8-bit name's bytes, where `UDFTransName` takes it of its characters in 16 bits.
- Linux drops the `/` a link's target ends with: a link to `..` is `..`, where NetBSD gives `../`.
- Linux does not mount mkudffs's UDF 1.50 CD-R (`testdata/udf/mkudffs-cdr-0150`): its VAT is in its node, after an extended attribute, which Linux reads as the table.

macOS's `hdiutil makehybrid -udf` records a symbolic link's target as its text, not as path components; NetBSD, and the port, fail to read it (EINVAL), and give its size as recorded.

## Bounded resources

A node and each of its allocation extents are a block; a node has at most 50 allocation extents, and a chain of indirect entries at most 1,024, as in NetBSD. The VAT is read whole, as NetBSD reads it, and the metadata file's node is kept: both only as large as the image has them. A file's data is read 64 KiB at a time, as NetBSD's buffers are, and a directory a block at a time, the last four kept.

## How it is shown

- **Unit tests** for the OSTA routines (the CRC of the specification's example, CS0, `UDFTransName` with illegal characters, extensions and long names) and for dates before 1970 and after 2100.
- **`tests/linux.rs`**: what Linux's udf file system reads of 27 images, the port must read the same. `tools/udf-images/make.sh`, run as root in a Linux with the udf module (in Docker on macOS), makes them with mkudffs (udftools 2.3) and genisoimage, fills them through Linux's udf file system where Linux writes (UDF up to 2.01, not on a VAT), and records what Linux reads of each mounted, with `tools/udf-images/answer.py`: for every entry, its type, permissions, owner, group, links, size, three times in nanoseconds, link target or device numbers, and the SHA-256 of its data. The images: hard disk media at UDF 1.02, 1.50, 2.00 and 2.01, with blocks of 512, 1024, 2048 and 4096 bytes, file entries or extended ones, short, long and in-ICB allocation descriptors, strategy 4096, and unallocated space tables; CD-RW and DVD-RW (sparable partitions), DVD-RAM; CD-R, DVD-R and BD-R with a VAT, at UDF 1.50 to 2.60, closed or not; and genisoimage's UDF beside ISO 9660. What fills them: files empty to 5 MB, a file with a hole, 300 files in a directory, names in Latin-1, Chinese, emoji, 250 characters long and with every character Windows refuses, symbolic links of every kind, a hard link, a FIFO, devices, setuid, setgid and sticky permissions, owners, and times from 1969 to 2099 with nanoseconds. The images are in `testdata/udf`, compressed with xz, with Linux's answers.
- **`tests/crafted.rs`**: what Linux reads of 9 images `tests/support/image.rs` writes, of what mkudffs and Linux do not record: metadata partitions (UDF 2.50 and 2.60) with their files, files on a VAT in its node and in blocks of its own, a sparable partition with a remapped packet, file entries and extended ones, blocks of 512, 2048 and 4096 bytes, an open integrity, allocation extents, strategy 4096 with indirect entries, files with holes and extents allocated but not recorded, data in the node, hidden and deleted entries, FIDs with implementation use, names in 8 and 16 bits, every path component of a link. `tools/udf-images/crafted.sh` records the answers, in `testdata/udf/crafted`, each with the SHA-256 of the image it is of, which the test checks.
- **`tests/edge.rs`**: what NetBSD does where Linux is no oracle, and `check_data`, which must fail where reading a file fails, on an image cut at each of its sectors past the anchor: no anchor, a domain that is not OSTA's, a broken main volume descriptor sequence read from its reserve, an unsupported strategy, an open integrity with `Options::strict`, reading a directory or a link as a file, hidden entries, a broken FID in a directory (the entries before it, then EIO, and looking up fails); and 600 images damaged at random, mounted and walked, without a panic.
- **Extraction**, in [extract.md](extract.md): six of `testdata/udf`'s volumes extract as Linux reads them, every file's SHA-256 the same.
- **Fuzzing**: the `udf` target mounts and walks any image the input describes sparsely (its sectors by number), twice: the same transcript both times, the names it looks up found, and no panic. In 1.4 million inputs it found one overflow, in `udf_tagsize`'s arithmetic, fixed. CI seeds it with the descriptors of `testdata/udf`'s images.
