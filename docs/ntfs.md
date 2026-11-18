# NTFS: the file system Windows writes

`hivepack::ntfs` reads NTFS, read-only. It is the third and last file system of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225), after [`fat`](fat.md) and [`ext`](ext.md): a container holds a disk, the disk's table names partitions ([`hivepack::image`](../crates/hivepack/src/image)), and a partition holds a file system. This is the one on the other side of every dual-boot machine, and on every external drive somebody plugged into Windows once.

It reads a [`Disk`](image.md), so a partition of an image is read by handing it `Part::new(&disk, part.at, part.size)`, and a file holding a file system as it is — what `mkntfs` writes into one — by handing it the file.

## It is not a port: it is a dependency

Every other format in this repository is read by code that is here. NTFS is not, and the reason is not technical:

- Microsoft has published no specification for NTFS. What is known of it is reverse engineering.
- The two complete readers are GPL-2.0 — ntfs-3g and the kernel's ntfs3. A port of either would put that license on this module and so on everybody who links hivepack.
- Colin Finck's [`ntfs`](https://crates.io/crates/ntfs) crate is MIT or Apache-2.0, `#![forbid(unsafe_code)]`, and reads the structures. 7355 lines, 4888 of them code — more than any single reader in this repository.

So the structures are read by that crate, and this module is the layer around it: the disk as the stream it wants, its answers as this crate's entries and byte streams, this crate's limits on top of its own, and **a refusal for every kind of data it does not actually read**.

The license question, which is what blocked NTFS until now, is settled and was checked rather than assumed: `cargo-deny check` with this repository's own `deny.toml` over the whole tree the dependency brings in — 14 crates and their proc macros — gives `licenses ok, advisories ok, bans ok, sources ok`. `bans` warns about three versions of `syn` in one tree, which this repository's policy warns about rather than refusing. The MSRV is 1.60 as released and 1.83 on the crate's `master`, both under this repository's 1.89.

## What it gives

- **`Ntfs::open(disk)`**, and then `label`, `cluster_size` and `size`.
- **`read_root`** and **`read_dir(&entry)`**: the entries of a directory.
- **`lookup_path`**: by name, without regard to case.
- **`file(&entry)`**: `io::Read` and `io::Seek` over the file's own data.
- **`streams(&entry)`** and **`stream(&entry, name)`**: the alternate data streams beside it, which are named `$DATA` attributes of the same record.
- **`walk`**: every file and directory with the path to it, depth first.

## What the library does, measured

Not read about. A 96 MiB file system built by `mkntfs`, filled through `ntfs-3g` with 2013 files, and read back by the crate, every file's md5 against `md5sum` of what went in:

- **2013 of 2013 names found.** None missing, none invented.
- **2012 of 2013 contents byte for byte.** Alternate data streams, sparse files, a hard link, a directory of 2000 names whose index is out in its own clusters, a file in hundreds of pieces, the times and the flags: all correct.
- **The one that was wrong was the compressed file, and it was wrong in silence.** 1 220 000 bytes declared, 151 552 bytes actually on the disk, and the crate returned 1 220 000 bytes with no error at all — the raw LZNT1 stream, padded out to the declared length. Its first bytes are `70 b1`, which is an LZNT1 chunk header, where the file begins `the same line over and over`. md5 `c6648ff6…` against the real `beac2a58…`. There is no LZNT1 anywhere in the crate; `compression_unit_exponent` is declared in a struct and never read.

  `NtfsAttribute::flags()` does report `COMPRESSED`, which is why this module can refuse instead of writing files that are not the ones in the image. **That refusal is the reason this module exists rather than a thin wrapper.**

- **The library never looks at the name a boot sector carries.** `BootSector::validate` checks the two bytes at the sector's end and nothing else, so a FAT file system and a partition table both reach it. Each of three was turned away, but each for an incidental reason and not for not being NTFS: FAT12 on "the total sector count is too big to be multiplied by the sector size", FAT32 on "a record size field ... denotes -128", a master boot record with a partition table on "sectors per cluster ... 0x00". So this module checks `"NTFS    "` at offset 3 itself.

- **It panics on damaged input. Two instances were found, and the shape is wider than both.**

  **A disk shorter than its boot sector**, which is the worse of the two because it is on the `open` path: lengths of 11, 100, 256, 460 and 511 bytes carrying the name all panic, and 512 and above are refused properly. `error.rs:236`, where `impl From<binrw::error::Error> for NtfsError` ends in `unreachable!("Got a binrw error of unexpected type")` under a comment saying no attribute it uses can produce another kind. binrw wraps an `Io` error from a derived struct in `Error::Backtrace`, so the `if let Error::Io` misses. This module prevents it by knowing all 512 bytes are there before handing the disk over.

  **A damaged directory index**: `index_entry.rs:205`, a `u16` read at offset 8 of a slice that the entry's own length field has truncated below its header. About 1 in 1700 images when 32 byte flips are aimed at the boot sector and the `$MFT`. hivepack cannot prevent this one from outside the library.

  **Two found is not two there are.** Both come from the same `unreachable!`, and it sits on the `From<binrw::error::Error>` conversion that every parse in the crate goes through, under the belief that a short read cannot happen. Reading 512 bytes closes the entry point that every other layer reaches NTFS through, which is why it was worth doing first, but it does not close the class: `structured_values/attribute_list.rs:188` reads a 26-byte header with no size check before it (the check is at line 302, after the read), and the four structured values that do check compare against the *declared* length, which for a non-resident value is read through the disk and so can end early on a damaged image. So the honest statement is that this library treats a short read as impossible, and two instances of that have been found.

  The sweep: 5600 damaged images, flips aimed at the boot sector and at the first 64 KiB of `$MFT`. At 2 flips, 4836 read and 164 refused; at 8, 4373 and 627; at 32, 2868 and 2129 with 3 panics; at 128, 535 and 4461 with 4 panics. **The first version of that harness flipped bytes anywhere in the image and reported 393 of 400 reads "fine" at 64 flips, which meant only that the flips were landing in free space.** A measurement that cannot fail says nothing, however green.

  No hang was seen in 4000 rounds with this module's own entry cap taken off. Upstream's PR #41 says an entry length of zero also keeps the iterator from advancing; that was not reproduced here, so it is their claim and not a measurement of ours.

- **Upstream is alive and has published nothing since 2023-06-13.** `master` was last pushed 2026-01-14 and carries two and a half years of unreleased work, including replacing binrw with zerocopy. `validate_size` on `master` is unchanged from the released version, so both panics are still there. PR #41 fixes the index one; it was opened on 2026-11-17 by `inferius`, found the same way — fuzzing a directory listing over a mutated image — on the same day as the measurements here, and independently of them. Issue #40 asks for a release. Issue #32 records that the `$MFT` may have an attribute list, which the crate's own comment says it assumes away.

- **The released version will stop compiling.** It pins `binrw` 0.11.3, which carries two future-incompatibility lints, one of them already `E0365` ("extern crate `binrw` is private and cannot be re-exported"). `cargo` says so on every build. There is no release of the crate without binrw.

- **Not exercised, so nothing is claimed about it:** the attribute-list path, encrypted `$DATA`, Windows' overlay-filter compression ("Compact OS", which is a reparse point and another algorithm again), and reparse points generally. Nothing on Linux writes the first three, so they need a volume written by Windows.

## The rules this module follows

- **The name is checked here.** A disk whose first 512 bytes are not all there, or that does not carry `"NTFS    "` at offset 3, is `Unrecognized` before the library sees it.
- **The records the file system keeps for itself are left out.** Record 5 is the root; `$MFT`, `$Volume`, `$Bitmap` and the rest are below 16, and the root's index holds an entry for itself. A walk that gave them out would come straight back to record 5, which is how this was found: the first test run answered `Again { at: 5 }`.
- **An 8.3 name beside a long one is left out.** A file may have both, and the index holds an entry for each; the namespace says which, and `Win32AndDos` means the one name is both at once and is kept. Nothing on Linux writes DOS names, so this rule is not covered by the tests here.
- **Sizes and times come from the record, not from the index.** NTFS keeps a copy of both in each directory entry, which Windows updates when it gets round to it. The record is the one that holds.
- **Where a file's bytes are is read once, when the file is opened**, and reading then goes straight to the `Disk`. So a `File` holds nothing of the file system and no borrow of the library, and reading is not quadratic in how fragmented the file is.
- **A hole reads as the zeroes it stands for.** A sparse run names no clusters, and the disk is not touched for it.
- **Two names of one file say one record.** `Entry::record` is what tells a hard link from a copy.
- **Nothing is cached**, and reads are at offsets, so one file system can be read from more than one thread. The `Disk` underneath may cache as it likes.
- **The library's own refusals are kept as text**, not as its error type, so which library reads NTFS stays an answer this crate can change.

## What it refuses

- No boot sector, or one whose name is not NTFS: `Unrecognized`.
- What the library turns away: `Says`, carrying its message.
- Compressed data: `Compressed`. Encrypted data: `Encrypted`. A reparse point, whose content is not its own data: `Reparse`.
- Data described by an attribute list: `AttributeList`.
- Runs that do not cover the length the file says: `Short { says, covers }`.
- A directory of more than 2^20 entries, or a file of more than 2^20 runs: `TooMany`. Directories inside directories past 1024 deep: `TooDeep`. A directory leading back to one already walked into: `Again { at }`.

## Taking the files out

With `extract` as well, `extract_ntfs` writes a volume's tree into a folder, or `extract_ntfs_to` into a `Sink`, under the same rules every other extractor here follows: [extract.md](extract.md) has the section. What NTFS keeps that cannot come out whole is refused and not approximated — compressed data above all, where the library answers with the compressed bytes and no error — so a file either comes out as it is in the image or does not come out at all. The streams beside a file are left where they are, and the security descriptor is not turned into a Unix owner or mode.

One thing the extraction found that reading alone did not: **which of two names of one record holds the bytes is the directory's order.** The first name met is the file and the second is a hard link to it, and an NTFS index is sorted, so for `hardlink.txt` beside `plain.txt` it is `hardlink.txt` that is written and `plain.txt` that points at it. Nothing in the format makes it the other way round, so the test asks for the pair rather than for a direction.

## Being told at all

`hivepack::open` tells an NTFS file system with no partition table in front of it as `Container::Ntfs` — a Windows partition taken out on its own, or what a `.vhdx` holds once the table has been read — and it tells it **whether or not the crate was built with `ntfs`**. Naming what a file is does not take the reader, and answering "data" about a Windows volume would be worse than naming it and letting the caller find that this build cannot read it.

So the rules are written again in `open/detect.rs`, as FAT's and ext's are, since `open` does not take those readers. `detect` asks for more than this module does: the name at offset 3 (which is the whole of what `Ntfs::open` adds to the library's own check), the fields NTFS leaves zero where FAT keeps its numbers — reserved sectors, tables, root entries, the 16-bit sector count, the table size — and the two NTFS fills instead, how long the volume is and where `$MFT` begins. **What is told is narrower than what this module opens, not wider**, so everything told as NTFS, `Ntfs::open` opens.

FAT and NTFS begin alike: the same jump, the same two bytes at 510. `is_fat` already refused an NTFS boot sector for having no reserved count and no table, and `is_ntfs` refuses a FAT one for its name; `detect`'s tests check each against the other's bytes, and `tests/open_open.rs` holds the one direction that matters — what the reader opens, the opener tells — over a real `mkntfs` image, as it is and under zstd. [open.md](open.md) has the order the containers are told in, and why a table in front wins.

## Why the feature is off by default

`ntfs` is not in `full`, as `rar` is not. RAR's reason is its license; this one's is the panics above — the two that were found, and the class they belong to. Every reader here is fuzzed, the fix for the index-entry panic is not in any release, and a fuzz target cannot be a gate while it finds a crash nobody here can fix.

What would turn it on: a release of the crate carrying PR #41, which also takes binrw out of the tree. Issue #40 is where that is being asked for.

## How it is checked

`crates/hivepack/tests/ntfs.rs` reads a file system and `crates/hivepack/tests/extract_ntfs.rs` extracts one, both built by `crates/hivepack/tests/ntfs_support/mod.rs`. The file system is built once per test binary: `mkntfs` makes it, `ntfs-3g` mounts it so files can be written into it, and `python3` sets the two things that are extended attributes rather than files — `system.ntfs_attrib_be` of `0x800` on a directory, which is what makes NTFS compress what is written in it from then on, and a stream beside a file. Each tool is asked for on its own and what is missing is printed, so a machine without them says so instead of passing quietly.

**And printing is not enough on its own.** `cargo test` hides what a passing test prints, so a run that found no tools and a run that read an image look the same from the outside — the green log of the first run of these tests on CI could not be told from a green log of nothing happening. So one CI job installs the tools and is held to having them with `HIVEPACK_NTFS_REQUIRED`, under which not being able to build the image is a failure rather than a reason, the way `HIVEPACK_TESTDATA_REQUIRED` works for the data sets.

One job and not every Linux job, measured rather than chosen: the arm runner answers `mount failed: Operation not permitted` to an unprivileged `ntfs-3g`, where the x86-64 one mounts. macOS and Windows have no such tools at all. Those jobs still run the tests, print why they skip, and run the two that need no tools. **An empty value is not a value**, either: a workflow that sets the variable everywhere and fills it in for one job leaves the rest holding an empty string, which is still set as far as the environment goes — the first version of the guard read it with `var_os` and failed on macOS and Windows for having been handed nothing.

The guard was checked by hiding `/usr/sbin` in a mount namespace so that `mkntfs` is gone: with the variable set the suite fails and names the missing tools; with it empty, unset, or with the tools there, it passes.

- **A tree read back as it went in**: every path, every length, every file's bytes, and nothing in the image that was never written.
- **The compressed file refused**, with the premise checked first: the test asserts the file system really did compress it, so that it cannot pass on an image where there was nothing to refuse.
- **The stream beside a file is not the file**, and is not a name in the directory either.
- **A hole reads as zeroes**, over a file with a megabyte that was never written.
- **Two names of one file are one record**, with the link count from the record.
- **A directory too long for its record**, read whole: 400 names.
- **A file in many pieces read in order**, in reads of 777 bytes so that none lines up with a run, and then the last byte alone after a seek from the end.
- **What is not NTFS is not opened**, and **a disk too short for a boot sector is not opened** — a FAT boot sector, zeroes, and the five lengths above. These two need no tools, so they run everywhere.

What the extraction tests add, over the same image:

- **A tree extracted comes out as it went in**: every file's bytes, every folder a folder, the counts and the total in the summary, and nothing in the destination that was never written.
- **The compressed file is refused rather than written**, both ways: with `OnRefused::Skip` its folder comes out and it does not, and by default the extraction stops with `Ntfs(Compressed)` **before the destination is made** — which the test asserts by looking for the folder and not finding it. The premise is checked first here too.
- **Two names of one record become one file**: the same inode and a link count of two, and two files holding the same bytes with `Links::AsFile`.
- **A hole and a file in a hundred pieces come out whole**, and a name that is not ASCII comes out as its characters.
- **The stream beside a file is not written**: nothing in the destination holds a colon, and `ads.txt` holds its own data.
- **A sink is given what the folder would get**: the same folders, the same files with the same lengths, and the hard link as a link after the file it names.

The build being fast enough to disbelieve — nine tests in under a tenth of a second, image and all — was settled by breaking one assertion on purpose and watching the test fail, rather than by argument.

**A fuzzer feeds it anything** (`fuzz/fuzz_targets/ntfs.rs`): the file system walked, every file and every stream read, every path looked up again, twice in pieces of different sizes the input picks, and the two must agree. It is the only target in this repository that **no CI step runs**, for the reasons above: it reaches the index-entry panic, which cannot be fixed here, and any run that gets past `open` may find another instance of the same class.

**It needs two things set, or it proves nothing.** A real NTFS image in the corpus, because the name is checked at `open` and random bytes never get past it. And `-max_len` at least as long as that image: left out, libFuzzer says "will not generate inputs larger than 1048576 bytes" and cuts the seeds down to that, which leaves a disk whose `$MFT` is off the end, so nothing behind the boot sector is read at all. Measured, and worth writing down because the failure is silent: with a known-crashing 8 MiB image sitting in the corpus, two runs of 121 and 61 seconds — 3.8 and 2.0 million executions — found nothing; the same corpus with `-max_len=8388608` died on `index_entry.rs:205` immediately. Of five images that panicked a harness driving the library directly, one panics through this module's own API, which is how that reachability was checked rather than assumed.
