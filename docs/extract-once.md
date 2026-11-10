# Reading an archive once (design)

> **Status:** built for `extract_tar` into a folder (hivepack-rs#184), and for `extract_cpio` and `extract_xar`, a package's payloads among them ([below](#cpio-and-xar)). Measured below.

`extract_tar` reads a tar stream twice into a folder: first the headers, for every check, then the entries are written (see [extract.md](extract.md#tar)). A compressed tar is therefore decompressed twice. On 3 GB of programs, 32 threads:

| | one file | tar into a folder |
|---|---|---|
| gz | 5.4 s | 10.9 s |
| xz | 1.4 s | 2.7 s |
| zst | 0.9 s | 1.6 s |
| bz2 | 3.2 s | 6.4 s |
| lz4 | 0.9 s | 1.4 s |

The rest of this note proposes reading the stream **once**. The entries are written into a private folder inside the destination as they come. Once the stream is read to its end and every check has passed, they are moved into place. If anything fails, the private folder is removed. Nothing appears in the destination unless the whole archive is sound, which is the promise the two readings keep today.

## What other tools do

GNU tar, bsdtar (libarchive, and with it File Roller, Ark and Windows' Explorer), Python's `tarfile` and The Unarchiver all read once. They check each entry as it comes and write it straight into the destination. An archive that fails late, for example on a bad name or a compressor's checksum at the end, leaves what came before it. 7-Zip reads a `.tar.gz` as a `.gz` holding a `.tar`, and for the inner archive it first writes the `.tar` to a temporary folder. hivepack's promise is stricter than all of them, and stays so.

## What the first reading gives today, and when it is known

The first reading collects every header (`read_headers`, `extract/tar.rs`), then plans:

| Check | Known from the entries before it | Needs the whole archive |
|---|---|---|
| A name that climbs out, is absolute, or that no system takes (`named_of`, `plan::named`) | yes | |
| The same path twice, by this file system's folding (`duplicate`) | yes: the later entry is refused | |
| `Links::Refuse`, devices, FIFOs (`refused`) | yes | |
| `select` | yes | |
| `max_entries`, `max_entry_size`, `max_total_size` | yes: running totals | |
| A hard link's target: a kept file earlier in the archive | yes | |
| `on_unnamable`: every name this system cannot take, asked once; `Rename` numbers names against every name that stays | | **yes** |
| Symbolic links: a chain through a later link, a target that is an archive directory (Windows), `on_links_outside` asked once | | **yes** (and they are created last already) |
| The stream to its end: gzip's and bzip2's CRC-32, xz's and zstd's checks, age's last chunk (`read_rest`) | | **yes** |
| Writer threads, by the number of files (`writer_threads`); progress totals | | yes (convenience) |

So only three checks need the whole archive. Symbolic links are already made after every file, and the unnamable names and the stream's end can be dealt with before the entries are moved into place.

## The design

### 1. A private folder in the destination

- `extract_tar` opens the destination as today (`Destination::open`), and remembers whether it created it.
- Inside it, it creates `.hivepack-extracting-<16 random hex>`, mode 0700. That folder becomes the `Destination` root everything is written to, through the same handles (cap-std, `O_NOFOLLOW`, `create_new`). Every write rule in [extract.md](extract.md#writing-by-handle) holds unchanged.
- Being inside the destination puts it on the same file system, so moving an entry into place is a `rename`: no data is copied.
- On Windows, where a leading dot hides nothing, the folder is given the hidden attribute (`SetFileAttributesW`, through `windows-sys`, already there for `cap-std`; see [safety.md](safety.md#dependencies-with-unsafe-code)). If that fails, the folder stays visible while it lasts, which changes nothing else.
- In it, a file named `owner` is created and **locked** (`File::try_lock`, std since Rust 1.89, the crate's minimum: `flock` on Unix, `LockFileEx` on Windows) for as long as the extraction runs. The system lets go of the lock when the process ends, however it ends: `kill -9`, a crash, the power. A folder whose `owner` can be locked has no one extracting into it.

### 2. One reading

The stream is read once, with the writer threads as before. Each header is kept, as the first reading kept them. Each file's data is written as it comes into the private folder, under `data/<its index in the archive>`, with its time, permissions, owners, extended attributes and mark of origin, which a rename or a hard link keeps. Data is written only for a file the checks may keep: one picked by `select`, whose name is one or may be renamed to one, and within the limit on one entry. Named by index, the data needs no name the system takes: a name that is not one yet waits, as its data does, for `on_unnamable`.

- A file's data that is damaged is kept as far as it was read, and noted. The question is asked with `on_damaged` when its turn comes to move into place, so the questions come in the archive's order, as before.
- The limit on all that is written counts every file written into the private folder, those the checks then leave out too: an archive cannot fill the disk with entries it then drops.
- The stream is read to its end (`read_rest`). A compressor's or age's failure there stops the extraction.

### 3. Before anything is moved

Once the stream has ended soundly, the checks are those a first reading led to, unchanged: `settle` (`on_unnamable`, asked once, with every name), `check`, and `plan_links` (symbolic links: chains, directories, `on_links_outside` asked once). Then what is in the destination already is looked at, by handle, for every entry to move, before any does (`Destination::in_the_way`):

- a directory there is merged into, as before;
- a file there stops the extraction with `Exists`, unless `overwrite` is set and it is a regular file;
- anything else in the way (a link, a file where a directory goes) stops it with `NotADirectory`, as before.

If anything stops here, nothing has moved.

### 4. Moving into place, and failing

- **Moving.** The entries are made in the destination in the archive's order, as the second reading made them: directories created, hard links and copies made, and each file moved from `data/<index>` to its name. A file is moved by a hard link to its new place, then removed from the private folder (`Dir::hard_link`, then `remove_file`). A link fails where something is there, so a file put in the destination after the conflicts were checked is never replaced. Where the file system has no hard links (FAT32, exFAT), the file is renamed after one more look, which leaves a window of microseconds. A directory renamed fails onto one that has entries; onto an empty one that appeared meanwhile, it takes its place, and nothing is lost. Directory times, owners and xattrs are set last, deepest first, as today. Then the private folder, by now empty, and its `owner` are removed.
- **Overwriting.** With `overwrite`, a file is replaced by a rename over it, where today it is truncated in place, as GNU tar and bsdtar replace a file by default. The new file is written whole before it replaces the old one, so a failure never leaves a half-written file. A hard link to the old file elsewhere keeps the old content, as with GNU tar's default.
- **Failing.** On any error, cancel or time limit, before the moves begin: the private folder is removed whole, by handle and without following links (cap-std `remove_dir_all` on its `Dir`). If the destination was created by this extraction and is now empty, it is removed too. Nothing of the archive is left.
- **A failure while moving** (rare: permissions changed, the disk gone) stops the moves. What was moved stays, the rest is removed, and the error says how many entries were moved. This is the one case where part of an archive appears, and it is said.

### 5. A process that does not end well

A crash, `kill -9` or the power leaves the private folder behind, with its `owner` unlocked:

- **hivepack**: `extract::remove_stale(destination)` removes every `.hivepack-extracting-*` in it whose `owner` can be locked, by handle. `extract_tar` calls it on the destination before it starts, so extracting again into the same place cleans up.
- **packwing**: before an extraction into a folder starts, it adds the folder to a journal in its data folder. When the extraction ends, however it ends, it takes the line out. When the app or `pkw` starts, it calls `extract::remove_stale` on each folder left in the journal, so a private folder left behind goes the next time packwing runs, wherever it was, even if nothing is extracted there again.

A private folder is never mistaken for one in use: its `owner` is locked for as long as its extraction runs.

### 6. What stays as it is

- **`extract_tar_to`** (into another archive, for packwing's conversions) has no folder to write into first. It reads twice, as today.
- **cpio and XAR** read once too, in the same private folder: see [cpio and XAR](#cpio-and-xar). **ISO 9660** reads twice still: an image is read where its directories say, so a second reading of an image on disk reads it again without decompressing anything, but for an image under a compressor.
- What is written, the summary, the errors and the order of the questions are the same as today. Two things change:
  - partial files and directories are never seen in the destination, where today an error after writing began left them;
  - a file `overwrite` replaces is renamed over, not truncated in place.

## Progress

The totals are counted once the entries are checked, after the one reading. While the files' data is written into the private folder, `Options::progress` is told all 0, to say it goes on: the data is counted as each entry moves into place, so that what is told never passes the totals, a file written into the private folder and then left out included. The caller, which knows the archive's size (packwing does, for a file), shows how far through it the reading is from the bytes it has read of it.

## What it costs, and what it saves

Measured on 2 GB of programs (a tar of `/usr/lib/x86_64-linux-gnu`, 5,012 files), 32 threads, before and after:

| | Read twice | Read once |
|---|---|---|
| `.tar.gz` | 9.0 s | 4.5 s |
| `.tar.xz` | 2.0 s | 1.05 s |
| `.tar.zst` | 3.0 s | 1.7 s |
| `.tar` | 0.52 s | 0.40 s |

No more space: the data is written once, on the destination's file system. Moving into place is a hard link and a removal for each file. Next to writing a few large files that is nothing to speak of, but it is all on the caller's thread, after the last entry is read. 26,749 files of 2.3 GB (programs and libraries, `.tar.zst` of one frame) extract into tmpfs in 1.70 s on 32 threads, in November 2026. The caller's thread spends its last 0.15 s moving them into place, while every other thread is done: the links and removals, and, most of it, the work on each path (`Path::components` from the end, the names joined, hashed and folded, the spooled file looked up).

**Not done yet: moving into place sooner.** Nothing is moved before the whole archive is checked (step 3), and that stays. Once it is, the moves are independent of one another, apart from the directories they need, which are made first. They could be shared among the threads that wrote the files, as their writes are. The path of each entry's place could also be worked out while it is read rather than at the end. Either would take most of that 0.15 s off.

## cpio and XAR

`extract_cpio` and `extract_xar` read twice as tar did, for the same reasons, so a compressed cpio archive (an RPM package's payload, an initramfs image) and a package's payloads were decompressed twice. XAR did more: its first reading read every file's data to its end for its checksums, and opened and read every payload through its layers (pbzx, gzip) to plan it, and its second reading did it all again. Both now read once, into the private folder of [the design](#the-design), with what tar shares with them in `extract/once.rs`: the private folder made and removed, a file's data written into it (by the writing threads, or on the caller's), the checks after the one reading, what is in the way looked at, and the moving into place. Into a sink, both read twice as before.

### cpio

A file with several names is an entry for each name, and its data comes with any of them: with the last in newc, as GNU cpio and RPM write it, the others empty; with each in odc. The first reading found the last of them with data (`groups`), and the second wrote the file under its first name when that data came. Read once:

- The data that comes with a file's first name, or with a later name of it (a hard link to an earlier entry's path, with data), is written into the private folder, named by the index of the entry it came with, if the file may be kept (picked, a name that is one or may be renamed to one, within the limit on one entry, by the size of this data).
- When a later name's data comes, what came before for the same file is removed from the private folder first, once a thread writing it is done, and no longer counts against `max_total_size`: an odc archive's file of three names is written three times, but takes room once, and passes the limit as it did, once.
- Once the stream has ended, the first name's size is the last data's, as before, for the checks. Moving into place, the first name takes the last data written, and the other names are linked to it in the archive's order, which always has the first name first: nothing waits for a later entry any more.
- A file whose names have no data at all is the empty file its first name wrote.

The stream `open` gives is read ahead by a thread of its own, as tar's is, with writing threads, so the reader is `Send`: `extract_cpio`'s signature changes as `extract_tar`'s did.

### XAR

A XAR archive's files are read in the order of their data in its heap. Each file's data is written into the private folder as it comes, and read to its end, where its checksums are: a file damaged anywhere stops the extraction before anything moves, as the first reading stopped it before anything was written. A file not kept is read to its end as before.

A payload, with `Packages::Expand`, is opened through its layers once, and its cpio archive read once into the same private folder as `extract_cpio` reads one, its files named by the payload's index and theirs (`3-17`), its data decoded in threads as before and read ahead by a thread of its own, its files written by the writing threads. What the payload's layers read of its entry's data before its container is known is copied as it goes into the file it would be, if it may be kept: a payload that is no cpio archive is a file, written as it is, layers and all, what its layers read of it first and then the rest; one that is, a folder, and the copy is removed before its archive is read. The copy holds what the layers read to tell: a few chunks at most.

Once the stream has ended, each payload is checked first, in the archive's order, as the first reading checked each as it came to it, then the archive's own entries; the limits count them all together, as before. What is in the destination is looked at for every entry to move, a payload's in its folder, before any does. Then the entries move into place in the archive's order, and each payload's into its folder when the folder is made, its links created and its directories' times set there, as before.

Two things change besides the reading:

- directories are told to `Options::on_written`, a payload's folder among them, as tar's are, where XAR told files alone;
- an error that came late in the stream, after a payload's checks would have stopped the first reading, now comes first: the payloads are checked once the whole archive is read.

### Measured

1,404 MB of programs and libraries (4,000 files of `/usr/lib/x86_64-linux-gnu`) into ext4 on NVMe, 32 threads, `open::Opener::threads` as many, the best of three:

| | Read twice | Read once |
|---|---|---|
| `.cpio` | 0.33 s | 0.26 s |
| `.cpio.gz` | 4.15 s | 1.91 s |
| `.cpio.xz` (`xz -T0`) | 1.34 s | 0.76 s |
| `.cpio.zst` | 2.23 s | 1.10 s |
| `.pkg`, its `Payload` pbzx over odc (16 MiB chunks, xz -1) | 1.19 s | 0.68 s |
| `.pkg`, its `Payload` gzip over odc | 4.16 s | 1.97 s |

## Tests

- All of `tests/extract_tar.rs` passes unchanged: names, links, limits, the Go archives, the CVE archives, damage. One thing changes: where an error used to leave files written, the destination is now as it was.
- A stream that fails its compressor's check at its end, after gigabytes, leaves the destination as it was.
- A refusal late in the archive (a duplicate path, a limit) leaves the destination as it was.
- `on_unnamable` with Rename, Skip and Stop gives the same names as today.
- Conflicts: a file in the way stops before anything moves; `overwrite` replaces; a directory there is merged.
- A private folder left by a process killed mid-extraction is removed by `remove_stale` and by the next extraction there. One whose owner still runs is never removed: a test holds the lock from another process.
- The fuzz targets `extract_tar`, `extract_cpio` and `extract_xar` run on the new path. Afterwards, nothing may be left in the destination but the archive's entries, and no `.hivepack-extracting-*` may remain.
- cpio (`tests/extract_cpio.rs`): read once into a folder, twice into a sink, where an archive that changes stops; refused at its last entry, or cancelled, the destination as it was; an odc file of three names whose data, larger than half the limit on all, passes it, with threads and without; what is in the way before anything moves. XAR (`tests/extract_xar.rs`): read once, payloads and all, and told by their paths there; refused in a payload, or a payload's file in the way in its folder, the destination as it was; a payload that is no cpio archive written as it is, layers and all, with threads and without, and left out when not picked.
- Timing on 3 GB, before and after, as above.

## Decisions

The points left open in the first draft, decided in review:

1. **Windows' hidden attribute:** hivepack sets it itself, through `windows-sys`, so every caller has it; `safety.md` lists it, as it lists `hivepack::memory`'s calls. A failure to set it is not an error.
2. **A file put in the destination meanwhile:** files move by hard link and removal, which never replaces; by a rename where the file system has no hard links, or where `overwrite` asks to replace.
3. **Progress:** the fraction of the archive read, against its size; the files and bytes written, without totals.
4. **`overwrite` replaces by a rename**, as GNU tar and bsdtar do, rather than truncating in place: a file is replaced only once its new content is whole.
