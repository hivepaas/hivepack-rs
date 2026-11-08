# Reading a tar archive once (design)

> **Status:** built for `extract_tar` into a folder (hivepack-rs#184). Measured below.

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
- **cpio, XAR and ISO 9660**, which also read twice, are left for later. cpio writes a file's data under its first name with its last header (`groups`), which needs its whole archive. The same private folder works for them once tar's is in.
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

No more space: the data is written once, on the destination's file system. Moving into place is a hard link and a removal for each file, which takes nothing to speak of next to writing it.

## Tests

- All of `tests/extract_tar.rs` passes unchanged: names, links, limits, the Go archives, the CVE archives, damage. One thing changes: where an error used to leave files written, the destination is now as it was.
- A stream that fails its compressor's check at its end, after gigabytes, leaves the destination as it was.
- A refusal late in the archive (a duplicate path, a limit) leaves the destination as it was.
- `on_unnamable` with Rename, Skip and Stop gives the same names as today.
- Conflicts: a file in the way stops before anything moves; `overwrite` replaces; a directory there is merged.
- A private folder left by a process killed mid-extraction is removed by `remove_stale` and by the next extraction there. One whose owner still runs is never removed: a test holds the lock from another process.
- The fuzz target `extract_tar` runs on the new path. Afterwards, nothing may be left in the destination but the archive's entries, and no `.hivepack-extracting-*` may remain.
- Timing on 3 GB, before and after, as above.

## Decisions

The points left open in the first draft, decided in review:

1. **Windows' hidden attribute:** hivepack sets it itself, through `windows-sys`, so every caller has it; `safety.md` lists it, as it lists `hivepack::memory`'s calls. A failure to set it is not an error.
2. **A file put in the destination meanwhile:** files move by hard link and removal, which never replaces; by a rename where the file system has no hard links, or where `overwrite` asks to replace.
3. **Progress:** the fraction of the archive read, against its size; the files and bytes written, without totals.
4. **`overwrite` replaces by a rename**, as GNU tar and bsdtar do, rather than truncating in place: a file is replaced only once its new content is whole.
