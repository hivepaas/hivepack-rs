# Reading a tar archive once (design)

> **Status:** designed, and its open points decided (below); being built.

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

The stream is read once, through the loop the second reading has today (`Reading::write`, the writer threads included). For each entry:

- The checks that need only the entries before it run as today, against what has been read so far: names, folding, refused kinds, select, limits, a hard link's target. A refusal stops the extraction as today; then everything goes (see 4).
- A file, directory or hard link is written into the private folder under its name, as the second reading writes it today: data, then owners, xattrs, mark of origin, time and permissions.
- A name that this system cannot take (`NameError::is_unnamable`), or that folds onto another one with a different spelling, cannot be written yet: the answer to `on_unnamable` is due once, for all of them. Its data is written under `.hivepack-extracting-…/.unnamed/<index>` instead, and the name is kept.
- A symbolic link is noted, not created, as today.
- The stream is read to its end (`read_rest`), and a compressor's or age's failure there stops the extraction.

Writer threads start with the second file, rather than from a count of files known beforehand. The first reading's list of entries is no longer kept whole: what stays is what the checks need, namely the names seen (for folding and links), the hard-link targets, and the unnamable and link entries.

### 3. Before anything is moved

Once the stream has ended soundly:

1. **`on_unnamable`** is asked once, with every name gathered, as today. `Rename` numbers against every name that stays (`free`), which is now known. Each `.unnamed/<index>` is moved to its new name, or removed with `Skip`, or the whole extraction stops.
2. **Symbolic links** are planned from every kept entry (`plan_links`): chains, directories, `on_links_outside` asked once. Then they are created in the private folder.
3. **Conflicts with what is in the destination** are found by walking the private folder against the destination, by handle, before anything moves:
   - a directory there is merged into, as today;
   - a file there stops the extraction with `Exists`, unless `overwrite` is set and it is a regular file;
   - anything else in the way (a link, a file where a directory goes) stops it with `NotADirectory`, as today.

   If anything stops here, nothing has moved.

### 4. Moving into place, and failing

- **Moving.** Each entry of the private folder's top level is moved into the destination by handle. A directory not in the destination moves whole, in one rename (`Dir::rename`). One that is there is descended into, and its entries are moved one by one. A file is moved by a hard link to its new place, then removed from the private folder (`Dir::hard_link`, then `remove_file`). A link fails where something is there, so a file put in the destination after the conflicts were checked is never replaced. Where the file system has no hard links (FAT32, exFAT), the file is renamed after one more look, which leaves a window of microseconds. A directory renamed fails onto one that has entries; onto an empty one that appeared meanwhile, it takes its place, and nothing is lost. Directory times, owners and xattrs are set last, deepest first, as today. Then the private folder, by now empty, and its `owner` are removed.
- **Overwriting.** With `overwrite`, a file is replaced by a rename over it, where today it is truncated in place, as GNU tar and bsdtar replace a file by default. The new file is written whole before it replaces the old one, so a failure never leaves a half-written file. A hard link to the old file elsewhere keeps the old content, as with GNU tar's default.
- **Failing.** On any error, cancel or time limit, before the moves begin: the private folder is removed whole, by handle and without following links (cap-std `remove_dir_all` on its `Dir`). If the destination was created by this extraction and is now empty, it is removed too. Nothing of the archive is left.
- **A failure while moving** (rare: permissions changed, the disk gone) stops the moves. What was moved stays, the rest is removed, and the error says how many entries were moved. This is the one case where part of an archive appears, and it is said.

### 5. A process that does not end well

A crash, `kill -9` or the power leaves the private folder behind, with its `owner` unlocked:

- **hivepack**: `extract::remove_stale(destination)` removes every `.hivepack-extracting-*` in it whose `owner` can be locked, by handle. `extract_tar` calls it on the destination before it starts, so extracting again into the same place cleans up.
- **packwing**: before an extraction starts, it adds the private folder's path to a journal in its data folder and syncs it. When the extraction ends, however it ends, it takes the line out. When the app or `pkw` starts, it calls `remove_stale` on each folder in the journal, so a folder left behind goes the next time packwing runs, wherever it was. hivepack tells the caller the private folder's path through a new `Options::on_staging` callback, called once it is created and before any data is written.

A private folder is never mistaken for one in use: its `owner` is locked for as long as its extraction runs.

### 6. What stays as it is

- **`extract_tar_to`** (into another archive, for packwing's conversions) has no folder to write into first. It reads twice, as today.
- **cpio, XAR and ISO 9660**, which also read twice, are left for later. cpio writes a file's data under its first name with its last header (`groups`), which needs its whole archive. The same private folder works for them once tar's is in.
- What is written, the summary, the errors and the order of the questions are the same as today. Two things change:
  - partial files and directories are never seen in the destination, where today an error after writing began left them;
  - a file `overwrite` replaces is renamed over, not truncated in place.

## Progress

Today the totals are counted by the first reading (`run.start`). With one reading they are not known beforehand. `Progress` gains the archive's bytes read so far, and its size when it is known (the compressed file's). How far through the archive the reading is, is what the time left comes from: decompressing takes time with the compressed bytes. The files and bytes written are still told, without a total. Where the archive's size is not known (a stream), there is no fraction. packwing shows the fraction of the archive read and the files written, and "Finishing…" while the entries move into place.

## What it costs, and what it saves

- **Time:** one decompression where there were two, so the table above's tar column comes near the one-file column. Expected: gz about 5.8 s, xz 1.6 s, zst 1.0 s, bz2 3.6 s, lz4 1.0 s. Moving into place is one rename per top-level entry, and one per entry inside directories that were already there.
- **Space:** none more. The data is written once, in the destination's file system.
- **Memory:** less. The first reading's list of every entry is gone, and what stays is a map of names.

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
