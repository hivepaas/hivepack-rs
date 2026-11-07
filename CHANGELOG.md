# Changelog

## Unreleased

- `open`: with `Opener::threads`, a bzip2 stream of more than 2 MiB, as `bzip2` and `lbzip2` write a file, is decoded a block in each thread, as lbzip2 and 7-Zip do: the blocks' magic found on any bit, each block decoded by a decoder made where one thread's would be at it (`bzip2::Decompress::at_block`, crate-private), and its data taken only if it ends where the next block starts. Anything else, damage too, is left to one thread's decoder made there: what is read, and the error, are the same as with one thread. Silesia as one `.tar.bz2` of `bzip2 -9`: 3.25 s on one thread, 0.46 s on eight, 0.25 s on sixteen. See [docs/open.md](docs/open.md#threads).
- `extract`: `extract_rar` with `Options::threads` writes the files of an archive that is not solid at once, each by a thread that opens the archive itself and goes through its headers: files larger than a share of the whole first, largest first, then the rest in the archive's order; the directories before, and hard links, file copies and links written as files after, in order. What is written, and the summary, are the same as with one thread. 22,540 files of 343 MB extract in 1.18 s on one thread, 0.28 s on eight and 0.22 s on sixteen. A solid archive is read on one thread, as before. See [docs/extract.md](docs/extract.md#threads).
- `extract`: `Options::memory_limit` lowers those threads until each one's window, as large as the archive's dictionary asks, and PPMd's model in RAR 4, fit; and with the feature `memory`, `Options::memory_budget` holds them from a `memory::Budget` once the first reading knows what they need. See [docs/memory.md](docs/memory.md#readers).
- `extract`: outside a solid stream, RAR entries that are not written (left out, or not picked by `Options::select`) are passed over, not decompressed: the data a picked file needs is its own.
- Breaking: `extract_rar`'s `open` is `Fn` and `Sync`, as each thread calls it. `extract_rar_to` takes an `FnMut`, as before.
- `extract`: a RAR header that is no link no longer counts the target of a link before it, which a header keeps, when the two readings are compared.
- `rar`: `Extract::threads` decodes an entry of RAR 5 or 7 in threads, as UnRAR's `-mt` does: each Huffman block decoded ahead in a thread of its own, and written into the window in order on the caller's thread. Not UnRAR's code, which differs from its own single thread on damaged data: `Unpack5`'s loop runs as it is and takes, at each block, what a thread decoded only where that is what it would decode itself, so what comes out is the same as with one thread, byte for byte, damaged data and errors too. Silesia's 211 MB as one entry, `-m3`: 0.46 s on one thread, 0.32 s on four or more, as UnRAR takes on eight. `Extract::threads_from`, 1 MiB by default, is the packed size from which an entry takes threads. Not for an entry going on in another volume, nor the older algorithms. See [docs/rar.md](docs/rar.md).
- `zip`: an archive that is Zip64 for its count of entries alone (more than 65,535), with data descriptors of 4-byte sizes, as Info-ZIP's zip, libarchive and File Roller write them for entries that need no more, opens with its local headers checked (`OpenFlags::CHECKCONS`). It was refused with "local and central headers do not match", as libzip refuses it: it read every descriptor's sizes as 8 bytes. A descriptor's sizes are now 4 bytes when that much is the compressed size of the central directory and a header follows, and 8 otherwise, as before.

## 0.9.0

- `extract`: `Links::Any` creates every symbolic link, its target as the archive has it, absolute or leading outside the destination too, as tar does, for archives that are trusted (a backup of one's own files). Links are still created after every other entry, so nothing is written through them, and a path under a link is still the link's; a target that is no path (empty, not UTF-8, a control character) is refused, and on Windows, into a folder, one from a root or a drive.
- `extract`: `Options::on_links_outside`, with `Links::Inside`, is asked once, before anything is written, about the links whose targets lead outside or through another link, each with its target (`LinkOutside`): stop, leave them out, or create them (`OnLinksOutside`), so that an application can show them and let its user choose. See [docs/extract.md](docs/extract.md#options).
- `extract`: a `Sink` may be given a link's target as the archive has it, with `Links::Any` or `OnLinksOutside::Create`.

## 0.8.0

- `memory`, a new module behind a feature of the same name, off by default: `memory::available()` measures how much memory the program may still take, the least of what the system has free and what its limits leave it, and says which bound applied (`Bound::System`, `ControlGroup`, `Ulimit`, `JobObject`). On Linux, `MemAvailable`, each control group from the program's own up to the root (version 2, and version 1's memory controller), and `ulimit -v` and `-d`; on Windows, the available physical memory and the job object's limits; on macOS, the pages free, of files and purgeable. `memory::Budget` shares memory between jobs at once: `hold_threads(wanted, need)` gives the most threads whose estimate fits what is left, one at least, and holds it until the `Held` is dropped. Nothing in hivepack calls it: [docs/memory.md](docs/memory.md#wiring-it-to-the-coders) shows how an application hands the threads and bytes to each coder. It calls the system through `unsafe` code on Windows and macOS ([docs/unsafe.md](docs/unsafe.md#system-calls)), with windows-sys and libc, and rustix on Linux.

## 0.7.0

- `zip`: `Archive::set_threads` compresses and encrypts new data in threads, ahead of the entry being written, the entries still written in order on the caller's thread, which draws the random bytes of salts and headers ahead in the order one thread draws them; the archive is the same, byte for byte, as with one thread, and so is an error and what was written before it. Up to 32 MiB per thread waits to be written; a larger entry is compressed and encrypted as it is written. See [docs/zip.md](docs/zip.md#compressing-in-threads).
- Memory limits for the coders that use threads, so that threads never make an application run out of memory: each takes a limit under which it lowers its threads until what it would take fits, one thread always allowed, as liblzma does; and each tells beforehand what a configuration takes, an upper bound of what it allocates. What is made is the same whatever the threads, so the limit changes how fast, never what. No limit by default. See [docs/memory.md](docs/memory.md).
- `sevenz`: `WriteOptions::memory_limit`, `WriteOptions::memory_usage(threads)` and `WriteOptions::threads_used()`, for LZMA2's blocks in threads: an encoder, a block and room for its output for each thread, 157 MiB at preset 6. The writer no longer keeps an encoder of one stream beside the threads' encoders, for nothing (94 MiB at preset 6, 674 MiB at preset 9), nor copies a block as it grows.
- `zstd`: `CCtx::estimate_memory(nb_workers)`, with workers or without, and `CCtx::set_workers_memory_limit`, which lowers each frame's workers, never to none; `CCtx::nb_workers_within_limit()`. Not libzstd's, beside the port, whose frames are the same.
- `bzip2`: `MtOptions::memory_limit`, `MtOptions::memory_usage(threads)` and `MtOptions::threads_used()`, for `CompressMt`.
- `open`: `Limits::bzip2_memlimit` bounds bzip2's threads (`Opener::threads`), about 20.5 MiB each; xz's are bounded by `xz_memlimit`, as before, and 7z's blocks by `sevenz::Options::decoder_memory_limit`.
- Breaking: `sevenz::WriteOptions` and `bzip2::MtOptions` have a field more (`memory_limit`), so one written out in full takes `..Default::default()`.

## 0.6.0

- `extract`: `Options::threads` lets `extract_zip` write that many files at once, each read and decompressed in a thread of its own, `Threads::One` by default; what is written, and the `Summary`, are the same. `extract_zip` now asks the archive's source to be `Sync`, as every `ReadAt` here is; a `Sink` is still given one entry at a time. See [docs/extract.md](docs/extract.md#threads).
- `bzip2`: `CompressMt` compresses in threads, as pbzip2 does: the input in pieces of a fixed size (`piece_size`, 95% of a block), each a bzip2 stream of its own, the streams one after the other, which `bzip2 -d` reads as one. It is called as `Compress` is, and its output is the same whatever the threads, one too. See [docs/bzip2.md](docs/bzip2.md#threads-beside-the-port).
- `open`: `Opener::threads` decodes bzip2 streams one after the other (pbzip2's, `CompressMt`'s) a stream in each thread. A file of one stream, as `bzip2` writes it, is read on the caller's thread as before; what is read is the same either way, errors too. See [docs/open.md](docs/open.md#threads).
- `sevenz`: `WriteOptions::lzma2_blocks` cuts LZMA2 in blocks that each reset the dictionary, as 7-Zip does in threads (`Lzma2Blocks::Auto`, 4 times the dictionary: 32 MiB for preset 6), and `WriteOptions::threads` compresses them in threads, the filter before them on the caller's thread. What is written is the same whatever the threads, and any 7z reader reads it; the default is one stream, as before. See [docs/7z.md](docs/7z.md#lzma2-in-blocks-in-threads).
- `sevenz`: `Archive::set_threads` decodes LZMA2 whose stream resets its dictionary on the way, a block in each thread, under `Options::decoder_memory_limit`: what 7-Zip writes in threads, and `Lzma2Blocks`. Other folders are decoded as before.
- `extract`: `Options::threads`, one by default, decodes 7z's LZMA2 blocks in threads too (`extract_7z`, `extract_7z_to`).
- Breaking: `extract_zip` asks its archive's source to be `Sync`, as every `ReadAt` here is; `sevenz::WriteOptions` has two fields more (`lzma2_blocks`, `threads`), so one written out in full takes `..WriteOptions::default()`.

## 0.5.0

- `Threads`: how many threads of its own a coder may use, `One` by default; the same output whatever it is.
- `open`: `Opener::threads` decodes an xz Stream whose Blocks have their sizes in their headers (`xz -T`, 7-Zip) a Block in each thread, under `Limits::xz_memlimit`. See [docs/open.md](docs/open.md#threads).
- `extract`: into a `Sink`, by this system's rules (`NameRules::Native`), any name an archive can hold is taken, on every system, Windows too: Windows' characters, device names, ends of names and long components no longer stop converting an archive on Windows. Only what leads outside where the archive made is extracted, on any system, is refused (`a\..\x`, `\x`, `C:x`), and control characters. See [docs/extract.md](docs/extract.md#into-something-other-than-a-folder).

## 0.4.0

- `extract`: names are checked by this system's rules by default (`Options::name_rules`, `NameRules::Native`): Windows' characters, device names and ends of names only on Windows, so that `a:b.txt` or `aux.txt` extract on Linux and macOS; and two names that differ only in case are one only where the destination's file system takes them for one, found by a file made there and taken away before anything is written (never in a `Sink`). `NameRules::Portable` keeps every system's rules, as before. What leads outside the destination is refused everywhere, as before, and a name that climbs through Windows' separator or a stream (`a\..\x`, `a.txt:..`) is now refused as `NameError::Dot`. See [docs/extract.md](docs/extract.md#refuse-do-not-repair).
- `extract`: `Options::on_unnamable` is asked once, before anything is written, about every entry whose name this system cannot take (`NameError::is_unnamable`, and names it takes for one), and can leave them out or rename them (`Summary::renamed`).
- `extract`: `Options::links_outside` leaves out a link whose target leads outside or through another link, whatever `on_refused` says.
- `extract`: `check_name_for` checks a name by `NameRules`.

## 0.3.0

- `extract`: each extractor writes into a `Sink` in place of a folder too (`extract_zip_to`, `extract_tar_to`, `extract_7z_to` and the others), after the same checks and in the same order: to convert an archive entry by entry, without a folder in between. See [docs/extract.md](docs/extract.md#into-something-other-than-a-folder).
- `extract`: `Options::on_damaged` is asked about each entry whose data is damaged (a check that fails, data that does not decompress or ends early), and can leave it out or keep what was read of it, and go on; `Summary::damaged` lists them. Everything else, names, links and the limits among it, still stops. A tar, cpio or ISO 9660 stream cut short is extracted up to there. See [docs/extract.md](docs/extract.md#damaged-data).
- `sevenz`: `Files::skip_folder` leaves a folder whose data failed, for the next.
- `zip`: `Writer` writes an archive an entry at a time, each entry's data read once from a `Read` as it is added, and the central directory at `finish`: to convert an archive entry by entry. What it writes is what `Archive::close_to` writes from the same entries. `Writer::set_random_source` gives where an encrypted entry's salt comes from, as Windows needs.

## 0.2.1

- `open`: a `.tlz` file is `.tar.lzma` (its short name, as file managers give it) when its bytes are no other format's: lzip's `.tlz` is still told by its magic.

## 0.2.0

- `sevenz`: `Writer::set_method` changes the method from the next file on, which starts a folder of its own: what is compressed already can be stored with `Method::Copy` beside what is not.

## 0.1.0

The first release, as one crate, `hivepack`, with a module and a feature for each format. Before 1.0 a minor release (0.2.0) may change an API; a patch release (0.1.x) only fixes.

- Ports, with the output, errors and speed of the libraries they come from: `deflate` (zlib 1.3.2), `bzip2` (libbzip2 1.0.8), `lz4` (liblz4 1.10.0), `xz` (liblzma 5.8.4), `zstd` (libzstd 1.5.7), `zip` (libzip 1.12.1), `tar` (Go 1.27.2), `sevenz` (LZMA SDK 26.05), `rar` (UnRAR 7.3.2), `age` (age v1.3.2), `iso`, `cpio`, `xar` (libarchive 3.8.10), `udf` (NetBSD).
- `extract`: extraction to disk, safe by default, for ZIP, tar, 7z, RAR (feature `rar`), cpio, XAR, ISO 9660 and UDF.
- `open`: finds and stacks the layers around an archive (age, zstd, xz, lzip, LZ4, gzip, bzip2, pbzx, RPM).
- `sign`: whole-file signatures in `ssh-keygen -Y sign`'s format, and hybrid Ed25519 + ML-DSA-65 keys.
- `crypto`: one small interface over RustCrypto and dalek crates; no cryptography of its own.
- `unsafe` code is forbidden in every module. The `unsafe-fast` features of `zstd`, `lz4` and `deflate` are off by default ([docs/unsafe.md](docs/unsafe.md)).
- Known limits: `ml-dsa` has not been audited independently (it never signs alone); `rar` is under UnRAR's license and never writes RAR; Windows does not mark a sparse file's holes on extraction; SSH RSA keys are not taken by `age` and `sign`.
