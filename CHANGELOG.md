# Changelog

## Unreleased

- `zip`: `Archive::set_threads` compresses and encrypts new data in threads, ahead of the entry being written, the entries still written in order on the caller's thread, which draws the random bytes of salts and headers ahead in the order one thread draws them; the archive is the same, byte for byte, as with one thread, and so is an error and what was written before it. Up to 32 MiB per thread waits to be written; a larger entry is compressed and encrypted as it is written. See [docs/zip.md](docs/zip.md#compressing-in-threads).

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
