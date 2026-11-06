# Porting UnRAR

`hivepack::rar` reads RAR archives: it lists them, checks them and gives their entries' data, from RAR 1.4 to RAR 7. It is a port of UnRAR, RARLAB's own source, to safe Rust, under UnRAR's license, and it is checked against a program built from the same source. It does not write RAR, and never will: UnRAR's license forbids it, and so does this plan.

> **Status:** done, all four steps: `hivepack::rar` reads what UnRAR reads, every algorithm, every cipher, volumes, comments and QuickOpen records, compared with UnRAR on the archives of libarchive, rarfile, junrar and unrar.rs and on damaged copies of them, and `hivepack::extract::extract_rar` writes it to disk (see [Progress](#progress)). Wiring it into packwing and a benchmark come next.

## Why UnRAR

RAR has one author and one reference: Alexander Roshal's RAR and its free decompressor, UnRAR, whose source RARLAB publishes ([rarlab.com](https://www.rarlab.com/rar_add.htm)). The archive format is documented for RAR 5 ([technote](https://www.rarlab.com/technote.htm)), but the compression algorithms are not, and the technote leaves the details of encryption to "UnRAR source code". Every other reader either derives from UnRAR or stops short of it.

- **UnRAR 7.3.2** reads every RAR version: 1.4 (`RE~^`), 1.5 to 4.x, and 5.0 to 7.x, with their compression algorithms (RAR 1.5, 2.x, 2.9/3.x with PPMd and its filters, 5.0, and 7.0 with dictionaries up to 64 GB), their encryption (RAR 1.3, 1.5 and 2.0's own ciphers, AES-128 for RAR 3, AES-256 for RAR 5, encrypted headers), volumes, links, and BLAKE2sp hashes. Its decoding core is about 10,500 lines of C++.
- **libarchive 3.8.10** (BSD-2-Clause), which Windows 11 uses to open RAR, reads RAR 2.9/3.x and RAR 5, but no encryption at all, no RAR 1.5 or 2.x compression, and no RAR 5 dictionary over 64 MB; it does not tell RAR 7's version 1 algorithm from version 0.
- **The Rust crates** are bindings to UnRAR's C++ (`unrar`, `unrar_sys`), a small nom parser (`rar`), or `rars`, which has `unsafe` code, needs Rust 1.89 and writes RAR, from sources it does not name.

HivePaaS chose UnRAR in October 2026, as the rest of hivepack ports the official library of each format.

## The licence

UnRAR's source is freeware under its own license, `UnRAR` in SPDX, which OSI does not approve. Its second paragraph is the one that matters:

> UnRAR source code may be used in any software to handle RAR archives without limitations free of charge, but cannot be used to develop RAR (WinRAR) compatible archiver and to re-create RAR compression algorithm, which is proprietary. Distribution of modified UnRAR source code in separate form or as a part of other software is permitted, provided that full text of this paragraph, starting from "UnRAR source code" words, is included in license, or in documentation if license is not available, and in source code comments of resulting package.

A port is modified UnRAR source, so `hivepack::rar`:

- is licensed `UnRAR`, with UnRAR's `license.txt` as its `LICENSE`, and that paragraph, in full, in a comment at the top of every source file;
- is a crate of its own, which no other crate depends on by default: `deny.toml` allows `UnRAR` for `hivepack::rar` only, and `hivepack::extract` takes it only with its feature `rar`, so the rest of hivepack stays under open licenses, and only those who want RAR take its terms. `hivepack::open` only tells a RAR archive by its signature, which takes no code of UnRAR's;
- reads RAR and never writes it: no compression, no archive writer, not even in tests, which use archives others made and damaged copies of them.

Reading RAR inside an archiver, closed or paid, is what the license allows ("in any software to handle RAR archives").

## The version

UnRAR 7.3.2 (`unrarsrc-7.3.2.tar.gz`, SHA-256 `f61a1160d6e2ebbda2ad353c8e82f62ab4312f97fde23c6c2c982d25e0014f99`), RARLAB's current source in October 2026. The version is pinned in `testdata/manifest.json`; moving to a newer UnRAR is a pull request of its own, which ports the changes and records the oracle's answers again.

## What following UnRAR means

The port does what UnRAR does, function by function, so that a RAR archive reads the same as with UnRAR, or fails where UnRAR fails, with the same reason:

- **Headers** are read in order, as `Archive::ReadHeader` reads them: the archive's signature (found after a self-extracting module too), its main header, then each file, service and end header, with their CRCs, and RAR 5's extra records (times, hashes, versions, links, owners). A header UnRAR calls broken is broken here.
- **Data** is read as UnRAR's `ComprDataIO` and `Unpack` read it: packed data, across volumes, decrypted, unpacked by the algorithm the header names, and checked at its end against the CRC-32 or BLAKE2sp it declares, the hash keyed by the password for encrypted files.
- **What is left to others**: UnRAR's command line, its console and messages, its file system code (creating files, setting their times and attributes, links, the Mark of the Web) and its recovery of damaged archives. Extracting to disk is `hivepack::extract`'s, through the same rules as ZIP and tar; repairing is not reading.

Where UnRAR depends on the system (a name in a RAR 4 archive without Unicode, which UnRAR decodes with the system's code page), the port says what it does instead, and the oracle is run so that both do the same.

## The map

| UnRAR | Port | |
|---|---|---|
| `archive.cpp`, `arcread.cpp`, `headers.hpp`, `headers5.hpp`, `headers.cpp`, `rawread.cpp` | `archive`, `headers`, `raw` | step 1 |
| `encname.cpp`, the parts of `unicode.cpp`, `strfn.cpp` and `timefn.cpp` that names and times need | `name`, `time` | step 1 |
| `crc.cpp`, `hash.cpp`, `blake2s.cpp`, `blake2sp.cpp` | `hash`; CRC-32 from `hivepack::deflate`; BLAKE2s and BLAKE2sp in `hivepack::crypto`, from `blake2s_simd` (formerly ported from the reference code, CC0) | step 1 |
| `rdwrfn.cpp` (`ComprDataIO`), the data path of `extract.cpp` | `extract` | steps 1 and 2 |
| `unpack.cpp`, `unpack15.cpp`, `unpack20.cpp`, `unpack30.cpp`, `unpack50.cpp`, `unpack50frag.cpp`, `unpackinline.cpp`, `getbits.cpp` | `unpack` | step 2 (2.9/3.x, 5.0, 7.0), step 3 (1.5, 2.x) |
| `model.cpp`, `suballoc.cpp` (PPMd variant H) | `ppm` | step 2 |
| `rarvm.cpp` (RAR 3's standard filters) | `filters` | step 2 |
| `crypt.cpp`, `crypt1.cpp`, `crypt2.cpp`, `crypt3.cpp`, `crypt5.cpp`, `secpassword.cpp` | `crypt`; AES decryption, HMAC-SHA256 and PBKDF2 from `hivepack::crypto` | step 3 |
| `volume.cpp`, `arccmt.cpp`, `qopen.cpp` | `volume`, `comment`, `quick_open` | step 3 |
| `rijndael.cpp`, `sha1.cpp`, `sha256.cpp` | not ported: `hivepack::crypto`'s AES (the `aes` crate's), SHA-1 and SHA-256 | |
| `unpack50mt.cpp`, `threadpool.cpp`, `threadmisc.cpp` | `unpack::v50mt`: its blocks decoded ahead in threads, written by `Unpack5`'s own loop; Rust's scoped threads for the pool | |
| `rar.cpp`, `cmddata.cpp`, `cmdfilter.cpp`, `cmdmix.cpp`, `options.cpp`, `consio.cpp`, `ui*.cpp`, `list.cpp`, `errhnd.cpp`, `resource.cpp`, `dll.cpp` | not ported: the command line, the console and the DLL API | |
| `file.cpp`, `filefn.cpp`, `filcreat.cpp`, `filestr.cpp`, `find.cpp`, `scantree.cpp`, `pathfn.cpp`, `extinfo.cpp`, `hardlinks.cpp`, `ulinks.cpp`, `uowners.cpp`, `motw.cpp`, `win32*.cpp`, `isnt.cpp`, `largepage.cpp`, `system.cpp` | not ported: writing to disk, which `hivepack::extract` does by its own rules | step 4 |
| `recvol*.cpp`, `rs.cpp`, `rs16.cpp` | not ported: recovery volumes and records repair, and reading does not need them; UnRAR's CVE-2026-14191, a heap write in `recvol5.cpp`, was there | |

The cryptography stays in `hivepack::crypto`, under its own license, where it is general (AES, SHA-256, HMAC, PBKDF2, BLAKE2), and only RAR's own uses of it (its key derivations, its password checks, its ciphers of RAR 1.3, 1.5 and 2.0) are in `hivepack::rar`.

## How it is shown

- **An oracle.** `tools/rar-oracle` is a small C++ program built by `scripts/testdata.py` from UnRAR 7.3.2's sources, with `-DRARDLL` as UnRAR's library is built. It reads requests and answers them by calling UnRAR's own `Archive` and extraction code: every header field of every entry of an archive, the data of each entry with its hash, and the error where UnRAR stops. The port answers the same requests, and the answers are compared as text, as `tools/zip-oracle` does for libzip. Where the oracle cannot be built, recorded answers (`testdata/oracle/rar-*.txt`) are replayed.
- **Archives others made.** libarchive's 131 RAR test archives (BSD-2-Clause), from RAR 2.9 to RAR 5: solid, multivolume, filters, PPMd, symbolic and hard links, Unicode names, encrypted headers and data, and damaged ones; then more from other open projects, each with its license.
- **Damaged copies** of those, bytes changed, cut or moved by a seeded generator, through the oracle: no archive is written, since nothing here writes RAR.
- **Fuzzing**: a target per step, from libarchive's archives, that nothing panics and that the port agrees with what it read before.

## Progress

**Step 1, the headers.** `Archive::open` finds the signature, at the start or after a self-extracting module in the first 4 MB, and reads up to the main header as `IsArchive` does; `read_header` reads each header as `ReadHeader` does, RAR 1.4's, RAR 1.5 to 4.x's and RAR 5's with their extra records, and `seek_to_next` moves past its data. What UnRAR keeps of each header is kept the same, its fields left as they were where UnRAR leaves them (`FileHeader::Reset` clears some fields only), and so are the archive's state, the positions, the broken header flag and the exit code UnRAR's `ErrHandler` would give. Headers that need a password stop the reading, as UnRAR's library stops without a callback; decryption is step 3. QuickOpen records, whose copies of the headers UnRAR reads in place of the headers when an archive has one, came in step 3.

The oracle prints all of that, field by field, after every header, and `crates/hivepack/tests/rar_oracle.rs` prints the same from the port. They agree on libarchive's 131 RAR archives, both with and without reading past a broken main header, on 2,500 damaged copies of the 125 under 64 KB in every run (`HIVEPACK_RAR_DAMAGED` and `HIVEPACK_RAR_SEED` make more: 250,000 agreed in a run by hand), and on the 2,000 inputs four minutes of fuzzing collected (`HIVEPACK_RAR_CORPUS`). Where UnRAR leaves a field unset, so that it holds what an earlier header or the heap left, neither side prints it. What the comparison found:

- UnRAR keeps a header type in its enum, an `int`: a RAR 5 type is cut to 32 bits, kept if that is negative, and made 0xff if it is over 0xff.
- A size that is not known is `INT64NDF`, 0x7fffffff7fffffff, not the largest `int64`.
- Names not in the code page are decoded as glibc decodes UTF-8, which takes four-byte sequences up to U+1FFFFF; what glibc refuses UnRAR maps to U+E080–U+E0FF behind a U+FFFE mark.
- `CRC32` and the BLAKE2sp digest are one union: only the one the hash type names means anything.

The comparison runs on Linux: UnRAR's macOS build decodes names with `UtfToWide`, where Linux's uses `mbsrtowcs`, and the port reads them as Linux's does. `testdata/oracle/rar-list.txt` holds the oracle's answers for libarchive's archives of 2 KB or less and damaged copies, 576 of them, replayed everywhere. The `rar_headers` fuzz target reads every header of its input twice: 7.4 million inputs over four minutes found nothing before the first commit.

**Step 1, stored data.** `Extract::current_file` is `CmdExtract::ExtractCurrentFile` as UnRAR tests an archive: it takes the header `read_header` read, reads a stored entry's data as `UnstoreFile`, `UnpRead` and `UnpWrite` do, gives it to a callback, and checks it against CRC-32, BLAKE2sp or RAR 1.4's checksum. Compressed, encrypted and split entries came in steps 2 and 3.

The oracle's `test` request drives UnRAR's own `CmdExtract` the same way, with the options UnRAR's library sets, and prints after each header how much data came out, its FNV-1a hash, whether its hash failed, the position and the exit code. They agree on libarchive's 131 archives, with and without a smaller dictionary limit, and on 625,000 damaged copies by hand and 2,500 in each run. What they had to agree on, which is not in the format's description:

- What follows a directory's header is read as the next header, whatever the directory's pack size says: UnRAR does not seek past it.
- Up to the pack size is read, and up to the unpacked size given out and hashed. A file cut short hashes what there is, and fails.
- A name that `ConvertPath` leaves empty, like `/` or `../`, is not read in a plain archive and is read without a hash in a solid one, where it would be needed for what follows.
- A record of an encryption version UnRAR does not know is a fatal error for that entry, stored or not, even when nothing else says the entry is encrypted; a solid archive stops there.
- A dictionary over 4 GiB stops everything with a fatal error, even for a stored entry, which needs none.
- Links have no data when testing. RAR 5's are checked against the hash of no data, and RAR 4's not at all, as their target is their data.
- A next volume that cannot be opened is `RARX_OPEN`, which the warning that follows does not replace.

No archive at hand stores data under BLAKE2sp or RAR 1.4's checksum, and hivepack does not make archives, so the `hash` request compares those with UnRAR's `DataHash` directly, in chunks of several sizes, and unit tests check the comparison. `rar5_blake2.rar` goes through a whole archive with BLAKE2sp since step 2; none of the archives at hand is RAR 1.4. Two things are left out on purpose, as they concern choosing files and not reading archives, and the port has no masks. With `*` as the only mask and no recursing, UnRAR stops after a first file named `*`, taking it for all that was asked for, so the oracle recurses. And the mask `*` does not match a name whose last part starts with `*` and goes on, like `*root.txt`, as `match` (rewritten on 2026-09-23) compares that `*` as a plain character before it treats it as a wildcard: UnRAR 7.3.2 silently leaves such a file out. The oracle passes over those entries, and so does the comparison.

`testdata/oracle/rar-test.txt` holds the oracle's answers for libarchive's stored archives and those of 2 KB or less with damaged copies, and for hashes, replayed everywhere. The `rar_test` fuzz target goes through its input twice: 7.1 million inputs over four minutes found nothing before the first commit.

**Step 2, decompression.** `Unpack` is UnRAR's `Unpack`: `v50` the algorithm of RAR 5.0 and 7.0 (unpack50.cpp), `v30` that of RAR 2.9 to 4 (unpack30.cpp), `ppm` its PPMd variant H (model.cpp, suballoc.cpp, coder.cpp) and `filters` its standard filters (rarvm.cpp). Solid entries go on from each other as they do in UnRAR. Three things differ from UnRAR, none in what comes out:

- **The window grows as data reaches it.** UnRAR allocates the whole dictionary an entry asks for. It only reads the window where it has been written, so a few damaged bytes asking for 4 GiB cost nothing here. The one exception is a RAR 3 filter of no length, which reads to the end of the dictionary: what is not there yet is zeros.
- **PPMd's heap is a byte array with 32-bit offsets**, in the layout of 6-byte states and 12-byte units that the algorithm was made for. UnRAR's larger structures are its adjustment to 64-bit pointers, which keeps to these sizes for every decision.
- **The fragmented window is left out**: it is for 32-bit systems that cannot allocate a whole window.
- **The threads are not UnRAR's code** (`unpack::v50mt`, `Extract::threads`). UnRAR's `Unpack5MT` decodes each block's Huffman codes ahead in a thread, into a list of literals, matches and filters, and writes the lists into the window in order, in a loop of its own; that loop differs from its single thread where data is damaged: a block without tables of its own is decoded with whatever tables its thread had last, not the block before's; a filter that cannot be read, or added, is gone on from; and its input is read in pieces of 4 MiB, so that what is read past the end differs. Here `Unpack5`'s own loop runs as it is, reading the packed data as it does, and at each block takes what a thread decoded ahead in place of decoding it, only where that is what it would decode: the block's header is where its own is, its codes start at the same bit, its Huffman tables were made from the same lengths, and the thread read nothing past the packed data. Each symbol taken moves its bits on by those the symbol took, so that its buffer is refilled where it would be, and a run of literals is written at once up to where anything in the loop would do more. Anything else it decodes itself, as with one thread. The threads read the packed data again, apart, from the archive's file (decrypted by a clone of the entry's cipher): a scan goes through the block headers and tables, each block where the one before ends as its header says, and hands each to a thread. What comes out is the same as with one thread, byte for byte, damaged data and errors too: `tests/rar_threads.rs` compares them on every archive at hand, whole and damaged, and the `rar_unpack` target on any bytes. Not for an entry going on in another volume, whose data cannot be read again apart, nor for the older algorithms, which UnRAR does not decode in threads either. On Silesia's 211 MB as one entry, RAR 5 `-m3`, 0.46 s on one thread and 0.32 s on four or more, where UnRAR 7.23 takes 0.47 s on one and 0.32 s on eight: what is left is the window's copies and the hash, on the caller's thread.

What they had to agree on, which is not written anywhere:

- Reading past what was read gives what the buffer held from before, as UnRAR's input buffer is not cleared.
- A filter with a type UnRAR does not know writes nothing, and what it covered still counts as written.
- A filter's output is not limited by the entry's unpacked size, while the data around filters is.
- A RAR 3 filter can be told to work on more than it was given, and reads what earlier filters left in its memory. That memory is uninitialized in UnRAR, so the oracle's `new[]` gives zeros, as the port's memory starts: an answer must not depend on the heap.
- A range coder that has failed stays failed: UnRAR never goes on with it, and it would divide by zero if it did.

Damage to libarchive's archives, which are small, does not get far into a decoder: mutants showed that most of the code could be wrong without a test noticing. So there is more than damage:

- **Damage with the headers' CRCs made right again**, which reaches solid flags, dictionaries, algorithms and sizes.
- **Bytes as packed data**: `tests/support/patch.rs` puts them in place of the data of a copy of `rar5_stored.rar` or `rar.rar`, one entry or two, which is how RAR 7's algorithm is reached at all, as no archive at hand uses it. Nothing here compresses, and nothing could make a valid stream. The `rar_unpack` fuzz target feeds this, and what it finds is compared with UnRAR.
- **The filters by themselves**: no archive at hand has RAR 3's Itanium, RGB or audio filters, whose code cannot be made up, so the `filter3` and `filter5` requests give the same bytes to `RarVM::Execute` and `Unpack::ApplyFilter`, reached by the oracle with `#define private public`.
- **PPMd's model by itself**: a stream that is not one stops a range decoder within a few hundred symbols, and the archives at hand are too short to fill the model's least memory. The `ppm` request gives `ModelPPM`, on both sides, a heap of a few kilobytes that no block could ask for, and starts it again where it stops.

They agree on libarchive's 131 archives, and in runs by hand on the last code: 2 million damaged copies with their data reached, 2 million with damaged headers, 4 million random packed streams, 320,000 filter requests, 16,000 PPMd streams and the 1,183 inputs left of the fuzzer's corpus. Of 118 mutants put by hand into the decoders, what CI runs catches 104. Of the 14 left, 8 change nothing that can be seen or next to nothing: a distance in 64 bits, the CRC and XOR that RAR 3's filters check themselves with, the size given to the E8 filter, where the VM puts its output, the choice in the RGB filter, how far the window wraps, and how PPMd starts again after an escape. The other 6 are not reached: the limit on the number of filters, chains of RAR 3 filters, the window size of solid entries, one table of PPMd (`ns2indx`), and its shrinking of units and its minimum for text.

`testdata/oracle/rar-unpack.txt` holds 790 of what the fuzzer found with UnRAR's answers, chosen so that they catch what the rest does not, and `rar-filters.txt` the answers for the filters, both replayed everywhere. A stream of 241 MB out of 176 KB takes about 1.6 times UnRAR's time, and a smaller one of binary data about 1.3 times. There is no large archive at hand to say more.

**Step 3, the rest of reading.** `v15` and `v20` are `Unpack15` and `Unpack20`, with RAR 2's audio blocks. `crypt` is `CryptData`: the ciphers of RAR 1.3, 1.5 and 2.0, RAR 3's AES with its own SHA-1 variant, RAR 5's AES with PBKDF2, the password check and the keyed hashes, with encrypted headers too. `Archive::open_with_password` takes the password, and nothing else asks for one: an entry without one stops the reading and says so, and one RAR 5's check refuses says that, both as UnRAR's library does. `Archive::open_volumes` takes a volume's name and how to open others by theirs; `merge_archive` is `MergeArchive`, and an entry's data goes on across volumes, encrypted too. `Archive::get_comment` is `GetComment` and `ReadSubData`. `quick_open` is `QuickOpen`.

What they had to agree on, which is not written anywhere:

- A stream of RAR 1.5 or 2.x goes on into RAR 3's and back. A window can be made again under a solid stream, and reads as zeros; a distance of 0 is copied onto itself; and a table of RAR 3 can decode past what RAR 2's static tables have, which is out of bounds in UnRAR and zero here.
- Entries of RAR 1.3 to 1.5 go by the archive's solid flag and how many entries came before, as they have none of their own.
- RAR 3's SHA-1 goes its own way only on long passwords, so the `crypt` request compares passwords of every length and alphabet.

**A QuickOpen record changes what an archive says.** RAR 5 puts copies of headers near an archive's end, each with where it belongs, and a main header's locator says where they are. UnRAR's library has them on, so while a record is loaded every read at such a place gets the copy and not what is there, for data as for headers. A copy passes the same CRC as a header, and nothing compares it with the header it stands for, so one archive can show one list of files to UnRAR and another to a reader that does not take QuickOpen into account, which is why the port follows it and the oracle runs with it on. The rest of what it comes to:

- The `Read`, `Seek` and `Tell` of `Archive` go by the record's position, and the file's own position goes its own way. When a record fails, reading goes on from wherever the file is, if a read was the last thing to touch it.
- `FileLength` goes by way of `Seek` and `Tell`, and going back before the copy at hand reads the record again from its start, so asking how long a file is can change the reading.
- `SubHead` is read when it is needed and not when the record is loaded: another service header on the way changes whether the record is taken as encrypted, and with what keys. Reading the record also leaves its own header in `SubHead`, and the check value of its keys.
- A record with no password for it is dropped without a word, with the file wherever it was.
- A locator further than `lseek` can go is a fatal error, `Error::BadSeek`, and a record of some other name is passed over.
- A copy of 2 MiB is out of reach. A block's size has three bytes, and a block saying more than those can is taken as invalid, which ends the record, before the check on a copy's size in `ReadNext` can say anything.

No archive at hand gives a record any trouble, so `tests/support/patch.rs` makes one from a fuzzer's bytes, `with_quick_open`, with its CRCs right: copies true or false, of other sizes, around the end of the record's 64 KiB buffer. `quick_open_copies_stand_for_headers` checks that the copies are what is read, because these inputs compare the same when no record is found: a mistake in the patch did that at first, and only mutants showed it.

Of 45 mutants of `quick_open` and what calls it, what CI runs catches 30. Of the 15 left, 7 change nothing: the locator's flag, which an offset cannot be set without, a position set again before it is read, the threshold for moving the buffer, which a block crossing its end does not depend on, the two checks of a block's size, either of which is enough as a size that does not end reads as 0, and the two limits on a copy's size. 5 next to nothing: what `FileLength` leaves when reading is over, `SubHead`'s check value, which nothing reads afterwards, and how many bytes of a last incomplete encrypted block are decrypted. The other 3 are not reached: a volume without a record after one with, a file's header at the locator with a record's service header before it, and a read of the file, then of a copy, then of the file.

They agree in a run by hand on this code, with `HIVEPACK_RAR_DAMAGED=300`: 37,500 damaged copies listed, 37,500 tested and 37,500 with damaged headers, 14,400 encrypted, 247,566 for comments and 74,277 of 82 sets of volumes, whole, from any volume, one missing and damaged, all with QuickOpen on. For the record itself, 5,000 inputs at random and the 636 the fuzzer found in six minutes, each read four ways: listed, tested without and with a password, and for its comment.

`testdata/oracle/rar-unpack-old.txt`, `rar-password.txt`, `rar-volumes.txt` and `rar-quick-open.txt` hold what the `rar_unpack_old`, `rar_password`, `rar_volumes` and `rar_quick_open` fuzz targets found, with UnRAR's answers, replayed everywhere.

**Step 4, extracting.** `hivepack::extract::extract_rar`, with that crate's feature `rar`, reads an archive twice, as `extract_tar` does. `Extract::headers_only` makes the first reading go through what the second will, without decompressing, because a list made by another route could differ: what follows a directory's header is read as a header whatever its pack size says, and a split entry goes on through `MergeArchive`. It stops the reading on anything UnRAR's library would report, a broken header, a missing volume or password, and RAR 5's check of the password, before anything is written. `Extract::link_targets` reads a RAR 4 Unix link's target as `ExtractUnixLink30` does: raw from where its data would be, never through a decompressor, up to `MAXPATHSIZE`.

The rules are `hivepack::extract`'s (see [extract.md](extract.md)), not UnRAR's own (`IsRelativeSymlinkSafe`, `ConvertPath`, which drops what climbs and writes the rest): a name or link that leaves the destination is refused, not cleaned. A name's `\` is what UnRAR on Linux makes it, on every system: a separator in RAR 4, and in RAR 5 `_` from Windows, kept from Unix, which the checks refuse. A file in a solid stream is held to its share of the stream's compressed data, as 7z's folders are. A file copy is a copy of what was extracted before it, and a hard link or file copy to anything else is refused.

On 158 archives of those four projects, what `extract_rar` writes is what `hivepack::rar` reads, 306 files by their bytes. The archives behind WinRAR's CVE-2023-38831, CVE-2025-8088 and CVE-2025-6218 and 7-Zip's CVE-2026-58052 are patched copies, in `crates/hivepack/tests/extract_rar.rs`, stored and with the names that did the harm: nothing here compresses. The `extract_rar` fuzz target found that a file copy, which writes under any option, was not counted in what progress says is to be written, and ran six minutes after the fix with no finding.

## The order of work

1. **Headers and stored data**, done. The signature, after a self-extracting module or not; the headers of RAR 1.4, 1.5 to 4.x and 5.0, their CRCs and RAR 5's extra records; listing; the data of stored entries, checked against CRC-32 or BLAKE2sp. `hivepack::crypto` gets BLAKE2s and BLAKE2sp.
2. **Decompression**, done: RAR 2.9/3.x (its LZ, PPMd and standard filters), and RAR 5.0 and 7.0, solid archives included. RAR 7's algorithm is only reached by the copies above, as no archive at hand uses it.
3. **The rest of reading**, done: QuickOpen records, encryption (RAR 1.3, 1.5, 2.0, 3.x and 5.0, headers too; `hivepack::crypto` gets AES decryption, HMAC-SHA256 and PBKDF2-HMAC-SHA256), volumes, comments, RAR 1.5 and 2.x compression.
4. **Extracting**, done: `extract_rar` in `hivepack::extract`, through its rules, with RAR's links and times, and the archives behind RAR's CVEs (WinRAR's CVE-2025-8088 and CVE-2025-6218, 7-Zip's CVE-2026-58052).

Each step is a pull request or a few, with its tests against the oracle.

## Questions to settle

- **Names in RAR 4 archives without Unicode** are bytes in the creating system's code page, which UnRAR decodes with the system's own. The port will take them as UTF-8 when they are valid UTF-8 and give the raw bytes otherwise, and the oracle will run in a UTF-8 locale; whether to decode them as a Windows code page by the archive's host system is to be decided with the archives in hand.
- **Memory**: RAR 7 dictionaries go to 64 GB. UnRAR asks before allocating one over its limit (`-mdx`); the port will refuse a dictionary over a limit the caller sets, 4 GB by default.
