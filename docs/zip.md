# Porting libzip

`hivepack-zip` will read and write ZIP archives. Its container logic is a port of [libzip](https://libzip.org) to safe Rust; its compression and encryption come from hivepack's own crates, each ported from or checked against an official library. What libzip does not do, such as split archives, legacy file name encodings and extracting to disk, is written for hivepack and checked against other implementations.

> **Status:** steps 1 to 4 are done. `hivepack-zip` opens archives, reads their central directory and local headers, and reads stored, deflated, bzip2, LZMA, XZ, Zstandard, Deflate64 and PPMd entries as libzip does (libzip reads no Deflate64 nor PPMd, which are read as zlib's `infback9` and 7-Zip read them), compared with libzip on its own test archives and on generated ones (see [Progress](#progress)). It edits archives, adds and replaces data, stored, deflated, bzip2, LZMA, XZ or Zstandard, and writes them as libzip does, byte for byte, and encrypts and decrypts ZipCrypto and WinZip AES entries, byte for byte as libzip with the same random bytes; 174 of libzip's own tests pass through `tools/ziptool`. What libzip does not do comes next (step 5): split archives are read, from their volumes, compared with 7-Zip.

## Why libzip

ZIP has a specification, PKWARE's [APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) (6.3.10), but no official library: PKWARE sells only a closed SDK. Implementations disagree with each other; a 2025 study had 50 parsers read the same archives and found 1221 of 1225 pairs disagreeing on at least one ([ZipDiff, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-you.pdf)). So the port follows the implementation that comes closest to a reference:

- **libzip** is under BSD-3-Clause, maintained (1.12.1, October 2026), and its stated goal is "Do not create corrupt files, even in case of errors". It has a strict mode that compares every local header with the central directory (`ZIP_CHECKCONS`), 199 regression tests with their archives, and runs on OSS-Fuzz.
- **minizip-ng** (Zlib) reads and writes split archives, but converts legacy file names through `iconv` or the Windows API, and checks paths as strings before it opens them.
- **libarchive** (BSD-2) and Go's `archive/zip` (BSD-3) reject multi-disk archives too, and are less strict.
- **Info-ZIP** has not been released since 2009, and its licence is not one `deny.toml` allows. **7-Zip** is under the LGPL.

None of these is copied from except libzip, but all of them are used as oracles: programs whose answers the tests compare with.

## The version

The port follows libzip **1.12.1** (tag `v1.12.1`, commit `8e037534ccd62f444abbe4ce265443ee74bbfeb3`). As with libzstd, it follows releases, not `main`.

## What following libzip means

The rules are those of [porting.md](porting.md):

- **The same layout.** Each file in `lib/` that is ported maps to a module: `lib/zip_open.c` becomes `crates/zip/src/open.rs`, `lib/zip_dirent.c` becomes `crates/zip/src/dirent.rs`.
- **The same names**, in snake case, without the `zip_` and `_zip_` prefixes: `_zip_find_central_dir` becomes `find_central_dir`. Every ported function's doc comment names its C original and file.
- **The same errors.** libzip's `ZIP_ER_*` codes and its `ZIP_ER_DETAIL_*` details (which say what is inconsistent, and in which entry) become one error type, so a test can check that both reject a file for the same reason.
- **Differences are marked** with a comment starting `Differs from libzip:`.

Unlike libzstd, libzip's value is in its rules, not its algorithms: which end of central directory record it accepts, what it checks and when, what it writes. Those are ported faithfully. Its C interface, built on layers of `zip_source` callbacks, is not; the Rust API reads by position (`ReaderAt`) and writes to `Write + Seek`.

## The map

libzip 1.12.1's `lib/` is about 22,000 lines of C. Roughly half of it is ported.

| libzip | Lines | What happens to it |
|---|---|---|
| `zip_open.c` | 1,039 | Ported: finding the end of central directory (backwards through the last 64 KiB), the Zip64 records, reading the central directory, Info-ZIP's entry count modulo 65,536, `ZIP_CHECKCONS` and the local header comparison, torrentzip detection |
| `zip_dirent.c` | 1,421 | Ported: reading and writing central and local headers, the Zip64, Unicode path/comment and WinZip AES extra fields, DOS times, attributes and `version made by`, the consistency checks |
| `zip_extra_field.c`, `zip_extra_field_api.c` | 896 | Ported |
| `zip_close.c` | 812 | Ported: writing an archive (local header, data, header rewritten once sizes are known, data descriptor, central directory), raw copies of unchanged entries, torrentzip order. Not the cloning of unchanged data (`begin_write_cloning`), which needs reflinks |
| `zip_utf-8.c` | 294 | Ported, then extended: libzip tells ASCII, UTF-8 and CP437 apart; hivepack adds the legacy code pages (see below) |
| `zip_string.c`, `zip_buffer.c`, `zip_io_util.c`, `zip_error*.c` | ~800 | Ported as small helpers; `zip_buffer` becomes a cursor over a slice |
| `zip_winzip_aes.c`, `zip_pkware.c`, `zip_source_winzip_aes_*.c`, `zip_source_pkware_*.c` | ~1,370 | Ported: the encryption framing (salt, password check, authentication code; ZipCrypto's header). The primitives come from `hivepack-crypto` |
| `zip_source_crc.c`, `zip_source_compress.c`, `zip_source_window.c`, `zip_source_zip_new.c`, `zip_algorithm_*.c` | ~2,500 | Their rules are ported (when the CRC and sizes are checked, the parameters given to each codec) into Rust readers and writers. The layering is not |
| `zip_hash.c`, `siphash.c` | 533 | Replaced by `std::collections::HashMap`, which already hashes with SipHash-1-3 and random keys, as libzip 1.12 does to stop hash flooding. Duplicate names are reported as libzip reports them |
| The rest of `zip_source_*.c`, `zip_fdopen.c`, `zip_memdup.c`, `zip_realloc.c`, `compat.h` | ~4,900 | Not ported: C plumbing |
| `zip_crypto_*.c`, `zip_random_*.c` | ~1,600 | Not ported: OpenSSL, GnuTLS, mbed TLS, CommonCrypto and Windows backends, replaced by `hivepack-crypto` (BearSSL's AES, SHA-1 and HMAC; see [crypto.md](crypto.md)); random bytes from `/dev/urandom` on Unix, as `zip_random_unix.c` reads them, and from the caller elsewhere |
| The editing API (`zip_add.c`, `zip_delete.c`, `zip_rename.c`, `zip_set_*.c`, `zip_unchange*.c`, …) | ~2,000 | Ported as an editor over `zip_close`'s model: an entry's original header plus its changes, written out as a new archive |

## What libzip does not do

These are hivepack's own, and each one has its own oracles.

| Missing from libzip | Where it shows | hivepack | Checked against |
|---|---|---|---|
| Split archives (`.z01`, `.z02`, …, `.zip`) | `check_eocd` and `_zip_read_eocd64` fail with `ZIP_ER_MULTIDISK` | Reading: `Volumes`, which joins the volumes as one byte space and tells where each starts, so that each disk's offsets count from its start (done, see [Split archives](#split-archives)). A writer that splits: later. A single volume on its own still fails with `ZIP_ER_MULTIDISK` | 7-Zip and Info-ZIP `zip -s` (done); minizip-ng, Commons Compress |
| `.zip.001` volumes | Not a ZIP feature: 7-Zip splits the bytes | The same `Volumes`, joined end to end (done) | 7-Zip |
| Legacy code pages | `zip_utf-8.c` knows only CP437 | Tables for CP932, CP936, CP949, CP950, CP866, CP1258 and others, chosen by the caller or guessed | 7-Zip `-mcp`, `unzip -O`, libarchive `hdrcharset`, Python `metadata_encoding` |
| Deflate64 and PPMd | Not among libzip's methods | Deflate64: read with `hivepack-deflate`'s `Inflate9`, which decodes as zlib's `contrib/infback9` (done). PPMd (method 98, PPMd var.I rev. 1): read with `ppmd8.rs`, the port of 7-Zip's `Ppmd8.c` and `Ppmd8Dec.c`, as 7-Zip's ZIP handler reads it (done) | 7-Zip, libarchive's test archives |
| Writing to a stream | `add_data` seeks back to rewrite the local header, and forces Zip64 when the size is unknown | A streaming writer with data descriptors | Every oracle reads what it writes |
| Reading a stream | Needs a seekable source | An opt-in streaming reader that checks what it read against the central directory at the end | libarchive's streaming reader |
| Parallel work | One thread | Entries decompressed in parallel through `ReaderAt`; compressed in parallel and written in order | The single-threaded output, byte for byte |
| Extracting to disk | None: libzip is an archive library | `hivepack-extract`, shared with tar and RAR, safe by default (see [extract.md](extract.md)) | ZipDiff samples, David Fifield's zip bombs, the archives behind recent CVEs in other extractors |

## Strict by default

libzip compares local headers with the central directory only with `ZIP_CHECKCONS`. Without it, `_zip_file_get_offset` reads a local header only for its length, so an archive whose local and central headers disagree opens, and different tools extract different files from it, which is how parser differentials are exploited. hivepack reads with `ZIP_CHECKCONS`'s checks on by default; libzip's default behaviour is the lenient option.

Two further checks are additions, marked `Differs from libzip:`: entries whose data overlap are refused (the non-recursive zip bomb), and the central directory is read under a limit on entries and memory. libzip keeps every entry in one array, sized from the end of central directory record once the record has been checked against the file's length; the port keeps the array.

## How it is shown

- **Reading.** Every archive in libzip's `regress/` is opened by the port and by libzip, with and without `ZIP_CHECKCONS`, from a buffer and from a file. Both must accept or refuse it, with the same error code and detail. The comparison goes through `tools/zip-oracle`, a small C program built from libzip 1.12.1's sources, as `tools/zstd-oracle` is built from libzstd's. For an archive that opens, the oracle answers what the reading API says about every entry: its name raw, guessed and strict, `zip_stat_index`, the external attributes, the comment, the extra fields of the central directory and of the local header, where its data starts, and `zip_name_locate` of its name with each flag. `crates/zip/tests/oracle.rs` also generates archives: names in ASCII, UTF-8, CP437, with NUL bytes, repeated, and with Info-ZIP Unicode fields whose CRC is right or wrong; Zip64 fields and records, right and wrong; WinZip AES fields; data descriptors; padding and garbage after extra fields; local headers that disagree with the central directory; torrentzip comments; prefixes, trailing bytes, wrong counts and disks; and some of them damaged. 1,500 are compared on each run, and 40,000 were before the first commit: every detail libzip reports when opening came up but two, `ZIP_ER_DETAIL_CDIR_LENGTH_INVALID` and `ZIP_ER_DETAIL_EOCD64_WRONG_MAGIC`, which the checks before them leave almost no way to reach. `testdata/oracle/zip-open.txt` replays 742 earlier answers where the oracle is not built (Windows, and the emulated i686 and s390x jobs).

  ZipDiff's archives (`testdata/zipdiff`, USENIX Security 2025), which ZIP parsers read differently, are compared the same way: each of the 5,926 under 1 MiB opened four ways and read three, from the sizes that disagree between headers to several ends of central directory, and the port agrees with libzip on every one. Where parsers disagree, the port takes libzip's side.

  Reading entries is compared the same way, through the oracle's `read` requests: every entry opened with `zip_fopen_index` (decompressed, or raw with `ZIP_FL_COMPRESSED` or `ZIP_FL_ENCRYPTED`), read with `zip_fread` in pieces of one byte to 64 KiB, to its end or to a limit, then closed. The port must return the same from every read, the same data, the same error at the end and the same from `zip_fclose`. The generated entries hold deflate streams from `hivepack-deflate`'s compressor, some cut short, followed by garbage or with a byte changed, and CRCs and sizes right or wrong; what came up includes CRC errors when the end is read and when an entry read to its last byte is closed, wrong lengths, zlib data errors, garbage after a stream with `ZIP_CHECKCONS`, compressed sizes past the end of the file, and local headers that cannot be read. 10,000 requests agreed before the first commit, every regress archive is read four ways on each run, and `testdata/oracle/zip-read.txt` replays 560 answers.

  Decryption is compared through the oracle's `decrypt` requests, which read as `read` does with a password: none, the default one (`zip_set_default_password`), or one given to `zip_fopen_index_encrypted`, alone or over a default. The archives are libzip's own: the oracle's `editb` request adds entries to an empty archive, of up to 9,000 bytes of text, random bytes and runs, stored or deflated, and encrypts them with `zip_file_set_encryption`, with ZipCrypto or WinZip AES-128, AES-192 or AES-256, each with its password or the default one; a quarter are then damaged. They are read with the right password, wrong ones, none, an empty one, and one with a NUL byte, where libzip's C string ends. What came up includes wrong passwords found by ZipCrypto's check byte and by WinZip's verifier, ZipCrypto passwords that pass the check and fail later with zlib or CRC errors, authentication codes that do not match, empty entries, and data cut short. The oracle's libzip is built with its GnuTLS backend, on nettle's sources and the part of GnuTLS it uses, written for the oracle (`tools/zip-oracle/gnutls/`), whose random bytes come from a stream the oracle restarts before each `zip_close`. 1,200 requests, on 400 archives, are compared on each run, and `testdata/oracle/zip-decrypt.txt` replays 365 answers.

  Encryption is compared through the same `edit` and `editb` requests, whose ops `y` (`zip_file_set_encryption`) and `P` (`zip_set_default_password`) encrypt. The port is given the oracle's random bytes (`Archive::set_random_source`), so it must write the same archive, byte for byte. The generated edits encrypt the generated archives; and libzip's archives of encrypted entries are written from nothing, then changed: encrypted anew with another method or password, or no longer, compressed again with the default password right or wrong, given another time, unchanged, replaced, or given a comment. 800 such requests are compared on each run, and `testdata/oracle/zip-encrypt.txt` replays 395.

  libzip's build writes `config.h`, `zipconf.h` and its error strings with CMake; `scripts/testdata.py` builds the oracle with the C compiler alone, from `tools/zip-oracle/config.h` and `zipconf.h` and the strings generated as CMake would.
- **libzip's own tests.** The 199 `.test` files in `regress/` are scripts for libzip's test programs (`ziptool`, `tryopen` and a few others), run by nihtest. `tools/ziptool` has the port's `ziptool`, with the commands libzip's tests add to it (`ziptool_regress`), `tryopen` and `zipcmp`, with libzip's output word for word, and `tools/ziptool/tests/regress.rs` runs the scripts as nihtest does: the test's files copied into a fresh folder, the program run there, its exit status, output and errors compared, and the files checked afterwards, an archive written as one with the same name with `zipcmp -pv` as libzip's `nihtest.conf` has it (which compares the entries, their sizes, CRCs, methods, comments and extra fields of both headers, in any order), one written as `.nzip` must differ from the `.zip` named (`files_differ`: encrypted with random bytes, not as without them), anything else byte for byte, and no other file may be left. 167 of them run and pass now, among them `zip64_creation`, which adds 4 GiB, every test that encrypts or decrypts, `ziptool_regress_nonrandom`'s byte for byte, and the four that compress to bzip2 and from it. The others wait for what they need: 9 need LZMA, Zstandard or `fts` (`zipcmp` on folders), 10 run other test programs, and 13 need a command or setup the runner does not have yet (cancelling, progress, `zip_fseek`, a source archive closed early, a time zone, cloning, standard input, a source with holes).
- **Editing.** The oracle's `edit` requests open an archive from a file, make a list of edits (delete, rename, set an entry's or the archive's comment, its time in MS-DOS or Unix form, its external attributes, undo one entry's changes or all of them, set an archive flag, add or replace data, add a directory, set the compression method and level), answer each edit's result and what the API then says of every entry, and write the archive with `zip_close`. The port must answer the same and write the same bytes, or nothing where libzip leaves the file as it was or removes it. The generated archives are mostly ones that open, so that the edits are made; the edits take names and comments from the archive or make them up, in each encoding flag, with indices in range and not, and times before 1980, after 2107 and past what `localtime_r` takes. 3,000 requests are compared on each run, every regress archive is edited four ways, an archive of 65,539 entries is written with and without the Zip64 end of central directory records, and `testdata/oracle/zip-edit.txt` replays 556 answers. New data comes from a source in memory with a time, its size known or not (which makes the entry Zip64): empty, text, runs and bytes that do not compress, of 1 byte to 20,000, stored, deflated at each level, or `ZIP_CM_DEFAULT`, which stores what does not get smaller; entries are compressed again when their method changes, and converted to torrentzip. The deflate streams are hivepack-deflate's, which are zlib's. The edits include setting and deleting extra fields in either header or both, and the archives are opened with each of `ZIP_CREATE`, `ZIP_EXCL`, `ZIP_TRUNCATE` and `ZIP_RDONLY`. The oracle's `editb` requests do the same on a buffer source in fragments of 1 byte to 4 KiB, or one, which clones the start of the archive where it can (`Archive::close_to_cloning`): 2,000 are compared on each run, of which about half clone. Each archive the port writes is opened again and must have the entries that are left, in order, with their names, comments, attributes, times, sizes and data, unless bytes in it look like end records (see below).
- **Writing.** For the same input, the port writes the same archive as libzip, byte for byte. libzip compresses with zlib's raw deflate (`windowBits` −15) at level 9 and `memLevel` 9 unless told otherwise (`zip_algorithm_deflate.c`), so this needs `hivepack-deflate` to give zlib's output at those settings, with libbzip2 at block size 9 and work factor 30 unless told otherwise (`zip_algorithm_bzip2.c`), which `hivepack-bzip2` gives the output of (see [bzip2.md](bzip2.md)), and with liblzma at preset 6 and its extreme flag unless told otherwise (`zip_algorithm_xz.c`), `.lzma` with a ZIP header of its own for method 14 and `.xz` with CRC64 for method 95, which `hivepack-xz` gives the output of (see [xz.md](xz.md)). Torrentzip output is compared too.
- **LZMA and XZ.** The oracle builds libzip's `zip_algorithm_xz.c` with liblzma 5.8.4. The generated archives have LZMA entries, with the end of stream marker (general purpose bit 1) or without it and with the size from the central directory, now and then with the bit saying otherwise, and `.xz` entries at random presets and checks, cut short, with garbage after them or a byte changed; edits compress entries again with both methods at every level. libzip's five `set_compression` tests of LZMA and XZ, which `tools/ziptool` now takes, pass too. Like libzip built with its defaults, the port sets no limit on the window of an LZMA or XZ entry, so a header can ask for 4 GiB, reserved and written only as far as data is decoded; the fuzz targets are built with a limit of 300 MiB (libzip's `LIMIT_LZMA_WINDOW`), since libFuzzer counts what is reserved.
- **Zstandard.** The oracle builds libzip's `zip_algorithm_zstd.c` with libzstd 1.5.7. The generated archives have Zstandard entries at low levels, with a checksum and the content size or not, some in two frames or after a skippable frame, cut short, with garbage after them or a byte changed; edits compress entries with it, and a test writes 300 KB at every level libzip can reach. Three things libzip does are kept: its `map_error` is given what libzstd's functions return, not `ZSTD_getErrorCode` of it, so every Zstandard error is `ZIP_ER_INTERNAL`, damaged data included, where `ZIP_ER_COMPRESSED_DATA` was meant; `zip_set_file_compression` cuts the flags to 16 bits, so negative levels are out of range and leave the level to libzstd; and a frame cut short is not an error of the method (it has no end to wait for), so the read ends and the CRC-32 says so (`ZIP_ER_CRC`). libzip's two `set_compression` tests of it pass too.
- **Fuzzing.** A fuzzer compares the port with the libzip oracle under AddressSanitizer, seeded with libzip's OSS-Fuzz corpus. For now `fuzz/fuzz_targets/zip_open.rs` opens its input and asks the reading API everything, which must not panic, seeded with the archives of `zip-open.txt`, and `fuzz/fuzz_targets/zip_edit.rs` makes the edits its first bytes pick and writes the archive, which must open again with the entries as edited.
- **Beyond libzip.** Info-ZIP `unzip`, 7-Zip, bsdtar, Python and Go read everything the port writes; ZipDiff's ambiguous archives are read, and where the oracles disagree, the manifest records which one hivepack follows.

## The speed

`tools/zip-bench` times the port against libzip on the same archives, in each thing an archive library does. libzip runs in a program of its own, `tools/zip-oracle/bench.c`, built with the same sources as the oracle: libzip 1.12.1, zlib 1.3.2, nettle 3.10.2, bzip2 1.0.8 and XZ Utils 5.8.4.

```sh
python3 scripts/testdata.py fetch --group bench
cargo run --release -p zip-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
```

AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the 12 Silesia files cut to 64 MiB in all, on a nearly idle machine. Each speed is the best of five rounds taken in turn. Opening and finding were measured after the work on opening below, and editing after the work on closing, the other rows before them, as that work does not touch them. "Small" entries are 20,000 pieces of 4 KiB (2,000 for AES), and "many" 200,000 entries of 16 bytes with paths for names. Everything the two wrote without encryption was the same, byte for byte.

| Workload | hivepack-zip | libzip | Port / libzip |
|---|---|---|---|
| **Opening many entries** | | | |
| Open | 5028 k entries/s | 6477 k entries/s | 0.78× |
| Open with `ZIP_CHECKCONS` | 4325 k entries/s | 3327 k entries/s | 1.30× |
| **Finding, many entries** | | | |
| `zip_stat_index`, each entry | 51041 k entries/s | 19098 k entries/s | 2.67× |
| `zip_name_locate`, each entry | 12497 k entries/s | 10783 k entries/s | 1.16× |
| **Reading** | | | |
| Stored | 5170 MB/s | 3773 MB/s | 1.37× |
| Deflate | 495 MB/s | 469 MB/s | 1.06× |
| bzip2 | 56.3 MB/s | 55.5 MB/s | 1.01× |
| LZMA | 127 MB/s | 166 MB/s | 0.76× |
| XZ | 122 MB/s | 154 MB/s | 0.79× |
| Stored, small entries | 836 k entries/s | 648 k entries/s | 1.29× |
| Deflate, small entries | 85.2 k entries/s | 86.5 k entries/s | 0.98× |
| **Writing** | | | |
| Stored | 2271 MB/s | 1882 MB/s | 1.21× |
| Deflate, level 1 | 147 MB/s | 139 MB/s | 1.05× |
| Deflate, level 6 | 42.8 MB/s | 42.7 MB/s | 1.00× |
| Deflate, level 9 | 22.0 MB/s | 22.0 MB/s | 1.00× |
| bzip2, level 1 | 26.7 MB/s | 26.0 MB/s | 1.03× |
| bzip2, level 9 | 25.5 MB/s | 24.9 MB/s | 1.02× |
| LZMA, level 1 | 5.5 MB/s | 5.4 MB/s | 1.02× |
| LZMA, level 6 | 4.5 MB/s | 4.5 MB/s | 1.02× |
| XZ, level 1 | 5.4 MB/s | 5.4 MB/s | 1.02× |
| XZ, level 6 | 4.6 MB/s | 4.6 MB/s | 1.01× |
| Stored, small entries | 260 k entries/s | 208 k entries/s | 1.25× |
| Deflate, small entries | 16.1 k entries/s | 16.8 k entries/s | 0.96× |
| **Decrypting** | | | |
| ZipCrypto | 115 MB/s | 124 MB/s | 0.93× |
| WinZip AES-128 | 206 MB/s | 325 MB/s | 0.64× |
| WinZip AES-256 | 169 MB/s | 273 MB/s | 0.62× |
| WinZip AES-256, small entries | 1.2 k entries/s | 2.1 k entries/s | 0.57× |
| **Encrypting** | | | |
| ZipCrypto | 221 MB/s | 245 MB/s | 0.90× |
| WinZip AES-128 | 194 MB/s | 294 MB/s | 0.66× |
| WinZip AES-256 | 160 MB/s | 251 MB/s | 0.64× |
| WinZip AES-256, small entries | 1.2 k entries/s | 2.1 k entries/s | 0.57× |
| **Editing** | | | |
| Rename one entry, the data copied | 9814 MB/s | 6174 MB/s | 1.59× |
| Add one entry, the data copied | 9584 MB/s | 6138 MB/s | 1.56× |
| Rename each of many entries | 1523 k entries/s | 1041 k entries/s | 1.46× |
| Set each of many entries' comment | 3343 k entries/s | 1683 k entries/s | 1.99× |
| Delete half of many entries | 4642 k entries/s | 3079 k entries/s | 1.51× |

What to read in it:

- **Compression and decompression** are the speed of hivepack's other ports, which their own documents go into: Deflate and bzip2 at their libraries' speed, and LZMA and XZ reading below liblzma's on x86-64, where its range decoder is inline assembly ([xz.md](xz.md)). Writing them, where the compressor is most of the time, is even.
- **Opening many entries** went from 0.33× to 0.78×, and with `ZIP_CHECKCONS` from 0.35× to 1.30×, once the port read ahead (`stdio` does that for libzip, and without it each entry was a system call or two) and stopped allocating and copying for each entry. About a quarter of what is left is hashing names. libzip hashes with SipHash and random keys too, and the port keeps them, so that an archive cannot be made to collide on purpose.
- **Editing many entries** went from 0.48–0.61× to 1.46–1.99×. Closing was five system calls an entry: asking a `BufWriter` where it is writes out its buffer, so each entry's `tell` was a write and a seek, and each read of a local header or of data a `pread`, from a view of the source of its own. Now the writer keeps its position, and the entries share a read ahead, for about 1% of the system calls, and share one copy buffer where each had 8 KiB allocated and cleared.
- **AES** compares two different things. libzip here uses nettle's C code, with no AES instructions and table lookups, where BearSSL's `aes_ct64`, which the port uses, runs in constant time. A profile of the AES-256 workloads, reading and writing, gives 44% to SHA-1 (WinZip AES authenticates with HMAC-SHA1, and hashes its key with PBKDF2) and about 30% to AES. A libzip that uses the processor's AES instructions, as a usual build with GnuTLS or OpenSSL does, would be further ahead than this table shows.
- **Not compared:** Deflate64 and PPMd, which libzip does not have, and split archives. Files are read and written on the machine's disk, through its cache.

## Progress

| libzip | Port | Status |
|---|---|---|
| `zip_error.c`, `zip_error_strerror.c`, `zip_err_str.c` (generated) | `error.rs` | done |
| `zip_buffer.c`, `zip_io_util.c`, `zip_string.c` | `buffer.rs`, `io_util.rs`, `string.rs`, `source_write.rs` (`_zip_write`) | done |
| `zip_utf-8.c` | `utf_8.rs` | done |
| `zip_extra_field.c`, `zip_extra_field_api.c` | `extra_field.rs`, `extra_field_api.rs` | done |
| `zip_dirent.c` | `dirent.rs` | done but `_zip_dirent_apply_attributes`, which comes with new data |
| `zip_open.c`, `zip_new.c` | `open.rs` | done |
| `zip_hash.c` | `hash.rs` | its rules, on `HashMap` |
| `zip_name_locate.c`, `zip_get_name.c`, `zip_stat_index.c`, `zip_stat_init.c`, `zip_file_get_comment.c`, `zip_file_get_external_attributes.c`, `zip_get_archive_comment.c`, `zip_get_archive_flag.c`, `zip_get_num_entries.c` | modules of the same names, `zip.rs` | done |
| `zip_file_get_offset.c` | `file_get_offset.rs` | done |
| The reading rules of `zip_source_seek.c`, `zip_source_read.c`, `zip_source_tell.c`, `zip_source_accept_empty.c`, and the file and buffer sources | `source.rs` | done |
| `zip_fopen.c`, `zip_fopen_index.c`, `zip_fopen_index_encrypted.c`, `zip_fopen_encrypted.c`, `zip_fread.c`, `zip_fclose.c`, `zip_set_default_password.c` | modules of the same names | done |
| `zip_pkware.c`, `zip_source_pkware_decode.c`, `zip_source_pkware_encode.c`, `zip_winzip_aes.c`, `zip_source_winzip_aes_decode.c`, `zip_source_winzip_aes_encode.c`, `zip_get_encryption_implementation.c`, `zip_file_set_encryption.c` | modules of the same names | done, on `hivepack-crypto` |
| `zip_random_unix.c` (`zip_secure_random`) | `random.rs` | `/dev/urandom` on Unix, or the caller's `RandomSource` |
| `zip_source_zip_new.c`, `zip_source_window.c`, `zip_source_crc.c` | modules of the same names | the reading of a whole entry |
| `zip_source_compress.c`, `zip_algorithm_deflate.c`, `zip_algorithm_bzip2.c`, `zip_algorithm_xz.c`, `zip_algorithm_zstd.c` | `source_compress.rs`, `algorithm_deflate.rs`, `algorithm_bzip2.rs`, `algorithm_xz.rs`, `algorithm_zstd.rs` | decompressing deflate, bzip2, LZMA, XZ and Zstandard |
| The rules of `zip_source_read.c`, `zip_source_open.c`, `zip_source_close.c`, `zip_source_at_eof.c`, `zip_source_stat.c`, `zip_source_layered.c` for those layers | `source_stack.rs` | done |
| Deflate64 (libzip has none) | `algorithm_deflate.rs`, with `Inflate9` | done: `tests/deflate64.rs` reads streams with long and far matches back to their data, checks the CRC and length, and refuses garbage after the stream with `ZIP_CHECKCONS` |
| PPMd (libzip has none): 7-Zip 26.05's `Ppmd8.c` and `Ppmd8Dec.c`, built without `PPMD8_FREEZE_SUPPORT` as 7-Zip is, and `PpmdZip.cpp`'s decoder for what to do with the stream | `ppmd8.rs`, `algorithm_ppmd.rs` | done: see [PPMd](#ppmd) |
| Split archives (libzip refuses them) | `volumes.rs`, and the disks in `open.rs` | done: see [Split archives](#split-archives) |
| `zip_source_zip_file_create` with a start and a length | `source_zip_new.rs`, `source_window.rs` (`UpperWindow`) | done: `Archive::fopen_index_range`, compared through the oracle's `range` requests |
| `src/ziptool.c`, `regress/programs/ziptool_regress.c` and `tryopen.c`; `src/zipcmp.c` and `diff_output.c` for archives | `tools/ziptool` | done: 167 of libzip's tests pass |
| `zip_delete.c`, `zip_file_rename.c`, `zip_set_name.c`, `zip_file_set_comment.c`, `zip_set_archive_comment.c`, `zip_file_set_mtime.c`, `zip_file_set_external_attributes.c`, `zip_set_archive_flag.c`, `zip_unchange.c`, `zip_unchange_all.c`, `zip_unchange_archive.c`, `zip_unchange_data.c` | modules of the same names, `zipint.rs` | done |
| `zip_close.c` | `close.rs` | done: written in whole (`Archive::close_to`) or with what is kept cloned (`Archive::close_to_cloning`), new data and recompression (`add_data`), torrentzip |
| `zip_file_add.c`, `zip_file_replace.c`, `zip_add_entry.c`, `zip_dir_add.c`, `zip_set_file_compression.c` | modules of the same names | done |
| `zip_source_buffer.c`, `zip_source_file_common.c`, `zip_source_file_stdio.c`, `zip_source_get_file_attributes.c`, for new data | `source_data.rs` (`BufferSource`, `FileSource`, `DataSource`) | done |
| `zip_source_zip.c` | `source_zip.rs` (`ZipFileSource`) | done |
| `zip_source_compress.c`, `zip_algorithm_deflate.c`, `zip_algorithm_bzip2.c`, `zip_algorithm_xz.c`, `zip_algorithm_zstd.c`, compressing | `source_compress.rs`, `algorithm_deflate.rs`, `algorithm_bzip2.rs`, `algorithm_xz.rs`, `algorithm_zstd.rs` | done |
| The layering in `add_data`, and `zip_source_get_dostime.c` | `source_stack.rs` (`WriteStack`) | done |
| The writing commands of `zip_source_write.c`, `zip_source_tell_write.c`, `zip_source_seek_write.c`, `zip_source_commit_write.c` | `source_write.rs` | on a `Write` and `Seek` |

Where the port differs from libzip, a `Differs from libzip:` comment says so. The differences so far:

- An archive is read through `ReadAt`, reads at a position, in place of a stack of `zip_source_t` callbacks; `Source` keeps the position and the rules of libzip's file and buffer sources (a seek outside the source fails with `ZIP_ER_INVAL`, reads stop at the length it had when opened, a failed read fails all later ones, and an empty buffer is an empty archive but an empty file is not one).
- Names are returned whole: libzip returns C strings, which end at a NUL byte in a name (`ZIP_CHECKCONS` refuses such names). Lookups compare names as libzip does, up to their first NUL.
- Times are taken as UTC, where libzip calls `mktime` in the machine's time zone; the oracle runs with `TZ=UTC`. `Archive::file_get_dos_time` gives the time as stored.
- The system error of an error is described by the standard library, whose text is `strerror`'s on Unix.
- `zip_source_zip_file_create` sets `ZIP_ER_COMPNOTSUPP` on the archive's error, not on the error it is given, which stays `ZIP_ER_OK`; `Archive::fopen_index_range` returns `ZIP_ER_COMPNOTSUPP`. The port's `ziptool` prints libzip's "No error" there.
- An entry is read through a struct of layers (a window on the archive, then decompression, then the CRC check), each with the state libzip keeps in its `zip_source_t`, in place of a chain of callbacks. Each open entry reads through a view of the archive's source with its own position, so several can be read at once from `&Archive`; a failed read fails only that entry's later reads.
- An archive is written by `Archive::close_to` to a `Write` and `Seek` of the caller's, from scratch, as libzip writes to a source that cannot clone the data it keeps; `Closed` says whether it wrote, or whether libzip would have left the file as it was or removed it. `Archive::close_to_cloning` writes as libzip does to a source that can clone, which keeps the start of the archive as it is: it asks the caller whether that length can be cloned, as libzip asks the source, and copies it from the archive's source. The archive stays open afterwards, where libzip discards it once written. On failure, both leave the archive as it was then.
- `Archive::close_to_stream` writes to a `Write` alone, which libzip has no way to do: an entry written here has a data descriptor, and no CRC or sizes in its local header, and the header is written after the first read, as compressing may give way to storing then.
- New data is a `DataSource`: its stat, attributes and MS-DOS time, and reads at a position, so that it can be shared and read by several open entries and by closing at once, where libzip seeks one source before each read. `BufferSource` and `FileSource` are libzip's buffer and file sources; `ZipFileSource`, its `zip_source_zip_file`, reads the entry once, in whole, the first time its data is asked for.
- Where an entry's method changes, a Deflate64 or PPMd entry is decompressed and compressed again, where libzip, which reads neither, fails with `ZIP_ER_COMPNOTSUPP`; the comparison with the oracle expects libzip's refusal there, if the rest of the answer agrees.
- An archive can be cloned, with its changes, when its source can, which `ziptool` uses to open an entry with `fopen` while the archive is changed afterwards, as libzip's open entries read what they were opened on.
- A size or offset of exactly 0xffffffff, which the header has as 0xffffffff, has its value in the Zip64 extra field too, and so has a disk number the header has as 0xffff when the field is written: libzip adds a value only when it is larger than 0xffffffff, and never the disk number, so it then refuses the archive it wrote, with `ZIP_ER_INCONS` and `ZIP_ER_DETAIL_INVALID_ZIP64_EF`. The comparison with the oracle expects a different archive there, if the rest of the answer agrees and libzip's archive does not read back; `zip64_edge_values_read_back` writes such entries and checks that the port's does, and that libzip's does not.
- `zip_file_set_mtime` takes the time as UTC, as `_zip_u2d_time` does with `localtime_r` where the time zone is UTC, and fails as `localtime_r` does for a year past what an `int` holds, with the platform's `EOVERFLOW` (75 on Linux, 84 on macOS and the BSDs); the recorded answers, from Linux, are replayed with 75 for it.
- A comment longer than 65,535 bytes is refused with `ZIP_ER_INVAL`, where libzip's `zip_uint16_t` length cuts it. `zip_unchange_all` and `zip_unchange_archive`, which cannot fail, return nothing.
- The oracle clears `errno` before each request, and in edit requests before each edit, each entry's answers and `zip_close`: libzip gives it, stale, with `ZIP_ER_SEEK` when a local header's extra fields cannot be reached, where the port gives 0.
- WinZip AES decrypts four blocks of counter at a time, as `hivepack-crypto`'s AES encrypts them, where libzip encrypts one; the data is the same. `zip_set_default_password`, which cannot fail but for memory, returns nothing. A password is taken up to its first NUL byte, as libzip takes a C string. Where `zip_source_zip_file_create` cannot make the decrypting layer because the data is shorter than its header, it sets `ZIP_ER_OPNOTSUPP` on the archive's error and not on the one it is given, as with `ZIP_ER_COMPNOTSUPP`; the port's `ziptool` prints "No error" there too. The random bytes that encrypting takes come from `/dev/urandom` on Unix, read with the standard library, as `zip_random_unix.c` reads them, or from a `RandomSource` the caller gives (`Archive::set_random_source`), which they must where the system is not Unix: libzip asks Windows' and Apple's functions, which need `unsafe` code. `ziptool_regress_nonrandom`, whose random bytes are zeros, is the port's `ziptool` with `HIVEPACK_ZIPTOOL_NONRANDOM` set. Of the compression methods, deflate and bzip2 are read and written, as the oracle's libzip is built with libbzip2 (bzip2 1.0.8's sources) and without LZMA and Zstandard, and Deflate64 and PPMd are read, which libzip does not read: where libzip refuses such an entry with `ZIP_ER_COMPNOTSUPP` (once the password and sizes are checked, before the local header is read), the port reads it. The comparison with the oracle expects libzip's refusal there, and `tests/deflate64.rs` and `tests/ppmd.rs` check the data. The generated archives give method 97 (WavPack), which nothing reads, to the bytes that stand for a method without a reader.

libzip's ways that the port keeps, though they surprise:

- Comments, names and data are written as they are, so bytes in them that look like an end of central directory record, or a Zip64 one and its locator, can be taken for the real one when the archive is read again.
- An archive comment removed with `zip_set_archive_comment` is still given by `zip_get_archive_comment` until the archive is written without it.
- An AES entry of AE-2 is written as AE-1, with its CRC, when it has 20 bytes or more. Its CRC is then checked when it is read, though AE-2 left it as it was (often zero), so it may not read again.
- Until the archive is written, an entry whose data was replaced has the method it had in its stat, and is read with it; one whose method is set to `ZIP_CM_DEFAULT` has 65,535, the method as a `zip_uint16_t`. An entry compressed again takes the length it decompresses to, which its header may have wrong, and its time from its stat, so an MS-DOS date out of range comes back in range.
- An entry deleted and then given changes (`zip_set_file_compression` and others do not check) has its name again, though it is not written.
- An entry encrypted anew is read through the layers that decrypt and decompress it, and the layer that encrypts stops reading at the first short read, so the data is never read to its end: its CRC is never checked (and `zip_close` ignores what closing the source says), and it is written with the CRC and length of its data, and the time of its stat.
- An entry whose general purpose flags have the strong encryption bit (6) without the encryption bit (0) keeps bit 6 when it is encrypted, so it reads back as encrypted with an unknown method (`ZIP_EM_UNKNOWN`), which nothing decrypts.
- An entry compressed again and encrypted with ZipCrypto keeps its MS-DOS time in its header, but the check byte of its encryption header comes from the time of its stat: from a time out of range (hour 24, say), put back in range, so that the password it was encrypted with is refused (`tests/oracle.rs`, `zipcrypto_check_byte_of_a_time_out_of_range_moves`).
- ZipCrypto encrypts with an empty password, which `zip_file_set_encryption` takes, but reading takes an empty password for none, so such an entry cannot be read; WinZip AES refuses it with `ZIP_ER_INVAL` when writing.
- An encrypted entry whose compression method is changed is decrypted with its compressed size unknown, as `zip_stat_index` leaves it out once the method changes: from a file, which does not tell it, that fails with `ZIP_ER_OPNOTSUPP`; from a buffer, which gives its own length, ZipCrypto works and WinZip AES reads past the entry and fails with `ZIP_ER_EOF`.

### PPMd

ZIP's method 98 is PPMd var.I rev. 1 [APPNOTE 5.10]: two bytes, little-endian, with the model's order less one (bits 0 to 3), its memory in MiB less one (bits 4 to 11) and what is done when that runs out (bits 12 to 15: restart the model, cut it off, or freeze it), then the range coder's bytes, to an end marker. libzip has no reader for it, and the reference is 7-Zip's: `ppmd8.rs` is a port of `Ppmd8.c` and `Ppmd8Dec.c` from 7-Zip 26.05 (public domain), on a byte array with 32-bit offsets as hivepack-7z's `ppmd7.rs` is, and `algorithm_ppmd.rs` reads the stream as `PpmdZip.cpp`'s decoder does in the full-file mode 7-Zip's ZIP handler sets:

- An order of 1 or a restore method past 2 is a data error (`ZIP_ER_COMPRESSED_DATA`); freezing the model (2) is not supported (`ZIP_ER_COMPNOTSUPP`), as 7-Zip is built without it. The memory, up to 256 MiB, is allocated zeroed, so that the system gives pages only as the model reaches them.
- The data must end with the marker, the range decoder there with nothing left to read (`Ppmd8_RangeDec_IsFinishedOK`), and no byte may be read past the data: otherwise a data error, after the bytes decoded before it. What follows the marker is the compressing layer's to refuse, with `ZIP_CHECKCONS` (`ZIP_ER_INCONS`, `ZIP_ER_DETAIL_COMPRESSED_DATA_TRAILING_GARBAGE`), as after the other methods' data; 7-Zip always refuses it.
- A symbol is decoded only with 1 KiB of input waiting, or all of it: it reads at most 8 bytes in each of at most 17 contexts, so that it reads what it would from the whole data, however the data comes. Its input has then always ended before the marker is read, where libzip's algorithms end before the end of their input is known, and are asked then what they kept; the compressing layer asks PPMd what is left after the marker instead.
- The divisions the C code makes by a context's total frequency (`CreateSuccessors`), by the escape frequency (`Rescale`) and by the range coder's total and range (`RC_GetThreshold`) cannot be by 0 in a model built from any input, though nothing in the code says so: the port divides by 1 in the first two and gives a data error in the last, where the C code would crash.

`src/ppmd8_oracle.rs` compares the decoder with 7-Zip's through `tools/7z-oracle`, built with `Ppmd8.c`, `Ppmd8Dec.c` and `Ppmd8Enc.c`: streams the oracle encodes from text, noise, runs, records and small alphabets, at orders 2 to 16 and with 4 KiB to 3 MiB (so that the model runs out of memory and is restarted or cut off), decoded whole, stopped early, with bits flipped, cut short, with bytes after them and with another model than they were made with. 1,000 requests are compared on each run, every function of the port reached, and `testdata/oracle/ppmd8.txt` replays 626 where the oracle is not built. `tests/ppmd.rs` reads archives `7zz` makes at levels 1, 5 and 9 and orders 2 to 16 with 1 MiB to 256 MiB, plain, with ZipCrypto and with WinZip AES, back to their files; refuses the copies with a bit flipped where `7zz t` refuses them, and reads the others; and reads libarchive's PPMd test archives, refusing the two that crashed it. The `zip_ppmd` fuzz target reads PPMd data in pieces of one byte and of growing sizes, which must give the same bytes and errors.

### Split archives

A split archive [APPNOTE 8.5] is one archive's bytes cut into volumes, or disks: `name.z01`, `name.z02`, …, then `name.zip`, which holds the end of central directory record (WinZip names a ZIPX's `name.zx01`, …, `name.zipx`). Each local header's offset counts from the start of the disk its central directory record names, the central directory's from the start of the disk the end record names, and the Zip64 records' likewise. libzip reads none: `check_eocd` and `_zip_read_eocd64` refuse any disk but 0 with `ZIP_ER_MULTIDISK`.

`Volumes` joins the volumes end to end as one source, and `ReadAt::volume_starts` tells where each starts; it is `None` for every other source, which is read as libzip reads it, a single volume of a split archive refused as there. `Volumes::open` finds the volumes by name (`volume_paths`): `name.z01` and on while they are there, then `name.zip`; the same with `zx` for `.zipx`; and 7-Zip's `name.zip.001`, `name.zip.002`, …, which are an archive of one disk cut where 7-Zip chose, read as that archive. From such a source, an archive whose end record (or Zip64 record) says it is on as many disks as there are volumes is read as split:

- The end record's disk is the last volume; the central directory starts on the disk it names, which may not be after the last, and the records the end record counts on its disk may not be more than all (`ZIP_ER_INCONS`, `ZIP_ER_DETAIL_CDIR_INVALID` or `ZIP_ER_DETAIL_CDIR_WRONG_ENTRIES_COUNT`). The Zip64 locator names the disk its record is on, and how many disks there are.
- Each entry's disk must be a volume (`ZIP_ER_DETAIL_CDIR_INVALID`, with the entry's index); its offset then counts from the start of the first volume, and its disk becomes 0, so that everything after, `ZIP_CHECKCONS` among it, reads it as on a single disk, and an archive written from it (`Archive::close_to`) is one of a single disk: the volumes joined.
- An archive on more disks than there are volumes, or fewer, is refused with `ZIP_ER_MULTIDISK`, before libzip's guesses about where a central directory on another disk would be.

`tests/split.rs` reads the split archives of `testdata/zip-split`, made by Info-ZIP's `zip -s 64k` (plain, Zip64 and ZipCrypto), back to the files they were made of; libzip finds the Zip64 one's local headers unlike its central directory under `ZIP_CHECKCONS`, as it does when the same files are zipped with `-fz` into one volume. It splits archives `7zz` makes (deflated, stored, and bzip2 with ZipCrypto) as Info-ZIP does, every header whole on one volume and the data cut where a volume is full, at volume sizes that put the cuts in the data, at the central directory and next to the end record, with the split signature and without: `7zz t` must find each sound, and the port must read the files back. The same archives cut anywhere, headers and records too, which no writer does, read back as well; with a volume missing they are refused with `ZIP_ER_MULTIDISK`, and with two volumes swapped an entry fails. 7-Zip's own `.zip.001` volumes read back too. The `zip_split` fuzz target cuts its input into volumes, reads every entry, and writes the archive again as one of a single disk, which must have the same entries.

## The order of work

1. **CRC-32 and inflate.** The decompressor and checksums of `hivepack-deflate`, ported from zlib 1.3.2 (`crc32.c`; `inflate.c`, `inftrees.c`, `inffast.c`). Nothing compressed can be read before them. Done: see [deflate.md](deflate.md).
2. **Reading.** Errors, buffers, extra fields, headers, file names, `open.rs`; stored and deflated entries; `tools/zip-oracle`, and `tools/ziptool`'s reading commands. Deflate64 entries, with `Inflate9` (see [deflate.md](deflate.md)): done.
3. **Writing.** Writing headers, `close.rs`, the editor; the compressor of `hivepack-deflate` (`deflate.c`, `trees.c`), with output identical to zlib's: done, see [deflate.md](deflate.md). Editing, adding data and writing archives, `ziptool`'s commands and the tests that use them: done.
4. **Encryption.** ZipCrypto and WinZip AES, on `hivepack-crypto` (AES, SHA-1, HMAC and PBKDF2, ported from BearSSL and compared with nettle; see [crypto.md](crypto.md)): decrypting and encrypting, done.
5. **Beyond libzip.** Legacy code pages, split archives (read: done; written: later), streaming, parallel work. `hivepack-extract` is built alongside step 2, so that nothing reads archives to disk without it.
6. **More methods.** bzip2, with `hivepack-bzip2` (see [bzip2.md](bzip2.md)), LZMA and XZ, with `hivepack-xz` (see [xz.md](xz.md)), and Zstandard, with `hivepack-zstd`: done. libzip keeps LZMA2 (method 33) disabled, because 7-Zip cannot unpack it, and so does the port. PPMd (method 98), read as 7-Zip reads it: done.

## Questions to settle first

- **Random numbers** (settled, October 2026). WinZip AES needs a random salt for each entry, and ZipCrypto random bytes for its header. libzip asks the operating system (`zip_random_*.c`). Rust's standard library has no stable API for it yet (`std::random` is nightly-only), and the `getrandom` crate uses `unsafe` and libc. So `hivepack-zip` reads `/dev/urandom` with the standard library on Unix, as `zip_random_unix.c` does, and takes the bytes from the caller elsewhere (`Archive::set_random_source`); an application can use `getrandom` for that.
- **Unsafe code inside dependencies** (settled, October 2026). Only where there is no other way, listed in [safety.md](safety.md#dependencies-with-unsafe-code). Extracting without races needs `openat2`, `openat` with `O_NOFOLLOW`, or `NtCreateFile` relative to a directory handle, which the standard library does not have yet: `hivepack-extract` takes them from cap-std (see [extract.md](extract.md)).
- **Strictness.** Whether `ZIP_CHECKCONS` by default refuses too many real archives (it refuses, for example, an archive comment whose length is wrong) is measured on the test corpora before it is fixed.

## Licences

The port is derived from libzip, which is under BSD-3-Clause (Copyright (C) Dieter Baron and Thomas Klausner). That is why `hivepack-zip` is under BSD-3-Clause, with libzip's notice in its `LICENSE`, as `hivepack-zstd` keeps Meta's. `ppmd8.rs` is derived from 7-Zip's `Ppmd8.c` and `Ppmd8Dec.c`, which Igor Pavlov put in the public domain (from Dmitry Shkarin's PPMd var.I and Dmitry Subbotin's range coder), as hivepack-7z's `ppmd7.rs` is from `Ppmd7.c`; `PpmdZip.cpp`, under the LGPL, was read for what it does, not ported. `hivepack-deflate`, which `hivepack-zip` takes CRC-32 from too, is derived from zlib and is under the zlib license, which asks that altered versions be marked as such. The rest of hivepack stays MIT.

APPNOTE.TXT may not be redistributed (its section 1.4.2), so the repository links to it and does not include it. The test archives from libzip, libarchive, Go, Commons Compress and .NET keep their own licences, listed in [testdata/README.md](../testdata/README.md).
