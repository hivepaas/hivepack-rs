# Porting squashfuse

`hivepack::squashfs` reads SquashFS images in safe Rust: snap packages, the image inside an AppImage, Linux live systems' root file systems, and what `mksquashfs` makes. It is a port of the reading library of [squashfuse](https://github.com/vasi/squashfuse), by Dave Vasilevsky, under the BSD-2-Clause license, with `squashfs_fs.h`, Phillip Lougher's, under the same license with his permission. squashfuse's library is what AppImage's runtime mounts an AppImage with, and reads every SquashFS 4.0 image that Linux reads. Only the library is ported, not the FUSE programs, and nothing writes.

[open.md](open.md) tells an image by its magic, and [extract.md](extract.md#squashfs) extracts one.

## The version

The port follows squashfuse **0.6.5** (tag `0.6.5`, commit `b3a880aacc63641c570f114ff8d45f221fc97d02`), the latest release as of November 2026, which `hivepack::squashfs::UPSTREAM_VERSION` names. Its sources are the `squashfuse-0.6.5-source` set of `scripts/testdata.py`, pinned by their SHA-256 and mirrored in hivepaas/hivepack-upstream.

## What following squashfuse means

As in the other ports ([porting.md](porting.md)), each C file is a module, functions keep their names in snake case (`sqfs_read_range`, `sqfs_dir_next`), each doc comment names its C original, and where the Rust works otherwise a comment starting with `Differs from squashfuse:` says how and why. The library is ported single-threaded, as squashfuse builds it by default, with `cache.c`, not `cache_mt.c`.

| squashfuse | Port | What |
|---|---|---|
| `squashfs_fs.h` | `squashfs_fs.rs` | the superblock, inodes, directory headers and entries, the fragment, xattr and id entries, and the constants |
| `swap.c`, `swap.c.inc` | `swap.rs` | the little-endian structures read |
| `common.h`, `fs.h`, `fs.c` | `fs.rs` | `sqfs_init`, metadata and data blocks through their caches (`sqfs_md_cache`, `sqfs_data_cache`), metadata cursors (`sqfs_md_read`), ids, `sqfs_readlink`, the export table, `sqfs_inode_get` and the inode's `xtra` union |
| `table.c` | `table.rs` | tables of entries in metadata blocks: the id, fragment, export and xattr id tables |
| `dir.c` | `dir.rs` | `sqfs_dir_open` (from an offset too, through the directory index), `sqfs_dir_next`, `sqfs_dir_lookup`, `sqfs_lookup_path_with_id` |
| `file.c` | `file.rs` | fragments, block lists, `sqfs_read_range` with holes, and the block index (`sqfs_blockidx_*`) |
| `xattr.c` | `xattr.rs` | the xattr id table, and going through an inode's attributes, their values inline or out of line |
| `stat.c` | `stat.rs` | `sqfs_stat` |
| `traverse.c`, `stack.c` | `traverse.rs` | `sqfs_traverse`, a walk of a tree depth first, its stack a `Vec` |
| `decompress.c` | `decompress.rs` | the decompressors, through hivepack's ports |
| `cache.c` | `cache.rs` | the caches, which a damaged image can read differently through, and are kept as they are |
| `nonstd-stat.c`, `nonstd-pread.c` | `nonstd.rs`, `fs.rs` | `sqfs_mode` and the `S_IF*` bits; `sqfs_pread` over `Read + Seek` |

The API is the library's: `Squashfs::open` and `open_at` (`sqfs_init` with its `offset`, where an AppImage's image starts), `inode` (`sqfs_inode_get`), `read_dir` and `read_dir_at` (`sqfs_dir_open`, `sqfs_dir_next`), `lookup` and `lookup_path`, `stat`, `read_link`, `xattrs` and `xattr` (`sqfs_xattr_lookup`), `read_at` and `file` (`sqfs_read_range`), `traverse`, `export_inode`. `check_data`, not in squashfuse, tells whether all of a file's data is on the image without reading it, for `extract_squashfs`, which checks every file before writing. Errors are squashfuse's `sqfs_err` (`SqfsErr`), with what failed.

| Compressor (id) | squashfuse calls | The port calls |
|---|---|---|
| zlib (1) | zlib's `uncompress` | `hivepack::deflate::Inflate`, driven as `uncompress` drives `inflate` |
| LZMA (2), the format squashfs-tools 4.0 to 4.3 wrote | liblzma's `lzma_alone_decoder`, with a header squashfuse took from squashfs-tools | `hivepack::xz::Stream::alone_decoder`, with the same header |
| LZO (3) | liblzo2's `lzo1x_decompress_safe` | `hivepack::lzo::decompress`, its port ([lzo.md](lzo.md)), every error a failure as in squashfuse, bytes after a block's end among them |
| xz (4) | liblzma's `lzma_stream_buffer_decode` | `hivepack::xz::Stream::stream_decoder`, called as `lzma_stream_buffer_decode` calls it |
| LZ4 (5) | liblz4's `LZ4_decompress_safe` | `hivepack::lz4::block::decompress_safe` |
| zstd (6) | libzstd's `ZSTD_decompress` | `hivepack::zstd::decompress` |

The compressor options mksquashfs writes after the superblock are not read, as squashfuse does not read them: a decoder needs none of them (xz's filters are in each stream).

## What differs

Where squashfuse would read past its buffers or go on for good, the port has a bound or an error:

- **A table's entry past the end of its metadata block is an error.** squashfuse copies the entry from the block's memory without looking at its size, and reads what is after it: in a damaged image, an id, a fragment entry, an export entry or an xattr id of whatever was in memory. The comparisons part there (below).
- **A walk goes at most 1,024 directories deep** (`MAX_DEPTH`). squashfuse has no bound, and goes on through a directory that holds itself, a damaged image's, until its memory runs out.
- **What is read grows as it is read**, so that a size the image does not hold takes no more memory than the image: a table's list of blocks, a link's target, an extended attribute's value, a file's block index. squashfuse allocates each from the size first. A read past the image's end fails before anything is read, as squashfuse's short `pread` fails after.
- **The block index**: entries squashfuse would leave as they were in memory, when a damaged file's metadata blocks are not the usual 8 KiB, are zeros.
- **Data an LZMA block does not have**, up to the size its header gives, is zeros, where squashfuse leaves what was in memory.
- **Sizes are 64-bit on every machine**, as squashfuse's `size_t` and `off_t` are on 64-bit ones; and the inode's `xtra` union is laid out as C lays it out on a 64-bit little-endian machine, on every machine, so that a damaged inode whose mode names another type than its own reads as squashfuse reads it there.
- **The cache** asserts, in squashfuse, that an entry it finds again is valid, which one whose block failed to read is not; built without assertions, as a release is, it gives it, and the caller reads the block again, as the port does.
- **A read into nothing reads nothing**: `read_at` with an empty buffer returns 0, where `sqfs_read_range` of no bytes fails.
- **The owners are the image's.** squashfuse's mount options that give every inode one owner and group (`uid=`, `gid=`) are not ported.

What squashfuse does that a reader may not expect is kept: the data and fragment caches (one block and three) are keyed by where a block is, not by the header it is read with, so in a damaged image two files that name one place with different headers both read what was read first; the block index is kept for 8 files, keyed by their inode number; a directory's entries are looked up through its index and then in order, as their names are sorted, by `strncmp`, which stops at a NUL; an image whose magic is in the other byte order has only its version swapped, and fails as SquashFS 3 or older; nothing checks the superblock's flags, its `bytes_used`, nor that a block is no larger than the block size: a stored block of more is read as it is.

## Bounded resources

A metadata block is at most 8 KiB once decompressed, 32 KiB stored; a data block at most the block size, 1 MiB, decompressed, and a stored one as large as its header says, if the image holds it. The caches keep 8 metadata blocks, one data block, three fragment blocks and the block indexes of 8 files. A walk keeps a directory's place for each level, at most 1,024. A file's block index is a 12-byte entry for each 8 KiB of its block sizes, made when a read starts in a later metadata block than the file's first, for files of more than 2,048 blocks.

## How it is shown

`tools/squashfs-oracle` is squashfuse's library, built from the release with the pinned zlib 1.3.2, XZ Utils 5.8.4, lz4 1.10.0, zstd 1.5.7 and LZO 2.10 sources by `scripts/testdata.py`. For an image, it opens it, walks it with `sqfs_traverse`, and gives one line for each thing it reads: the superblock; for every entry its path, type, inode number and inode; every inode's fields (`sqfs_inode` whole: the base inode, the link count, the xattr index, where its metadata goes on, and the file's, directory's, link's or device's fields); `sqfs_stat`'s attributes; a link's target; every extended attribute's name and value; the export table's entry for the inode's number; what `sqfs_lookup_path_with_id` finds for its path from the root; and every file's data, read with `sqfs_read_range` 64 KiB at a time, its length and FNV-1a hash; with the error of anything that fails, and how the walk ended. `tests/squashfs_oracle.rs` asks the port the same, in the same order (squashfuse's caches make the order matter in a damaged image), and the answers must be the same, line for line.

- **The images.** squashfs-tools 4.6.1's `mksquashfs`, built from the release with the same compressor sources (`scripts/testdata.py`, set `mksquashfs`; a test tool, never shipped), makes them from trees `tools/squashfs-images/make.py` writes, without root: files of every size around a block, a file of 9 MiB whose block list spans metadata blocks, files with holes and of zeros, duplicate files, three names of one file, symbolic links up to 4,000 bytes, an empty directory, a tree 120 deep, a directory of 2,000 entries (with an index), names of 255 bytes and in UTF-8, and from a pseudo file block and character devices (majors up to 4095, minors up to 1048575), a FIFO, a socket, owners 0 to 4294967294, setuid, setgid and sticky modes, and extended attributes in each prefix, on files, directories, links and devices, some stored out of line. The 27 images of `squashfs-images` (110 MB) are one per compressor, gzip with blocks of 4 KiB, 8 KiB, 64 KiB and 1 MiB, zstd with 4 KiB and 1 MiB, nothing compressed (`-noI -noD -noF -noX`, and zstd's `-no-compression`), `-no-fragments`, `-tailends`, `-no-exports`, `-no-xattrs`, `-no-sparse`, `-no-duplicates`, `-no-hardlinks`, xz with `-Xbcj x86` and `-Xdict-size 8K`, LZ4 `-Xhc`, zstd level 19, gzip level 1 and LZO's `lzo1x_1`. `testdata/squashfs` keeps seven small ones of a smaller tree (4 to 12 KiB), one per compressor and one with nothing compressed.
- **Real files**: KeeWeb 1.18.7's snap (96 MB, xz, 385 entries) and appimagetool 1.9.1's AppImage (15 MB, its image of zstd at byte 944,632, the end of its ELF program), fetched by their pinned URL and SHA-256 (`squashfs-real`), read whole.
- **Damaged copies**: each image cut short at the start and in the middle of each of its parts (superblock, data, inode table, directory table, fragment, export, id and xattr tables), a byte off its end, and changed in each part in turn: a bit, up to four bits, a byte set to 0xff or 0. Each copy is compared with up to 3,000 entries and 256 KiB of each file.
- **The counts.** Every image whole, and in CI 300 damaged copies of each committed image (2,107 comparisons, which `testdata/oracle/squashfs.txt` replays where the oracle is not built: Windows, and the emulated i686 and s390x jobs), 48 of each generated image (1,323), and 68 of the real files, damaged in their tables (70). Once, 400 of each generated image: 10,827 comparisons. All agree, but where squashfuse reads past a metadata block (30 of the 10,827, none of the committed ones' 2,107): there the port fails, and the answers must be the same up to that line, which must be of the same kind.
- **LZO images**, the three that mksquashfs makes (`-comp lzo`, its default `lzo1x_999`, and `-Xalgorithm lzo1x_1`), and the committed one, are compared as the others, whole and damaged.
- **Extraction**, in [extract.md](extract.md#squashfs).
- **Fuzzing**: the `squashfs` target opens any input as an image and walks it twice, as the oracle test does, and lists each directory again from each entry's `next_offset`; the transcripts must be the same and nothing may panic. The `extract_squashfs` target extracts it, as `extract_udf`'s does a UDF volume. CI seeds both with `testdata/squashfs`. The first fifteen minutes of `squashfs`, 276,000 inputs, and five of `extract_squashfs`, 3.3 million, found nothing.

## Speed

Reading every file of an image, 128 KiB at a time, from opening it on, by squashfuse (`tools/squashfs-oracle`'s `read`) and by the port, in turns, the best of seven rounds each (`cargo test --release -p hivepack --test squashfs_oracle speed -- --ignored --nocapture`; AMD Ryzen 9 9950X, Linux, November 2026; squashfuse with its default `-O2`, and the compressors built from the same sources):

| Image | Files | Bytes read | squashfuse | Port | Port ÷ squashfuse |
|---|---|---|---|---|---|
| KeeWeb 1.18.7's snap (xz, 96 MB) | 244 | 406.7 MB | 3.044 s (134 MB/s) | 3.224 s (126 MB/s) | 0.94× |
| appimagetool 1.9.1's AppImage (zstd) | 8 | 36.9 MB | 30 ms (1,224 MB/s) | 39 ms (952 MB/s) | 0.78× |
| the full tree, gzip | 2,044 | 19.8 MB | 14 ms | 9 ms | 1.52× |
| the full tree, LZMA | 2,044 | 19.8 MB | 53 ms | 57 ms | 0.93× |
| the full tree, LZO | 2,044 | 19.8 MB | 7.0 ms | 4.9 ms | 1.45× |
| the full tree, xz | 2,044 | 19.8 MB | 55 ms | 58 ms | 0.96× |
| the full tree, LZ4 | 2,044 | 19.8 MB | 2.1 ms | 2.9 ms | 0.73× |
| the full tree, zstd | 2,044 | 19.8 MB | 5.1 ms | 6.3 ms | 0.82× |
| the full tree, zstd, blocks of 1 MiB | 2,044 | 19.8 MB | 4.2 ms | 5.4 ms | 0.78× |
| the full tree, nothing compressed | 2,044 | 19.8 MB | 0.55 ms | 0.72 ms | 0.76× |

A snap is xz, and there the time is liblzma's and hivepack::xz's, which is 0.94× liblzma's assembly on Silesia ([xz.md](xz.md)): reading a snap takes 6% longer than squashfuse. gzip is faster through hivepack::deflate's inflate ([deflate.md](deflate.md#where-decompression-stands)). So is LZO, through hivepack::lzo ([lzo.md](lzo.md)), which squashfuse's liblzo2 decodes at 0.7× its speed on mksquashfs's `lzo1x_999` blocks. Where the decoder is fast (LZ4, zstd, nothing compressed), what is left is the port's own work for each block: its output zeroed before it is decoded into, the block read into memory zeroed first, and its metadata copied. The zstd and zlib decoders are kept from one block to the next, which squashfuse's calls do not, and a block after the one read last is read without seeking; neither changed these numbers by more than 2%.

## Following new releases

When squashfuse makes a release, compare its library files (the table above) with 0.6.5's, port what changed in the reading path, add the release's source set to `testdata/manifest.json` (and mirror it with `python3 scripts/testdata.py mirror --set squashfuse-<version>-source`), point `squashfs-oracle` at it, change `UPSTREAM_VERSION` and the oracle's `version` answer, and run the comparisons; record the answers again (`cargo test -p hivepack --test squashfs_oracle record_oracle_answers -- --ignored`). A new squashfs-tools makes new images: its `mksquashfs` set and `make.py` are the tests' only use of it.
