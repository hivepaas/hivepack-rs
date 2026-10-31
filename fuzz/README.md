# Fuzzing

`cargo-fuzz` targets that compare hivepack-zstd with libzstd,
hivepack-deflate with zlib, hivepack-bzip2 with libbzip2, hivepack-lz4 with
liblz4, and hivepack-xz with liblzma, and that feed hivepack-zip,
hivepack-extract, hivepack-age, hivepack-tar, hivepack-iso, hivepack-cpio, hivepack-open, hivepack-7z and hivepack-udf any input. They need
nightly, where `rust-toolchain.toml` pins a stable: the nightly CI uses
(`NIGHTLY` in `.github/workflows/ci.yml`), chosen for the shell with
`export RUSTUP_TOOLCHAIN=<that nightly>`, and
`cargo install cargo-fuzz`.

| Target | What it checks |
|---|---|
| `decompress` | Decoding the input in one call: the same output as libzstd, or the same error |
| `compress` | Compressing the input in one call, at a level its first byte picks, with the blocks split after their sequences when a bit of it is set, and with worker threads when another is (then also streamed with its size unknown, which takes them), and with a target size for compressed blocks for some sizes: the same frame as libzstd, which decodes back |
| `compress_stream` | Streaming the input, with parameters (long distance matching and a target size for compressed blocks among them), pieces, directives and room for output its first 8 bytes pick: every call the same as libzstd's, and a frame that decodes back. A quarter of the time with worker threads, a different number on each side, where each side goes through the same steps on its own: the same frame |
| `sequences` | The sequence API, which zstd-safe does not offer (the oracle's tests compare it with libzstd): with the input's first byte, its sequences generated at a level and compressed back with `compress_sequences`, with their block delimiters and merged without, and with `compress_sequences_and_literals`, every frame decoding back to it; or sequences of any values read from its start, compressed over the rest as given and as a sequence producer's for every block: a frame or an error, never a panic |
| `zdict` | Training a dictionary on samples cut from the input (in one size, at a byte that ends each, or by sizes read from it, as its third byte picks), into a room its first two bytes pick, with the default trainer (`train_from_buffer`, libzstd's `ZDICT_trainFromBuffer`): the same dictionary as libzstd, byte for byte, or the same error; a dictionary that works, a sample compressed with it decoding back (the oracle's tests compare the other trainers, which zstd-safe does not offer) |
| `divsufsort` | The suffix array of a text, as the dictionary builder sorts its samples (`divsufsort`; the oracle's tests compare it with libzstd's): the rest of the input as it is, repeated, twice over or as runs, its first byte picks which, so that long repeats come easily. A permutation of the text's positions, each suffix smaller than the next, and for texts up to 512 bytes the suffixes sorted as slices |
| `inflate` | Inflating the input (raw, zlib or gzip, chosen by its first byte) in pieces chosen by its next eight: every call gives the same result, message, bytes read and written, and output as zlib |
| `deflate` | Compressing the input at a level and with a wrapper its first byte picks, in pieces and with flushes its next eight pick: every call gives the same result, bytes read and written, and bytes as zlib |
| `zip_open` | Opening the input as a ZIP archive, leniently and with `ZIP_CHECKCONS`, asking the reading API about every entry, and reading every entry's data, decompressed, raw, and decrypted with the password "foo": no panic (`crates/zip/tests/oracle.rs` compares the answers with libzip) |
| `zip_ppmd` | Reading the input as the data of a PPMd entry (ZIP's method 98) in an archive of that one entry, leniently and with `ZIP_CHECKCONS`, in pieces of one byte and of growing sizes: the same bytes and error both ways (libzip has no PPMd: `crates/zip/src/ppmd8_oracle.rs` compares the model with 7-Zip's `Ppmd8.c`) |
| `zip_split` | Cutting the input into volumes its first bytes pick and opening them as a split archive (`Volumes`), leniently and with `ZIP_CHECKCONS`, reading every entry, decompressed and raw: no panic, and written again as an archive of one disk, the same entries (libzip reads no split archives: `crates/zip/tests/split.rs` compares them with 7-Zip) |
| `extract` | Extracting the input as a ZIP archive with hivepack-extract, with options its first byte picks, cancelled after some progress if it says so: nothing written beside the destination, every link created staying inside it, the summary counting what is there, and no file left cut off |
| `zip_edit` | Opening the input as a ZIP archive, making the edits its first bytes pick (encrypting among them) and writing it: the archive written opens with the entries as edited, their names, comments, attributes, times, sizes and data, read with the passwords the edits set (`crates/zip/tests/oracle.rs` compares the edits and the bytes written with libzip) |
| `inflate9` | Decoding the input as Deflate64 all at once and in pieces its first eight bytes pick: the same result, message, input used and output calls both ways, and with `Inflate9` in pieces of input and output the same end, message and output (zlib's Deflate64 decoder is not in libz-sys; `crates/deflate/tests/deflate64.rs` compares with it) |
| `sevenz` | Opening the input as a 7z archive, listing it, reading its files in pieces of all sizes, decoding its folders and extracting its files, with small limits on memory and output: no panic (`crates/7z/tests/oracle.rs` compares the results with the LZMA SDK's) |
| `lz4` | After a mode byte and eight bytes of seed: decoding the rest as a block with `LZ4_decompress_safe` into an output of a size the seed picks, with the same result and every byte of the output the same, past what is decoded too, as liblz4; reading it as a frame in reads of sizes the seed picks, through the lz4 crate's `Decoder` and the same loop over the port's context, with the same bytes from every read; decoding it partially, with dictionaries, after a prefix and in a stream, and reading it with the port's `Decoder`: no panic (`crates/lz4/tests/oracle.rs` compares those with liblz4); compressing the rest into a block, fast or at a high-compression level, and into a frame through the lz4 crate's `Encoder` and the port's, with preferences, writes and flushes the seed picks, with the same block or frame as liblz4; and compressing it in the ways the lz4 crate cannot reach (dictionaries, digested or not, negative levels, stored blocks, outputs too small, as much as fits): no panic, and all of it decompresses to what was given |
| `bzip2` | With an even first byte, decompressing the rest, fast or small, in pieces chosen by the next eight bytes: every call, up to the first error, gives the same result, bytes read and written, and output as libbzip2. With an odd one, compressing the rest at a block size and work factor the first byte picks, in pieces with flushes on the way: every call the same as libbzip2's, and a stream that decompresses back |
| `xz` | Decoding the rest of the input with the decoder its first byte picks (`.xz`, automatic, `.lz`, `.lzma`, raw LZMA1 or LZMA2 with up to three delta and BCJ filters before it, or the threaded `.xz` decoder), with flags, a memory limit or options and pieces its next eight pick, and memory limits set between calls: every call, up to the first error, gives the same result, bytes read and written, and output as liblzma (built from liblzma-sys's bundled 5.8.4 sources). The threaded decoders, whose calls read and write as their threads let them, without flags, give the same end, and after the end of a Stream the same output and bytes read. The automatic decoder skips `.lz` input, which liblzma-sys's build of the automatic decoder takes for `.lzma` |
| `xz_encode` | Encoding the rest of the input with the encoder its first byte picks (`.xz` of a preset, `.xz` of LZMA2 with options, `.lzma`, raw LZMA1 or LZMA2, all but `.lzma` and the preset with up to three delta and BCJ filters before LZMA, or the threaded `.xz` encoder), with the preset, check, options, filters, threads, pieces and flushes its next eight bytes pick: every call gives the same result, bytes read and written, and output as liblzma; the threaded encoders, whose calls read and write as their threads let them, end with the same Stream (built with liblzma-sys's `parallel` feature) |
| `age` | Decrypting the input as an age file, armored or not, with CCTV's usual X25519 key and the passphrase `password` (work factors up to 2^4), twice, in pieces of different sizes its first eight bytes pick: the same plaintext and the same end both times, and no panic (`crates/age/tests/oracle.rs` compares the outcomes with age) |
| `age_keys` | Reading the input as an identity file, as `age -i` does (a file of keys, an SSH key, a file of keys encrypted with age): no panic. Only the parsing, as decrypting an encrypted key file could ask scrypt for 4 GiB |
| `tar` | Reading the input as a tar archive, every entry and up to 4 MiB of each one's data, twice, in pieces of different sizes its first eight bytes pick: the same headers, data and end both times, and no panic (`crates/tar/tests/oracle.rs` compares the answers with Go's archive/tar), and going through the entries without their data with `Reader::new` and `Reader::seekable`: the same |
| `tar_write` | Reading the input as a tar archive and writing each entry again with `Writer`, the header as it came or changed as the first eight bytes' hash picks (format, times, a name made long), up to 1 MiB of each one's data: the reader takes what was written, with the same names, sizes and data, the writer's errors are the ones a caller can expect, and no panic (`crates/tar/tests/writer.rs` compares every byte with Go's archive/tar) |
| `rar_headers` | Opening the input as a RAR archive, its first byte choosing whether a broken main header is read past, and reading every header, twice: the same headers both times, each past the one before |
| `rar_test` | Going through the input as UnRAR tests an archive, twice: the same data both times, no more of a stored entry than its header's pack and unpacked sizes |
| `rar_unpack` | The input as the packed data of a copy of an existing RAR 5 or RAR 4 archive, one or two entries, decompressed twice: the same data both times. What it finds is compared with UnRAR by `HIVEPACK_RAR_UNPACK_CORPUS` |
| `rar_unpack_old` | The same with RAR 1.5 and 2.x, whose entries can go on from each other and from RAR 3's |
| `rar_password` | The input as an archive read with a password, as `rar_test` does, so that it gets to what is encrypted. Key derivation is cut short in fuzzing builds. What it finds is compared with UnRAR by hand, without that |
| `rar_quick_open` | The input as `support::patch::with_quick_open` makes a QuickOpen record of it, read with no password and with one, so that it gets past the record's CRCs. What it finds is compared with UnRAR by hand |
| `extract_rar` | The input as a RAR archive extracted by `hivepack_extract::extract_rar`, its first byte choosing the options, into a scratch folder: nothing outside it, no link leading out, and no file left cut off |
| `rar_volumes` | The input as two volumes of an archive with a password, its comment first, as `rar_test` does. What it finds is compared with UnRAR |
| `extract_tar` | Extracting the input as a tar archive with hivepack-extract, as `extract` does a ZIP archive: options from its first byte, cancelled after some progress if it says so; nothing written beside the destination, every link created staying inside it, the summary counting what is there (a hard link's file once), and no file left cut off |
| `iso` | Reading the input as an ISO 9660 image, as an input that cannot seek and as one that can, every entry and up to 4 MiB of each one's data, twice each, in pieces of different sizes its first eight bytes pick: the same headers, data, warnings and end both times, and no panic (`crates/iso/tests/oracle.rs` compares the answers with libarchive) |
| `cpio` | Reading the input as a cpio archive, with the `pwb` option or without as its first eight bytes pick, every entry and all of its data, twice, from pieces of the input and in pieces of different sizes they pick: the same headers, data and end both times; with some entries' data left for `next` to skip, the same headers; and when the RPM filter's bid takes the input for a package, its payload twice the same, read as a cpio archive too; no panic (`crates/cpio/tests/oracle.rs` compares the answers with libarchive) |
| `extract_iso` | Extracting the input as an ISO 9660 image with hivepack-extract, as `extract_tar` does a tar archive: options from its first byte, cancelled after some progress if it says so; nothing written beside the destination, every link created staying inside it, the summary counting what is there (a hard link's file once), and no file left cut off |
| `extract_cpio` | Extracting the input as a cpio archive with hivepack-extract, as `extract_iso` does an ISO 9660 image: options from its first byte, cancelled after some progress if it says so; nothing written beside the destination, every link created staying inside it, the summary counting what is there (a hard link's file once, whichever name its data came with), and no file left cut off |
| `extract_xar` | Extracting the input as a XAR archive with hivepack-extract, as `extract_cpio` does a cpio archive, a package's payloads expanded or written as files as its first byte picks, with the same checks: nothing written beside the destination, every link created staying inside it, the summary counting what is there, and no file left cut off |
| `open` | Opening the input through its layers with hivepack-open (the age key of `crates/open/tests/age.rs`'s files; a name ending in `.lzma` if its first byte is odd; small limits), three times with one opener, the later opens with the file keys kept, and reading up to 4 MiB in pieces of different sizes: the same layers, container and end each time, the same data, or after an error data of which one starts the other (libzstd gives out less before an error when its output buffer is larger), and no panic |
| `udf` | Mounting the image the input describes (its first byte the sector size, its next three the number of sectors, then sectors by number, length and bytes) and walking it twice: every directory listed, every node's attributes, every link's target, up to 1 MiB of every file, the first 16 names of each directory looked up: the same both times, every name found when its directory reads whole, and no panic (`crates/udf/tests` compares the answers with Linux) |
| `extract_udf` | Extracting the image the input describes, after a byte of options (as `extract_iso`'s, and whether hidden entries are listed), as the `udf` target reads it, with hivepack-extract: nothing written beside the destination, every link created staying inside it, the summary counting what is there (a hard link's file once), and no file left cut off |

Seed the corpus with the frames in `testdata`, then run, with the
`unsafe-fast` feature or without:

```sh
mkdir -p fuzz/corpus/decompress
find testdata -name '*.zst' -exec cp {} fuzz/corpus/decompress/ \;
cargo fuzz run --features unsafe-fast decompress -- -max_total_time=3600
```

CI seeds `sequences` with the same files as `compress`, and `zdict` with
the systemd units of `testdata/ruzstd/dict/files`, whose samples it cuts
at their newlines.

`compress` and `compress_stream` take the feature too: with it, the row
match finder gathers its candidates and prefetches them, as libzstd does,
so fuzz them both ways (CI runs `compress` with it, `compress_stream`
without).

The `inflate`, `deflate`, `inflate9` and `divsufsort` targets start from
an empty corpus, CI seeds `bzip2` with the streams and inputs of
`testdata/oracle/bzip2.txt`, `xz` with the inputs of
`testdata/oracle/xz.txt` and `testdata/oracle/xz-mt.txt`, behind the byte for their decoder, and `xz_encode`
with those of `testdata/oracle/xz-encode.txt`, behind the byte for their
encoder:

```sh
cargo fuzz run inflate -- -max_total_time=3600
cargo fuzz run deflate -- -max_total_time=3600
cargo fuzz run inflate9 -- -max_total_time=3600
cargo fuzz run bzip2 -- -max_total_time=3600
cargo fuzz run divsufsort -- -max_total_time=3600 -rss_limit_mb=4096
cargo fuzz run xz -- -max_total_time=3600 -rss_limit_mb=4096
cargo fuzz run xz_encode -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `lz4` with the blocks and frames of `testdata/oracle/lz4.txt`, each
behind the mode bytes that decode it as a block and as a frame, and with the
inputs of its compression requests, behind the modes that compress them:

```sh
cargo fuzz run lz4 -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `sevenz` with the archives of `testdata/oracle/7z.txt`, and
`extract_7z` with those of `testdata/7z` behind a byte of options:

```sh
mkdir -p fuzz/corpus/extract_7z
for f in testdata/7z/*.7z; do { printf '\x12'; cat "$f"; } > "fuzz/corpus/extract_7z/$(basename "$f")"; done
cargo fuzz run sevenz -- -max_total_time=3600 -rss_limit_mb=4096
cargo fuzz run extract_7z -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `zip_open` with the archives of `testdata/oracle/zip-open.txt` and
those libzip encrypted in `testdata/oracle/zip-decrypt.txt` (some with
"foo"), and `zip_edit` with the same archives behind two edits (encrypting, for
the encrypted ones).

CI seeds `zip_ppmd` with the streams of `testdata/oracle/ppmd8.txt` made
with a whole number of MiB, behind ZIP's two bytes of parameters.

CI seeds `zip_split` with the split archives of `testdata/zip-split`, behind
their number of volumes and where each ends.

CI seeds `iso` with libarchive's test images, uncompressed, and
`extract_iso` with the same images behind a byte of options:

```sh
mkdir -p fuzz/corpus/iso fuzz/corpus/extract_iso
for f in testdata/libarchive-iso/*.iso.xz; do xz -dc "$f" > "fuzz/corpus/iso/$(basename "$f" .xz)"; done
for f in fuzz/corpus/iso/*; do { printf '\x22'; cat "$f"; } > "fuzz/corpus/extract_iso/$(basename "$f")"; done
cargo fuzz run iso -- -max_total_time=3600 -rss_limit_mb=4096
cargo fuzz run extract_iso -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `udf` with the descriptors of `testdata/udf`'s images, and
`extract_udf` with the same images behind a byte of options;
`tools/udf-images/seed.py` takes the crafted ones too:

```sh
UDF_CRAFTED=$PWD/target/udf-crafted cargo test -p hivepack-udf --test crafted write_crafted_images -- --ignored
python3 tools/udf-images/seed.py fuzz/corpus/udf target/udf-crafted
mkdir -p fuzz/corpus/extract_udf
for f in fuzz/corpus/udf/*; do { printf '\x22'; cat "$f"; } > "fuzz/corpus/extract_udf/$(basename "$f")"; done
cargo fuzz run udf -- -max_total_time=3600 -rss_limit_mb=4096 -max_len=400000
cargo fuzz run extract_udf -- -max_total_time=3600 -rss_limit_mb=4096 -max_len=400000
```

`cargo fuzz` builds with AddressSanitizer, so with the feature an access out
of bounds in its unchecked copies stops the run as a crash, as a difference
from libzstd does. CI runs each target for a few minutes.
