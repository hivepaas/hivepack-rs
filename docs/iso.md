# Porting libarchive's ISO 9660 reader

`hivepack::iso` reads ISO 9660 images in safe Rust: CD and DVD images, Linux distributions' installers, and most `.iso` files people have. It is a port of the ISO 9660 reader of [libarchive](https://github.com/libarchive/libarchive), under the BSD-2-Clause license. libarchive's reader goes through an image in one pass, reads Rock Ridge, Joliet, files in several extents and zisofs, and has been hardened against hostile images for years; its tests come with the images that broke it.

UDF, the file system of DVDs, Blu-ray discs and Windows' installation images, is not here: libarchive does not read it. On an image with both (a "UDF bridge"), this reads the ISO 9660 side, which on Windows' images holds only a `README.TXT`.

## The source

The port follows **libarchive 3.8.10**, the latest release as of October 2026. `hivepack::iso::UPSTREAM_VERSION` names it. As in the other ports ([porting.md](porting.md)), each C file is a module without the `archive_` prefix, functions keep their names in snake case, and each doc comment names its C original.

| libarchive | Port | What |
|---|---|---|
| `archive_read_support_format_iso9660.c` | `read_support_format_iso9660.rs` (`Iso9660`, `Format`) | the volume descriptors, directory records, SUSP and Rock Ridge entries, continuation areas, `rr_moved` and its CL and RE entries, files in several extents, zisofs, hard links |
| `archive_read.c` | `read.rs` (`Input`), `lib.rs` (`Reader`) | looking ahead, consuming and seeking in the input; the states of `archive_read_next_header` and `archive_read_data_block` |
| `archive_entry.c` | `entry.rs` (`Header`) | the fields the reader sets, and the link name that symbolic and hard links share |
| `archive_string.c` | `string.rs`, and `ArchiveString` in `read_support_format_iso9660.rs` | Joliet's UTF-16BE names in UTF-8; strings whose buffer keeps its old text when emptied |

The reader keeps its records in lists linked through pointers inside them, one record sometimes in two lists through the same link. The port keeps them in a `Vec` and links them by index, with the same links, so that a damaged image takes the same path through them.

## What differs

- **Bytes, not C strings.** Paths, link targets and the names in messages are `Vec<u8>`: Rock Ridge's and ISO 9660's names as the image has them, Joliet's in UTF-8. libarchive converts Joliet's names to the locale's charset; the tests run it in a UTF-8 locale.
- **No Unicode normalization.** libarchive normalizes the names it converts from UTF-16, to NFC (NFD on macOS), with tables of Unicode 6.0. The port gives them as the image has them; normalizing for a file system belongs to hivepack::extract.
- **Errors are a type, with libarchive's messages.** `ARCHIVE_FATAL` is an [`Error`], whose `message` is libarchive's, byte for byte, names and numbers included. `ARCHIVE_WARN` on a header is the header's `warning`; on data (a part of a file in several extents behind the place read to), an `io::Error` holding `Error::Warning`, after which reading goes on, as it does in libarchive. A failure is kept and returned again by every later call.
- **The input is read as libarchive reads an image in memory** (`archive_read_open_memory`): what the reader looks ahead at is there if the image has it, however the input comes. `Reader::seekable` can go back, as libarchive can in memory, for a file whose data is before its directory; `Reader::new` cannot, and gives such a file with `Warning::FileOutOfOrder` and no data, as libarchive does with an input it cannot seek in. Where an entry's data was left matters only for images whose files overlap: the port goes on from where the reading stopped, libarchive from the end of the block it last gave out.
- **Modes and device numbers at full width.** libarchive keeps them in `mode_t` and `dev_t`, 16 and 32 bits on macOS; the port keeps Rock Ridge's 32-bit mode and 64-bit device number.
- **Times as glibc's `timegm` makes them.** libarchive turns dates into seconds with the system's `timegm`. macOS's gives up on a date before 1900 once its time zone is taken off, and libarchive then says 1970; glibc's, and the port, go on.
- **Where libarchive never stops, the port does.** A zisofs block whose zlib stream ends before the block does is returned as nothing, again and again, by libarchive; the port fails with `Error::ZisofsStuck`. Rock Ridge's CL and RE entries can make a directory its own ancestor: libarchive's walk up the parents then never ends, where the port takes the loop as found (`Error::Loop`, or "Invalid Rockridge CL"); and making a Joliet path through such a loop overflows libarchive's stack, where its length stops the port (`Error::PathnameTooLong`).
- **The volume descriptors are looked for in 16 MiB.** With the image in memory, libarchive looks until the Volume Descriptor Set Terminator or the end, holding everything it looked at; the port, which holds it too, stops at 8,192 descriptors. Real images have a handful.
- **Not ported:** the writer (`archive_write_set_format_iso9660.c`). The reader's options are both here: `set_joliet` and `set_rock_ridge`.

## What libarchive gives that a reader should know

- **A zisofs file's data can end before its size.** zisofs stores a block of zeros as nothing; libarchive gives such a block as zeros when compressed blocks come after it, but stops at the last compressed byte, so the blocks of zeros at a file's end are not given (libarchive's own test image `test_read_format_iso_zisofs` has a file of 12,345,684 bytes whose data, as libarchive reads it, is its first 32 KiB). libarchive's extraction (`archive_write_disk`) makes the file its size with zeros, and so does `hivepack::extract::extract_iso`.
- **The data of a damaged zisofs file can go past its size**, by the blocks of zeros its block pointers claim: extractors write up to the size.

## Bounded resources

As in libarchive: a directory is read whole, up to the 4 GiB its size field holds, and the records of the whole image are kept while it is read. Both take memory only as the image has the bytes: a directory larger than the image fails. A zisofs file's block pointers take at most 512 KiB, and its decompressed block at most 128 KiB; its data can be far larger than the image (blocks of zeros cost nothing), so readers bound what they take, as hivepack::extract does.

## How it is shown

- **Unit tests** for Joliet's names (surrogate pairs, lone surrogates, U+0000) and dates (time zones at their limits, February 31, one second before 1970).
- **`tests/oracle.rs`**: comparison with libarchive 3.8.10 through `tools/iso-oracle`, a C program `scripts/testdata.py` builds from libarchive's and zlib's sources, with `archive_string.c`'s normalization taken out and, on macOS, glibc's arithmetic for `timegm` (see above). Both read every entry and all of its data, the port in pieces of random sizes; the answers must be the same: the header (path, mode, owner, group, links, size, the four times, device, symbolic and hard link), its warning, the data's length and FNV-1a hash (of up to 64 MiB), the warnings while reading it, and how the data and the image end. Each image is read up to five ways: in memory or as a stream that cannot seek, with Joliet or Rock Ridge turned off. The images:
  - libarchive's 22 test images (`testdata/libarchive-iso`), read the five ways, and each damaged 60 ways (10 for the three largest): a bit flipped or a byte changed in a directory record or volume descriptor; a record's length, name length, extent, size, flags or date; a SUSP entry's length, version, name or numbers; a volume descriptor's root directory, block size, volume size or type; cut anywhere; a sector copied over another or zeroed; bytes after the end.
  - 300 images libarchive's writer makes from random trees, read four ways and each damaged four times: Rock Ridge strict, useful or off, Joliet on, long or off, zisofs, ISO levels 1 to 4, with and without the depth limit that moves directories to `rr_moved`; names in ASCII, long, in UTF-8 and outside the BMP; files, directories, symbolic and hard links, devices and FIFOs; times before 1970 and after 2100.
  - 400 images the test makes itself (`tests/support/image.rs`), with what libarchive's writer does not make, read the five ways and each damaged four times: names and links in several NM and SL entries, every SL component, PN, PX of every length, TF in both formats with dates out of range, ST, unknown entries, continuation areas (some pointing back), directories moved to `rr_moved` with CL and RE, files in several extents (some empty), zisofs files with blocks of zeros, random blocks that do not compress, streams cut short, needing a dictionary or with bytes after their end, and spoiled headers and pointers; Joliet names with lone surrogates, U+0000 and odd lengths, files whose data is before their directory, directories out of order, boot records.

  About 7,300 images are compared where the oracle is built (Linux and macOS in CI), and every kind of warning and most of libarchive's errors come up among them; the test checks that the common ones do. `ISO_SEED=<n> ISO_COUNT=<count> cargo test --release -p hivepack --all-features --test iso_oracle crafted` compares more images made by the test. `testdata/oracle/iso.txt` replays 824 answers everywhere else: libarchive's images and damaged copies by name and number, and images made by the test by number, which the test makes again.
- **Fuzzing**: the `iso` target reads any input, as an input that can seek and as one that cannot, every entry and up to 4 MiB of its data, twice each, in pieces of different sizes: the same headers, data, warnings and end both times, and no panic. CI seeds it with libarchive's test images.

## Following new releases

A new libarchive release's changes to `archive_read_support_format_iso9660.c`, and to what it calls in `archive_read.c`, `archive_entry.c` and `archive_string.c`, are ported; the manifest's `libarchive-*-source` set and `UPSTREAM_VERSION` name the release, and `testdata/libarchive-iso` takes its new test images.

## Licenses

The port is derived from libarchive, under the BSD-2-Clause license (Copyright Tim Kientzle, Andreas Henriksson, Michihiro NAKAJIMA and Martin Matuska); `hivepack::iso` is under the same license, with libarchive's notice in its [LICENSE](../crates/hivepack/src/iso/LICENSE). libarchive's test images in `testdata/libarchive-iso` are under it too, with libarchive's `COPYING` beside them, as `LICENSE`.
