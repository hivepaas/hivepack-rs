# Porting libarchive's ar reader

`hivepack::ar` reads ar archives in safe Rust: Debian packages (`.deb`, `.udeb`), and the static libraries (`.a`) of GNU, SVR4 and BSD systems. It is a port of the ar reader of [libarchive](https://github.com/libarchive/libarchive), under the BSD-2-Clause license, as `hivepack::cpio`, `hivepack::iso` and `hivepack::xar` are of its other readers.

`hivepack::open` takes a Debian package off as a layer, down to its `data.tar`: opened, a package is the files it installs, as `dpkg-deb --fsys-tarfile` gives them (see [open.md](open.md)).

## The source

The port follows **libarchive 3.8.10**, the release `hivepack::cpio` follows too. `hivepack::ar::UPSTREAM_VERSION` names it. As in the other ports ([porting.md](porting.md)), each C file is a module without the `archive_` prefix, functions keep their names in snake case, and each doc comment names its C original.

| libarchive | Port | What |
|---|---|---|
| `archive_read_support_format_ar.c` | `read_support_format_ar.rs` (`Ar`, `Format`, `bid`) | the bid on `!<arch>\n`; the 60-byte headers and their numbers; GNU/SVR4's names, symbol table (`/`) and filename table (`//`), BSD's long names (`#1/<length>`); the data and its padding to an even offset |
| `archive_read.c` | `read.rs` (`Input`), `mod.rs` (`Reader`) | looking ahead and consuming in the input; the states of `archive_read_next_header` and `archive_read_data_block`, and the skip of the data not read |
| `archive_entry.c` | `entry.rs` (`Header`) | the fields the reader sets |

## What differs

- **Bytes, not C strings.** A name is a `Vec<u8>`, up to its first NUL, as the archive has it.
- **Modes at full width.** libarchive keeps a mode in a `mode_t`, 16 bits on macOS; the port keeps 32, as on Linux.
- **Errors are a type, with libarchive's messages.** `ARCHIVE_FATAL` is an [`Error`], whose `message` is libarchive's, byte for byte, numbers included. The reader gives no warnings. Where libarchive fails without a message (an archive that ends in its filename table), the error is `Error::Unspecified`. A failure is kept and returned again by every later call.
- **The input is read as libarchive reads an archive in memory** (`archive_read_open_memory`): what the reader looks ahead at is there if the archive has it, however the input comes. The port never seeks: `Reader::new` reads any `io::Read`.
- **Not ported:** the ar writers (`archive_write_set_format_ar.c`), which the tests use to make archives.

## What libarchive gives that a reader should know

- **Every entry is a regular file.** The mode's permission bits are the header's, in octal; its type is always a regular file, whatever the header says.
- **The end is where no whole header is left.** An archive that ends inside a header, or with fewer than 60 bytes after its last entry, ends there, without an error. An entry whose data is cut short fails ("Truncated ar archive"), and so does one of an odd size without its padding byte, at its end ("Truncated input file (needed 1 bytes, only 0 available)").
- **The variant is guessed from the names**, and then kept: a name with a `/` is GNU's (and loses its last `/`), `#1/` and `__.SYMDEF` are BSD's (`Reader::format`).
- **The symbol table and the filename table are not entries.** GNU's `/` is passed over; `//` is read and its names, ended by `/\n` (or `\\\n`, Windows'), are what the names `/<offset>` point at. BSD's `__.SYMDEF` and GNU's `/SYM64/` are entries like the others.
- **Numbers stop at their first character that is not a digit.** Spaces and tabs before them are passed over; a field of spaces is 0. The mode is octal, the others decimal.
- **A name can be empty**: one whose first byte is NUL, a BSD name of length 0, or a GNU name pointing at a NUL in the table. A name of spaces only is refused ("Found entry with empty filename").

## Bounded resources

As in libarchive: a GNU filename table is at most 1 GiB, and is held while the archive is read; a BSD name is at most 1 MiB, held while its header is read. Data is read through, never held.

## How it is shown

- **Unit tests** for the numbers (fields of spaces, tabs before digits, digits that are not octal) and the bid.
- **`tests/ar_oracle.rs`**: comparison with libarchive 3.8.10 through `tools/ar-oracle`, a C program `scripts/testdata.py` builds from libarchive's sources: its ar reader alone, and its ar writers. Both read every entry and all of its data, or leave it for the next header to skip; the port from an input that comes in pieces of random sizes, its data in pieces of random sizes too. The answers must be the same: the format libarchive names, the path, mode, owner, group, size and time, the data's length and FNV-1a hash and how it ends, and how the archive ends. The archives:
  - libarchive's test archive (the `libarchive-ar` set: GNU's, with a filename table), read four ways (in memory or as a stream, data read or skipped), and 400 damaged copies: a bit flipped or a byte or a field changed in a header, a bit anywhere, cut anywhere, bytes put in or taken out, bytes after the end.
  - About 290 archives libarchive's BSD and SVR4 writers make, with names of 1 to 100 bytes (SVR4's long ones in a filename table), modes, owners, times and data of 0 to 4,097 bytes, each read twice and damaged three times.
  - 1,500 archives the test makes itself (`tests/ar_support/mod.rs`), with what the writers do not make, read twice and damaged once: symbol tables, filename tables with each separator and padding, right and wrong, two tables, a table after the names that use it, GNU long names pointing anywhere, `/9xyz`, BSD long names of length 0, longer than their entry and longer than 1 MiB, `__.SYMDEF`, `/SYM64/`, names of spaces, NULs, slashes and bytes past ASCII, fields with spaces, tabs, digits past their radix and other characters, sizes that are not the data's, odd sizes with their padding byte, another byte or none, a wrong header signature, another global header, and archives cut anywhere; and 600 headers whose fields are as ar never writes them.

  About 7,000 answers are compared where the oracle is built (Linux and macOS in CI), and every error libarchive's ar reader can give comes up among them; the test checks that each does. `AR_SEED=<n> AR_COUNT=<count> cargo test --release -p hivepack --all-features --test ar_oracle crafted` compares more archives made by the test: 20,000 more (60,000 answers) were compared on Linux (x86-64) for the port. `testdata/oracle/ar.txt` replays 1,294 answers libarchive gave on Linux everywhere else: libarchive's archive and damaged copies of it, and archives its writers made, as the requests' bytes, and archives the test makes by number, which it makes again.
- **`tests/open_open.rs`**: Debian packages made by the tests, their `data.tar` in gzip, xz, Zstandard, bzip2, LZMA or none, with GNU's names and members dpkg passes over, opened and extracted through `hivepack::open`; packages without their data, cut short or broken; and GNU hello's packages from Debian (the `debian-packages` set), one of 2023 in xz and one of 2009 in gzip, opened and extracted.
- **Fuzzing**: the `ar` target reads any input, every entry and its data, twice, from pieces of the input and in pieces of different sizes: the same headers, data and end both times, and the same headers when some data is left to skip; no panic. CI seeds it with the archives of the recorded answers.

## Following new releases

The release followed until now is kept in the [mirror of upstream sources](../testdata/README.md#the-upstream-sources-mirrored), to compare the new one with even once its URL is gone. The new release's source set goes into the manifest and the mirror: `python3 scripts/testdata.py mirror --set <name>`.

A new libarchive release's changes to `archive_read_support_format_ar.c`, and to what it calls in `archive_read.c` and `archive_entry.c`, are ported; the manifest's `libarchive-*-source` set and `UPSTREAM_VERSION` name the release, and the `libarchive-ar` set takes its new test archive.

## Licenses

The port is derived from libarchive, under the BSD-2-Clause license (Copyright Tim Kientzle and Kai Wang); `hivepack::ar` is under the same license, with libarchive's notice in its [LICENSE](../crates/hivepack/src/ar/LICENSE). libarchive's test archive, which the tests take from its release (the `libarchive-ar` set), is under it too. GNU hello's packages, which the tests fetch from Debian (the `debian-packages` set), are under the GPL-3.0-or-later, and are not in the repository.
