# WIM: the archive a Windows disc is made of

`hivepack::wim` reads the Windows Imaging Format, read-only. `install.wim` and `boot.wim` on every Windows disc are WIMs, a `.esd` is one, and `DISM`, `wimlib` and 7-Zip all write them. It is the format behind "I downloaded a Windows ISO and want one file out of it" — the ISO's [`iso`](open.md) or [`udf`](udf.md) side holds `sources/install.wim`, and the files are inside that.

**It is not a port.** The layout is Microsoft's published *Windows Imaging File Format (WIM)* specification, the compressions are Microsoft's **[MS-XCA]** and **[MS-PATCH]**, and it is checked against two writers: 7-Zip, which writes an uncompressed WIM and reads every kind, and `wimlib-imagex`, which writes every kind and is the only oracle for a compressed one. wimlib is GPL-3.0-or-later; it is built by `scripts/testdata.py` and run as a program, and nothing in this repository is read from it.

## A WIM is not an archive of files in a row

Two things make it unlike every other archive here:

- **It holds resources, named by what they hold.** A resource is a run of bytes in the file, and the table at the end names each by the **SHA-1 of its contents**. Two files with the same bytes are one resource however many names point at it, so a `.wim` holding five Windows editions is mostly one set of resources with five trees over it. That is also how hard links come out: two entries carrying one hash.
- **It holds images: whole trees of names.** An image is a resource of its own — a *metadata* resource — holding the security descriptors and then the directory tree, each entry naming its data by hash. `install.wim` has one image per edition, and the XML at the end gives each a name (`Windows 11 Pro`).

## What it reads now, and what comes next

This is the first of the layers. What is here:

- **`Wim::open(reader)`** — the header, the table of resources, and the XML. `compression`, `chunk_size`, `images` and `resources` say what the archive is.
- **`Wim::entries(index)`** — one image's tree, parents before what they hold, each entry with the path to it, its name, the short name where it has one, the length and SHA-1 from the table, the three times, Windows' attributes, the Unix mode where 7-Zip wrote one, which set of hard links it belongs to, and how many streams beside its own it names.
- **`Wim::read(&entry)`** — a file's bytes: its chunks decompressed where its resource is compressed with XPRESS or LZX, and refused by name where it is LZMS or a solid block.

What is **named and refused**, each with its own `Unsupported`:

| | |
|---|---|
| `Unsupported::Lzms` | resources compressed with LZMS — what a `.esd` holds |
| `Unsupported::Solid` | a solid block: many files compressed together, as a `.esd` and `wimlib --solid` write |
| `Unsupported::Spanned` | a part of a split archive (`.swm`), whose other parts are files this cannot reach |
| `Unsupported::Reparse` | a file whose data is a reparse point — a symbolic link, a junction, a placeholder — which is not a file's bytes |

So **an uncompressed WIM reads whole, an XPRESS one reads whole, and an LZX one reads whole** — which is what a Windows disc's `install.wim` is. A `.esd`, and anything else holding LZMS or solid resources, opens and says which compression it needs, but its tree is not read: an image's metadata is a resource like any other, and a compressed archive compresses that too. This was measured rather than reasoned about: `wimlib-imagex capture --compress=XPRESS|LZX|LZMS` writes the metadata resource with `METADATA | COMPRESSED` every time, and 7-Zip, which writes WIMs with no compression at all, cannot be asked for one that has it. An earlier version of this page said such an archive still lists every file with its length and SHA-1; that came from an archive whose header was turned over by hand with its resources left uncompressed, which is not what any tool writes, and it was wrong.

What a `.esd` does tell, with no decoder for LZMS:

- **the header** — which compression, and the chunk size (32768 for XPRESS and LZX, 131072 for LZMS);
- **the table of resources** — how many there are, and each one's length before and after compression with its SHA-1. The table is a resource too, but every tool writes it uncompressed;
- **the XML** — each image's name (`Windows 11 Pro`), how many files and directories it holds and how many bytes they come to.

The names, the tree and what is a hard link of what are in the metadata resource, behind the same decoder as the files. **LZMS has no published specification** and the only implementation of it is GPL-3.0-or-later, so it stays named and refused unless that changes; a solid block is LZMS as well.

## A resource is chunks, not one stream

A compressed resource is not one compressed stream. It is the file cut into chunks of the header's chunk size, each compressed on its own, with a table at the front saying where each begins — which is what lets one byte of a 4 GiB file be reached without the rest.

**This layout was measured, not read off a specification.** Microsoft's 2007 *Windows Imaging File Format (WIM)* paper is not published on its own site any more and the copies about are other people's, so `wim::chunks` takes the layout off what `wimlib-imagex` writes and checks every number against it — the same way [`image::Vdi`](image.md) is held to `qemu-img`. On a 140000-byte file in chunks of 32768:

```text
size=140000 packed=41124 chunks=5          chunks = ceil(size / chunk)
table = [32768, 40283, 40558, 40833]       one entry for every chunk but the first,
                                           each counted from the table's end
  chunk 0: 32768 <- 32768 bytes   stored, since compressing it did not pay
  chunk 1:   7515 <- 32768 bytes   XPRESS
  chunk 2:    275 <- 32768 bytes   XPRESS
  chunk 3:    275 <- 32768 bytes   XPRESS
  chunk 4:    275 <-  8928 bytes   XPRESS, the last one holding the rest
```

A chunk's compressed length is the gap to the next chunk's offset, the last reaching the resource's end; an entry is four bytes, or eight where the resource holds more than 4 GiB. And **a chunk as long compressed as it is uncompressed is held as it is**, not compressed — which is why a resource marked compressed whose one chunk is its own length reads as itself, a case `tests/wim.rs` holds on to.

## XPRESS

`wim::xpress` decodes XPRESS with Huffman coding, from Microsoft's **[MS-XCA]: Xpress Compression Algorithm** (v20240423), published under its Open Specification Promise, whose §2.2.4 gives the decompression algorithm as pseudocode. Nothing here is a port: wimlib's decompressor is GPL-3.0-or-later and was not read — it is built by `scripts/testdata.py` and run as a program to write the archives the tests read back.

A block begins with **256 bytes holding 512 four-bit code lengths**, from which the canonical Huffman codes are rebuilt. A symbol under 256 is that byte; at or above it, the symbol carries both the match's length and how many bits of its distance follow:

```text
HuffmanSymbol = 256 + min(Length - 3, 15) + 16 * GetHighBit(Distance)
```

Three things in the specification needed deciding rather than copying, and each is written down where it is handled:

- **A length of 15 means 18 or more**, and the rest is in *bytes* taken from the stream — not from the bits. They sit where a reader taking halfwords has got to, which is what §2.1.4.3 means by "the next bytes that the decompression function will read". `a_long_match_takes_its_length_from_a_byte` counts that position out.
- **The specification's encoder and decoder disagree** about lengths of 65536 and over: the encoder writes a halfword of zero and then a 32-bit length, the decoder refuses a halfword under 15 instead of reading one. A block holds 65536 bytes, so no such length fits in one, and the reader keeps the decoder's rule.
- **A distance of 1 has no bits** to read, and the pseudocode's shift by `32 - MatchOffsetBitLength` does not say so; none are read.

One chunk is one block. A chunk longer than a block (65536 bytes) is refused rather than read as though the table at its start covered all of it; a WIM compresses XPRESS in chunks of 32768, so the case does not arise in an archive a tool wrote.

## LZX

`wim::lzx` decodes LZX, which is what a Windows disc's `install.wim` holds, from Microsoft's **[MS-PATCH]: LZX DELTA Compression and Decompression**, published under its Open Specification Promise, whose §2.7 gives the decoding of a match or a literal as pseudocode. It was read from Microsoft's own Open Specifications pages, which carry a revision date per section; the newest of the ones that matter here is §2.6.3, revised 2025-05-20. LZXD is LZX with delta compression added; a WIM gives the decoder no reference data, so §2.1.3 never arises and what is left is LZX itself. Nothing here is a port: wimlib's decompressor is GPL-3.0-or-later and was not read.

A chunk holds one or more **blocks**, each with its own Huffman trees. The **main tree** has 256 symbols for the literal bytes and eight more for each position slot, so a match's symbol carries both its length header, of [0, 7], and the slot its offset falls in; the slot's **base position** and **footer bits** are what the window decides, 30 slots for the 32768 a WIM's chunks are. The **length tree** holds the rest of a length over eight, the **aligned offset tree** the low three bits of an offset in an aligned offset block, and a **pretree** the path lengths of the others, written as the difference from the lengths of the block before. Three **repeated offsets** stand for the offsets of the last three matches.

**A WIM does four things the specification does not**, and no specification of the WIM variant is published, so these were measured against archives `wimlib-imagex` wrote:

1. **No chunk-size prefix** (§2.2.1): a WIM's own table of chunks already says how long each is.
2. **No E8 header bit** (§2.2.2) — and yet **x86 call translation is always on**. Nothing in the stream says whether the calls were rewritten; every chunk is undone with an `E8_file_size` of **12000000** and a `chunk_offset` of **zero**, a chunk being translated on its own as it is compressed on its own. Measured against a file of nothing but `E8` calls over three chunks, with displacements on each side of every edge of the rule — 0, 1, 1000, 11999999, 12000000, -1, -2³¹ — of which that one reading gives back all 70000 bytes and no other gives even 95% of them: a cumulative `chunk_offset` misses 3892 bytes and a file size of 10000000 misses 6938. A **stored** chunk is not translated: its bytes are the file's own, which a resource whose first chunk compresses and whose second does not says.
3. **No Extra Length field** (§2.6.6). That field is LZXD's own, for the matches of up to 32768 bytes §2.1.5 gives; a WIM's LZX is the older format, whose longest match is the 257 the length tree reaches. Reading the field where it is not there is what a WIM shows plainest: a match of 257 bytes is taken as one of 427, which over text that repeats every 44 bytes still copies the right bytes, so the nine bits it swallows only come out as rubbish a line later.
4. **The Block Size field is not 24 bits** (§2.3.1.2). One bit after the block type says the block holds 32768 bytes; where it does not, a field follows that is 16 bits for a window of 32768 or less and 24 bits for a larger one:

```text
chunk 32768, block 32768:  001 1              verbatim, 32768
chunk 32768, block  4896:  001 0 0x1320       verbatim, 4896    (16 bits)
chunk 65536, block 65536:  001 0 0x010000     verbatim, 65536   (24 bits)
chunk 65536, block 37664:  001 0 0x009320     verbatim, 37664   (24 bits)
chunk 32768, block   624:  010 0 0x0270       aligned offset, 624
```

And one place where **the specification disagrees with itself**: for a slot of exactly three footer bits, §2.6.3 splits the low three bits off into the aligned offset tree, as it does for every offset over 15, while §2.7's pseudocode asks for *more* than three footer bits before it does. Archives are written §2.6.3's way, so that is what is read — the other way round, an aligned offset block whose offsets are 16 to 31 comes out as rubbish, which is how the disagreement was found: an image's metadata is an aligned offset block, and it was the first thing that would not read.

An **uncompressed block** (§2.3.2.1) is the one rule here with no archive to hold it to. Nothing writes one into a WIM — a chunk that does not compress is stored as it is, which `wim::chunks` reads — so its padding, which §2.3.2.1 gives as "1 to 16 bits", is implemented as the specification words it and checked only against streams written here.

## A `.esd` says it is a different version

An archive that may hold LZMS or solid resources carries **version `0x0e00`** in its header rather than the `0x00010d00` everything else writes, and its resources for files inside a solid block carry offsets **into that block** rather than onto the file. Both are read here: the version is accepted so that such an archive can be told apart and say that it needs LZMS, and a solid resource is kept as it stands rather than measured against the file, so that it is refused by name (`Unsupported::Solid`) instead of being called a broken table. Measured on what `wimlib-imagex capture --solid` writes.

## The rules it follows

- **The header's own compression bit is what counts.** A tool that leaves a compression bit set with `FLAG_COMPRESSION` clear means none of it, so the archive is read as uncompressed and the stray bit ignored. A compression bit nothing here knows is `Unsupported::Compression` with the bits it holds, rather than a guess.
- **A part of a split archive is refused at the door**, by the count of parts and by the flag alike: every resource it names could be in another file, so reading it would be reading an archive that is mostly missing.
- **The images are the metadata resources, in the order the table holds them**, and the XML names them by index. The header's own count of images is a hint and is not relied on: an archive a tool stopped half way through writing says more than it holds, and the trees it does have still read.
- **The XML is a label, not a map.** It is read for an image's name and the counts it gives, and nothing else: the tree is what says what an image holds. It is UTF-16 with a byte order mark, written by whatever made the archive, so it is walked for the few elements wanted rather than parsed as XML, a name is cut at 1024 characters, and what is not the text it expects gives nothing.
- **A file of no bytes carries a hash of nothing**, and the table holds no resource for it: that is what every tool writes, and it reads as a file of no bytes rather than as a file whose resource is missing.
- **The length and the SHA-1 come from the table**, which is where a WIM keeps them. An entry whose hash is in no resource is read as a file of no bytes.
- **The tree is checked as it is walked.** An entry has to hold itself (a length of at least 102 bytes, the base the format fixes) and to lie inside the metadata; a child list has to be inside it too; **a directory naming a child list already walked into is a loop** (`Error::TreeLoops`) — including the image's own top level, which the first version of this missed, so that an entry pointing back at the root walked the whole tree a second time.
- **A name is UTF-16 and is refused where it is not** (`Error::Tree`), rather than being replaced: what would come out is a name no file ever had, and extraction would then write it.
- **The security descriptors are stepped over.** What they hold is Windows' own access control, which nothing here turns into a Unix owner or mode. 7-Zip's own extension — a Unix mode in the high half of the attribute field, marked by `0x8000` — is read where it says it is there (`Entry::unix_mode`), because that is what a WIM written on a Unix system carries.
- **The times are FILETIME**, hundreds of nanoseconds from 1601, and a zero is no time rather than 1601. 7-Zip writes the modified time only; Windows' own tools write all three.

## How it is checked

`crates/hivepack/tests/wim.rs`, against 7-Zip as `scripts/testdata.py` builds it (the `generated` group, so CI fails rather than skips where it is required):

- **An archive 7-Zip wrote**, read back: the whole tree with every file's bytes, compared with what went in, and **the paths and lengths `7zz l -slt` lists out of the same archive**, so the two agree rather than each being consistent with itself. A name of more than ASCII, a file of no bytes, a folder inside a folder, a file of 200 KB.
- **Two names of one file**: the entries carry the same SHA-1, the archive holds two resources (the bytes and the tree), and both names read the same bytes.
- **The times**: the modified time within a second of what the file on disk had, and the two 7-Zip leaves out coming back as none.
- **Archives changed by hand**, for what no tool writes: each compression named and refused, both ways it says it is a split set, a version this does not read, a header of the wrong size, a table of resources that is not on the file, a table whose length is not a whole number of entries, and **a tree that leads back into itself**, which is built by pointing a real archive's directory at the root's own child list. That test failed before the loop check covered the root, which is how the gap was found.
- **A fuzz target, `wim`**, which opens any input, walks every image and reads every file, twice, and compares. Each input is fed again with the header turned over to say XPRESS, LZX in chunks of 32768 and LZX in chunks of 65536, because a resource is only decompressed where the header names a compression there is a decoder for: without that, the fuzzer would have to write those four bytes itself before it ever reached a decoder.

`crates/hivepack/tests/wim_wimlib.rs`, against `wimlib-imagex`, which is the only oracle for a **compressed** archive, since 7-Zip reads XPRESS and LZX but writes neither:

- **An uncompressed archive wimlib wrote**, read back as the tree that went in — the same tree 7-Zip's test reads, so what is read is the format and not one tool's habits.
- **An XPRESS archive**, and **LZX archives in chunks of 32768, 65536 and 131072**, each read back as the tree that went in, with every file's bytes compared. The chunk size decides three things at once, so each is read: how wide the Block Size field is, how many position slots the window has (30, 32, 34), and whether a chunk holds more than one block — wimlib ends a block every 100000 bytes, so the 131072 chunks hold two, each with its trees written as the difference from the trees of the block before.
- The tree those archives hold is what says they read: a file over five chunks, one that does not compress at all, one whose first chunk compresses and whose second is stored, a file of nothing but `E8` x86 calls, a name with accents, a file of no bytes — and the image's metadata, which is a compressed resource too, and an aligned offset block where the files are verbatim ones.
- **Every entry field of an LZX archive against the uncompressed archive of the same tree** — the names, the short names, the lengths, the hashes, the times, the attributes, the reparse tags, the hard-link sets. The metadata resource is the same bytes in both, so this is how far a compressed one is read: field by field, and not only as far as the paths and the files. All but the time a file was last *read*, which moves on its own, writing the second archive of a tree being a read of it.
- **An LZMS archive and a `--solid` one**, which say which compression they need by name, and what they still tell without a decoder: the compression, the chunk size, how many resources there are, and the names of their images.

And `wim::lzx`'s and `wim::xpress`'s own tests, which build streams bit by bit from the specifications' own encodings — the only way to reach what no archive here holds: an uncompressed LZX block, a tree that is not a canonical code, a block of a type the format has not, a match reaching before the chunk or past its own block, and the position slot table, whose 30, 32, 34, 36, 38, 42, 50, 66, 98, 162 and 290 slots — one for each window LZX has, from 2^15 to 2^25 — are checked against the rows §2.1.6 tabulates.

## What a reader should know

- **A dentry is 102 bytes before its names**, and the whole entry is padded to eight. The names follow it: the long name, a NUL, then the short name and a NUL. Measured against what 7-Zip writes — a directory called `tree` is 112 bytes, 102 + 8 + 2 — rather than taken from a field in the specification.
- **The twelve bytes after the hash are one thing or the other**: for a reparse point, what kind it is; for anything else, which set of hard links the entry belongs to.
- **The table's entries are 50 bytes**: a resource header of 24, which part of a split set holds it, how many names point at it, and the hash.
- **A resource header's first eight bytes are a length and a flag byte together**: 56 bits of length, then the flags, of which `0x02` says the resource is an image's tree, `0x04` that it is compressed and `0x10` that it is a solid block.
