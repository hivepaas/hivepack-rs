# WIM: the archive a Windows disc is made of

`hivepack::wim` reads the Windows Imaging Format, read-only. `install.wim` and `boot.wim` on every Windows disc are WIMs, a `.esd` is one, and `DISM`, `wimlib` and 7-Zip all write them. It is the format behind "I downloaded a Windows ISO and want one file out of it" — the ISO's [`iso`](open.md) or [`udf`](udf.md) side holds `sources/install.wim`, and the files are inside that.

**It is not a port.** The layout is Microsoft's published *Windows Imaging File Format (WIM)* specification, and it is checked against 7-Zip, which writes an uncompressed WIM and reads every kind.

## A WIM is not an archive of files in a row

Two things make it unlike every other archive here:

- **It holds resources, named by what they hold.** A resource is a run of bytes in the file, and the table at the end names each by the **SHA-1 of its contents**. Two files with the same bytes are one resource however many names point at it, so a `.wim` holding five Windows editions is mostly one set of resources with five trees over it. That is also how hard links come out: two entries carrying one hash.
- **It holds images: whole trees of names.** An image is a resource of its own — a *metadata* resource — holding the security descriptors and then the directory tree, each entry naming its data by hash. `install.wim` has one image per edition, and the XML at the end gives each a name (`Windows 11 Pro`).

## What it reads now, and what comes next

This is the first of the layers. What is here:

- **`Wim::open(reader)`** — the header, the table of resources, and the XML. `compression`, `chunk_size`, `images` and `resources` say what the archive is.
- **`Wim::entries(index)`** — one image's tree, parents before what they hold, each entry with the path to it, its name, the short name where it has one, the length and SHA-1 from the table, the three times, Windows' attributes, the Unix mode where 7-Zip wrote one, which set of hard links it belongs to, and how many streams beside its own it names.
- **`Wim::read(&entry)`** — a file's bytes, **where its resource is not compressed**.

What is **named and refused**, each with its own `Unsupported`:

| | |
|---|---|
| `Unsupported::Xpress` | resources compressed with XPRESS |
| `Unsupported::Lzx` | resources compressed with LZX — what a Windows disc's `install.wim` holds |
| `Unsupported::Lzms` | resources compressed with LZMS — what a `.esd` holds |
| `Unsupported::Solid` | a solid block: many files compressed together, as a `.esd` and `wimlib --solid` write |
| `Unsupported::Spanned` | a part of a split archive (`.swm`), whose other parts are files this cannot reach |
| `Unsupported::Reparse` | a file whose data is a reparse point — a symbolic link, a junction, a placeholder — which is not a file's bytes |

So **an uncompressed WIM reads whole. A compressed one opens and says which compression it needs, but its tree is not read** — an image's metadata is a resource like any other, and a compressed archive compresses that too. This was measured rather than reasoned about: `wimlib-imagex capture --compress=XPRESS|LZX|LZMS` writes the metadata resource with `METADATA | COMPRESSED` every time, and 7-Zip, which writes WIMs with no compression at all, cannot be asked for one that has it. An earlier version of this page said such an archive still lists every file with its length and SHA-1; that came from an archive whose header was turned over by hand with its resources left uncompressed, which is not what any tool writes, and it was wrong.

What a compressed archive does tell, with no decoder at all:

- **the header** — which compression, and the chunk size (32768 for XPRESS and LZX, 131072 for LZMS);
- **the table of resources** — how many there are, and each one's length before and after compression with its SHA-1. The table is a resource too, but every tool writes it uncompressed;
- **the XML** — each image's name (`Windows 11 Pro`), how many files and directories it holds and how many bytes they come to.

The names, the tree and what is a hard link of what are in the metadata resource, behind the same decoder as the files. The decoders come next, one at a time: XPRESS, then LZX, then LZMS.

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
- **A fuzz target, `wim`**, which opens any input, walks every image and reads every file, twice, and compares.

## What a reader should know

- **A dentry is 102 bytes before its names**, and the whole entry is padded to eight. The names follow it: the long name, a NUL, then the short name and a NUL. Measured against what 7-Zip writes — a directory called `tree` is 112 bytes, 102 + 8 + 2 — rather than taken from a field in the specification.
- **The twelve bytes after the hash are one thing or the other**: for a reparse point, what kind it is; for anything else, which set of hard links the entry belongs to.
- **The table's entries are 50 bytes**: a resource header of 24, which part of a split set holds it, how many names point at it, and the hash.
- **A resource header's first eight bytes are a length and a flag byte together**: 56 bits of length, then the flags, of which `0x02` says the resource is an image's tree, `0x04` that it is compressed and `0x10` that it is a solid block.
