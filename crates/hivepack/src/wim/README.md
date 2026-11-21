# hivepack::wim

Reading WIM archives in safe Rust, read-only: the Windows Imaging Format — `install.wim` and `boot.wim` of a Windows disc, a `.esd`, what `DISM` and `wimlib` write.

> **Status:** the header, the table of resources, the XML that names the images, and each image's tree, with every entry's name, length, SHA-1, times, attributes, hard-link set and short name — and the files themselves. **XPRESS and LZX are decoded** (`xpress`, from Microsoft's [MS-XCA]; `lzx`, from [MS-PATCH]), so an archive compressed with either reads whole — its tree as well as its files, since an image's metadata is itself a compressed resource. **A Windows disc's `install.wim` is LZX, and reads whole.** LZMS and solid blocks are named and refused rather than guessed at: LZMS has no published specification and the only implementation of it is GPL-3.0-or-later, so a `.esd` opens and says it needs LZMS, telling its header, its table of resources with each one's length and SHA-1, and the XML that names its images. Such an archive carries WIM version `0x0e00`, which is read so that it can say so. A compressed resource is chunks with a table of offsets, not one stream, and that layout was measured off `wimlib-imagex` rather than read off a paper, as were the four things a WIM's LZX does that [MS-PATCH] does not. Checked against what 7-Zip and `wimlib-imagex` write and list, and against archives changed by hand. Writing is not here and is not planned.

```rust
use hivepack::wim::Wim;

let mut wim = Wim::open(std::fs::File::open("install.wim")?)?;
for image in wim.images().to_vec() {
    println!("{} {:?}", image.index, image.name);
    for entry in wim.entries(image.index)? {
        println!("  {} {} bytes", entry.path, entry.size);
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## A WIM is not an archive of files in a row

It holds **resources**, each named by the SHA-1 of what it holds, and **images** — whole trees of names — that point at them. Two files with the same bytes are one resource however many names point at it, which is also how a hard link comes out: two entries carrying one hash. A `.wim` of five Windows editions is mostly one set of resources with five trees over it.

## What it gives

- **`Wim::open(reader)`** — the archive, or why it is not one. `compression`, `chunk_size`, `images` and `resources` say what it is.
- **`Wim::entries(index)`** — one image's tree, parents before what they hold, each entry with the path to it.
- **`Wim::read(&entry)`** — a file's bytes, its chunks decompressed where its resource is compressed with XPRESS or LZX; a directory, a reparse point and a resource needing LZMS are refused by name.
- **`Entry`** — the name, the short name, the length and SHA-1 from the table, the three times, Windows' attributes, the Unix mode 7-Zip writes on a Unix system, the reparse tag where it is one, and which set of hard links it belongs to.

## Nothing here is a port

The layout is Microsoft's published *Windows Imaging File Format (WIM)* specification, and the compressions are Microsoft's [MS-XCA] and [MS-PATCH], both published under its Open Specification Promise. wimlib, the only other reader of all of this, is GPL-3.0-or-later: it is built by `scripts/testdata.py` and run as a program to write the archives the tests read back, and nothing here is read from it. So the repository's own MIT license covers this module and it has no `LICENSE` of its own. The rules it follows, what it refuses, and how it is checked are in [docs/wim.md](../../../../docs/wim.md).
