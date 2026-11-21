# hivepack::wim

Reading WIM archives in safe Rust, read-only: the Windows Imaging Format — `install.wim` and `boot.wim` of a Windows disc, a `.esd`, what `DISM` and `wimlib` write.

> **Status:** the header, the table of resources, the XML that names the images, and each image's tree, with every entry's name, length, SHA-1, times, attributes, hard-link set and short name — and the files whose resources are **not compressed**. **XPRESS is decoded** (`xpress`, from Microsoft's [MS-XCA] specification), so an XPRESS archive reads whole — its tree as well as its files, since an image's metadata is itself a compressed resource. LZX and LZMS are named and refused rather than guessed at, and their decoders are what comes next; a Windows disc's `install.wim` is LZX, so it opens and says it needs LZX, telling its header, its table of resources with each one's length and SHA-1, and the XML that names its images. A `.esd` and anything else holding solid resources carries WIM version `0x0e00`, which is read so that it can say it needs LZMS. A compressed resource is chunks with a table of offsets, not one stream, and that layout was measured off `wimlib-imagex` rather than read off a paper. Checked against what 7-Zip writes and lists, and against archives changed by hand. Writing is not here and is not planned.

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
- **`Wim::read(&entry)`** — a file's bytes, where its resource is not compressed; a directory and a reparse point are refused by name.
- **`Entry`** — the name, the short name, the length and SHA-1 from the table, the three times, Windows' attributes, the Unix mode 7-Zip writes on a Unix system, the reparse tag where it is one, and which set of hard links it belongs to.

## Nothing here is a port

The layout is Microsoft's published *Windows Imaging File Format (WIM)* specification. So the repository's own MIT license covers this module and it has no `LICENSE` of its own. The rules it follows, what it refuses, and how it is checked are in [docs/wim.md](../../../../docs/wim.md).
