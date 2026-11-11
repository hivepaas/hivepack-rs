# hivepack::squashfs

Reading SquashFS images (snap packages, AppImages' images, live systems' root file systems) in safe Rust, ported from squashfuse's library.

> **Status:** reads SquashFS 4.0 as squashfuse 0.6.5 does: every inode type, basic and extended (directories with their index, files with fragments, holes and the block index, symbolic links, block and character devices, FIFOs, sockets), hard links, owners, extended attributes stored inline and out of line, and the export table; data and metadata compressed with zlib, LZMA, LZO, xz, LZ4 or zstd through hivepack's own decoders, or stored. What it reads is squashfuse's, line for line, on 31 images mksquashfs 4.6.1 makes (all but its LZO ones), a snap and an AppImage, and thousands of damaged copies of them. Writing is not ported. This crate is not on crates.io.

```rust
use std::io::Read;

use hivepack::squashfs::{Squashfs, Step};

let mut fs = Squashfs::open(std::fs::File::open("app.snap")?)?;
let root = fs.root()?;
let mut walk = fs.traverse(&root)?;
while let Some(step) = walk.next(&mut fs)? {
    if let Step::Entry { path, entry } = step {
        let inode = fs.inode(entry.inode)?;
        if inode.is_file() {
            let mut data = Vec::new();
            fs.file(&inode).read_to_end(&mut data)?;
            println!("{} {} bytes", String::from_utf8_lossy(&path), data.len());
        }
    }
}
```

`Squashfs::open` opens an image (`sqfs_init`), and `open_at` one that starts further in a file, as an AppImage's does after its program. `inode` reads an inode (`sqfs_inode_get`), `read_dir` lists a directory, `lookup` and `lookup_path` find a name and a path, `stat` gives the attributes (`sqfs_stat`), `read_link` a link's target, `xattrs` its extended attributes, `read_at` or `file` a file's data (`sqfs_read_range`), `traverse` walks a tree (`sqfs_traverse`), and `export_inode` finds an inode by its number. Errors are squashfuse's `sqfs_err`, with what failed. Extracting to disk, with its checks on names and links, belongs to hivepack::extract (`extract_squashfs`), and telling an image from what else a file is to hivepack::open.

How the port follows squashfuse, where it does not, and how it is checked, is in [docs/squashfs.md](../../../../docs/squashfs.md).

## License

BSD-2-Clause, as squashfuse is; its `squashfs_fs.h` is Phillip Lougher's, under the same license with his permission (see [LICENSE](LICENSE)).
