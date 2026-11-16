# hivepack::ext

Reading ext2, ext3 and ext4 file systems in safe Rust, read-only.

> **Status:** reads the directories, the inodes and the files of an ext file system on a [`Disk`](../image) — a partition of a card or of a disk image, or a file that holds one as it is. The block numbers ext2 kept in the inode and the indirect blocks after them, the trees of extents ext4 brought, files with holes (which read as zeroes, as what is in them is zeroes), both kinds of symbolic link, devices, pipes and sockets, hard links, names that are bytes rather than text, what each inode says about owner, mode, links and times down to the nanosecond, and the extended attributes beside it, in the inode's own room and in a block. Checked against trees put into file systems by `mke2fs -d` and read back out, against what `debugfs` reads of the same image, and against file systems built byte by byte that `e2fsck` is run over. Writing is not here and is not planned; NTFS is what is left of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225).

```rust
use std::io::Read;

use hivepack::ext::Ext;

let fs = Ext::open(std::fs::File::open("root.img")?)?;
println!("{} {:?} {}", fs.kind().says(), fs.label(), fs.uuid_text());
let mut walk = fs.walk()?;
while let Some(step) = walk.next(&fs)? {
    println!("{} {} bytes", step.entry.name_text(), step.node.size);
    if step.node.is_file() {
        let mut data = Vec::new();
        fs.file(&step.node)?.read_to_end(&mut data)?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

A partition is read by giving it the partition: `Ext::open(Part::new(&disk, part.at, part.size))`, where `part` came from [`hivepack::image::partitions`](../image). That is the layering these modules are for — a container holds a disk, the disk's table names partitions, and a partition holds a file system.

## What it gives

- **`Ext::open(disk)`** — the file system, or why it is not one. `kind`, `label`, `uuid`, `block_size`, `blocks` and `inodes` say what it is. Which of the three it is, is read off the features it has, because nothing in a file system says what it is called.
- **`root`** and **`node(ino)`** — an inode by number, with `What` saying what it is.
- **`read_dir(&node)`** — a directory's entries, in the order its records hold them. `.` and `..` are left out.
- **`lookup_path("sub/file.txt")`** — by the bytes of each name. A symbolic link in the middle of a path is **not** followed.
- **`file(&node)`** — the data, as `io::Read` and `io::Seek`. Blocks that follow one another are read in one go, and a hole reads as zeroes.
- **`read_link(&node)`** — what a link points at, which is bytes.
- **`xattrs(&node)`** and **`xattr(&node, name)`** — the extended attributes kept beside an inode, in the room left over in it and in a block of its own: a file's SELinux label, the capabilities a program is given, its access control lists. The name comes back whole, with the beginning the file system kept as a number put back on.
- **`walk`** — every file and directory, each as a `Step` of a path, the record that named it and the inode behind it.

**A name is bytes, not text.** Linux puts no meaning on a name's bytes beyond `/` and the byte that ends a string, so `Entry::name` is a `Vec<u8>` and a path is too; `Entry::name_text` makes text of one for showing, and loses what is not UTF-8.

## Nothing here is a port

The layout is what the kernel's own documentation (`Documentation/filesystems/ext4/`) and e2fsprogs' on-disk description give. Linux's reader is GPL-2.0 and nothing here needed it, so the repository's own MIT license covers this module and it has no `LICENSE` of its own, as `image` and `fat` have none. What it refuses, and how it is checked, are in [docs/ext.md](../../../../docs/ext.md).
