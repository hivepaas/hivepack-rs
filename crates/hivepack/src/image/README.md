# hivepack::image

Reading disk images in safe Rust: the block device in the image, and the partitions the table at its start names.

> **Status:** reads a raw image (`.img`, `.bin`, a `dd` of a card) and every container QEMU writes — VHD (`.vhd`, fixed and growing), QCOW2 (`.qcow2`, clusters compressed by deflate or Zstandard), VHDX (`.vhdx`, the only one that says what a sector is on the disk it holds) and VMDK (`.vmdk`, one file or a descriptor naming several, a stream of compressed grains among them) — and the partitions of a master boot record (its own four, and the logical ones in an extended partition's chain) or a GUID partition table (both copies, each checked by its own CRC-32), in 512-byte and 4096-byte sectors. Checked byte for byte against what `qemu-img` writes and reads, and against tables and images built byte by byte. A partition's file system is read by a module of its own: [`hivepack::fat`](../fat) for FAT12, FAT16 and FAT32, with ext2/3/4 and NTFS left of [issue #225](https://github.com/hivepaas/hivepack-rs/issues/225).

```rust
let image = std::fs::File::open("card.img")?;
if let Some(found) = hivepack::image::partitions(&image)? {
    for part in &found.partitions {
        println!(
            "{} at {}, {} bytes, {}",
            part.number,
            part.at,
            part.size,
            part.kind.says().unwrap_or("of a kind not in the list")
        );
    }
}
```

Nothing here is a port, the containers included: a partition table has no library behind it, and the container formats have published specifications (Microsoft's for VHD and VHDX, QEMU's own interoperability specification for QCOW2, VMware's for VMDK), so they are implemented from those and checked against `qemu-img` — a tool that is run, not code that is copied. Porting QEMU's block drivers would have put this module under GPL-2.0. A master boot record's layout is the one every system has agreed on, and a GUID partition table's is the UEFI specification's (2.10, §5.3), so the repository's own MIT license covers this module and it has no `LICENSE` of its own. The rules it follows, and how it is checked, are in [docs/image.md](../../../../docs/image.md).

A `Disk` is a size and reads at offsets, never a position, so one can be read from several threads. `Part` is one partition as a disk of its own, which is what a file system in it will be read from. A GUID partition table says what a sector is by where its header lies; a master boot record cannot say, so it is read in 512-byte sectors, and `partitions_in` reads one in the sectors a caller knows the disk to have.
