# hivepack::udf

Reading UDF volumes (DVD, Blu-ray and disk images) in safe Rust, ported from NetBSD's UDF file system.

> **Status:** reads UDF 1.02 to 2.60 as NetBSD mounts it: physical, sparable, virtual (VAT) and metadata partitions, blocks of 512 to 4096 bytes, file entries and extended ones, every allocation descriptor and allocation extents, strategy 4096, hidden and deleted entries, names in OSTA compressed Unicode, symbolic links, devices, permissions, owners and times. What it reads is the same as Linux's udf file system on 36 images mkudffs, genisoimage and its tests make, and hundreds of damaged ones do not make it panic. Writing is not ported.

```rust
let mut udf = hivepack::udf::Udf::open(std::fs::File::open("disc.iso")?)?;
let root = udf.root().clone();
let entries: Vec<_> = udf.read_dir(&root)?.collect::<Result<_, _>>()?;
for entry in entries {
    if entry.is_parent() {
        continue;
    }
    let node = udf.node(entry.icb)?;
    let stat = udf.stat(&node);
    println!("{} {} bytes", String::from_utf8_lossy(&entry.name), stat.size);
}
```

`Udf::open` mounts the volume, trying the usual sector sizes. A directory's entries come as NetBSD lists them (with `..`, without hidden ones unless `Options::unhide`); `node` reads an entry's node, `stat` gives its attributes, `read_link` a link's target, and `read_at` or `file` a file's data. Errors are NetBSD's errno values, with what failed. Extracting to disk, with its checks on names and links, belongs to hivepack::extract (`extract_udf`), and telling a UDF volume from what else a file is to hivepack::open.

How the port follows NetBSD, where it does not, and how it is checked, is in [docs/udf.md](../../../../docs/udf.md).

## License

BSD-2-Clause, as NetBSD's UDF file system is, and BSD-3-Clause for the conversion of dates from NetBSD's `clock_subr.c` (see [LICENSE](LICENSE)). The OSTA specification's routines are free to use.
