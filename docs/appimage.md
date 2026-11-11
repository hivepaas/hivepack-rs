# AppImages

An AppImage is a program for Linux in one file: an ELF program, AppImage's runtime, with a file system image that holds the application. `hivepack::appimage` finds the image as the runtime does, and [hivepack::squashfs](squashfs.md) or [hivepack::iso](iso.md) reads it.

- **Type 2**, the AppImages made since 2016 and all that appimagetool makes: a SquashFS image after the program. The runtime mounts it from where the program ends, which it finds from the ELF header and the last section header (`appimage_get_elf_size`); so does `hivepack::appimage::open_squashfs`, through `Squashfs::open_at`.
- **Type 1**, the older: an ISO 9660 image whose system area, its first 32 KiB, holds the program. It is an ISO 9660 image from the file's start, which `hivepack::iso` reads as any other.

Bytes 8 to 10 of the ELF header, padding in `e_ident`, are `AI` and the type, 1 or 2, as AppImage's specification says and `file` and the runtime look for. [open.md](open.md) tells an AppImage by them, before anything else (a type 1 AppImage is an ISO 9660 image too); an ELF program without them is data.

## The source

`elf_size` is a port of `appimage_get_elf_size`, `read_elf32` and `read_elf64` of `src/runtime/runtime.c` of [AppImage's type 2 runtime](https://github.com/AppImage/type2-runtime), release 20251108 (commit `dd6cebedcbddde9c82f89b011e8e1d40b6e43868`), under the MIT license, which `hivepack::appimage::UPSTREAM_VERSION` names; its sources are the `type2-runtime-20251108-source` set of `scripts/testdata.py`, mirrored in hivepaas/hivepack-upstream. A new release's `runtime.c` is compared with it, and what changed in these three functions ported. The rest of the runtime mounts the image with squashfuse, which [squashfs.md](squashfs.md) ports.

The runtime reads `e_ident`: its byte order (`EI_DATA`, little or big endian, else an error) and its class (`EI_CLASS`, 32 or 64 bits, else an error). Then the ELF header of that class, its `e_shoff`, `e_shentsize` and `e_shnum` in that byte order, and the last section header, at `e_shoff + e_shentsize × (e_shnum − 1)`. The program ends at the end of the section header table or of the last section (`sh_offset + sh_size`), whichever is later: a program's sections are before its section headers, but a section can be put after them. The ELF magic itself is not checked: telling one is `appimage_type`'s.

## What differs

- **A 32-bit program of the other byte order** than the machine's: the runtime swaps its last section's offset and size, 32-bit numbers, as 64-bit ones (`file64_to_cpu`), and so finds an end past 4 GiB. The port reads them as the 32-bit numbers they are, in the file's order, on every machine.
- **The arithmetic is checked.** In the runtime, an `e_shnum` of 0 puts the last section header one entry before the table, and an offset past 2^63 wraps; in the port, no section headers, and a table or section past the largest offset, are errors.
- **The messages** are the runtime's, without the file's name and `strerror`; a read error of the file is `Error::Io`.

## How it is shown

`tests/appimage_appimage.rs`:

- ELF headers of 32 and 64 bits in both byte orders, ending with their section headers, with their last section after them, and with one section header.
- Headers cut short (in `e_ident`, in the header, in the last section header), an unknown class or byte order, no section headers, section headers past the file, and a table or section past the largest offset: each an error.
- ELF files that are no AppImage, by bytes 8 to 10 (none, `AI` with type 0 or 3, another case), and the test's own program on Linux: data to `hivepack::open`, and its end found inside it.
- AppImages made of `testdata/squashfs`'s images after programs of each class and byte order: told as type 2, the image found where the program ends and read there as squashfuse reads the image alone, line for line; cut where the image would start, an error.
- A type 1 AppImage made of libarchive's ISO 9660 test image, a program in its system area: told as type 1, and read by `hivepack::iso` as the image alone.
- appimagetool 1.9.1's AppImage (`squashfs-real`): type 2, its program ending at byte 944,632 where its image starts, told under zstd too, and its image read as squashfuse reads it from there.
