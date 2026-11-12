# hivepack::appimage

AppImages in safe Rust: where the program at the start of an AppImage ends, ported from AppImage's type 2 runtime, and the image after it.

> **Status:** finds the end of 32-bit and 64-bit ELF programs of either byte order, as the type 2 runtime 20251108's `appimage_get_elf_size` finds it, and opens a type 2 AppImage's SquashFS image there with `hivepack::squashfs`; a type 1 AppImage is an ISO 9660 image, which `hivepack::iso` reads. Checked with appimagetool 1.9.1's AppImage, read as squashfuse reads it, with AppImages made of the SquashFS and ISO 9660 test images, ELF programs that are not AppImages, and damaged headers.

```rust
use hivepack::appimage::{AppImageType, appimage_type, open_squashfs};

let mut file = std::fs::File::open("app.AppImage")?;
let mut head = [0u8; 16];
std::io::Read::read_exact(&mut file, &mut head)?;
if appimage_type(&head) == Some(AppImageType::Two) {
    let mut fs = open_squashfs(file)?;
    let root = fs.root()?;
    for entry in fs.read_dir(&root)? {
        println!("{}", String::from_utf8_lossy(&entry?.name));
    }
}
```

`appimage_type` tells an AppImage by its first bytes (an ELF file's magic, and `AI` with its type at byte 8), `elf_size` finds where its program ends, and `open_squashfs` opens the image there. `hivepack::extract::extract_squashfs` extracts it, and `hivepack::open` tells an AppImage of each type from what else a file is.

How the port follows the runtime, and how it is checked, is in [docs/appimage.md](../../../../docs/appimage.md).

## License

MIT, as AppImage's type 2 runtime is (see [LICENSE](LICENSE)).
