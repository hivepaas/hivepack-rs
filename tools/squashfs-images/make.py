#!/usr/bin/env python3
"""SquashFS images for hivepack::squashfs's tests, made by mksquashfs from
trees of files this script writes.

    make.py full <mksquashfs> <out>     the images of the squashfs-images set
    make.py small <mksquashfs> <out>    the small images of testdata/squashfs

scripts/testdata.py runs the first with squashfs-tools 4.6.1's mksquashfs,
which it builds (the mksquashfs set); the second was run once, as
testdata/squashfs/LICENSE says, and its images are committed.

The trees are the same on every run and every system: their contents come
from a seeded random number generator, their permissions and modification
times are set here, owners from mksquashfs's -force-uid and -force-gid,
and the image's time from -mkfs-time. Extended attributes come only from
the pseudo file (-xattrs-exclude drops any the file system has), and so do
devices, FIFOs, sockets, the owners other than root, setuid, setgid and
sticky modes, and a symbolic link longer than macOS allows: no root is
needed. Hard links are made in the tree: the pseudo file's (`l`) would not
be, as mksquashfs matches them to the file they name by its whole stat,
which -force-uid has changed by then. <out>/manifest.txt lists each image
with the arguments mksquashfs was given after the tree and the image.
"""

import os
import random
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

# The image's time, and the first of the files' modification times.
MKFS_TIME = 1700000000
FILE_TIME = 1600000000
# The modification time of what the pseudo file makes.
PSEUDO_TIME = 1650000000

# What every image is made with: no appending to an old image, one
# compressor thread, the image's time, every file owned by root unless the
# pseudo file says otherwise, and no extended attributes from the file
# system.
COMMON = ["-noappend", "-quiet", "-no-progress", "-processors", "1", "-mkfs-time", str(MKFS_TIME),
          "-force-uid", "0", "-force-gid", "0", "-pseudo-override"]
NO_SYSTEM_XATTRS = ["-xattrs-exclude", "."]

# The images of the full tree: their names and the options that make them.
# -always-use-fragments is left out: it is another name for -tailends, and
# makes the same image. -no-compression with gzip makes the same image as
# -noI -noD -noF -noX (with -noId too, as an id table that does not shrink
# is stored uncompressed anyway), so it is given with zstd: an image whose
# superblock names a compressor that compressed nothing.
FULL_IMAGES = [
    ("gzip", ["-comp", "gzip"]),
    ("lzma", ["-comp", "lzma"]),
    ("lzo", ["-comp", "lzo"]),
    ("xz", ["-comp", "xz"]),
    ("lz4", ["-comp", "lz4"]),
    ("zstd", ["-comp", "zstd"]),
    ("gzip-b4k", ["-comp", "gzip", "-b", "4K"]),
    ("gzip-b8k", ["-comp", "gzip", "-b", "8K"]),
    ("gzip-b64k", ["-comp", "gzip", "-b", "64K"]),
    ("gzip-b1m", ["-comp", "gzip", "-b", "1M"]),
    ("zstd-b4k", ["-comp", "zstd", "-b", "4K"]),
    ("zstd-b1m", ["-comp", "zstd", "-b", "1M"]),
    ("gzip-uncompressed", ["-comp", "gzip", "-noI", "-noD", "-noF", "-noX"]),
    ("zstd-no-compression", ["-comp", "zstd", "-no-compression"]),
    ("no-fragments", ["-no-fragments"]),
    ("tailends", ["-tailends"]),
    ("no-exports", ["-no-exports"]),
    ("no-xattrs", ["-no-xattrs"]),
    ("no-sparse", ["-no-sparse"]),
    ("no-duplicates", ["-no-duplicates"]),
    ("no-hardlinks", ["-no-hardlinks"]),
    ("xz-bcj-x86", ["-comp", "xz", "-Xbcj", "x86"]),
    ("xz-dict-8k", ["-comp", "xz", "-Xdict-size", "8K"]),
    ("lz4-hc", ["-comp", "lz4", "-Xhc"]),
    ("zstd-level19", ["-comp", "zstd", "-Xcompression-level", "19"]),
    ("gzip-level1", ["-comp", "gzip", "-Xcompression-level", "1"]),
    ("lzo-lzo1x_1", ["-comp", "lzo", "-Xalgorithm", "lzo1x_1"]),
]

# The small images: one for each compressor and one with nothing
# compressed, in 4 KiB blocks.
SMALL_IMAGES = [(name, ["-comp", name, "-b", "4K"]) for name in ("gzip", "lzma", "lzo", "xz", "lz4", "zstd")]
SMALL_IMAGES.append(("uncompressed", ["-comp", "gzip", "-b", "4K", "-noI", "-noD", "-noF", "-noX"]))

WORDS = ("squash file system block fragment inode directory table index xattr id export "
         "super compress data metadata entry name link device fifo socket owner group mode "
         "time size offset start count list hash value key root tree node leaf page cache "
         "read write seek map zero sparse tail end").split()


def text(rng: random.Random, size: int) -> bytes:
    """size bytes of lines of words: data that compresses."""
    out = bytearray()
    while len(out) < size:
        out += (" ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 14))) + "\n").encode()
    return bytes(out[:size])


def mixed(rng: random.Random, size: int, chunk: int) -> bytes:
    """size bytes of text with a chunk of random bytes in every four, so that
    some blocks compress and others are stored as they are."""
    out = bytearray()
    while len(out) < size:
        out += rng.randbytes(chunk) if len(out) // chunk % 4 == 1 else text(rng, chunk)
    return bytes(out[:size])


def numbered(size: int) -> bytes:
    """size bytes of numbered lines: each block different, all compressing
    well."""
    out = bytearray()
    line = 0
    while len(out) < size:
        out += f"line {line:09d} of the file that spans many blocks\n".encode()
        line += 1
    return bytes(out[:size])


def x86(rng: random.Random, size: int) -> bytes:
    """size bytes that look like x86 code to XZ's BCJ filter: relative calls
    (E8) to a few functions, between bytes of common instructions. The
    filter makes their targets absolute, the same for every call."""
    functions = [rng.randrange(1 << 20) for _ in range(16)]
    filler = [b"\x55", b"\x48\x89\xe5", b"\x48\x83\xec\x10", b"\x5d", b"\xc3", b"\x90", b"\x31\xc0"]
    out = bytearray()
    while len(out) < size:
        for _ in range(rng.randint(1, 4)):
            out += rng.choice(filler)
        target = rng.choice(functions)
        out += b"\xe8" + ((target - (len(out) + 5)) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out[:size])


class Tree:
    """A tree of files written under root, and the lines of its pseudo
    file."""

    def __init__(self, root: Path):
        self.root = root
        self.pseudo = []
        self.modes = {}
        root.mkdir(parents=True)
        self.modes[root] = 0o755

    def parents(self, path: Path) -> None:
        """The folders above path, made with 0755 if they are not there."""
        for parent in reversed(path.parents):
            if parent not in self.modes and self.root in parent.parents:
                parent.mkdir()
                self.modes[parent] = 0o755

    def dir(self, rel: str, mode: int = 0o755) -> None:
        path = self.root / rel
        self.parents(path)
        path.mkdir(exist_ok=True)
        self.modes[path] = mode

    def file(self, rel: str, data: bytes, mode: int = 0o644) -> None:
        path = self.root / rel
        self.parents(path)
        path.write_bytes(data)
        self.modes[path] = mode

    def symlink(self, rel: str, target: str) -> None:
        path = self.root / rel
        self.parents(path)
        os.symlink(target, path)
        self.modes[path] = None

    def hardlink(self, rel: str, existing: str) -> None:
        os.link(self.root / existing, self.root / rel)

    def define(self, line: str) -> None:
        self.pseudo.append(line)

    def finish(self) -> None:
        """The permissions, then the modification times, a second apart in
        the order of the paths, the deepest first so that setting a file's
        does not change its directory's."""
        for path, mode in self.modes.items():
            if mode is not None:
                os.chmod(path, mode)
        paths = sorted(self.modes, key=lambda p: str(p).encode())
        times = {path: FILE_TIME + i for i, path in enumerate(paths)}
        for path in sorted(paths, key=lambda p: -len(p.parts)):
            os.utime(path, (times[path], times[path]), follow_symlinks=False)


def full_tree(root: Path) -> Tree:
    """The tree most images are made of."""
    rng = random.Random(20261111)
    t = Tree(root)

    # Files of every size that matters to blocks and fragments.
    t.dir("files")
    t.file("files/empty", b"")
    t.file("files/one-byte", b"x")
    for size in (4095, 4096, 4097):
        t.file(f"files/size-{size}", text(rng, size))
    t.file("files/size-100000", rng.randbytes(100000))
    t.file("files/mib-plus-3", mixed(rng, (1 << 20) + 3, 16384))
    t.file("files/mixed-3m", mixed(rng, 3 << 20, 65536))
    t.file("files/hole-3m", text(rng, 1 << 20) + bytes(1 << 20) + text(rng, 1 << 20))
    t.file("files/zeros-2m", bytes(2 << 20))
    # 2,304 blocks of 4 KiB: a block list of 9 KiB, more than one metadata
    # block.
    t.file("files/numbered-9m", numbered(9 << 20))
    t.file("files/x86-code", x86(rng, 262144))
    duplicate = text(rng, 200000) + rng.randbytes(50000)
    t.file("files/duplicate-a", duplicate)
    t.file("files/duplicate-b", duplicate)
    t.file("files/hardlink-a", text(rng, 30000))
    t.hardlink("files/hardlink-b", "files/hardlink-a")
    t.dir("dirs")
    t.hardlink("dirs/hardlink-c", "files/hardlink-a")
    t.file("files/read-only", text(rng, 500), 0o444)
    t.file("files/private", text(rng, 700), 0o600)
    t.file("files/script", b"#!/bin/sh\necho squashfs\n", 0o755)

    t.dir("links")
    t.symlink("links/short", "../files/one-byte")
    t.symlink("links/absolute", "/usr/bin/env")
    t.symlink("links/dangling", "nowhere/at/all")
    t.symlink("links/to-dir", "../dirs/empty")
    # 4,000 bytes: longer than macOS lets a symbolic link be.
    t.define(f"links/long S {PSEUDO_TIME} 0777 0 0 " + ("segment/" * 500)[:4000])

    t.dir("dirs")
    t.dir("dirs/empty")
    deep = "dirs/deep"
    for level in range(1, 121):
        deep += f"/d{level}"
    t.file(deep + "/bottom", b"120 levels down\n")
    # 2,000 entries with long names: a directory of more than 8 KiB, which
    # mksquashfs gives an index.
    t.dir("dirs/many")
    for i in range(2000):
        name = f"entry-{i:04d}-" + "with-a-long-name-" * (3 + i % 5)
        t.file(f"dirs/many/{name}", text(rng, 40) if i % 100 == 0 else b"")
    t.dir("dirs/names")
    t.file("dirs/names/" + "n" * 255, b"255 bytes of name\n")
    t.file("dirs/names/" + "é" * 127 + "e", b"255 bytes of Latin-1 accents\n")
    t.file("dirs/names/" + "字" * 85, b"255 bytes of CJK\n")
    t.file("dirs/names/café naïve Ångström", b"Latin-1 accents\n")
    t.file("dirs/names/日本語のファイル名", b"CJK\n")
    t.file("dirs/names/emoji 😀🎉", b"emoji\n")
    t.file("dirs/names/name with spaces", b"spaces\n")
    t.file("dirs/names/trailing space ", b"a space at the end\n")

    # Devices, a FIFO and a socket, from the pseudo file only.
    t.dir("special")
    t.define(f"special/block-8-1 B {PSEUDO_TIME} 0660 0 6 8 1")
    t.define(f"special/block-max B {PSEUDO_TIME} 0660 0 6 4095 1048575")
    t.define(f"special/char-1-3 C {PSEUDO_TIME} 0666 0 0 1 3")
    t.define(f"special/char-max C {PSEUDO_TIME} 0600 0 0 4095 1048575")
    t.define(f"special/fifo I {PSEUDO_TIME} 0644 0 0 f")
    t.define(f"special/socket I {PSEUDO_TIME} 0755 0 0 s")
    t.define(f"special/pseudo-dir D {PSEUDO_TIME} 0700 1000 1000")

    # Owners and modes.
    t.dir("owners")
    for name, uid, gid, mode in [("root", 0, 0, "0644"), ("user", 1000, 1000, "0644"),
                                 ("nobody", 65534, 65534, "0640"), ("max", 4294967294, 4294967294, "0600"),
                                 ("user-root", 1000, 0, "0644"), ("setuid", 0, 0, "4755"),
                                 ("setgid", 0, 1000, "2755"), ("setuid-setgid", 1000, 1000, "6711")]:
        t.file(f"owners/{name}", name.encode() + b"\n")
        t.define(f"owners/{name} M {PSEUDO_TIME} {mode} {uid} {gid}")
    t.dir("owners/sticky")
    t.define(f"owners/sticky M {PSEUDO_TIME} 1777 0 0")
    t.dir("owners/sticky-setgid")
    t.define(f"owners/sticky-setgid M {PSEUDO_TIME} 3775 65534 65534")

    # Extended attributes: on files, a directory, a symbolic link and a
    # device, so that the extended inode types appear; a value of 3,000
    # bytes; the same value in two sets, which mksquashfs keeps once and
    # points to from the other; and one set given to two files, which share
    # it. mksquashfs keeps user.* ones on files and directories only, as
    # Linux does (man 7 xattr), so the others have trusted.* and security.*
    # ones.
    t.dir("xattrs")
    t.file("xattrs/plain", b"plain\n")
    t.define("xattrs/plain x user.a=hello")
    t.define("xattrs/plain x user.binary=0x00ff7f80")
    t.file("xattrs/namespaces", b"namespaces\n")
    t.define("xattrs/namespaces x user.u=user")
    t.define("xattrs/namespaces x trusted.t=trusted")
    t.define("xattrs/namespaces x security.s=security")
    t.file("xattrs/big", b"big\n")
    t.define("xattrs/big x user.big=" + text(rng, 3000).decode().replace("\n", " "))
    shared = " ".join(["a value that two xattr sets hold"] * 4)
    t.file("xattrs/shared-value-1", b"1\n")
    t.define(f"xattrs/shared-value-1 x user.shared={shared}")
    t.define("xattrs/shared-value-1 x user.one=1")
    t.file("xattrs/shared-value-2", b"2\n")
    t.define(f"xattrs/shared-value-2 x user.shared={shared}")
    t.define("xattrs/shared-value-2 x user.two=2")
    for name in ("same-set-1", "same-set-2"):
        t.file(f"xattrs/{name}", name.encode() + b"\n")
        t.define(f"xattrs/{name} x user.same=one set for two files")
    t.define("xattrs x user.dir=a directory")
    t.define("links/short x trusted.link=a symbolic link")
    t.define("special/block-8-1 x security.dev=a device")
    t.define("special/char-1-3 x trusted.dev=a device")
    t.define("special/fifo x trusted.fifo=a fifo")
    t.define("special/socket x trusted.socket=a socket")
    t.define("files/hardlink-a x user.hardlink=two names")
    return t


def small_tree(root: Path) -> Tree:
    """The tree of the small images: a few of each kind of entry."""
    rng = random.Random(16384)
    t = Tree(root)
    t.file("hello.txt", b"Hello, SquashFS!\n")
    # Two blocks of 4 KiB and a tail in a fragment.
    t.file("blocks.txt", text(rng, 9000))
    t.symlink("link", "hello.txt")
    t.dir("dir")
    t.file("dir/inner.txt", b"inside a directory\n")
    t.hardlink("dir/hardlink.txt", "hello.txt")
    t.define(f"device B {PSEUDO_TIME} 0660 0 6 8 1")
    t.define(f"fifo I {PSEUDO_TIME} 0644 0 0 f")
    t.define("hello.txt x user.comment=small")
    t.define("link x trusted.link=a symbolic link")
    return t


def make(mksquashfs: str, kind: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    work = out / f".{kind}-tree"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    try:
        tree = (full_tree if kind == "full" else small_tree)(work / kind)
        tree.finish()
        pseudo = work / "pseudo"
        pseudo.write_text("\n".join(tree.pseudo) + "\n", encoding="utf-8")
        images = FULL_IMAGES if kind == "full" else SMALL_IMAGES
        lines = [f"# mksquashfs {kind} <image> <arguments>, from tools/squashfs-images/make.py {kind}"]
        for name, options in images:
            image = out / f"{name}.sqfs"
            if image.exists():
                image.unlink()
            xattrs = [] if "-no-xattrs" in options else NO_SYSTEM_XATTRS
            args = [*COMMON, "-pf", "pseudo", *xattrs, *options]
            result = subprocess.run([mksquashfs, kind, str(image.resolve()), *args], cwd=work,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if result.returncode != 0:
                sys.exit(f"mksquashfs failed for {name}:\n{result.stdout}")
            lines.append(f"{image.name} {shlex.join(args)}")
            print(f"  {image.name}: {image.stat().st_size} bytes")
        (out / "manifest.txt").write_text("\n".join(lines) + "\n")
    finally:
        shutil.rmtree(work)


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("full", "small"):
        sys.exit(__doc__)
    make(sys.argv[2], sys.argv[1], Path(sys.argv[3]))


if __name__ == "__main__":
    main()
