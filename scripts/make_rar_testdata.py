#!/usr/bin/env python3
"""Makes testdata/rar/, which the port never writes itself: the archives
tools/rar-bench reads, from data of this repository's own, with RARLAB's programs.

    python3 scripts/make_rar_testdata.py RAR7 RAR6

RAR7 and RAR6 are RAR 7's and RAR 6's `rar`: RAR 7 no longer writes RAR 4's format.
They are not needed for anything else, and are not in this repository.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT_LIMIT = 6 << 20
BINARY_SIZE = 2 << 20
PASSWORD = "hivepack"

# The archive's name, which program, and how: one thread, as the port reads.
VARIANTS = [
    ("rar5-m1", 7, ["-ma5", "-m1"]),
    ("rar5-m3", 7, ["-ma5", "-m3"]),
    ("rar5-m5", 7, ["-ma5", "-m5"]),
    ("rar5-m3-solid", 7, ["-ma5", "-m3", "-s"]),
    ("rar5-m3-password", 7, ["-ma5", "-m3", f"-p{PASSWORD}"]),
    ("rar4-m1", 6, ["-ma4", "-m1"]),
    ("rar4-m3", 6, ["-ma4", "-m3"]),
    ("rar4-m5-solid", 6, ["-ma4", "-m5", "-s"]),
    ("rar4-m3-ppmd", 6, ["-ma4", "-m3", "-mct+"]),
    ("rar4-m3-password", 6, ["-ma4", "-m3", f"-p{PASSWORD}"]),
]


def binary_data() -> bytes:
    """Bytes with some structure, as a program's or a picture's have: runs, records
    that repeat with changes, and noise, always the same."""
    state = 0x12345678
    out = bytearray()

    def next_word() -> int:
        nonlocal state
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        return state

    while len(out) < BINARY_SIZE:
        kind = next_word() % 4
        length = 64 + next_word() % 4096
        if kind == 0:
            out += bytes([next_word() & 0xFF]) * length
        elif kind == 1 and len(out) > length:
            start = next_word() % (len(out) - length)
            piece = bytearray(out[start:start + length])
            for at in range(0, len(piece), 16):
                piece[at] = next_word() & 0xFF
            out += piece
        elif kind == 2:
            out += b"".join((i * 3 & 0xFFFFFFFF).to_bytes(4, "little") for i in range(length // 4))
        else:
            out += b"".join(next_word().to_bytes(4, "little") for _ in range(length // 4))
    return bytes(out[:BINARY_SIZE])


def make_input(folder: Path) -> None:
    listed = subprocess.run(["git", "ls-files", "crates/hivepack/src/*/*.rs", "docs/*.md"], cwd=ROOT, check=True,
                            capture_output=True, text=True).stdout.split("\n")
    total = 0
    for name in sorted(filter(None, listed)):
        source = ROOT / name
        total += source.stat().st_size
        if total > TEXT_LIMIT:
            break
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (folder / "data.bin").write_bytes(binary_data())


def main() -> None:
    programs = {7: sys.argv[1], 6: sys.argv[2]}
    out = ROOT / "testdata" / "rar"
    out.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        make_input(Path(temp))
        for name, version, options in VARIANTS:
            target = out / f"{name}.rar"
            target.unlink(missing_ok=True)
            subprocess.run([programs[version], "a", "-r", "-idq", "-mt1", *options, str(target), "."],
                           cwd=temp, check=True)
            print(f"{target.name}: {target.stat().st_size} bytes")


if __name__ == "__main__":
    main()
