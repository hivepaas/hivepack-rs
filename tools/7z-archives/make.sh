#!/bin/bash
# Makes the 7z test archives of testdata/7z with 7-Zip's 7zz, as
# scripts/testdata.py builds it (target/testdata/7zz/7zz) or another 7zz
# of 26.05:
#
#   tools/7z-archives/make.sh testdata/7z [path/to/7zz]
#
# Each archive holds the same few files, made here with fixed times and
# modes, so that crates/hivepack/tests/extract_sevenz.rs knows what each must
# extract to.

set -euo pipefail

out=$(realpath -m "${1:?the folder to write to}")
here=$(cd "$(dirname "$0")" && pwd)
tool=$(realpath "${2:-$here/../../target/testdata/7zz/7zz}")
mkdir -p "$out"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The files: text, a block of bytes that compresses, an empty file, an
# empty folder, a program's mode, and a name with an accent.
files=$work/files
mkdir -p "$files/docs/plans" "$files/empty folder"
printf 'Notes from inside the archive.\n' > "$files/docs/notes.txt"
python3 -c "import sys; sys.stdout.buffer.write(bytes((i * 7) % 251 for i in range(70000)))" > "$files/docs/plans/pattern.bin"
printf '# Read me\n' > "$files/readme.md"
: > "$files/empty"
printf '#!/bin/sh\necho run\n' > "$files/run.sh"
printf 'café\n' > "$files/café.txt"
chmod 644 "$files/docs/notes.txt" "$files/docs/plans/pattern.bin" "$files/readme.md" "$files/empty" "$files/café.txt"
chmod 755 "$files/run.sh"
find "$files" -exec touch -h -d '2026-09-01 12:00:00 UTC' {} +

make() {
    local name=$1
    shift
    rm -f "$out/$name"
    (cd "$work/${SOURCE:-files}" && "$tool" a -bd -bso0 -bsp0 -y -mtc=off -mta=off "$@" "$out/$name" -- *)
}

# LZMA2, solid, headers compressed: 7zz's defaults.
make plain.7z
# Deflate, a folder for each file, headers not compressed.
make deflate.7z -m0=Deflate -ms=off -mhc=off
# Stored, one solid folder, headers not compressed: the tests change its
# names and data where they are.
make stored.7z -m0=Copy -mhc=off
# BCJ2 and LZMA, with BZip2 and LZMA for its other streams.
make bcj2.7z -m0=BCJ2 -m1=LZMA -m2=LZMA -m3=BZip2 -mb0s0:1 -mb0s1:2 -mb0s2:3
# AES-256 on the data, and on the headers too. Password: secret.
make encrypted.7z -psecret
make encrypted-headers.7z -psecret -mhe=on

# Symbolic links, stored as links (-snl): one inside, one that climbs out.
links=$work/links
mkdir -p "$links/docs"
printf 'Notes from inside the archive.\n' > "$links/docs/notes.txt"
ln -s notes.txt "$links/docs/link"
ln -s ../../etc/passwd "$links/escape"
find "$links" -exec touch -h -d '2026-09-01 12:00:00 UTC' {} +
SOURCE=links make links.7z -snl -mhc=off

# Two names of one path to a case-insensitive file system.
cases=$work/cases
mkdir -p "$cases"
printf 'upper\n' > "$cases/Notes.txt"
printf 'lower\n' > "$cases/notes.txt"
find "$cases" -exec touch -h -d '2026-09-01 12:00:00 UTC' {} +
SOURCE=cases make cases.7z

# A setuid program, whose bit is not kept.
modes=$work/modes
mkdir -p "$modes"
printf '#!/bin/sh\n' > "$modes/setuid.sh"
chmod 4775 "$modes/setuid.sh"
find "$modes" -exec touch -h -d '2026-09-01 12:00:00 UTC' {} +
SOURCE=modes make modes.7z

ls -l "$out"
