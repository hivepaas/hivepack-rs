#!/bin/bash
# Records what Linux reads of the images crates/hivepack/tests/udf_crafted.rs
# writes, in testdata/udf/crafted: from the repository,
#
#   UDF_CRAFTED=$PWD/target/udf-crafted cargo test -p hivepack --all-features \
#       --test crafted write_crafted_images -- --ignored
#   docker run --rm --privileged -v "$PWD":/repo -w /repo ubuntu:24.04 \
#       tools/udf-images/crafted.sh target/udf-crafted testdata/udf/crafted
#
# Each <name>.txt starts with the SHA-256 of the image it is of.

set -euo pipefail

in=${1:?the folder of the images}
out=${2:?the folder to write to}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"

if ! command -v python3 >/dev/null || ! command -v mount >/dev/null; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
fi

mnt=$(mktemp -d)
trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt"' EXIT

for img in "$in"/*.udf; do
    name=$(basename "$img" .udf)
    # The block size is in the name, else 2048.
    bs=$(echo "$name" | sed -n 's/.*-bs\([0-9]*\).*/\1/p')
    bs=${bs:-2048}
    sum=$(sha256sum "$img" | cut -d' ' -f1)
    if mount -o "loop,ro,utf8,bs=$bs" -t udf "$img" "$mnt" 2>/dev/null; then
        { echo "# sha256 $sum"; python3 "$here/answer.py" "$mnt"; } > "$out/$name.txt"
        umount "$mnt"
        echo "$name: $(($(wc -l < "$out/$name.txt") - 1)) entries"
    else
        { echo "# sha256 $sum"; echo "# Linux does not mount it:"; dmesg 2>/dev/null | grep UDF-fs | tail -3 | sed 's/^\[[^]]*\] /# /'; } > "$out/$name.txt"
        echo "$name: not mounted"
    fi
done
