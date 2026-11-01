#!/usr/bin/env python3
"""Fetch and generate the test data that is too big to keep in the repository.

testdata/manifest.json lists every set:
- Sets with a "path" are committed under testdata/.
- Sets with "fetch" are downloaded, checked against their SHA-256 and unpacked
  into <cache>/<name>.
- Sets with "generate" are made in <cache>/<name> by zstd's own tools, or
  by the oracles in tools/, built from the pinned zstd, zlib, bzip2, lz4,
  XZ Utils, libzip, nettle, libarchive and libxml2 releases, or with Go from the
  modules their go.sum pins.

The cache is target/testdata, or $HIVEPACK_TESTDATA when set.

    python3 scripts/testdata.py fetch [--group core|generated|fuzz|bench|all ...] [--set NAME ...]
    python3 scripts/testdata.py list

Only the standard library is used, so any Python 3.9 or newer runs it.
"""

import argparse
import binascii
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "testdata" / "manifest.json"
GROUPS = ["core", "generated", "fuzz", "bench"]


def cache_dir() -> Path:
    return Path(os.environ.get("HIVEPACK_TESTDATA", ROOT / "target" / "testdata"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, want: str, downloads: Path) -> Path:
    """The file at url, kept in downloads, once its SHA-256 is want."""
    target = downloads / f"{want[:16]}-{PurePosixPath(url).name}"
    if target.exists() and sha256(target) == want:
        return target
    downloads.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "hivepack-testdata"})
            with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as out:
                shutil.copyfileobj(response, out)
            break
        except OSError as error:
            if attempt == 3:
                raise SystemExit(f"download failed: {url}: {error}")
            time.sleep(2 ** attempt)
    got = sha256(partial)
    if got != want:
        partial.unlink()
        raise SystemExit(f"checksum mismatch for {url}: want {want}, got {got}")
    partial.replace(target)
    return target


def safe_member(name: str) -> PurePosixPath:
    """A member name as a relative path, refusing anything that would land
    outside the set's folder."""
    path = PurePosixPath(name)
    parts = [p for p in path.parts if p not in ("", ".")]
    if path.is_absolute() or ".." in parts or (parts and ":" in parts[0]):
        raise SystemExit(f"refusing archive member {name!r}")
    return PurePosixPath(*parts) if parts else PurePosixPath()


def unpack(archive: Path, kind: str, into: Path) -> None:
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                rel = safe_member(info.filename)
                if info.is_dir() or not rel.parts:
                    continue
                dest = into.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
    elif kind in ("tar.gz", "tar.xz"):
        with tarfile.open(archive, "r:gz" if kind == "tar.gz" else "r:xz") as t:
            for member in t.getmembers():
                rel = safe_member(member.name)
                if not rel.parts:
                    continue
                dest = into.joinpath(*rel.parts)
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src = t.extractfile(member)
                    assert src is not None
                    with src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    dest.chmod(0o755 if member.mode & 0o111 else 0o644)
                # Links and devices are not needed and are skipped.
    elif kind == "none":
        into.mkdir(parents=True, exist_ok=True)
        name = archive.name.split("-", 1)[1]
        shutil.copyfile(archive, into / name)
    else:
        raise SystemExit(f"unknown unpack kind {kind!r}")


def stamp_of(entry: dict) -> str:
    """What a finished set was made from: its manifest entry, and the
    repository sources a generated set is built from."""
    stamp = {"spec": entry.get("fetch") or entry.get("generate")}
    for source in entry.get("generate", {}).get("sources", []):
        stamp[source] = sha256(ROOT / source)
    return json.dumps(stamp, sort_keys=True)


def is_current(folder: Path, stamp: str) -> bool:
    marker = folder / ".complete"
    return marker.exists() and marker.read_text() == stamp


def mark_current(folder: Path, stamp: str) -> None:
    (folder / ".complete").write_text(stamp)


def fetch_set(entry: dict, cache: Path) -> None:
    folder = cache / entry["name"]
    stamp = stamp_of(entry)
    if is_current(folder, stamp):
        print(f"  {entry['name']}: up to date")
        return
    if folder.exists():
        shutil.rmtree(folder)
    staging = cache / f".{entry['name']}.partial"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for file in entry["fetch"]["files"]:
        archive = download(file["url"], file["sha256"], cache / "downloads")
        unpack(archive, file.get("unpack", "none"), staging)
    mark_current(staging, stamp)
    staging.replace(folder)
    print(f"  {entry['name']}: fetched")


def build_tool(source: Path, tool: str) -> Path:
    """zstd's test tool built from the release sources, with zstd's own
    Makefile and the system C compiler."""
    tests = next(source.glob("zstd-*/tests"))
    binary = tests / tool
    if not binary.exists():
        print(f"  building {tool} from {tests.parent.name}")
        jobs = str(os.cpu_count() or 2)
        subprocess.run(["make", "-C", str(tests), "-j", jobs, tool], check=True,
                       stdout=subprocess.DEVNULL)
    return binary


def build_7zz(source: Path, folder: Path) -> None:
    """7-Zip's console program from the release's sources, with its own
    makefile: what makes the archives the tests read. The makefile for GCC
    leaves out assembly; the one for arm64 macs has it. On Windows, the same
    makefile finds MinGW's compiler by itself."""
    bundle = source / "CPP" / "7zip" / "Bundles" / "Alone2"
    print(f"  building 7zz from {source.name}")
    makefile = "cmpl_gcc.mak"
    if sys.platform == "darwin":
        makefile = "cmpl_mac_arm64.mak" if platform.machine() == "arm64" else "cmpl_mac_x64.mak"
    jobs = str(os.cpu_count() or 2)
    make = "mingw32-make" if sys.platform == "win32" else "make"
    build = subprocess.run([make, "-f", f"../../{makefile}", "-j", jobs], cwd=bundle,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if build.returncode != 0:
        # The end of what it said: it warns a lot before an error.
        print(build.stderr[-4000:], file=sys.stderr)
        raise SystemExit(f"building 7zz failed with {build.returncode}")
    program = next(bundle.glob("b/*/7zz*"))
    shutil.copy2(program, folder / program.name)


def libzip_sources(lib: Path) -> list:
    """The library's C files, as lib/CMakeLists.txt lists them in ZIP_SOURCES,
    with the ones it adds for the system; zip_err_str.c is generated apart."""
    text = (lib / "CMakeLists.txt").read_text()
    listed = text.split("set(ZIP_SOURCES", 1)[1].split(")", 1)[0].split()
    names = [n for n in listed if n.endswith(".c") and not n.startswith("$")]
    if sys.platform == "win32":
        return names + ["zip_source_file_win32.c", "zip_source_file_win32_named.c",
                        "zip_source_file_win32_utf16.c", "zip_source_file_win32_utf8.c",
                        "zip_source_file_win32_ansi.c", "zip_random_win32.c"]
    return names + ["zip_source_file_stdio_named.c", "zip_random_unix.c"]


# libbzip2: the library's files of bzip2's Makefile (OBJS), without the
# bzip2 program and its tools.
BZIP2_SOURCES = [
    "blocksort.c", "huffman.c", "crctable.c", "randtable.c", "compress.c", "decompress.c",
    "bzlib.c",
]


# The LZMA SDK's 7z decoder: the files C/Util/7z/makefile.gcc builds 7zdec
# with, without its LZMA assembly loop and with PPMd, as it builds it.
SEVENZ_SOURCES = [
    "Bcj2.c", "Bra.c", "Bra86.c", "BraIA64.c", "CpuArch.c", "Delta.c", "Lzma2Dec.c", "LzmaDec.c",
    "Ppmd7.c", "Ppmd7Dec.c", "Ppmd8.c", "Ppmd8Dec.c", "Ppmd8Enc.c", "7zCrc.c", "7zCrcOpt.c", "7zAlloc.c", "7zArcIn.c", "7zBuf.c",
    "7zBuf2.c", "7zDec.c", "7zFile.c", "7zStream.c",
]
SEVENZ_FLAGS = ["-DZ7_PPMD_SUPPORT", "-DZ7_EXTRACT_ONLY"]


# liblz4: the library's files (lib/), as lz4's lib/Makefile builds them,
# with xxHash's names prefixed as there.
LZ4_SOURCES = ["lz4.c", "lz4frame.c", "lz4hc.c", "xxhash.c"]
LZ4_FLAGS = ["-DXXH_NAMESPACE=LZ4_"]


# liblzma: the folders of its C files, without the multithreaded coders, the
# hardware queries (which need tuklib), the small CRCs of HAVE_SMALL, and
# the programs that write tables. delta/ and simple/ are left out with
# their filters (see tools/xz-oracle/config.h); only their headers, which
# the filter tables include, are on the include path.
LIBLZMA_DIRS = ["common", "check", "lz", "lzma", "rangecoder", "delta", "simple"]
LIBLZMA_LEFT_OUT = ["hardware_",
                    "crc32_small", "crc64_small", "tablegen", "crc_clmul_consts_gen"]


# nettle's AES (encryption only), SHA-1, MD5, HMAC-SHA1 and PBKDF2-HMAC-SHA1,
# in C: what the oracles call, without the assembly versions or the fat
# builds that choose between them.
NETTLE_SOURCES = [
    "aes-set-encrypt-key.c", "aes128-set-encrypt-key.c", "aes192-set-encrypt-key.c",
    "aes256-set-encrypt-key.c", "aes-set-key-internal.c", "aes-encrypt-internal.c",
    "aes-encrypt-table.c", "aes128-encrypt.c", "aes192-encrypt.c", "aes256-encrypt.c",
    "sha1.c", "sha1-compress.c", "sha1-meta.c", "md5.c", "hmac.c", "hmac-sha1.c", "pbkdf2.c",
    "pbkdf2-hmac-sha1.c", "memxor.c", "write-be32.c", "write-le32.c",
]


# What nettle's C files need of the config.h its configure writes: alloca,
# which every system the oracles are built on has. Without it, nettle's
# temporary arrays are local to the block that declares them, and
# hmac_set_key keeps a pointer to the digest of a key longer than a block
# past its block: gcc happens to leave it there, clang does not.
NETTLE_FLAGS = ["-DHAVE_ALLOCA=1", "-include", "malloc.h" if sys.platform == "win32" else "alloca.h"]


def nettle_headers(nettle: Path, folder: Path) -> Path:
    """A folder with nettle's headers in nettle/, as an installed nettle has
    them, for `#include <nettle/aes.h>`. Without config.h (HAVE_CONFIG_H
    unset, NETTLE_FLAGS in its place), nettle's C files assume a
    little-endian machine, which the oracles are built on."""
    include = folder / "include"
    (include / "nettle").mkdir(parents=True)
    for header in nettle.glob("*.h"):
        shutil.copy(header, include / "nettle" / header.name)
    return include


# What lib/CMakeLists.txt adds to ZIP_SOURCES with HAVE_CRYPTO and
# HAVE_GNUTLS, and with HAVE_LIBBZ2.
LIBZIP_CRYPTO_SOURCES = [
    "zip_crypto_gnutls.c", "zip_winzip_aes.c", "zip_source_winzip_aes_decode.c",
    "zip_source_winzip_aes_encode.c",
]
LIBZIP_BZIP2_SOURCES = ["zip_algorithm_bzip2.c"]
LIBZIP_XZ_SOURCES = ["zip_algorithm_xz.c"]
LIBZIP_ZSTD_SOURCES = ["zip_algorithm_zstd.c"]


# libarchive: the reader and writer of ISO 9660 images, what they call, and
# the memory and callback inputs and outputs the oracle uses.
LIBARCHIVE_SOURCES = [
    "archive_acl.c", "archive_check_magic.c", "archive_entry.c", "archive_entry_sparse.c",
    "archive_entry_xattr.c", "archive_options.c", "archive_random.c", "archive_rb.c",
    "archive_read.c", "archive_read_open_memory.c", "archive_read_set_options.c",
    "archive_read_support_format_iso9660.c", "archive_string_sprintf.c", "archive_util.c",
    "archive_virtual.c", "archive_write.c", "archive_write_add_filter_none.c",
    "archive_write_set_format_iso9660.c", "archive_write_set_options.c",
]


# libarchive: the cpio reader, the RPM filter and the raw format that shows
# what it gives, the cpio writers, what they call, and the memory and
# callback inputs and outputs tools/cpio-oracle uses.
LIBARCHIVE_CPIO_SOURCES = [
    "archive_acl.c", "archive_check_magic.c", "archive_entry.c", "archive_entry_sparse.c",
    "archive_entry_xattr.c", "archive_options.c", "archive_read.c", "archive_read_open_memory.c",
    "archive_read_set_options.c", "archive_read_support_filter_rpm.c",
    "archive_read_support_format_cpio.c", "archive_read_support_format_empty.c",
    "archive_read_support_format_raw.c", "archive_string.c", "archive_string_sprintf.c",
    "archive_util.c", "archive_virtual.c", "archive_write.c", "archive_write_add_filter_none.c",
    "archive_write_set_format_cpio_binary.c", "archive_write_set_format_cpio_newc.c",
    "archive_write_set_format_cpio_odc.c",
]


# libarchive: the reader and writer of XAR archives, what they call (the
# checksums of archive_digest.c among them), and the memory and callback
# inputs and outputs the oracle uses.
XAR_LIBARCHIVE_SOURCES = [
    "archive_acl.c", "archive_check_magic.c", "archive_digest.c", "archive_entry.c",
    "archive_entry_sparse.c", "archive_entry_xattr.c", "archive_options.c", "archive_random.c",
    "archive_rb.c", "archive_read.c", "archive_read_open_memory.c", "archive_read_set_options.c",
    "archive_read_support_format_xar.c", "archive_string_sprintf.c", "archive_util.c",
    "archive_virtual.c", "archive_write.c", "archive_write_add_filter_none.c",
    "archive_write_set_format_xar.c", "archive_write_set_options.c",
]


# nettle's MD5, SHA-1, SHA-256 and SHA-512, in C, without the assembly
# versions: the checksums libarchive's archive_digest.c takes from nettle.
XAR_NETTLE_SOURCES = [
    "md5.c", "sha1.c", "sha1-compress.c", "sha256.c", "sha256-compress-n.c", "sha512.c",
    "sha512-compress.c", "write-be32.c", "write-le32.c",
]


# libxml2: its core, as CMakeLists.txt lists it in LIBXML2_SRCS, and the
# modules the XAR reader and writer use: the reader (xmlreader.c), the
# writer (xmlwriter.c) and the serialization it needs (xmlsave.c), and
# regular expressions (xmlregexp.c), which validation takes. The others
# are left out, as tools/xar-oracle/libxml2/libxml/xmlversion.h says.
LIBXML2_SOURCES = [
    "buf.c", "chvalid.c", "dict.c", "encoding.c", "entities.c", "error.c", "globals.c", "hash.c",
    "list.c", "parser.c", "parserInternals.c", "SAX2.c", "threads.c", "tree.c", "uri.c", "valid.c",
    "xmlIO.c", "xmlmemory.c", "xmlstring.c", "xmlsave.c", "xmlreader.c", "xmlregexp.c",
    "xmlwriter.c",
]


def liblzma_objects(xz: Path, folder: Path, compiler: str) -> list:
    """liblzma's C files compiled apart, with tools/xz-oracle/config.h, as it
    has a config.h of its own: the objects."""
    objects = folder / "liblzma"
    objects.mkdir()
    dirs = [xz / d for d in LIBLZMA_DIRS]
    xz_files = sorted(str(f) for d in dirs for f in d.glob("*.c")
                      if not any(part in f.name for part in LIBLZMA_LEFT_OUT))
    xz_includes = [f"-I{d}" for d in [ROOT / "tools/xz-oracle", xz / "api", *dirs, xz.parent / "common"]]
    subprocess.run([compiler, "-O2", "-w", "-pthread", "-DHAVE_CONFIG_H", *xz_includes, "-c", *xz_files],
                   check=True, cwd=objects)
    return sorted(str(f) for f in objects.glob("*.o"))


def build_xar_oracle(libarchive: Path, sources: list, folder: Path, extra: list, compiler: str) -> None:
    """tools/xar-oracle: libarchive's XAR reader and writer with libxml2,
    zlib, libbzip2, liblzma and nettle. libxml2 has a config.h of its own
    (tools/xar-oracle/libxml2/config.h, with the xmlversion.h its build
    writes beside it) and liblzma too, so both are compiled apart."""
    zlib = next(extra[0].glob("zlib-*"))
    bzip2 = next(extra[1].glob("bzip2-*"))
    xz = next(extra[2].glob("xz-*/src/liblzma"))
    nettle = next(extra[3].glob("nettle-*"))
    libxml2 = next(extra[4].glob("libxml2-*"))
    config = ROOT / Path(sources[0]).parent
    xml_config = config / "libxml2"
    objects = folder / "libxml2"
    objects.mkdir()
    subprocess.run([compiler, "-O2", "-w", "-pthread", f"-I{xml_config}", f"-I{libxml2 / 'include'}", "-c",
                    *[str(libxml2 / name) for name in LIBXML2_SOURCES]], check=True, cwd=objects)
    files = [str(ROOT / s) for s in sources if s.endswith(".c")]
    files += [str(libarchive / name) for name in XAR_LIBARCHIVE_SOURCES]
    files += [str(libarchive_string(libarchive, folder))]
    files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
    files += [str(bzip2 / name) for name in BZIP2_SOURCES]
    files += [str(nettle / name) for name in XAR_NETTLE_SOURCES]
    files += liblzma_objects(xz, folder, compiler)
    files += sorted(str(f) for f in objects.glob("*.o"))
    include = nettle_headers(nettle, folder)
    subprocess.run([compiler, "-O2", "-w", "-pthread", "-DHAVE_CONFIG_H", f"-I{config}", f"-I{libarchive}",
                    f"-I{zlib}", f"-I{bzip2}", f"-I{xz / 'api'}", f"-I{include}", f"-I{nettle}",
                    f"-I{xml_config}", f"-I{libxml2 / 'include'}", *files, "-o", str(folder / "oracle")],
                   check=True)


# archive_string.c without the Unicode normalization of names converted from
# UTF-16 or UTF-8 (NFC, or NFD on macOS), which hivepack-iso leaves out: Joliet
# names come out as the image has them.
LIBARCHIVE_NORMALIZATION = """\
	if ((flag & SCONV_FROM_CHARSET) &&
	    (flag & (SCONV_FROM_UTF16 | SCONV_FROM_UTF8))) {
#if defined(__APPLE__)
		if (flag & SCONV_TO_UTF8)
			flag |= SCONV_NORMALIZATION_D;
		else
#endif
			flag |= SCONV_NORMALIZATION_C;
	}
"""


def libarchive_string(lib: Path, folder: Path) -> Path:
    """archive_string.c, with LIBARCHIVE_NORMALIZATION taken out."""
    text = (lib / "archive_string.c").read_text()
    if text.count(LIBARCHIVE_NORMALIZATION) != 1:
        sys.exit("archive_string.c: the normalization to take out is not there")
    patched = folder / "patched"
    patched.mkdir()
    (patched / "archive_string.c").write_text(text.replace(LIBARCHIVE_NORMALIZATION, ""))
    return patched / "archive_string.c"


def zip_err_str(lib: Path) -> str:
    """zip_err_str.c, as libzip's cmake/GenerateZipErrorStrings.cmake writes
    it from the comments in zip.h and zipint.h."""
    pattern = r"#define ZIP_ER_{}([A-Z0-9_]+) ([0-9]+)[ \t]+/([-*0-9a-zA-Z, ']*)/"
    errors = re.findall(pattern.format(""), (lib / "zip.h").read_text())
    details = re.findall(pattern.format("DETAIL_"), (lib / "zipint.h").read_text())
    out = ['#include "zipint.h"', "#define L ZIP_ET_LIBZIP", "#define N ZIP_ET_NONE",
           "#define S ZIP_ET_SYS", "#define Z ZIP_ET_ZLIB", "#define E ZIP_DETAIL_ET_ENTRY",
           "#define G ZIP_DETAIL_ET_GLOBAL", "const struct _zip_err_info _zip_err_str[] = {"]
    for _, _, text in errors:
        kind, description = re.search(r"([LNSZ]+) ([-0-9a-zA-Z, ']*)", text).groups()
        out.append(f'    {{ {kind}, "{description.strip()}" }},')
    out += ["};", "const int _zip_err_str_count = sizeof(_zip_err_str)/sizeof(_zip_err_str[0]);",
            "const struct _zip_err_info _zip_err_details[] = {"]
    for _, _, text in details:
        kind, description = re.search(r"([EG]+) ([-0-9a-zA-Z, ']*)", text).groups()
        out.append(f'    {{ {kind}, "{description.strip()}" }},')
    out += ["};", "const int _zip_err_details_count = sizeof(_zip_err_details)/sizeof(_zip_err_details[0]);"]
    return "\n".join(out) + "\n"


# UnRAR's library build (`make lib`): -DRARDLL, as its makefile defines it,
# without RAR_SMP, the threads, which give the same output.
# Signed chars, as on x86-64, whose UnRAR the port follows: `char` is unsigned
# on Linux on ARM, and names that are not UTF-8 would decode differently.
UNRAR_FLAGS = ["-DRARDLL", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-fsigned-char"]


def unrar_sources(unrar: Path) -> list:
    """The sources of UnRAR's library: its makefile's OBJECTS and LIB_OBJ."""
    makefile = (unrar / "makefile").read_text()
    objects = re.search(r"^OBJECTS=(.*?)(?:\n\n|\n[A-Z_]+=)", makefile, re.S | re.M).group(1)
    lib_obj = re.search(r"^LIB_OBJ=(.*)$", makefile, re.M).group(1)
    names = (objects + " " + lib_obj).replace("\\", " ").split()
    return [name[:-2] + ".cpp" for name in names if name.endswith(".o")]


def uudecode(text: str) -> bytes:
    """A uuencoded file's bytes, as libarchive's tests keep their archives."""
    data = bytearray()
    started = False
    for line in text.splitlines():
        if line.startswith("begin "):
            started = True
            continue
        if not started or not line:
            continue
        if line.strip() == "end":
            break
        count = (ord(line[0]) - 32) & 63
        # As many characters as the count needs: some lines end in spaces
        # that were trimmed, or in padding.
        line = line[: 1 + (count + 2) // 3 * 4].ljust(1 + (count + 2) // 3 * 4, " ")
        data += binascii.a2b_uu(line)[:count]
    return bytes(data)


def build_oracle(source: Path, sources: list, included: list, folder: Path, extra: list) -> None:
    """An oracle program, compiled with the library's own sources.

    tools/zstd-oracle is built with libzstd's, its dictionary builder
    (lib/dictBuilder) among them (without the assembly loop, which the port
    does not have either, and with its threads, which cover.c's pool needs
    for its trials to run on several); the `included` files are left out,
    as the oracle includes them itself to reach their static functions.
    tools/zlib-oracle is built with zlib's, without the gzip file functions
    (gz*.c), which it does not use, and with contrib/infback9 for
    Deflate64. tools/bzip2-oracle is built with libbzip2's BZIP2_SOURCES,
    tools/lz4-oracle with liblz4's LZ4_SOURCES, and tools/xz-oracle with
    liblzma's, from LIBLZMA_DIRS, and its own config.h.
    tools/nettle-oracle is built with nettle's NETTLE_SOURCES.
    tools/iso-oracle is built with libarchive's LIBARCHIVE_SOURCES, its
    archive_string.c without the Unicode normalization (libarchive_string),
    its own config.h, and zlib's (the `extra` set); tools/cpio-oracle, told
    by its folder, with LIBARCHIVE_CPIO_SOURCES and its own config.h;
    tools/xar-oracle, told by its folder too, with XAR_LIBARCHIVE_SOURCES,
    the same archive_string.c, and libxml2's, zlib's, libbzip2's,
    liblzma's and nettle's (build_xar_oracle).
    tools/zip-oracle is built with libzip's, its crypto backend for
    GnuTLS and its bzip2 algorithm among them, its own config.h and
    zipconf.h in place of those libzip's CMake build writes, the part of
    GnuTLS that backend uses in gnutls/, and zlib's, nettle's, libbzip2's
    and liblzma's (the `extra` sets)."""
    files = [str(ROOT / s) for s in sources if s.endswith(".c")]
    compiler = os.environ.get("CC", "cc")
    if (source / "C" / "7zArcIn.c").exists():
        sdk = source / "C"
        files += [str(sdk / name) for name in SEVENZ_SOURCES]
        subprocess.run([compiler, "-O2", "-w", *SEVENZ_FLAGS, f"-I{sdk}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    unrar = source / "unrar"
    if unrar.is_dir():
        files = [str(ROOT / s) for s in sources if s.endswith(".cpp")]
        files += [str(unrar / name) for name in unrar_sources(unrar)]
        subprocess.run([os.environ.get("CXX", "c++"), "-O2", "-w", "-std=c++11", *UNRAR_FLAGS,
                        f"-I{unrar}", *files, "-o", str(folder / "oracle"), "-lpthread"], check=True)
        return
    libzip = next(source.glob("libzip-*"), None)
    if libzip is not None:
        lib = libzip / "lib"
        zlib = next(extra[0].glob("zlib-*"))
        nettle = next(extra[1].glob("nettle-*"))
        bzip2 = next(extra[2].glob("bzip2-*"))
        xz = next(extra[3].glob("xz-*/src/liblzma"))
        zstd = next(extra[4].glob("zstd-*/lib"))
        generated = folder / "generated"
        generated.mkdir()
        (generated / "zip_err_str.c").write_text(zip_err_str(lib))
        files += [str(lib / name) for name in
                  libzip_sources(lib) + LIBZIP_CRYPTO_SOURCES + LIBZIP_BZIP2_SOURCES
                  + LIBZIP_XZ_SOURCES + LIBZIP_ZSTD_SOURCES]
        files += [str(generated / "zip_err_str.c")]
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        files += [str(nettle / name) for name in NETTLE_SOURCES]
        files += [str(bzip2 / name) for name in BZIP2_SOURCES]
        include = nettle_headers(nettle, folder)
        config = ROOT / Path(sources[0]).parent
        # liblzma has a config.h of its own, so it is compiled apart.
        files += liblzma_objects(xz, folder, compiler)
        # So is libzstd, whose headers have common names.
        objects = folder / "libzstd"
        objects.mkdir()
        zstd_files = sorted(str(f) for part in ("common", "compress", "decompress")
                            for f in (zstd / part).glob("*.c"))
        subprocess.run([compiler, "-O2", "-w", "-DZSTD_DISABLE_ASM", "-c", *zstd_files],
                       check=True, cwd=objects)
        files += sorted(str(f) for f in objects.glob("*.o"))
        system = ["-DWIN32_LEAN_AND_MEAN", "-lbcrypt"] if sys.platform == "win32" else []
        subprocess.run([compiler, "-O2", "-w", "-pthread", *NETTLE_FLAGS, f"-I{config}", f"-I{lib}", f"-I{zlib}",
                        f"-I{include}", f"-I{nettle}", f"-I{bzip2}", f"-I{xz / 'api'}", f"-I{zstd}", *files,
                        "-o", str(folder / "oracle"), *system],
                       check=True)
        return
    libarchive = next(source.glob("libarchive-*/libarchive"), None)
    if libarchive is not None and Path(sources[0]).parent.name == "xar-oracle":
        build_xar_oracle(libarchive, sources, folder, extra, compiler)
        return
    if libarchive is not None and folder.name == "cpio-oracle":
        files += [str(libarchive / name) for name in LIBARCHIVE_CPIO_SOURCES]
        config = ROOT / Path(sources[0]).parent
        subprocess.run([compiler, "-O2", "-w", "-DHAVE_CONFIG_H", f"-I{config}", f"-I{libarchive}",
                        *files, "-o", str(folder / "oracle")], check=True)
        return
    if libarchive is not None:
        zlib = next(extra[0].glob("zlib-*"))
        files += [str(libarchive / name) for name in LIBARCHIVE_SOURCES]
        files += [str(libarchive_string(libarchive, folder))]
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        config = ROOT / Path(sources[0]).parent
        subprocess.run([compiler, "-O2", "-w", "-DHAVE_CONFIG_H", f"-I{config}", f"-I{libarchive}",
                        f"-I{zlib}", *files, "-o", str(folder / "oracle")], check=True)
        return
    zlib = next(source.glob("zlib-*"), None)
    if zlib is not None:
        infback9 = zlib / "contrib" / "infback9"
        files += sorted(str(f) for f in zlib.glob("*.c") if not f.name.startswith("gz"))
        files += [str(infback9 / "infback9.c"), str(infback9 / "inftree9.c")]
        subprocess.run([compiler, "-O2", f"-I{zlib}", f"-I{infback9}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    xz = next(source.glob("xz-*/src/liblzma"), None)
    if xz is not None:
        dirs = [xz / d for d in LIBLZMA_DIRS]
        files += sorted(str(f) for d in dirs for f in d.glob("*.c")
                        if not any(part in f.name for part in LIBLZMA_LEFT_OUT))
        config = ROOT / Path(sources[0]).parent
        headers = [xz / "api", *dirs, xz.parent / "common"]
        includes = [f"-I{d}" for d in [config, *headers]]
        subprocess.run([compiler, "-O2", "-w", "-pthread", "-DHAVE_CONFIG_H", *includes, *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    bzip2 = next(source.glob("bzip2-*"), None)
    if bzip2 is not None:
        files += [str(bzip2 / name) for name in BZIP2_SOURCES]
        subprocess.run([compiler, "-O2", "-D_FILE_OFFSET_BITS=64", f"-I{bzip2}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    lz4 = next(source.glob("lz4-*/lib"), None)
    if lz4 is not None:
        files += [str(lz4 / name) for name in LZ4_SOURCES]
        subprocess.run([compiler, "-O2", *LZ4_FLAGS, f"-I{lz4}", *files, "-o", str(folder / "oracle")],
                       check=True)
        return
    nettle = next(source.glob("nettle-*"), None)
    if nettle is not None:
        include = nettle_headers(nettle, folder)
        files += [str(nettle / name) for name in NETTLE_SOURCES]
        subprocess.run([compiler, "-O2", *NETTLE_FLAGS, f"-I{include}", f"-I{nettle}", *files,
                        "-o", str(folder / "oracle")], check=True)
        return
    lib = next(source.glob("zstd-*/lib"))
    for part in ("common", "compress", "decompress", "dictBuilder"):
        files += sorted(str(f) for f in (lib / part).glob("*.c")
                        if f"{part}/{f.name}" not in included)
    subprocess.run([compiler, "-O2", "-DZSTD_DISABLE_ASM", "-DZSTD_MULTITHREAD", "-pthread",
                    f"-I{lib}", f"-I{lib / 'common'}", *files, "-o", str(folder / "oracle")],
                   check=True)


def build_go(sources: list, folder: Path) -> None:
    """An oracle written in Go, built by the go command from its module in
    tools/. go.sum pins the modules it downloads, which the go command also
    checks against Go's checksum database; -mod=readonly keeps it from
    changing go.mod. An installed Go older than the one go.mod asks for
    downloads that one (GOTOOLCHAIN=auto, the default)."""
    go = shutil.which("go")
    if go is None:
        sys.exit("building the Go oracles needs Go: https://go.dev/dl/")
    module = ROOT / Path(sources[0]).parent
    # Windows runs a program by its .exe, which a program's path may leave out.
    name = "oracle.exe" if sys.platform == "win32" else "oracle"
    subprocess.run([go, "build", "-trimpath", "-mod=readonly", "-o", str(folder / name), "."],
                   cwd=module, check=True, env={**os.environ, "CGO_ENABLED": "0"})


def generate_set(entry: dict, cache: Path, sets: dict) -> None:
    folder = cache / entry["name"]
    generate = entry["generate"]
    stamp = stamp_of(entry)
    if is_current(folder, stamp):
        print(f"  {entry['name']}: up to date")
        return
    if generate["tool"] == "go":
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        build_go(generate["sources"], folder)
        mark_current(folder, stamp)
        print(f"  {entry['name']}: generated")
        return
    origin = sets[generate["from"]]
    fetch_set(origin, cache)
    extra = [sets[name] for name in generate.get("with", [])]
    for entry_with in extra:
        fetch_set(entry_with, cache)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    if generate["tool"] == "7zz":
        build_7zz(cache / origin["name"], folder)
    elif generate["tool"] == "uudecode":
        # Each file the glob (or globs) finds, decoded, named without its
        # `.uu` and libarchive's `test_read_format_`.
        globs = generate["glob"] if isinstance(generate["glob"], list) else [generate["glob"]]
        found = {uu for pattern in globs for uu in (cache / origin["name"]).glob(pattern)}
        for uu in sorted(found):
            name = uu.name[:-3].replace("test_read_format_", "")
            (folder / name).write_bytes(uudecode(uu.read_text(errors="replace")))
    elif generate["tool"] == "oracle":
        build_oracle(cache / origin["name"], generate["sources"], generate.get("included", []), folder,
                     [cache / e["name"] for e in extra])
    else:
        binary = build_tool(cache / origin["name"], generate["tool"])
        # Each frame goes to z<number>.zst with its original at z<number>.
        subprocess.run([str(binary), f"-p{folder}", f"-o{folder}", *generate["args"]], check=True,
                       stdout=subprocess.DEVNULL)
    mark_current(folder, stamp)
    print(f"  {entry['name']}: generated")


def load_sets() -> dict:
    manifest = json.loads(MANIFEST.read_text())
    return {entry["name"]: entry for entry in manifest["sets"]}


def group_of(entry: dict):
    for key in ("fetch", "generate"):
        if key in entry:
            return entry[key]["group"]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="download and generate sets")
    fetch.add_argument("--group", action="append", choices=GROUPS + ["all"],
                       help="sets to get (default: core); repeat for several")
    fetch.add_argument("--set", action="append", default=[], metavar="NAME",
                       help="a set by its name, as `list` shows them, in place of the groups; "
                            "repeat for several")
    sub.add_parser("list", help="show every set and where it lives")
    args = parser.parse_args()

    sets = load_sets()
    cache = cache_dir()
    if args.command == "list":
        for entry in sets.values():
            group = group_of(entry)
            where = f"testdata/{entry['path']}" if group is None else f"{cache / entry['name']} ({group})"
            print(f"{entry['name']:36} {entry['kind']:12} {where}")
        return

    unknown = [name for name in args.set if name not in sets]
    if unknown:
        sys.exit(f"no such set: {', '.join(unknown)}")
    groups = set(args.group or ([] if args.set else ["core"]))
    if "all" in groups:
        groups = set(GROUPS)
    for entry in sets.values():
        group = group_of(entry)
        if group not in groups and entry["name"] not in args.set:
            continue
        if "fetch" in entry:
            fetch_set(entry, cache)
        else:
            generate_set(entry, cache, sets)


if __name__ == "__main__":
    sys.exit(main())
