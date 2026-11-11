/*
 * The configuration of the squashfuse 0.6.5 sources that tools/squashfs-oracle
 * is built with, in place of the config.h squashfuse's configure script
 * writes: its library without FUSE and without threads (cache.c, not
 * cache_mt.c), with zlib, liblzma (for LZMA and XZ), liblzo2, lz4 and zstd,
 * on Linux or macOS. Only what those sources ask for is here.
 */
#ifndef SQFS_CONFIG_H
#define SQFS_CONFIG_H

#define HAVE_ZLIB_H 1
#define HAVE_LZMA_H 1
#define HAVE_LZO_LZO1X_H 1
#define HAVE_LZ4_H 1
#define HAVE_ZSTD_H 1

/* makedev, which glibc declares in sys/sysmacros.h and macOS in sys/types.h. */
#ifdef __linux__
#define HAVE_SYS_SYSMACROS_H 1
#endif

/*
 * The feature macro nonstd-internal.h defines before pread, S_IFSOCK and
 * makedev are declared: 0 is none of its choices, as the defaults of glibc
 * and macOS declare all three.
 */
#define NONSTD_PREAD_DEF 0
#define NONSTD_S_IFSOCK_DEF 0
#define NONSTD_MAKEDEV_DEF 0

#endif
