/*
 * config.h for building libzip 1.12.1 into the oracle on 64-bit Linux and
 * macOS, and with MinGW on Windows, in place of the one libzip's CMake build writes from
 * config.h.in: what those systems have, with libbzip2 (bzip2 1.0.8's
 * sources), liblzma (XZ Utils 5.8.4's, built apart with
 * tools/xz-oracle/config.h) and libzstd (1.5.7's, built apart) but not the
 * other optional libraries. The crypto backend is
 * GnuTLS's, on nettle's sources and the part of GnuTLS in gnutls/. oracle.c gives zip_random_uint32 (temporary file
 * names) apart from the random bytes, so that encrypting draws the same
 * bytes from gnutls_rnd whatever file is written.
 */
#ifndef HAD_CONFIG_H
#define HAD_CONFIG_H
#ifndef _HAD_ZIPCONF_H
#include "zipconf.h"
#endif
#define ENABLE_FDOPEN
#define HAVE_FILENO
#ifndef _WIN32
#define HAVE_FCHMOD
#endif
#define HAVE_FSEEKO
#define HAVE_FTELLO
#ifdef _WIN32
#define HAVE_LOCALTIME_S
#else
#define HAVE_LOCALTIME_R
#define HAVE_MKSTEMP
#endif
#define HAVE_SNPRINTF
#define HAVE_STRCASECMP
#define HAVE_STRDUP
#define HAVE_STRTOLL
#define HAVE_STRTOULL
#define HAVE_STDBOOL_H
#define HAVE_STRINGS_H
#define HAVE_UNISTD_H
#define HAVE_DIRENT_H
#define HAVE_CRYPTO
#define HAVE_GNUTLS
#define HAVE_RANDOM_UINT32
#define HAVE_LIBBZ2
#define HAVE_LIBLZMA
#define HAVE_LIBZSTD
#define LZMA_WINDOW_LIMIT UINT64_MAX
#define SIZEOF_OFF_T 8
#define SIZEOF_SIZE_T 8
#define PACKAGE "libzip"
#define VERSION "1.12.1"
#endif /* HAD_CONFIG_H */
