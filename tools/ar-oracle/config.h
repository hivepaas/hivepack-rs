/*
 * The configuration of the libarchive 3.8.10 sources that tools/ar-oracle
 * is built with, in place of the config.h libarchive's CMake or configure
 * script writes: the ar reader and writer, on Linux or macOS. Only what
 * those sources ask for is here.
 */

#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_ERRNO_H 1
#define HAVE_UNISTD_H 1
#define HAVE_FCNTL_H 1
#define HAVE_FCNTL 1
#define HAVE_LIMITS_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TIME_H 1
#define HAVE_WCHAR_H 1
#define HAVE_LOCALE_H 1
#define HAVE_LANGINFO_H 1
#define HAVE_NL_LANGINFO 1
#define HAVE_GMTIME_R 1
#define HAVE_LOCALTIME_R 1
#define HAVE_MKSTEMP 1
#define HAVE_WCSCPY 1
#define HAVE_WCSLEN 1
#define HAVE_WMEMCMP 1
#define HAVE_WMEMCPY 1
#define HAVE_WMEMMOVE 1
#define HAVE_WCRTOMB 1
#define HAVE_MBRTOWC 1
#define HAVE_EILSEQ 1
#define HAVE_DECL_SIZE_MAX 1
#define HAVE_DECL_SSIZE_MAX 1
#define HAVE_DECL_INT32_MAX 1
#define HAVE_DECL_INT32_MIN 1
#define HAVE_DECL_UINT32_MAX 1
#define HAVE_DECL_INT64_MAX 1
#define HAVE_DECL_INT64_MIN 1
#define HAVE_DECL_UINT64_MAX 1
#define HAVE_DECL_INTMAX_MAX 1
#define HAVE_DECL_INTMAX_MIN 1
#define HAVE_DECL_UINTMAX_MAX 1
#define HAVE_UINTMAX_T 1
#define HAVE_INTMAX_T 1
#define HAVE_UINT64_T 1
#define HAVE_INT64_T 1
#define HAVE_UINT32_T 1
#define HAVE_INT32_T 1
#define HAVE_UINT16_T 1
#define HAVE_INT16_T 1
#define HAVE_UINT8_T 1
#define HAVE_WORKING_EXT2_IOC_GETFLAGS 0
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_WCHAR_T 4
#define ARCHIVE_ACL_FREEBSD 0
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

/*
 * glibc's major, minor and makedev are in <sys/sysmacros.h>, as libarchive's
 * CMake build finds; without them archive_entry.c would use its own, which
 * keep 8 bits of the major number. macOS has them in <sys/types.h>.
 */
#if defined(__linux__)
#define MAJOR_IN_SYSMACROS 1
#endif
