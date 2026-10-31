/* The LZMA SDK's side of tools/7z-bench: one request a line on stdin, one
 * answer a line on stdout, "<nanoseconds> <value>", or "error <message>". Only
 * what the nanoseconds name is timed: what comes before it, opening an archive
 * to read it, and hashing what was read, is left out, as on the port's side.
 *
 *   open PATH     SzArEx_Open; the value is the number of files
 *   names PATH    SzArEx_GetFileNameUtf16 for each file, into a buffer kept
 *                 from one to the next; the value is their units
 *   decode PATH   SzAr_DecodeFolder for each folder, into a buffer allocated
 *                 for it; the value adds up the FNV-1a of each
 *   extract PATH  SzArEx_Extract for each file, with its folder kept between
 *                 them; the value adds up the FNV-1a of each
 *
 * Built by scripts/testdata.py with the SDK's C files, as tools/7z-oracle's
 * oracle is, without assembly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "7z.h"
#include "7zAlloc.h"
#include "7zBuf.h"
#include "7zCrc.h"
#include "7zFile.h"

#define BUF_SIZE ((size_t)1 << 18)

static const ISzAlloc g_alloc = { SzAlloc, SzFree };

static unsigned long long now(void) {
#ifdef _WIN32
    LARGE_INTEGER count, frequency;
    QueryPerformanceCounter(&count);
    QueryPerformanceFrequency(&frequency);
    return (unsigned long long)((double)count.QuadPart * 1e9 / (double)frequency.QuadPart);
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
#endif
}

static unsigned long long fnv64(const unsigned char *bytes, size_t len) {
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

struct opened {
    CFileInStream file;
    CLookToRead2 look;
    CSzArEx db;
};

static void fail(const char *what, int res) {
    printf("error %s: %d\n", what, res);
    fflush(stdout);
    exit(1);
}

/* The archive at path, with the time SzArEx_Open took in *time if any. */
static void open_archive(struct opened *a, const char *path, unsigned long long *time) {
    unsigned long long start;
    SRes res;
    if (InFile_Open(&a->file.file, path) != 0)
        fail(path, -1);
    FileInStream_CreateVTable(&a->file);
    a->file.wres = 0;
    LookToRead2_CreateVTable(&a->look, False);
    a->look.buf = (Byte *)ISzAlloc_Alloc(&g_alloc, BUF_SIZE);
    a->look.bufSize = BUF_SIZE;
    a->look.realStream = &a->file.vt;
    LookToRead2_INIT(&a->look)
    SzArEx_Init(&a->db);
    start = now();
    res = SzArEx_Open(&a->db, &a->look.vt, &g_alloc, &g_alloc);
    if (time != NULL)
        *time = now() - start;
    if (res != SZ_OK)
        fail("SzArEx_Open", res);
}

static void close_archive(struct opened *a) {
    SzArEx_Free(&a->db, &g_alloc);
    ISzAlloc_Free(&g_alloc, a->look.buf);
    File_Close(&a->file.file);
}

static void do_open(const char *path) {
    static struct opened a;
    unsigned long long time;
    open_archive(&a, path, &time);
    printf("%llu %u\n", time, a.db.NumFiles);
    close_archive(&a);
}

static void do_names(const char *path) {
    static struct opened a;
    UInt16 name[1 << 16];
    unsigned long long start, end, value = 0;
    UInt32 i;
    open_archive(&a, path, NULL);
    start = now();
    for (i = 0; i < a.db.NumFiles; i++) {
        size_t len = SzArEx_GetFileNameUtf16(&a.db, i, NULL);
        if (len > 1 << 16)
            fail("a long name", (int)len);
        SzArEx_GetFileNameUtf16(&a.db, i, name);
        /* Without the 0 at its end. */
        value += len - 1;
    }
    end = now();
    printf("%llu %llu\n", end - start, value);
    close_archive(&a);
}

static void do_decode(const char *path) {
    static struct opened a;
    unsigned long long total = 0, value = 0;
    UInt32 i;
    open_archive(&a, path, NULL);
    for (i = 0; i < a.db.db.NumFolders; i++) {
        size_t size = (size_t)SzAr_GetFolderUnpackSize(&a.db.db, i);
        unsigned long long start = now();
        Byte *buf = (Byte *)calloc(size ? size : 1, 1);
        SRes res = SzAr_DecodeFolder(&a.db.db, i, &a.look.vt, a.db.dataPos, buf, size, &g_alloc);
        total += now() - start;
        if (res != SZ_OK)
            fail("SzAr_DecodeFolder", res);
        value += fnv64(buf, size);
        free(buf);
    }
    printf("%llu %llu\n", total, value);
    close_archive(&a);
}

static void do_extract(const char *path) {
    static struct opened a;
    UInt32 block = 0xFFFFFFFF;
    Byte *out = NULL;
    size_t out_size = 0;
    unsigned long long total = 0, value = 0;
    UInt32 i;
    open_archive(&a, path, NULL);
    for (i = 0; i < a.db.NumFiles; i++) {
        size_t offset = 0, processed = 0;
        unsigned long long start = now();
        SRes res = SzArEx_Extract(&a.db, &a.look.vt, i, &block, &out, &out_size, &offset, &processed,
                                  &g_alloc, &g_alloc);
        total += now() - start;
        if (res != SZ_OK)
            fail("SzArEx_Extract", res);
        value += fnv64(out + offset, processed);
    }
    ISzAlloc_Free(&g_alloc, out);
    printf("%llu %llu\n", total, value);
    close_archive(&a);
}

int main(void) {
    static char line[8192];
    CrcGenerateTable();
    while (fgets(line, sizeof line, stdin) != NULL) {
        char *word = strtok(line, " \n");
        char *path = strtok(NULL, " \n");
        if (word == NULL || path == NULL)
            fail("a bad request", 0);
        else if (strcmp(word, "open") == 0)
            do_open(path);
        else if (strcmp(word, "names") == 0)
            do_names(path);
        else if (strcmp(word, "decode") == 0)
            do_decode(path);
        else if (strcmp(word, "extract") == 0)
            do_extract(path);
        else
            fail(word, 0);
        fflush(stdout);
    }
    return 0;
}
