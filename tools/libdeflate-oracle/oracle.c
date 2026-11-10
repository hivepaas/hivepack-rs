/*
 * The libdeflate side of hivepack::deflate's comparison tests with
 * libdeflate's compressor.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libdeflate 1.26. The Rust tests ask the port the same
 * questions and compare the answers as text. scripts/testdata.py builds it
 * from the libdeflate release sources.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. Hashes are FNV-1a
 * (64 bits).
 *
 *   compress <level> <capacities> <hex>
 *       libdeflate_deflate_compress of <hex> with the compressor of <level>,
 *       once for each of the comma-separated output <capacities>, each into
 *       a buffer of exactly that many bytes. The program keeps one
 *       compressor for each level, made the first time the level is asked
 *       for, as a program that compresses many buffers would. Answered "ok",
 *       then " <ret>/<hash>" for each capacity: what the call returned, and
 *       the hash of the <ret> bytes it wrote. A level libdeflate refuses
 *       (libdeflate_alloc_compressor returns NULL) is answered "null".
 *
 *   output <level> <capacity> <hex>
 *       The same with one capacity, answered "<ret> <hex>" with the bytes
 *       themselves, to see where two streams part.
 *
 *   bound <level> <len>
 *       libdeflate_deflate_compress_bound for <len> bytes. Answered with
 *       the bound, or "null" for a level libdeflate refuses.
 *
 *   time <level> <rounds> <path>
 *       Compresses the file at <path> once, then <rounds> times timed,
 *       into a buffer of libdeflate_deflate_compress_bound bytes, for the
 *       benchmarks.
 *       Answered "<ret> <hash> <ns>": the size, the hash of the stream and
 *       the fastest round in nanoseconds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libdeflate.h"

static int nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

static unsigned char *unhex(const char *text, size_t *len) {
    size_t n, i;
    unsigned char *bytes;
    if (strcmp(text, "-") == 0) {
        *len = 0;
        return malloc(1);
    }
    n = strlen(text) / 2;
    bytes = malloc(n + 1);
    for (i = 0; i < n; i++)
        bytes[i] = (unsigned char)(nibble(text[2 * i]) << 4 | nibble(text[2 * i + 1]));
    *len = n;
    return bytes;
}

static unsigned long long fnv64(const unsigned char *bytes, size_t len) {
    unsigned long long hash = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x00000100000001b3ULL;
    }
    return hash;
}

/* One compressor for each level from -1 to 12, made when first asked for. */
static struct libdeflate_compressor *compressors[14];

static struct libdeflate_compressor *compressor(int level) {
    if (level < -1 || level > 12)
        return libdeflate_alloc_compressor(level);
    if (!compressors[level + 1])
        compressors[level + 1] = libdeflate_alloc_compressor(level);
    return compressors[level + 1];
}

static void do_compress(int level, char *capacities, const char *data_hex) {
    size_t len;
    unsigned char *data;
    struct libdeflate_compressor *c = compressor(level);
    char *p, *next;
    if (!c) {
        puts("null");
        return;
    }
    data = unhex(data_hex, &len);
    printf("ok");
    for (p = capacities; p; p = next) {
        size_t capacity, ret;
        unsigned char *out;
        next = strchr(p, ',');
        if (next)
            *next++ = '\0';
        capacity = (size_t)strtoull(p, NULL, 10);
        /* Exactly the capacity, so that a write past it is caught by tools
         * that watch the heap. */
        out = malloc(capacity ? capacity : 1);
        ret = libdeflate_deflate_compress(c, data, len, out, capacity);
        printf(" %zu/%016llx", ret, fnv64(out, ret));
        free(out);
    }
    printf("\n");
    free(data);
}

static void do_output(int level, size_t capacity, const char *data_hex) {
    size_t len, ret, i;
    unsigned char *data, *out;
    struct libdeflate_compressor *c = compressor(level);
    if (!c) {
        puts("null");
        return;
    }
    data = unhex(data_hex, &len);
    out = malloc(capacity ? capacity : 1);
    ret = libdeflate_deflate_compress(c, data, len, out, capacity);
    printf("%zu ", ret);
    if (ret == 0)
        printf("-");
    for (i = 0; i < ret; i++)
        printf("%02x", out[i]);
    printf("\n");
    free(out);
    free(data);
}

static void do_bound(int level, size_t len) {
    struct libdeflate_compressor *c = compressor(level);
    if (!c) {
        puts("null");
        return;
    }
    printf("%zu\n", libdeflate_deflate_compress_bound(c, len));
}

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void do_time(int level, int rounds, const char *path) {
    FILE *f = fopen(path, "rb");
    struct libdeflate_compressor *c = compressor(level);
    unsigned char *data, *out;
    size_t len, capacity, ret = 0;
    long long best = -1;
    int i;
    if (!f || !c) {
        puts("bad");
        if (f)
            fclose(f);
        return;
    }
    fseek(f, 0, SEEK_END);
    len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    data = malloc(len ? len : 1);
    if (fread(data, 1, len, f) != len) {
        puts("bad");
        fclose(f);
        free(data);
        return;
    }
    fclose(f);
    capacity = libdeflate_deflate_compress_bound(c, len);
    out = malloc(capacity);
    /* Once untimed, so that the output's pages are there. */
    ret = libdeflate_deflate_compress(c, data, len, out, capacity);
    for (i = 0; i < rounds; i++) {
        long long start = now_ns(), took;
        ret = libdeflate_deflate_compress(c, data, len, out, capacity);
        took = now_ns() - start;
        if (best < 0 || took < best)
            best = took;
    }
    printf("%zu %016llx %lld\n", ret, fnv64(out, ret), best);
    free(out);
    free(data);
}

int main(void) {
    size_t cap = 1 << 20;
    char *line = malloc(cap);
    while (fgets(line, (int)cap, stdin)) {
        size_t n = strlen(line);
        char *words[5];
        int count = 0;
        char *word;
        while (n == cap - 1 && line[n - 1] != '\n') {
            cap *= 2;
            line = realloc(line, cap);
            if (!fgets(line + n, (int)(cap - n), stdin))
                break;
            n = strlen(line);
        }
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        for (word = strtok(line, " "); word && count < 5; word = strtok(NULL, " "))
            words[count++] = word;
        if (count == 4 && strcmp(words[0], "compress") == 0)
            do_compress(atoi(words[1]), words[2], words[3]);
        else if (count == 4 && strcmp(words[0], "output") == 0)
            do_output(atoi(words[1]), (size_t)strtoull(words[2], NULL, 10), words[3]);
        else if (count == 3 && strcmp(words[0], "bound") == 0)
            do_bound(atoi(words[1]), (size_t)strtoull(words[2], NULL, 10));
        else if (count == 4 && strcmp(words[0], "time") == 0)
            do_time(atoi(words[1]), atoi(words[2]), words[3]);
        else
            puts("bad");
        fflush(stdout);
    }
    free(line);
    return 0;
}
