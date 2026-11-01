/* libzip's side of tools/zip-bench: one request a line on stdin, one answer a
 * line on stdout, "<nanoseconds> <value>", or "error <message>". Only what the
 * nanoseconds name is timed: what comes before it, opening an archive to read
 * its entries, or copying one to edit it, is left out, on both sides.
 *
 *   open PATH CHECKCONS            zip_open, with ZIP_CHECKCONS if 1; the
 *                                  value is the number of entries
 *   list PATH                      zip_stat_index for each entry; the value
 *                                  adds up their sizes and names' lengths
 *   locate PATH                    zip_name_locate for each entry's name; the
 *                                  value adds up the indices
 *   read PATH CHUNK PASSWORD       each entry read in CHUNK bytes at a time,
 *                                  with a password or "-"; the value is the
 *                                  bytes read
 *   write OUT LIST METHOD LEVEL EM PASSWORD
 *                                  a new archive at OUT, of LIST's entries from
 *                                  memory: lines of name, file, offset and
 *                                  length, by tabs. The value is its size
 *   edit IN OUT KIND               a copy of IN at OUT, opened, changed by KIND
 *                                  (rename-one, rename-all, comment-all,
 *                                  delete-half or add-one) and closed. The
 *                                  value is its size
 *
 * Built by scripts/testdata.py, as tools/zip-oracle/oracle.c is, with the
 * same libzip, zlib, nettle, libbzip2 and liblzma, without assembly files.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "zipint.h"

/* What tools/zip-oracle/gnutls stands in for, as the oracle has it, and
 * zip_random_uni.c, which is not built. */
static uint64_t random_state = 0x123456789abcdefULL;

int gnutls_rnd(int level, void *data, size_t len) {
    unsigned char *bytes = data;
    (void)level;
    for (size_t i = 0; i < len; i++) {
        random_state = random_state * 6364136223846793005ULL + 1442695040888963407ULL;
        bytes[i] = (unsigned char)(random_state >> 56);
    }
    return 0;
}

zip_uint32_t zip_random_uint32(void) {
    random_state = random_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (zip_uint32_t)(random_state >> 32);
}

/* The mtime of every entry written, so that the bytes can be compared. */
#define MTIME 1700000000

static void fail(const char *what, const char *detail) {
    printf("error %s: %s\n", what, detail);
    fflush(stdout);
    exit(1);
}

static uint64_t now(void) {
#ifdef _WIN32
    LARGE_INTEGER count, frequency;
    QueryPerformanceCounter(&count);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)((double)count.QuadPart * 1e9 / (double)frequency.QuadPart);
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
#endif
}

static zip_t *open_archive(const char *path, int flags) {
    int error = 0;
    zip_t *za = zip_open(path, flags, &error);
    if (za == NULL) {
        zip_error_t e;
        zip_error_init_with_code(&e, error);
        fail(path, zip_error_strerror(&e));
    }
    return za;
}

static void do_open(const char *path, int check) {
    uint64_t start = now();
    zip_t *za = open_archive(path, ZIP_RDONLY | (check ? ZIP_CHECKCONS : 0));
    uint64_t end = now();
    long long entries = (long long)zip_get_num_entries(za, 0);
    zip_discard(za);
    printf("%llu %lld\n", (unsigned long long)(end - start), entries);
}

static void do_list(const char *path) {
    zip_t *za = open_archive(path, ZIP_RDONLY);
    zip_int64_t n = zip_get_num_entries(za, 0);
    uint64_t value = 0;
    uint64_t start = now();
    for (zip_int64_t i = 0; i < n; i++) {
        zip_stat_t st;
        if (zip_stat_index(za, (zip_uint64_t)i, 0, &st) != 0)
            fail("zip_stat_index", zip_strerror(za));
        value += st.size + strlen(st.name);
    }
    uint64_t end = now();
    zip_discard(za);
    printf("%llu %llu\n", (unsigned long long)(end - start), (unsigned long long)value);
}

static void do_locate(const char *path) {
    zip_t *za = open_archive(path, ZIP_RDONLY);
    zip_int64_t n = zip_get_num_entries(za, 0);
    const char **names = malloc(sizeof(char *) * (size_t)n);
    uint64_t value = 0;
    for (zip_int64_t i = 0; i < n; i++)
        names[i] = zip_get_name(za, (zip_uint64_t)i, 0);
    uint64_t start = now();
    for (zip_int64_t i = 0; i < n; i++)
        value += (uint64_t)zip_name_locate(za, names[i], 0);
    uint64_t end = now();
    free(names);
    zip_discard(za);
    printf("%llu %llu\n", (unsigned long long)(end - start), (unsigned long long)value);
}

static void do_read(const char *path, size_t chunk, const char *password) {
    zip_t *za = open_archive(path, ZIP_RDONLY);
    unsigned char *buf = malloc(chunk);
    zip_int64_t n = zip_get_num_entries(za, 0);
    uint64_t value = 0;
    if (strcmp(password, "-") != 0 && zip_set_default_password(za, password) != 0)
        fail("zip_set_default_password", zip_strerror(za));
    uint64_t start = now();
    for (zip_int64_t i = 0; i < n; i++) {
        zip_file_t *f = zip_fopen_index(za, (zip_uint64_t)i, 0);
        zip_int64_t got;
        if (f == NULL)
            fail("zip_fopen_index", zip_strerror(za));
        while ((got = zip_fread(f, buf, chunk)) > 0)
            value += (uint64_t)got;
        if (got < 0)
            fail("zip_fread", zip_file_strerror(f));
        if (zip_fclose(f) != 0)
            fail("zip_fclose", zip_strerror(za));
    }
    uint64_t end = now();
    free(buf);
    zip_discard(za);
    printf("%llu %llu\n", (unsigned long long)(end - start), (unsigned long long)value);
}

/* The files that lists refer to, kept in memory. */
struct loaded {
    char *path;
    unsigned char *data;
    size_t len;
};
static struct loaded *files = NULL;
static size_t num_files = 0;

static const unsigned char *load(const char *path) {
    for (size_t i = 0; i < num_files; i++)
        if (strcmp(files[i].path, path) == 0)
            return files[i].data;
    FILE *f = fopen(path, "rb");
    struct stat st;
    if (f == NULL || fstat(fileno(f), &st) != 0)
        fail(path, strerror(errno));
    files = realloc(files, sizeof(struct loaded) * (num_files + 1));
    files[num_files].path = strdup(path);
    files[num_files].len = (size_t)st.st_size;
    files[num_files].data = malloc((size_t)st.st_size + 1);
    if (fread(files[num_files].data, 1, (size_t)st.st_size, f) != (size_t)st.st_size)
        fail(path, "short read");
    fclose(f);
    return files[num_files++].data;
}

struct item {
    char *name;
    const unsigned char *data;
    size_t len;
};
struct list {
    char *path;
    struct item *items;
    size_t count;
};
static struct list *lists = NULL;
static size_t num_lists = 0;

static const struct list *list_of(const char *path) {
    for (size_t i = 0; i < num_lists; i++)
        if (strcmp(lists[i].path, path) == 0)
            return &lists[i];
    FILE *f = fopen(path, "r");
    char line[4096];
    if (f == NULL)
        fail(path, strerror(errno));
    lists = realloc(lists, sizeof(struct list) * (num_lists + 1));
    struct list *l = &lists[num_lists++];
    l->path = strdup(path);
    l->items = NULL;
    l->count = 0;
    size_t room = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *name = strtok(line, "\t");
        char *file = strtok(NULL, "\t");
        char *offset = strtok(NULL, "\t");
        char *length = strtok(NULL, "\t\n");
        if (length == NULL)
            fail(path, "a bad line");
        if (l->count == room) {
            room = room ? room * 2 : 1024;
            l->items = realloc(l->items, sizeof(struct item) * room);
        }
        l->items[l->count].name = strdup(name);
        l->items[l->count].data = load(file) + strtoull(offset, NULL, 10);
        l->items[l->count].len = strtoull(length, NULL, 10);
        l->count++;
    }
    fclose(f);
    return l;
}

static uint64_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0)
        fail(path, strerror(errno));
    return (uint64_t)st.st_size;
}

static void do_write(const char *out, const char *list_path, int method, unsigned level, unsigned em,
                     const char *password) {
    const struct list *l = list_of(list_path);
    unlink(out);
    uint64_t start = now();
    zip_t *za = open_archive(out, ZIP_CREATE | ZIP_TRUNCATE);
    for (size_t i = 0; i < l->count; i++) {
        zip_source_t *src = zip_source_buffer(za, l->items[i].data, l->items[i].len, 0);
        zip_int64_t index;
        if (src == NULL || (index = zip_file_add(za, l->items[i].name, src, 0)) < 0)
            fail("zip_file_add", zip_strerror(za));
        if (zip_file_set_mtime(za, (zip_uint64_t)index, MTIME, 0) != 0
            || zip_set_file_compression(za, (zip_uint64_t)index, method, level) != 0)
            fail("zip_set_file_compression", zip_strerror(za));
        if (em != 0 && zip_file_set_encryption(za, (zip_uint64_t)index, (zip_uint16_t)em, password) != 0)
            fail("zip_file_set_encryption", zip_strerror(za));
    }
    if (zip_close(za) != 0)
        fail("zip_close", zip_strerror(za));
    uint64_t end = now();
    printf("%llu %llu\n", (unsigned long long)(end - start), (unsigned long long)file_size(out));
}

static void copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb");
    FILE *out = fopen(to, "wb");
    static char buf[1 << 20];
    size_t got;
    if (in == NULL || out == NULL)
        fail("copying", strerror(errno));
    while ((got = fread(buf, 1, sizeof buf, in)) > 0)
        fwrite(buf, 1, got, out);
    fclose(in);
    fclose(out);
}

static void do_edit(const char *in, const char *out, const char *kind) {
    static unsigned char added[4096];
    copy_file(in, out);
    zip_t *za = open_archive(out, 0);
    zip_int64_t n = zip_get_num_entries(za, 0);
    int ok = 1;
    char **names = NULL;
    if (strcmp(kind, "rename-all") == 0) {
        names = malloc(sizeof(char *) * (size_t)n);
        for (zip_int64_t i = 0; i < n; i++) {
            const char *name = zip_get_name(za, (zip_uint64_t)i, 0);
            names[i] = malloc(strlen(name) + 9);
            sprintf(names[i], "renamed/%s", name);
        }
    }
    uint64_t start = now();
    if (strcmp(kind, "rename-one") == 0) {
        ok = zip_file_rename(za, 0, "renamed", 0) == 0;
    } else if (strcmp(kind, "rename-all") == 0) {
        for (zip_int64_t i = 0; i < n && ok; i++)
            ok = zip_file_rename(za, (zip_uint64_t)i, names[i], 0) == 0;
    } else if (strcmp(kind, "comment-all") == 0) {
        for (zip_int64_t i = 0; i < n && ok; i++)
            ok = zip_file_set_comment(za, (zip_uint64_t)i, "a comment", 9, 0) == 0;
    } else if (strcmp(kind, "delete-half") == 0) {
        for (zip_int64_t i = 0; i < n && ok; i += 2)
            ok = zip_delete(za, (zip_uint64_t)i) == 0;
    } else if (strcmp(kind, "add-one") == 0) {
        zip_source_t *src = zip_source_buffer(za, added, sizeof added, 0);
        zip_int64_t index = src == NULL ? -1 : zip_file_add(za, "added", src, 0);
        ok = index >= 0 && zip_file_set_mtime(za, (zip_uint64_t)index, MTIME, 0) == 0
             && zip_set_file_compression(za, (zip_uint64_t)index, ZIP_CM_STORE, 0) == 0;
    } else {
        fail("edit", kind);
    }
    if (!ok)
        fail(kind, zip_strerror(za));
    if (zip_close(za) != 0)
        fail("zip_close", zip_strerror(za));
    uint64_t end = now();
    if (names != NULL) {
        for (zip_int64_t i = 0; i < n; i++)
            free(names[i]);
        free(names);
    }
    printf("%llu %llu\n", (unsigned long long)(end - start), (unsigned long long)file_size(out));
}

int main(void) {
    static char line[8192];
    while (fgets(line, sizeof line, stdin) != NULL) {
        char *words[8] = {0};
        int count = 0;
        for (char *word = strtok(line, " \n"); word != NULL && count < 8; word = strtok(NULL, " \n"))
            words[count++] = word;
        if (count == 3 && strcmp(words[0], "open") == 0)
            do_open(words[1], atoi(words[2]));
        else if (count == 2 && strcmp(words[0], "list") == 0)
            do_list(words[1]);
        else if (count == 2 && strcmp(words[0], "locate") == 0)
            do_locate(words[1]);
        else if (count == 4 && strcmp(words[0], "read") == 0)
            do_read(words[1], strtoull(words[2], NULL, 10), words[3]);
        else if (count == 7 && strcmp(words[0], "write") == 0)
            do_write(words[1], words[2], atoi(words[3]), (unsigned)atoi(words[4]), (unsigned)atoi(words[5]), words[6]);
        else if (count == 4 && strcmp(words[0], "edit") == 0)
            do_edit(words[1], words[2], words[3]);
        else
            fail("a bad request", count > 0 ? words[0] : "");
        fflush(stdout);
    }
    return 0;
}
