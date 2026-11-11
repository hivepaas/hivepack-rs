/*
 * The liblzo2 side of hivepack::lzo's comparison tests, with lzokay's own
 * decompressor beside it.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling liblzo2 2.10 and lzokay (the commit hivepack::lzo
 * ports). The Rust tests ask the port the same questions and compare the
 * answers as text. scripts/testdata.py builds it from the two source sets:
 * liblzo2's C files compiled apart, then this file and lzokay.cpp. liblzo2
 * is under the GPL (version 2 or later): it is only built here, as a test
 * oracle, and never into hivepack.
 *
 * Byte strings are hexadecimal, and "-" is an empty one. Hashes are FNV-1a
 * (64 bits).
 *
 *   compress <method> <hex>
 *       Compresses <hex> into one block with liblzo2's compressor <method>:
 *       1 (lzo1x_1_compress), 1_11, 1_12, 1_15 (lzo1x_1_11_compress and the
 *       others), 999 (lzo1x_999_compress), or 999_<level>
 *       (lzo1x_999_compress_level, levels 1 to 9, without a dictionary).
 *       Answered "<len> <hex>", or "bad" for an unknown method.
 *
 *   decompress <capacity> <hex>
 *       Decompresses <hex> into a buffer of exactly <capacity> bytes,
 *       filled with a pattern (byte i is i * 31 + 7) before the call, once
 *       with lzo1x_decompress_safe and once with lzokay::decompress.
 *       Answered "<ret> <len> <hash> <ret> <len> <hash>": for liblzo2 and
 *       then lzokay, what the call returned (LZO_E_* and lzokay::EResult as
 *       numbers), the output length it set, and the hash of the whole
 *       buffer, past what was written too. lzokay reads its input from a
 *       copy followed by a byte 0xff: on a damaged stream its count of zero
 *       bytes reads on past the input's end, and the 0xff stops it there.
 *
 *   compressfile <method> <block> <in> <out>
 *       Compresses the file <in> in blocks of <block> bytes (the last
 *       shorter; 0 for one block) with <method>, as SquashFS compresses a
 *       file's blocks, and writes them to the file <out>, each as its
 *       compressed length and its length (little-endian, 32 bits each),
 *       then its bytes. Answered "<blocks> <compressed bytes>".
 *
 *   decompressfile <path>
 *       Decompresses each block of a file that compressfile wrote, with
 *       lzo1x_decompress_safe into exactly its length. Answered
 *       "<blocks> <bad> <bytes> <hash>": the blocks, those that did not
 *       decompress to their length with LZO_E_OK, and the length and hash
 *       of all the output.
 *
 *   time <rounds> <path>
 *       Decompresses the blocks of the file at <path> (written by
 *       compressfile) once untimed, then <rounds> times timed, each round
 *       with lzo1x_decompress_safe and then lzokay::decompress, for the
 *       benchmark. Answered "<hash> <ns> <ns>": the hash of all the output
 *       and the fastest round of each in nanoseconds.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "lzo/lzo1x.h"
#include "lzokay.hpp"

static int nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

static std::vector<unsigned char> unhex(const char *text) {
    std::vector<unsigned char> bytes;
    if (strcmp(text, "-") == 0)
        return bytes;
    size_t n = strlen(text) / 2;
    bytes.resize(n);
    for (size_t i = 0; i < n; i++)
        bytes[i] = (unsigned char)(nibble(text[2 * i]) << 4 | nibble(text[2 * i + 1]));
    return bytes;
}

static unsigned long long fnv64(const unsigned char *bytes, size_t len,
                                unsigned long long hash = 0xcbf29ce484222325ULL) {
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x00000100000001b3ULL;
    }
    return hash;
}

/*
 * <data> compressed with <method> into <out>: whether the method is known
 * and liblzo2 compressed it.
 */
static bool compress(const char *method, const unsigned char *data, size_t len,
                     std::vector<unsigned char> &out) {
    static std::vector<unsigned char> wrkmem(LZO1X_999_MEM_COMPRESS);
    out.resize(len + len / 16 + 64 + 3);
    lzo_uint out_len = (lzo_uint)out.size();
    int ret;
    if (strcmp(method, "1") == 0)
        ret = lzo1x_1_compress(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data());
    else if (strcmp(method, "1_11") == 0)
        ret = lzo1x_1_11_compress(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data());
    else if (strcmp(method, "1_12") == 0)
        ret = lzo1x_1_12_compress(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data());
    else if (strcmp(method, "1_15") == 0)
        ret = lzo1x_1_15_compress(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data());
    else if (strcmp(method, "999") == 0)
        ret = lzo1x_999_compress(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data());
    else if (strncmp(method, "999_", 4) == 0 && method[4] >= '1' && method[4] <= '9' &&
             method[5] == '\0')
        ret = lzo1x_999_compress_level(data, (lzo_uint)len, out.data(), &out_len, wrkmem.data(),
                                       NULL, 0, 0, method[4] - '0');
    else
        return false;
    if (ret != LZO_E_OK)
        return false;
    out.resize(out_len);
    return true;
}

static void do_compress(const char *method, const char *data_hex) {
    std::vector<unsigned char> data = unhex(data_hex), out;
    if (!compress(method, data.data(), data.size(), out)) {
        puts("bad");
        return;
    }
    printf("%zu ", out.size());
    if (out.empty())
        putchar('-');
    for (unsigned char byte : out)
        printf("%02x", byte);
    putchar('\n');
}

static void fill(std::vector<unsigned char> &out) {
    for (size_t i = 0; i < out.size(); i++)
        out[i] = (unsigned char)(i * 31 + 7);
}

static void do_decompress(size_t capacity, const char *data_hex) {
    std::vector<unsigned char> data = unhex(data_hex);
    /* Exactly the capacity, so that a write past it is caught by tools that
     * watch the heap; one byte at least, for a pointer to pass. */
    std::vector<unsigned char> out(capacity), copy(data);
    unsigned char none = 0;
    fill(out);
    lzo_uint out_len = (lzo_uint)capacity;
    int ret = lzo1x_decompress_safe(data.empty() ? &none : data.data(), (lzo_uint)data.size(),
                                    capacity ? out.data() : &none, &out_len, NULL);
    printf("%d %lu %016llx", ret, (unsigned long)out_len, fnv64(out.data(), out.size()));

    fill(out);
    copy.push_back(0xff);
    std::size_t lzokay_len = 0;
    lzokay::EResult result = lzokay::decompress(copy.data(), data.size(),
                                                capacity ? out.data() : &none, capacity,
                                                lzokay_len);
    printf(" %d %zu %016llx\n", (int)result, lzokay_len, fnv64(out.data(), out.size()));
}

static bool read_file(const char *path, std::vector<unsigned char> &data) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data.resize((size_t)len);
    bool ok = fread(data.data(), 1, data.size(), f) == data.size();
    fclose(f);
    return ok;
}

static void put32(std::vector<unsigned char> &out, uint32_t value) {
    for (int i = 0; i < 4; i++)
        out.push_back((unsigned char)(value >> (8 * i)));
}

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void do_compressfile(const char *method, size_t block, const char *in, const char *out_path) {
    std::vector<unsigned char> data, out, piece;
    if (!read_file(in, data)) {
        puts("bad");
        return;
    }
    if (block == 0)
        block = data.size() ? data.size() : 1;
    size_t blocks = 0, compressed = 0;
    for (size_t at = 0; at < data.size() || (at == 0 && blocks == 0); at += block) {
        size_t len = data.size() - at < block ? data.size() - at : block;
        if (!compress(method, data.data() + at, len, piece)) {
            puts("bad");
            return;
        }
        put32(out, (uint32_t)piece.size());
        put32(out, (uint32_t)len);
        out.insert(out.end(), piece.begin(), piece.end());
        blocks++;
        compressed += piece.size();
        if (data.empty())
            break;
    }
    FILE *f = fopen(out_path, "wb");
    if (!f || fwrite(out.data(), 1, out.size(), f) != out.size()) {
        puts("bad");
        if (f)
            fclose(f);
        return;
    }
    fclose(f);
    printf("%zu %zu\n", blocks, compressed);
}

/* The blocks of a file compressfile wrote: where each starts, its compressed
 * length and its length. */
struct Block {
    size_t at, compressed, len;
};

static bool blocks_of(const std::vector<unsigned char> &file, std::vector<Block> &blocks,
                      size_t &total) {
    total = 0;
    for (size_t at = 0; at < file.size();) {
        if (file.size() - at < 8)
            return false;
        Block b = {at + 8, get32(&file[at]), get32(&file[at + 4])};
        if (file.size() - b.at < b.compressed)
            return false;
        blocks.push_back(b);
        total += b.len;
        at = b.at + b.compressed;
    }
    return true;
}

static void do_decompressfile(const char *path) {
    std::vector<unsigned char> file;
    std::vector<Block> blocks;
    size_t total;
    if (!read_file(path, file) || !blocks_of(file, blocks, total)) {
        puts("bad");
        return;
    }
    std::vector<unsigned char> out(total + 1);
    size_t bad = 0, written = 0;
    for (const Block &b : blocks) {
        lzo_uint out_len = (lzo_uint)b.len;
        int ret = lzo1x_decompress_safe(&file[b.at], (lzo_uint)b.compressed, &out[written],
                                        &out_len, NULL);
        if (ret != LZO_E_OK || out_len != b.len)
            bad++;
        written += b.len;
    }
    printf("%zu %zu %zu %016llx\n", blocks.size(), bad, total, fnv64(out.data(), total));
}

static long long now_ns() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void do_time(int rounds, const char *path) {
    std::vector<unsigned char> file;
    std::vector<Block> blocks;
    size_t total;
    if (!read_file(path, file) || !blocks_of(file, blocks, total)) {
        puts("bad");
        return;
    }
    std::vector<unsigned char> out(total + 1);
    long long best_lzo = -1, best_lzokay = -1;
    /* Once untimed, so that the output's pages are there. */
    for (int round = -1; round < rounds; round++) {
        long long start = now_ns();
        size_t written = 0;
        for (const Block &b : blocks) {
            lzo_uint out_len = (lzo_uint)b.len;
            lzo1x_decompress_safe(&file[b.at], (lzo_uint)b.compressed, &out[written], &out_len,
                                  NULL);
            written += b.len;
        }
        long long took = now_ns() - start;
        if (round >= 0 && (best_lzo < 0 || took < best_lzo))
            best_lzo = took;

        start = now_ns();
        written = 0;
        for (const Block &b : blocks) {
            std::size_t out_len = 0;
            lzokay::decompress(&file[b.at], b.compressed, &out[written], b.len, out_len);
            written += b.len;
        }
        took = now_ns() - start;
        if (round >= 0 && (best_lzokay < 0 || took < best_lzokay))
            best_lzokay = took;
    }
    printf("%016llx %lld %lld\n", fnv64(out.data(), total), best_lzo, best_lzokay);
}

int main() {
    if (lzo_init() != LZO_E_OK) {
        puts("lzo_init failed");
        return 1;
    }
    std::string line;
    int c;
    for (;;) {
        line.clear();
        while ((c = getchar()) != EOF && c != '\n')
            line.push_back((char)c);
        if (c == EOF && line.empty())
            break;
        std::vector<char *> words;
        for (char *word = strtok(&line[0], " "); word && words.size() < 6;
             word = strtok(NULL, " "))
            words.push_back(word);
        size_t count = words.size();
        if (count == 3 && strcmp(words[0], "compress") == 0)
            do_compress(words[1], words[2]);
        else if (count == 3 && strcmp(words[0], "decompress") == 0)
            do_decompress((size_t)strtoull(words[1], NULL, 10), words[2]);
        else if (count == 5 && strcmp(words[0], "compressfile") == 0)
            do_compressfile(words[1], (size_t)strtoull(words[2], NULL, 10), words[3], words[4]);
        else if (count == 2 && strcmp(words[0], "decompressfile") == 0)
            do_decompressfile(words[1]);
        else if (count == 3 && strcmp(words[0], "time") == 0)
            do_time(atoi(words[1]), words[2]);
        else
            puts("bad");
        fflush(stdout);
        if (c == EOF)
            break;
    }
    return 0;
}
