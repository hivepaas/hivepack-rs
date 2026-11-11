/*
 * The libarchive side of hivepack-ar's comparison tests.
 *
 * It reads one request per line on stdin and answers each on one line of
 * stdout, by calling libarchive 3.8.10, whose ar reader hivepack-ar ports,
 * and whose ar writers make some of the archives the tests read. The Rust
 * tests ask the port the same questions and compare the answers as text.
 * scripts/testdata.py builds it from the libarchive release sources, with
 * config.h.
 *
 * Byte strings are hexadecimal, "-" is an empty one and "~" none at all.
 * A request the oracle cannot answer, or an answer libarchive should not
 * give, has "BAD" in it.
 *
 *   sizes
 *       The size of mode_t, which libarchive stores an entry's mode in:
 *       "ok <mode_t>".
 *
 *   read <mode> <archive>
 *       Every entry of <archive>, read with archive_read_support_format_ar
 *       alone, and all of its data with archive_read_data_block. <mode> is
 *       two characters: "m" to open the archive in memory
 *       (archive_read_open_memory) or "s" to give it as one block through a
 *       read callback that cannot seek; "d" to read each entry's data, or
 *       "k" to leave it to archive_read_next_header to skip. Answered with
 *       fields separated by "|": "open", or "fatal:<message>" alone when the
 *       archive is not opened; then one field per entry, and how the
 *       reading ended: "eof", "fatal:<message>", or "stop" after the data
 *       of an entry ended other than by "eof".
 *
 *       An entry is "ok;<header>;<data>". <header> is, separated by ",":
 *       archive_format, the path, the mode in octal, uid, gid, the size and
 *       the modification time; "~" for what is not set. <data> is "skip"
 *       with "k", else the length of the data, its FNV-1a hash and its end:
 *       "eof" or "fatal:<message>".
 *
 *   write <format> <entries>
 *       An archive written by archive_write_set_format_ar_<format> ("bsd"
 *       or "svr4"), unblocked, from <entries>, lines separated by "\n",
 *       each
 *         <path> <mode> <uid> <gid> <mtime> <data>
 *       a regular file of that data; the mode in octal; the path and the
 *       data as byte strings. A "//" entry is SVR4's filename table, which
 *       its writer takes from the caller. Answered "ok <archive>" or
 *       "err <message>" for the first entry the writer refuses.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "archive.h"
#include "archive_entry.h"

static char *line_buf;
static size_t line_cap;

static void out_char(char c) { putchar(c); }

static void out_str(const char *s) { fputs(s, stdout); }

static void out_hex(const unsigned char *p, size_t n)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	if (n == 0) {
		out_char('-');
		return;
	}
	for (i = 0; i < n; i++) {
		out_char(digits[p[i] >> 4]);
		out_char(digits[p[i] & 15]);
	}
}

/* A C string as a byte string, or "~" for NULL. */
static void out_cstr(const char *s)
{
	if (s == NULL)
		out_char('~');
	else
		out_hex((const unsigned char *)s, strlen(s));
}

static void out_error(struct archive *a)
{
	out_cstr(archive_error_string(a));
}

static int unhex_digit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/* A byte string in place; returns its length, or -1. */
static long unhex(char *s)
{
	size_t n, i;

	if (strcmp(s, "-") == 0)
		return 0;
	n = strlen(s);
	if (n % 2 != 0)
		return -1;
	for (i = 0; i < n / 2; i++) {
		int hi = unhex_digit((unsigned char)s[2 * i]);
		int lo = unhex_digit((unsigned char)s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		s[i] = (char)(hi * 16 + lo);
	}
	return (long)(n / 2);
}

/* The read callback of mode "s": the whole archive in one block, no seek. */
struct stream {
	const unsigned char *data;
	size_t size;
	int done;
};

static la_ssize_t stream_read(struct archive *a, void *client, const void **buff)
{
	struct stream *s = client;

	(void)a;
	if (s->done) {
		*buff = NULL;
		return 0;
	}
	s->done = 1;
	*buff = s->data;
	return (la_ssize_t)s->size;
}

static void out_header(struct archive *a, struct archive_entry *e)
{
	printf("%d,", archive_format(a));
	out_cstr(archive_entry_pathname(e));
	printf(",%o,%lld,%lld,", (unsigned)archive_entry_mode(e),
	    (long long)archive_entry_uid(e), (long long)archive_entry_gid(e));
	if (archive_entry_size_is_set(e))
		printf("%lld", (long long)archive_entry_size(e));
	else
		out_char('~');
	out_char(',');
	if (archive_entry_mtime_is_set(e))
		printf("%lld", (long long)archive_entry_mtime(e));
	else
		out_char('~');
}

/* The data of the current entry; returns 0 when reading can go on. */
static int out_data(struct archive *a)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	int64_t total = 0;
	const char *end = NULL;

	for (;;) {
		const void *buff;
		size_t size, i;
		la_int64_t offset;
		int r = archive_read_data_block(a, &buff, &size, &offset);

		if (r == ARCHIVE_OK) {
			if (offset != total) {
				end = "BAD";
				break;
			}
			for (i = 0; i < size; i++) {
				hash ^= ((const unsigned char *)buff)[i];
				hash *= 0x100000001b3ULL;
			}
			total += (int64_t)size;
			continue;
		}
		if (r == ARCHIVE_EOF)
			end = "eof";
		else if (r == ARCHIVE_FATAL)
			end = "fatal:";
		else
			end = "BAD";
		break;
	}
	printf(";%lld,%016llx,%s", (long long)total, (unsigned long long)hash, end);
	if (strcmp(end, "fatal:") == 0)
		out_error(a);
	return strcmp(end, "eof") == 0 ? 0 : 1;
}

/* Opens <archive> in memory or as a stream; returns what archive_read_open
 * does. */
static int open_archive(struct archive *a, char mode, struct stream *s,
    const char *archive, size_t n)
{
	if (mode == 'm')
		return archive_read_open_memory(a, archive, n);
	s->data = (const unsigned char *)archive;
	s->size = n;
	s->done = 0;
	return archive_read_open(a, s, NULL, stream_read, NULL);
}

static void do_read(char *mode, char *archive)
{
	struct archive *a;
	struct archive_entry *e;
	struct stream s;
	long n = unhex(archive);
	int r;

	if (strlen(mode) != 2 || n < 0) {
		out_str("BAD");
		return;
	}
	a = archive_read_new();
	archive_read_support_format_ar(a);
	r = open_archive(a, mode[0], &s, archive, (size_t)n);
	if (r != ARCHIVE_OK) {
		out_str("fatal:");
		out_error(a);
		archive_read_free(a);
		return;
	}
	out_str("open");
	for (;;) {
		r = archive_read_next_header(a, &e);
		out_char('|');
		if (r == ARCHIVE_EOF) {
			out_str("eof");
			break;
		}
		if (r == ARCHIVE_FATAL) {
			out_str("fatal:");
			out_error(a);
			break;
		}
		if (r != ARCHIVE_OK) {
			printf(" BAD");
			break;
		}
		out_str("ok;");
		out_header(a, e);
		if (mode[1] == 'k') {
			out_str(";skip");
			continue;
		}
		if (out_data(a) != 0) {
			out_str("|stop");
			break;
		}
	}
	archive_read_free(a);
}

/* The archive being written, grown as the writer calls back. */
struct sink {
	unsigned char *data;
	size_t size, cap;
};

static la_ssize_t sink_write(struct archive *a, void *client, const void *buff, size_t n)
{
	struct sink *s = client;

	(void)a;
	if (s->size + n > s->cap) {
		size_t cap = s->cap ? s->cap : 1 << 16;
		unsigned char *p;
		while (cap < s->size + n)
			cap *= 2;
		p = realloc(s->data, cap);
		if (p == NULL)
			return -1;
		s->data = p;
		s->cap = cap;
	}
	memcpy(s->data + s->size, buff, n);
	s->size += n;
	return (la_ssize_t)n;
}

static void do_write(char *format, char *entries)
{
	struct archive *a;
	struct sink s = { NULL, 0, 0 };
	long n = unhex(entries);
	char *line, *next;
	int r;

	if (n < 0) {
		out_str("BAD");
		return;
	}
	entries[n] = '\0';
	a = archive_write_new();
	if (strcmp(format, "bsd") == 0)
		r = archive_write_set_format_ar_bsd(a);
	else if (strcmp(format, "svr4") == 0)
		r = archive_write_set_format_ar_svr4(a);
	else
		r = ARCHIVE_FATAL;
	if (r != ARCHIVE_OK) {
		out_str("BAD");
		archive_write_free(a);
		return;
	}
	archive_write_add_filter_none(a);
	archive_write_set_bytes_per_block(a, 0);
	if (archive_write_open(a, &s, NULL, sink_write, NULL) != ARCHIVE_OK) {
		out_str("BAD");
		archive_write_free(a);
		return;
	}
	for (line = entries; line != NULL && *line != '\0'; line = next) {
		char *fields[6], *save;
		struct archive_entry *e;
		long path_len, data_len;
		int nfields = 0;

		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		for (char *f = strtok_r(line, " ", &save); f != NULL && nfields < 6;
		    f = strtok_r(NULL, " ", &save))
			fields[nfields++] = f;
		if (nfields != 6) {
			out_str("BAD");
			archive_write_free(a);
			free(s.data);
			return;
		}
		path_len = unhex(fields[0]);
		data_len = unhex(fields[5]);
		if (path_len < 0 || data_len < 0) {
			out_str("BAD");
			archive_write_free(a);
			free(s.data);
			return;
		}
		fields[0][path_len] = '\0';
		e = archive_entry_new();
		archive_entry_copy_pathname(e, fields[0]);
		archive_entry_set_filetype(e, AE_IFREG);
		archive_entry_set_perm(e, (mode_t)strtoul(fields[1], NULL, 8));
		archive_entry_set_uid(e, strtoll(fields[2], NULL, 10));
		archive_entry_set_gid(e, strtoll(fields[3], NULL, 10));
		archive_entry_set_mtime(e, (time_t)strtoll(fields[4], NULL, 10), 0);
		archive_entry_set_size(e, data_len);
		r = archive_write_header(a, e);
		if (r == ARCHIVE_OK && data_len > 0 &&
		    archive_write_data(a, fields[5], (size_t)data_len) != data_len)
			r = ARCHIVE_FATAL;
		archive_entry_free(e);
		if (r != ARCHIVE_OK) {
			out_str("err ");
			out_error(a);
			archive_write_free(a);
			free(s.data);
			return;
		}
	}
	if (archive_write_close(a) != ARCHIVE_OK) {
		out_str("err ");
		out_error(a);
	} else {
		out_str("ok ");
		out_hex(s.data, s.size);
	}
	archive_write_free(a);
	free(s.data);
}

int main(void)
{
	for (;;) {
		ssize_t len = getline(&line_buf, &line_cap, stdin);
		char *cmd, *arg1, *arg2, *save;

		if (len < 0)
			break;
		if (len > 0 && line_buf[len - 1] == '\n')
			line_buf[len - 1] = '\0';
		cmd = strtok_r(line_buf, " ", &save);
		arg1 = strtok_r(NULL, " ", &save);
		arg2 = strtok_r(NULL, " ", &save);
		if (cmd == NULL) {
			out_str("BAD");
		} else if (strcmp(cmd, "sizes") == 0) {
			printf("ok %zu", sizeof(mode_t));
		} else if (strcmp(cmd, "read") == 0 && arg1 != NULL && arg2 != NULL) {
			do_read(arg1, arg2);
		} else if (strcmp(cmd, "write") == 0 && arg1 != NULL && arg2 != NULL) {
			do_write(arg1, arg2);
		} else {
			out_str("BAD");
		}
		out_char('\n');
		fflush(stdout);
	}
	free(line_buf);
	return 0;
}
