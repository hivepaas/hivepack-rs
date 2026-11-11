/*
 * The squashfuse side of hivepack::squashfs's comparison tests.
 *
 * It reads one request per line on stdin and answers each with lines on
 * stdout, the last of which starts with "end", by calling squashfuse 0.6.5's
 * library (libsquashfuse: fs.c, table.c, dir.c, file.c, xattr.c, stat.c,
 * traverse.c, decompress.c, cache.c), which hivepack::squashfs ports. The
 * Rust tests (crates/hivepack/tests/squashfs_oracle.rs) walk the port the
 * same way, in the same order, and compare the answers as text: the order
 * matters, as squashfuse's caches of data blocks and fragments are keyed by
 * where a block is, not by what its header says, and a damaged image can
 * read differently through them. scripts/testdata.py builds it from the
 * squashfuse release sources and those of zlib, XZ Utils, lz4, zstd and
 * LZO, with config.h.
 *
 * Byte strings are hexadecimal, "-" for an empty one. Numbers are decimal,
 * modes octal. <err> is a sqfs_err: 1 SQFS_ERR, 2 SQFS_BADFORMAT,
 * 3 SQFS_BADVERSION, 4 SQFS_BADCOMP, 5 SQFS_UNSUP.
 *
 *   version
 *       "end 0.6.5": the squashfuse release it is built from.
 *
 *   list <offset> <max entries> <max data> <image>
 *       Opens <image> with sqfs_init at <offset>. If that fails, "end init
 *       <err>". Otherwise:
 *
 *       "super <s_major> <s_minor> <compression> <block_size> <block_log>
 *       <flags> <inodes> <fragments> <no_ids> <mkfs_time> <bytes_used>
 *       <root_inode>", then the root inode, described as below, then each
 *       item sqfs_traverse_next gives from the root: "up" when a directory
 *       ends, or an entry, "entry <path> <type> <inode_number> <inode>"
 *       (sqfs_dentry_type, sqfs_dentry_inode_num, sqfs_dentry_inode), then
 *       its inode described; then "export <inode>" or "export err <err>",
 *       sqfs_export_inode of its number, if the image is exportable; then
 *       "path 1 <inode>", "path 0" or "path err <err>", what
 *       sqfs_lookup_path_with_id finds for its path from the root (the
 *       path as a C string: to its first NUL, if a damaged name has one).
 *
 *       An inode is described by:
 *       - "inode err <err>" (and nothing more), or "inode <inode_type>
 *         <mode> <uid> <guid> <mtime> <inode_number> <nlink> <xattr>
 *         <next.block> <next.offset>", the fields of sqfs_inode, and for a
 *         file " <start_block> <file_size> <frag_idx> <frag_off>", a
 *         directory " <start_block> <offset> <dir_size> <idx_count>
 *         <parent_inode>", a symbolic link " <symlink_size>", a device
 *         " <major> <minor>";
 *       - "stat err <err>" or "stat <mode> <uid> <gid> <mtime> <size>
 *         <blksize> <blocks>", from sqfs_stat (its st_nlink is the inode's
 *         nlink, in a type whose width differs between systems);
 *       - for a symbolic link, "link <target>" or "link err <err>", from
 *         sqfs_readlink;
 *       - "xattrs err <err>" or "xattrs <count>" from sqfs_xattr_open, then
 *         for each, "xattr <name> <value>" (sqfs_xattr_read, sqfs_xattr_name
 *         with its prefix, sqfs_xattr_value_size, sqfs_xattr_value), or
 *         "xattr err <err>", the last;
 *       - for a regular file, "data <length> <hash> <how>": its data read
 *         from the start with sqfs_read_range, 65,536 bytes at a time, its
 *         FNV-1a hash (64 bits), and "end" when all was read, "err <err>"
 *         when a read failed, or "limit" when <max data> bytes were read
 *         and there is more.
 *
 *       How the walk ended: "end ok"; "end walk <err>" when
 *       sqfs_traverse_next failed; "end deep" when the next item would
 *       descend into a directory MAX_DEPTH deep, which the port refuses
 *       (squashfuse would go on, through a directory that holds itself,
 *       until its memory runs out); "end many" when <max entries> entries
 *       were given, before anything more is asked of the walk, and before
 *       "end deep" is.
 *
 *   read <offset> <image>
 *       For the speed comparison: opens <image> at <offset> and reads every
 *       regular file sqfs_traverse finds with sqfs_read_range, 128 KiB at a
 *       time, as fast as it can: "end <files> <bytes> <nanoseconds>", the
 *       time from sqfs_init to the last read, or "end err <err>".
 *
 *   quit
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "squashfuse.h"
#include "dir.h"
#include "fs.h"
#include "stat.h"
#include "traverse.h"
#include "xattr.h"

/* As hivepack::squashfs::MAX_DEPTH. */
#define MAX_DEPTH 1024

#define CHUNK 65536

static void hex(const unsigned char *bytes, size_t len) {
	size_t i;
	if (len == 0) {
		fputs("-", stdout);
		return;
	}
	for (i = 0; i < len; ++i)
		printf("%02x", bytes[i]);
}

static uint64_t fnv1a(uint64_t hash, const unsigned char *bytes, size_t len) {
	size_t i;
	for (i = 0; i < len; ++i) {
		hash ^= bytes[i];
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

static void describe(sqfs *fs, sqfs_inode_id id, uint64_t max_data) {
	sqfs_inode inode;
	struct stat st;
	sqfs_err err;
	sqfs_xattr x;

	err = sqfs_inode_get(fs, &inode, id);
	if (err) {
		printf("inode err %d\n", err);
		return;
	}
	printf("inode %u %o %u %u %u %u %d %u %lld %llu",
		inode.base.inode_type, inode.base.mode, inode.base.uid,
		inode.base.guid, inode.base.mtime, inode.base.inode_number,
		inode.nlink, inode.xattr, (long long)inode.next.block,
		(unsigned long long)inode.next.offset);
	if (S_ISREG(inode.base.mode)) {
		printf(" %llu %llu %u %u",
			(unsigned long long)inode.xtra.reg.start_block,
			(unsigned long long)inode.xtra.reg.file_size,
			inode.xtra.reg.frag_idx, inode.xtra.reg.frag_off);
	} else if (S_ISDIR(inode.base.mode)) {
		printf(" %u %u %u %u %u", inode.xtra.dir.start_block,
			inode.xtra.dir.offset, inode.xtra.dir.dir_size,
			inode.xtra.dir.idx_count, inode.xtra.dir.parent_inode);
	} else if (S_ISLNK(inode.base.mode)) {
		printf(" %llu", (unsigned long long)inode.xtra.symlink_size);
	} else if (S_ISBLK(inode.base.mode) || S_ISCHR(inode.base.mode)) {
		printf(" %d %d", inode.xtra.dev.major, inode.xtra.dev.minor);
	}
	printf("\n");

	err = sqfs_stat(fs, &inode, &st);
	if (err)
		printf("stat err %d\n", err);
	else
		printf("stat %o %llu %llu %lld %lld %lld %lld\n",
			(unsigned)st.st_mode, (unsigned long long)st.st_uid, (unsigned long long)st.st_gid,
			(long long)st.st_mtime, (long long)st.st_size,
			(long long)st.st_blksize, (long long)st.st_blocks);

	if (S_ISLNK(inode.base.mode)) {
		size_t size;
		char *target;
		sqfs_readlink(fs, &inode, NULL, &size);
		target = malloc(size);
		if (!target) {
			printf("link err nomem\n");
		} else {
			err = sqfs_readlink(fs, &inode, target, &size);
			if (err) {
				printf("link err %d\n", err);
			} else {
				printf("link ");
				hex((unsigned char *)target, size - 1);
				printf("\n");
			}
			free(target);
		}
	}

	err = sqfs_xattr_open(fs, &inode, &x);
	if (err) {
		printf("xattrs err %d\n", err);
	} else {
		printf("xattrs %llu\n", (unsigned long long)x.remain);
		while (x.remain > 0) {
			size_t name_size, value_size;
			char *name, *value;
			if ((err = sqfs_xattr_read(&x))) {
				printf("xattr err %d\n", err);
				break;
			}
			name_size = sqfs_xattr_name_size(&x);
			name = malloc(name_size + 1);
			if ((err = sqfs_xattr_name(&x, name, true))) {
				free(name);
				printf("xattr err %d\n", err);
				break;
			}
			if ((err = sqfs_xattr_value_size(&x, &value_size))) {
				free(name);
				printf("xattr err %d\n", err);
				break;
			}
			value = malloc(value_size + 1);
			if ((err = sqfs_xattr_value(&x, value))) {
				free(name);
				free(value);
				printf("xattr err %d\n", err);
				break;
			}
			printf("xattr ");
			hex((unsigned char *)name, name_size);
			printf(" ");
			hex((unsigned char *)value, value_size);
			printf("\n");
			free(name);
			free(value);
		}
	}

	if (S_ISREG(inode.base.mode)) {
		static unsigned char buf[CHUNK];
		uint64_t hash = 0xcbf29ce484222325ULL;
		uint64_t at = 0;
		uint64_t size = inode.xtra.reg.file_size;
		const char *how = "end";
		int read_err = 0;
		while (at < size) {
			sqfs_off_t want;
			if (at >= max_data) {
				how = "limit";
				break;
			}
			want = size - at > CHUNK ? CHUNK : (sqfs_off_t)(size - at);
			if (want > (sqfs_off_t)(max_data - at))
				want = (sqfs_off_t)(max_data - at);
			err = sqfs_read_range(fs, &inode, (sqfs_off_t)at, &want, buf);
			if (err) {
				read_err = err;
				break;
			}
			hash = fnv1a(hash, buf, (size_t)want);
			at += (uint64_t)want;
		}
		if (read_err)
			printf("data %llu %016llx err %d\n", (unsigned long long)at,
				(unsigned long long)hash, read_err);
		else
			printf("data %llu %016llx %s\n", (unsigned long long)at,
				(unsigned long long)hash, how);
	}
}

static void list(uint64_t offset, uint64_t max_entries, uint64_t max_data,
		const char *path) {
	sqfs fs;
	sqfs_err err;
	sqfs_traverse trv;
	uint64_t entries = 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("end bad open\n");
		return;
	}
	err = sqfs_init(&fs, fd, (size_t)offset);
	if (err) {
		printf("end init %d\n", err);
		close(fd);
		return;
	}
	printf("super %u %u %u %u %u %u %u %u %u %u %llu %llu\n",
		fs.sb.s_major, fs.sb.s_minor, fs.sb.compression, fs.sb.block_size,
		fs.sb.block_log, fs.sb.flags, fs.sb.inodes, fs.sb.fragments,
		fs.sb.no_ids, fs.sb.mkfs_time, (unsigned long long)fs.sb.bytes_used,
		(unsigned long long)fs.sb.root_inode);
	describe(&fs, sqfs_inode_root(&fs), max_data);

	err = sqfs_traverse_open(&trv, &fs, sqfs_inode_root(&fs));
	if (err) {
		printf("end walk %d\n", err);
		sqfs_destroy(&fs);
		close(fd);
		return;
	}
	while (1) {
		if (entries == max_entries) {
			printf("end many\n");
			break;
		}
		if (trv.state == 0 /* TRAVERSE_DESCEND */
				&& trv.stack.size >= MAX_DEPTH) {
			printf("end deep\n");
			break;
		}
		if (!sqfs_traverse_next(&trv, &err)) {
			if (err)
				printf("end walk %d\n", err);
			else
				printf("end ok\n");
			break;
		}
		if (trv.dir_end) {
			printf("up\n");
			continue;
		}
		++entries;
		printf("entry ");
		hex((unsigned char *)trv.path, trv.path_size - 1);
		printf(" %d %u %llu\n", sqfs_dentry_type(&trv.entry),
			sqfs_dentry_inode_num(&trv.entry),
			(unsigned long long)sqfs_dentry_inode(&trv.entry));
		describe(&fs, sqfs_dentry_inode(&trv.entry), max_data);
		if (sqfs_export_ok(&fs)) {
			sqfs_inode_id found;
			err = sqfs_export_inode(&fs, sqfs_dentry_inode_num(&trv.entry),
				&found);
			if (err)
				printf("export err %d\n", err);
			else
				printf("export %llu\n", (unsigned long long)found);
		}
		{
			sqfs_inode inode;
			sqfs_inode_id found_id = 0;
			bool found = false;
			char *copy = malloc(trv.path_size);
			memcpy(copy, trv.path, trv.path_size);
			err = sqfs_inode_get(&fs, &inode, sqfs_inode_root(&fs));
			if (!err)
				err = sqfs_lookup_path_with_id(&fs, &inode, copy, &found,
					&found_id);
			if (err)
				printf("path err %d\n", err);
			else if (found)
				printf("path 1 %llu\n", (unsigned long long)found_id);
			else
				printf("path 0\n");
			free(copy);
		}
	}
	sqfs_traverse_close(&trv);
	sqfs_destroy(&fs);
	close(fd);
}

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void read_all(uint64_t offset, const char *path) {
	static unsigned char buf[1 << 17];
	sqfs fs;
	sqfs_err err;
	sqfs_traverse trv;
	uint64_t files = 0, bytes = 0, start;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("end bad open\n");
		return;
	}
	start = now_ns();
	if ((err = sqfs_init(&fs, fd, (size_t)offset))) {
		printf("end err %d\n", err);
		close(fd);
		return;
	}
	if ((err = sqfs_traverse_open(&trv, &fs, sqfs_inode_root(&fs)))) {
		printf("end err %d\n", err);
		sqfs_destroy(&fs);
		close(fd);
		return;
	}
	while (sqfs_traverse_next(&trv, &err)) {
		sqfs_inode inode;
		uint64_t at = 0;
		if (trv.dir_end)
			continue;
		if ((err = sqfs_inode_get(&fs, &inode, sqfs_dentry_inode(&trv.entry))))
			break;
		if (!S_ISREG(inode.base.mode))
			continue;
		++files;
		while (at < inode.xtra.reg.file_size) {
			sqfs_off_t want = sizeof(buf);
			if ((err = sqfs_read_range(&fs, &inode, (sqfs_off_t)at, &want, buf)))
				break;
			at += (uint64_t)want;
		}
		if (err)
			break;
		bytes += at;
	}
	if (err)
		printf("end err %d\n", err);
	else
		printf("end %llu %llu %llu\n", (unsigned long long)files,
			(unsigned long long)bytes, (unsigned long long)(now_ns() - start));
	sqfs_traverse_close(&trv);
	sqfs_destroy(&fs);
	close(fd);
}

int main(void) {
	static char line[1 << 16];
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	while (fgets(line, sizeof(line), stdin)) {
		char *nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		if (strcmp(line, "quit") == 0) {
			break;
		} else if (strcmp(line, "version") == 0) {
			printf("end 0.6.5\n");
		} else if (strncmp(line, "read ", 5) == 0) {
			unsigned long long offset;
			int used = 0;
			if (sscanf(line + 5, "%llu %n", &offset, &used) != 1 || used == 0)
				printf("end bad\n");
			else
				read_all(offset, line + 5 + used);
		} else if (strncmp(line, "list ", 5) == 0) {
			unsigned long long offset, max_entries, max_data;
			int used = 0;
			if (sscanf(line + 5, "%llu %llu %llu %n", &offset, &max_entries,
					&max_data, &used) != 3 || used == 0) {
				printf("end bad\n");
			} else {
				list(offset, max_entries, max_data, line + 5 + used);
			}
		} else {
			printf("end bad\n");
		}
		fflush(stdout);
	}
	return 0;
}
