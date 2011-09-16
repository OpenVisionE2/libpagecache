/*
 * userspace pagecache management using LD_PRELOAD, fadvise and
 * sync_file_range().
 *
 * Original by
 * Andrew Morton <akpm@linux-foundation.org>
 * March, 2007
 *
 * Andreas Monzner <andreas.monzner@dream-property.net>
 * July, 2011
 *
 */

#include "libpagecache-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include "symbol.h"

enum fd_state {
	FDS_UNKNOWN = 0,	/* We know nothing about this fd */
	FDS_IGNORE,		/* Ignore this file (!S_ISREG?) */
	FDS_ACTIVE,		/* We're managing this file's pagecache */
};

struct fd_status {
	enum fd_state state;
	unsigned int bytes;
};


static pthread_mutex_t realloc_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int pagecache_flush_interval = 1024*1024; // default 1MB

static int (*libc_close)(int fd);
static int (*libc_dup2)(int oldfd, int newfd);
static int (*libc_fclose)(FILE *fp);
static size_t (*libc_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*libc_fread_unlocked)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*libc_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*libc_fwrite_unlocked)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
static ssize_t (*libc_sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);

static void initialize_globals(void) __attribute__ ((constructor));
static void initialize_globals(void)
{
	char *e = getenv("PAGECACHE_FLUSH_INTERVAL");
	if (e != NULL)
		pagecache_flush_interval = strtoul(e, NULL, 10);

	libc_close = find_symbol("close");
	libc_dup2 = find_symbol("dup2");
	libc_fclose = find_symbol("fclose");
	libc_fread = find_symbol("fread");
	libc_fread_unlocked = find_symbol("fread_unlocked");
	libc_fwrite = find_symbol("fwrite");
	libc_fwrite_unlocked = find_symbol("fwrite_unlocked");
	libc_pread = find_symbol("pread");
	libc_pwrite = find_symbol("pwrite");
	libc_read = find_symbol("read");
	libc_write = find_symbol("write");
	libc_sendfile = find_symbol("sendfile");
}

static struct fd_status *get_fd_status(int fd)
{
	static struct fd_status *fd_status;
	volatile static int nr_fd_status;	/* Number at *fd_status */

	if (fd + 1 > nr_fd_status) {
		pthread_mutex_lock(&realloc_mutex);
		if (fd + 1 > nr_fd_status) { // check again.....
			fd_status = realloc(fd_status, sizeof(*fd_status) * (fd + 1));
			memset(fd_status + nr_fd_status, 0,
				sizeof(*fd_status) * (fd + 1 - nr_fd_status));
			nr_fd_status = fd + 1;
		}
		pthread_mutex_unlock(&realloc_mutex);
	}

	return &fd_status[fd];
}

/*
 * Work out if we're interested in this fd
 */
static void inspect_fd(int fd, struct fd_status *fds)
{
	struct stat stat_buf;

	if (fstat(fd, &stat_buf))
		abort();
	fds->bytes = 0;
	if (S_ISREG(stat_buf.st_mode) || S_ISBLK(stat_buf.st_mode))
		fds->state = FDS_ACTIVE;
	else
		fds->state = FDS_IGNORE;
}

static void fd_touched_bytes(int fd, ssize_t count)
{
	struct fd_status *fds;

	if (pagecache_flush_interval == 0)
		return;
	if (fd < 0)
		return;
	if (count <= 0)
		return;

	fds = get_fd_status(fd);

	if (fds->state == FDS_UNKNOWN)
		inspect_fd(fd, fds);

	if (fds->state == FDS_IGNORE)
		return;

	fds->bytes += count;

	if (fds->bytes >= pagecache_flush_interval) {
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
		fds->bytes = 0;
	}
}

static void fd_pre_close(int fd)
{
	struct fd_status *fds;

	if (pagecache_flush_interval == 0)
		return;
	if (fd < 0)
		return;

	fds = get_fd_status(fd);
	sync_file_range(fd, 0, LONG_LONG_MAX,
		SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER);
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	fds->state = FDS_UNKNOWN;
}

static void file_touched_bytes(size_t size, size_t nmemb, FILE *stream)
{
	/* does not prevent possible overflow of size * nmemb */
	if (stream != NULL)
		fd_touched_bytes(fileno(stream), size * nmemb);
}

static void file_pre_close(FILE *fp)
{
	if (fp != NULL)
		fd_pre_close(fileno(fp));
}

/*
 * syscall interface
 */

ssize_t write(int fd, const void *buf, size_t count)
{
	ssize_t ret = libc_write(fd, buf, count);
	fd_touched_bytes(fd, ret);
	return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t ret = libc_pwrite(fd, buf, count, offset);
	fd_touched_bytes(fd, ret);
	return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = libc_fwrite(ptr, size, nmemb, stream);
	file_touched_bytes(size, ret, stream);
	return ret;
}

#ifdef fwrite_unlocked
#undef fwrite_unlocked
#endif

size_t fwrite_unlocked(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = libc_fwrite_unlocked(ptr, size, nmemb, stream);
	file_touched_bytes(size, ret, stream);
	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret = libc_read(fd, buf, count);
	fd_touched_bytes(fd, ret);
	return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret = libc_pread(fd, buf, count, offset);
	fd_touched_bytes(fd, ret);
	return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = libc_fread(ptr, size, nmemb, stream);
	file_touched_bytes(size, ret, stream);
	return ret;
}

#ifdef fread_unlocked
#undef fread_unlocked
#endif

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = libc_fread_unlocked(ptr, size, nmemb, stream);
	file_touched_bytes(size, ret, stream);
	return ret;
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t processed=0;
	while (processed < count) {
		ssize_t ret;
		size_t rest = count - processed;
		if (rest > pagecache_flush_interval)
			rest = pagecache_flush_interval;
		ret = libc_sendfile(out_fd, in_fd, offset, rest);
		if (ret <= 0) { // error, EOF or interrupted syscall
			if (processed == 0)
				processed = ret;
			break;
		}

		processed += ret;
		fd_touched_bytes(in_fd, ret);
		fd_touched_bytes(out_fd, ret);
	};
	return processed;
}

int fclose(FILE *fp)
{
	file_pre_close(fp);
	return libc_fclose(fp);
}

int close(int fd)
{
	fd_pre_close(fd);
	return libc_close(fd);
}

int dup2(int oldfd, int newfd)
{
	if ((oldfd >= 0) && (newfd != oldfd))
		fd_pre_close(newfd);
	return libc_dup2(oldfd, newfd);
}
