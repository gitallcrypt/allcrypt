/* kill_at_write: a preload library that stops a process at a chosen
 * write into a file's data area, as a crash or a power cut would. For
 * scripts/make_luks_reencrypt_fixtures.py, which stops `cryptsetup
 * reencrypt` with it.
 *
 *   KILL_DATA_OFFSET  writes at or past this byte offset count
 *   KILL_AT           which of them (from 1) is the last
 *   KILL_KEEP         bytes of that write to let through first (0: none),
 *                     then fdatasync and _exit(9)
 *   KILL_SIGNAL       instead: raise this signal before that write, and
 *                     carry on as the process's handler decides
 *
 * write() is taken at the descriptor's offset, pwrite() at its own. Only
 * descriptors above 2 count for write(). Built by the script:
 *
 *   cc -shared -fPIC -O2 -o kill_at_write.so kill_at_write.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static long count;
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);

static void bind(void) {
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    if (!real_pwrite) real_pwrite = dlsym(RTLD_NEXT, "pwrite64");
}

static void check(int fd, const void *buf, size_t n, off_t at, int positioned) {
    const char *offset = getenv("KILL_DATA_OFFSET"), *which = getenv("KILL_AT");
    const char *keep_text = getenv("KILL_KEEP"), *signal_text = getenv("KILL_SIGNAL");
    if (!offset || !which || at < atoll(offset) || ++count != atol(which)) return;
    if (signal_text) {
        raise(atoi(signal_text));
        return;
    }
    size_t keep = keep_text ? (size_t)atoll(keep_text) : 0;
    if (keep > n) keep = n;
    if (keep) {
        if (positioned) real_pwrite(fd, buf, keep, at);
        else real_write(fd, buf, keep);
        fdatasync(fd);
    }
    _exit(9);
}

ssize_t write(int fd, const void *buf, size_t n) {
    bind();
    if (fd > 2) check(fd, buf, n, lseek(fd, 0, SEEK_CUR), 0);
    return real_write(fd, buf, n);
}

ssize_t pwrite64(int fd, const void *buf, size_t n, off_t at) {
    bind();
    check(fd, buf, n, at, 1);
    return real_pwrite(fd, buf, n, at);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t at) {
    return pwrite64(fd, buf, n, at);
}
