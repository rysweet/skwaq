/* CWE-772: Missing Release of Resource after Effective Lifetime
 * File descriptors and file handles leaked on error paths. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int copy_file(const char *src, const char *dst) {
    int fd_src = open(src, O_RDONLY);
    if (fd_src < 0) return -1;

    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_dst < 0) return -1;  /* Leaks fd_src */

    char buf[4096];
    ssize_t n;
    while ((n = read(fd_src, buf, sizeof(buf))) > 0) {
        if (write(fd_dst, buf, n) != n)
            return -1;  /* Leaks both fds */
    }
    close(fd_src);
    close(fd_dst);
    return 0;
}

FILE *open_log(const char *path) {
    FILE *f = fopen(path, "a");
    /* Caller may forget to close; no tracking of open handles */
    return f;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    copy_file(argv[1], argv[2]);
    FILE *log = open_log("/tmp/app.log");
    fprintf(log, "Operation complete\n");
    /* log handle never closed */
    return 0;
}
