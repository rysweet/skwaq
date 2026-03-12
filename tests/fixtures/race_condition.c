#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* CWE-367: TOCTOU race condition */
int safe_write(const char *path, const char *data) {
    /* Check if file exists and is writable */
    if (access(path, W_OK) != 0) {
        fprintf(stderr, "No write access to %s\n", path);
        return -1;
    }

    /* TOCTOU gap: file could be replaced with symlink between access() and fopen() */
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(data, f);
    fclose(f);
    return 0;
}

/* CWE-362: Race on shared temp file */
void write_temp_results(const char *data) {
    char *tmpfile = "/tmp/skwaq_results.txt";  /* Predictable path */
    /* Another process could create a symlink at this path */
    FILE *f = fopen(tmpfile, "w");
    if (f) {
        fputs(data, f);
        fclose(f);
    }
}

/* CWE-367: Check-then-act on file permissions */
int process_if_owned(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    /* Check ownership */
    if (st.st_uid != getuid()) {
        fprintf(stderr, "File not owned by current user\n");
        return -1;
    }

    /* TOCTOU: file could be replaced between stat() and open() */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[1024];
    read(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_write(argv[1], "test data");
        process_if_owned(argv[1]);
    }
    write_temp_results("results");
    return 0;
}
