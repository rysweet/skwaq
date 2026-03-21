/* CWE-362: Race Condition (TOCTOU pattern)
 * Time-of-check to time-of-use race on file operations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int safe_write(const char *path, const char *data) {
    struct stat st;
    /* TOCTOU: file state can change between stat and open */
    if (stat(path, &st) == 0) {
        if (st.st_uid != getuid()) {
            fprintf(stderr, "Not owner of %s\n", path);
            return -1;
        }
    }
    /* Race window: attacker can replace file with symlink here */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    write(fd, data, strlen(data));
    close(fd);
    return 0;
}

int check_and_read(const char *path) {
    if (access(path, R_OK) != 0) {
        fprintf(stderr, "No read access to %s\n", path);
        return -1;
    }
    /* Race: permissions can change between access() and fopen() */
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[256];
    while (fgets(buf, sizeof(buf), f))
        printf("%s", buf);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    safe_write(argv[1], "secret data\n");
    check_and_read(argv[1]);
    return 0;
}
