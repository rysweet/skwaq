/* CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * Constructs file path from user input without sanitizing ".." sequences. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "/var/www/uploads"

int serve_file(const char *filename) {
    char filepath[512];
    /* No validation of ".." in filename */
    snprintf(filepath, sizeof(filepath), "%s/%s", BASE_DIR, filename);

    FILE *f = fopen(filepath, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    return serve_file(argv[1]);
}
