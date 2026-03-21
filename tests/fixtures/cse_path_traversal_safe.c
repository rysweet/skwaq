/* CWE-22 Safe Variant: Path Traversal (with sanitization)
 * Validates and canonicalizes path before use. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BASE_DIR "/var/www/uploads"

int serve_file(const char *filename) {
    /* Reject filenames containing ".." */
    if (strstr(filename, "..") != NULL) {
        fprintf(stderr, "Rejected: path traversal attempt\n");
        return -1;
    }
    /* Reject absolute paths */
    if (filename[0] == '/') {
        fprintf(stderr, "Rejected: absolute path\n");
        return -1;
    }

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/%s", BASE_DIR, filename);

    /* Canonicalize and verify prefix */
    char resolved[PATH_MAX];
    if (!realpath(filepath, resolved)) {
        perror("realpath");
        return -1;
    }
    if (strncmp(resolved, BASE_DIR, strlen(BASE_DIR)) != 0) {
        fprintf(stderr, "Rejected: outside base directory\n");
        return -1;
    }

    FILE *f = fopen(resolved, "r");
    if (!f) { perror("fopen"); return -1; }
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return serve_file(argv[1]);
}
