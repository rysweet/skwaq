/* CWE-22: Path Traversal (symlink following pattern)
 * Opens files via user-controlled path that may be a symlink. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UPLOAD_DIR "/var/uploads"

int save_upload(const char *filename, const char *content) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", UPLOAD_DIR, filename);

    /* No symlink check, no canonicalization */
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(content, f);
    fclose(f);
    return 0;
}

int read_config(const char *name) {
    char path[256];
    /* Allows directory traversal and symlink following */
    snprintf(path, sizeof(path), "/etc/myapp/%s.conf", name);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f))
        printf("%s", line);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    save_upload(argv[1], argv[2]);
    return 0;
}
