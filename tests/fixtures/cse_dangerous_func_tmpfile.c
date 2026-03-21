/* CWE-676: Use of Potentially Dangerous Function (temp file pattern)
 * Uses mktemp, tmpnam, and other insecure temp file functions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *create_temp_file(void) {
    char template[] = "/tmp/myapp_XXXXXX";
    /* mktemp is dangerous: race between name generation and file creation */
    char *name = mktemp(template);
    FILE *f = fopen(name, "w");
    if (f) {
        fputs("temp data\n", f);
        fclose(f);
    }
    return strdup(name);
}

void write_temp_data(const char *data) {
    char path[256];
    /* tmpnam is dangerous: predictable names, race conditions */
    tmpnam(path);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(data, f);
    fclose(f);
    printf("Written to %s\n", path);
}

int main(int argc, char **argv) {
    char *tmp = create_temp_file();
    if (tmp) {
        printf("Temp file: %s\n", tmp);
        free(tmp);
    }
    write_temp_data(argc > 1 ? argv[1] : "default");
    return 0;
}
