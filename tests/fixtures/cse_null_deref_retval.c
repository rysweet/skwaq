/* CWE-476: NULL Pointer Dereference (unchecked return value)
 * Uses malloc/fopen return without NULL check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_file(const char *path) {
    FILE *f = fopen(path, "r");
    /* Missing NULL check on fopen */
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }
    fclose(f);
}

void copy_data(size_t size) {
    char *buf = (char *)malloc(size);
    /* Missing NULL check on malloc */
    memset(buf, 0, size);
    strcpy(buf, "initialized");
    printf("Data: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) process_file(argv[1]);
    copy_data(1024);
    return 0;
}
