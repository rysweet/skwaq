#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void allocate_buffer(unsigned short size) {
    // Integer overflow: if size is close to USHRT_MAX,
    // size + 1 wraps to 0, allocating tiny buffer
    char *buf = malloc(size + 1);
    if (buf) {
        memset(buf, 'A', size);  // Writes 'size' bytes to tiny buffer
        buf[size] = '\0';
        printf("Allocated %d bytes\n", size);
        free(buf);
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        unsigned short size = (unsigned short)atoi(argv[1]);
        allocate_buffer(size);
    }
    return 0;
}
