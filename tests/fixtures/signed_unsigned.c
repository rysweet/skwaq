#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-195: Signed to unsigned conversion error */
void copy_data(int length, const char *src) {
    if (length > 1024) {
        printf("Too long\n");
        return;
    }
    /* If length is negative, this check passes but (size_t)length wraps to huge value */
    char *buf = malloc((size_t)length);
    memcpy(buf, src, (size_t)length);  /* Massive heap overflow with negative length */
    free(buf);
}

/* CWE-197: Integer truncation */
void allocate_buffer(unsigned long requested_size) {
    /* Truncation: on 32-bit, unsigned short can't hold large values */
    unsigned short actual_size = (unsigned short)requested_size;
    char *buf = malloc(actual_size);
    if (buf) {
        /* requested_size might be 0x10000 but actual_size is 0 */
        memset(buf, 'A', requested_size);  /* Heap overflow */
        free(buf);
    }
}

/* CWE-681: Integer-to-integer conversion with data loss */
int parse_count(const char *s) {
    long val = atol(s);
    /* Unchecked narrowing: val could exceed INT_MAX */
    int count = (int)val;
    return count;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        int len = atoi(argv[1]);
        copy_data(len, "AAAAAAAAAAAAAAAAAAAAAAAA");

        unsigned long big = 0x10000;
        allocate_buffer(big);

        int count = parse_count(argv[1]);
        printf("Count: %d\n", count);
    }
    return 0;
}
