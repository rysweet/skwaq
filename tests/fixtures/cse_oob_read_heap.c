/* CWE-125: Out-of-bounds Read (heap buffer pattern)
 * Reads beyond allocated heap buffer via incorrect length. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x ", buf[i]);
    printf("\n");
}

int leak_data(const char *input) {
    size_t input_len = strlen(input);
    char *buf = (char *)malloc(input_len + 1);
    if (!buf) return -1;
    strcpy(buf, input);

    /* Reads 64 bytes regardless of actual allocation size */
    print_hex((unsigned char *)buf, 64);  /* OOB read if input < 63 chars */

    free(buf);
    return 0;
}

char *get_field(const char *data, int field_index, int field_size) {
    /* No check: field_index * field_size may exceed data allocation */
    return (char *)&data[field_index * field_size];
}

int main(int argc, char **argv) {
    leak_data(argc > 1 ? argv[1] : "short");
    return 0;
}
