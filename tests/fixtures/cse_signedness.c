/* CWE-195/CWE-681: Signed to Unsigned Conversion Error
 * Negative value interpreted as large unsigned, causing OOB access. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_data(char *dst, const char *src, int len) {
    /* If len is negative, memcpy sees it as huge unsigned size_t */
    if (len > 256) {
        printf("Too long\n");
        return;
    }
    memcpy(dst, src, len);  /* Negative len wraps to huge value */
}

int read_at_index(const int *array, int size, int index) {
    /* Negative index not caught by this check */
    if (index > size) return -1;
    return array[index];
}

int main(int argc, char **argv) {
    char dst[256];
    if (argc > 1) {
        int len = atoi(argv[1]);
        copy_data(dst, "source data", len);
    }
    int arr[] = {10, 20, 30, 40, 50};
    if (argc > 2) {
        int idx = atoi(argv[2]);
        printf("Value: %d\n", read_at_index(arr, 5, idx));
    }
    return 0;
}
