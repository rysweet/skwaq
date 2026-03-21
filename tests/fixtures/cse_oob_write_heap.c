/* CWE-787: Out-of-bounds Write (heap buffer pattern)
 * Writes past end of heap-allocated buffer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *duplicate_and_append(const char *str, const char *suffix) {
    /* Allocates only enough for str, not str + suffix */
    char *result = (char *)malloc(strlen(str) + 1);
    if (!result) return NULL;
    strcpy(result, str);
    strcat(result, suffix);  /* Heap buffer overflow */
    return result;
}

void fill_buffer(int *buf, int alloc_count, int fill_count) {
    /* fill_count can exceed alloc_count */
    for (int i = 0; i < fill_count; i++) {
        buf[i] = i + 1;  /* OOB write when fill_count > alloc_count */
    }
}

int main(int argc, char **argv) {
    char *s = duplicate_and_append("hello", "_world_extended_suffix");
    if (s) {
        printf("%s\n", s);
        free(s);
    }
    int *arr = (int *)malloc(5 * sizeof(int));
    if (arr) {
        fill_buffer(arr, 5, 10);
        free(arr);
    }
    return 0;
}
