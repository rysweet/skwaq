/* CWE-680: Integer Overflow to Buffer Overflow
 * Multiplied size overflows, leading to undersized allocation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record {
    char name[64];
    int value;
};

struct record *allocate_records(unsigned int count) {
    /* Integer overflow: count * sizeof(struct record) can wrap around */
    size_t total = count * sizeof(struct record);
    struct record *records = (struct record *)malloc(total);
    if (!records) return NULL;
    memset(records, 0, total);
    return records;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    unsigned int n = (unsigned int)atoi(argv[1]);
    struct record *recs = allocate_records(n);
    if (recs) {
        for (unsigned int i = 0; i < n && i < 10; i++) {
            snprintf(recs[i].name, sizeof(recs[i].name), "record_%u", i);
            recs[i].value = (int)i;
        }
        free(recs);
    }
    return 0;
}
