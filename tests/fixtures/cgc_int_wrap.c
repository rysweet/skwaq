/*
 * CGC-style challenge: Integer wraparound leading to small allocation
 * CWE-190: Integer Overflow or Wraparound
 * CWE-680: Integer Overflow to Buffer Overflow
 *
 * A data importer reads a count of records and multiplies by the record
 * size to compute the allocation.  A large count wraps the 32-bit
 * multiplication to a small value, and the subsequent copy overflows.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define RECORD_SIZE 64

struct record {
    char data[RECORD_SIZE];
};

static struct record *import_records(unsigned int count) {
    /* VULN: if count is large (e.g., 0x04000001), then
       count * sizeof(struct record) wraps around 32-bit arithmetic
       to a small value, causing a tiny allocation */
    uint32_t total = count * (uint32_t)sizeof(struct record);

    struct record *buf = malloc(total);
    if (!buf) {
        printf("Allocation failed\n");
        return NULL;
    }

    printf("Allocated %u bytes for %u records\n", total, count);

    /* Copy count * RECORD_SIZE bytes into the undersized buffer */
    for (unsigned int i = 0; i < count && i < 16; i++) {
        printf("Enter record %u: ", i);
        if (!fgets(buf[i].data, RECORD_SIZE, stdin))
            break;
    }

    return buf;
}

int main(void) {
    unsigned int n;
    printf("Number of records: ");
    scanf("%u", &n);
    getchar();

    struct record *records = import_records(n);
    if (records) {
        printf("Import complete (%u records)\n", n);
        free(records);
    }
    return 0;
}
