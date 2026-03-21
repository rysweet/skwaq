/* CWE-787: Out-of-bounds Write
 * Off-by-one and index-based OOB writes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 10

void fill_table(int *table, int count) {
    /* Off-by-one: writes one past the end */
    for (int i = 0; i <= count; i++) {
        table[i] = i * i;
    }
}

void set_entry(int *table, int index, int value) {
    /* No bounds check on index */
    table[index] = value;
}

int main(int argc, char **argv) {
    int table[MAX_ENTRIES];
    fill_table(table, MAX_ENTRIES);
    if (argc > 2) {
        int idx = atoi(argv[1]);
        int val = atoi(argv[2]);
        set_entry(table, idx, val);  /* Arbitrary OOB write */
    }
    for (int i = 0; i < MAX_ENTRIES; i++)
        printf("table[%d] = %d\n", i, table[i]);
    return 0;
}
