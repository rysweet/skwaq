/* CWE-787 Safe Variant: Out-of-bounds Write (bounds-checked)
 * All array accesses validated against bounds. */
#include <stdio.h>
#include <stdlib.h>

#define MAX_ENTRIES 10

void fill_table(int *table, int count) {
    for (int i = 0; i < count; i++) {  /* Correct: i < count, not i <= count */
        table[i] = i * i;
    }
}

int set_entry(int *table, int size, int index, int value) {
    if (index < 0 || index >= size) {
        fprintf(stderr, "Index %d out of bounds [0, %d)\n", index, size);
        return -1;
    }
    table[index] = value;
    return 0;
}

int main(int argc, char **argv) {
    int table[MAX_ENTRIES];
    fill_table(table, MAX_ENTRIES);
    if (argc > 2) {
        int idx = atoi(argv[1]);
        int val = atoi(argv[2]);
        set_entry(table, MAX_ENTRIES, idx, val);
    }
    for (int i = 0; i < MAX_ENTRIES; i++)
        printf("table[%d] = %d\n", i, table[i]);
    return 0;
}
