/* CWE-125: Out-of-bounds Read
 * Reads past buffer end via user-controlled index. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_SLOTS 8

static const char *slots[NUM_SLOTS] = {
    "alpha", "bravo", "charlie", "delta",
    "echo", "foxtrot", "golf", "hotel"
};

const char *get_slot(int index) {
    /* No bounds check: index can be negative or >= NUM_SLOTS */
    return slots[index];
}

void read_past_end(const char *data, size_t data_len) {
    /* Reads 16 bytes regardless of actual data length */
    char buf[16];
    for (int i = 0; i < 16; i++) {
        buf[i] = data[i];  /* OOB if data_len < 16 */
    }
    buf[15] = '\0';
    printf("Read: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int idx = atoi(argv[1]);
    printf("Slot: %s\n", get_slot(idx));
    read_past_end("short", 5);
    return 0;
}
