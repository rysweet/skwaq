/* CWE-190: Integer Overflow or Wraparound (loop counter pattern)
 * Short integer used as loop counter overflows, causing infinite loop or OOB. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_chunks(const unsigned char *data, unsigned short total_len) {
    unsigned short offset = 0;
    while (offset < total_len) {
        unsigned short chunk_size = (data[offset] << 8) | data[offset + 1];
        /* chunk_size from attacker: offset + chunk_size can overflow unsigned short */
        offset += chunk_size + 2;
        printf("Processed chunk of size %u at offset %u\n", chunk_size, offset);
    }
}

int sum_array(const int *arr, int count) {
    int total = 0;  /* Can overflow with large values */
    for (int i = 0; i < count; i++) {
        total += arr[i];  /* No overflow check */
    }
    return total;
}

int main(void) {
    unsigned char data[] = {0x00, 0x04, 'A', 'B', 'C', 'D',
                            0xFF, 0xFE, 'X', 'Y'};
    process_chunks(data, sizeof(data));
    return 0;
}
