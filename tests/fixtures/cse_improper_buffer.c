/* CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
 * Reads and writes beyond buffer boundaries in parsing logic. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 8

struct packet {
    unsigned char header[HEADER_SIZE];
    unsigned char payload[256];
};

int parse_packet(const unsigned char *raw, size_t raw_len) {
    struct packet pkt;
    /* Copies raw_len bytes without checking against struct size */
    memcpy(&pkt, raw, raw_len);  /* OOB if raw_len > sizeof(pkt) */

    unsigned int payload_len = (pkt.header[4] << 8) | pkt.header[5];
    /* Uses attacker-controlled payload_len for further copy */
    char output[128];
    memcpy(output, pkt.payload, payload_len);  /* OOB write */
    output[payload_len] = '\0';
    printf("Payload: %s\n", output);
    return 0;
}

int main(void) {
    unsigned char data[512];
    size_t n = fread(data, 1, sizeof(data), stdin);
    if (n > 0) parse_packet(data, n);
    return 0;
}
