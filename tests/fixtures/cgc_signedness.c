/*
 * CGC-style challenge: Signedness comparison error
 * CWE-195: Signed to Unsigned Conversion Error
 *
 * A packet parser reads a user-supplied "length" field as a signed int.
 * The bounds check passes for negative values, but when the length is
 * later used as an unsigned size_t in memcpy, it becomes enormous.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 256

struct packet {
    int  length;     /* signed -- attacker-controlled */
    char payload[MAX_PAYLOAD];
};

static int receive_packet(struct packet *pkt) {
    printf("Payload length: ");
    scanf("%d", &pkt->length);

    /* VULN: signed comparison -- a negative length passes this check */
    if (pkt->length > MAX_PAYLOAD) {
        printf("Payload too large\n");
        return -1;
    }

    printf("Payload data: ");
    getchar();
    fgets(pkt->payload, MAX_PAYLOAD, stdin);
    return 0;
}

static void process_packet(struct packet *pkt) {
    char output[MAX_PAYLOAD];

    /* VULN: pkt->length is implicitly converted to size_t (unsigned).
       A negative value like -1 becomes SIZE_MAX, causing massive overread
       or overflow in the destination buffer. */
    memcpy(output, pkt->payload, (size_t)pkt->length);
    output[MAX_PAYLOAD - 1] = '\0';
    printf("Processed: %s\n", output);
}

int main(void) {
    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (receive_packet(&pkt) == 0)
        process_packet(&pkt);
    return 0;
}
