/* CWE-119: Improper Restriction of Operations within Bounds of a Memory Buffer
 * Uses variable-length array with unchecked size. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_message(const char *data, int claimed_len) {
    /* VLA with attacker-controlled size: can cause stack overflow */
    char buf[claimed_len];
    memcpy(buf, data, claimed_len);  /* May read OOB from data too */
    buf[claimed_len - 1] = '\0';
    printf("Message: %s\n", buf);
}

void decode_payload(const unsigned char *raw, size_t raw_len) {
    if (raw_len < 4) return;
    unsigned int out_len = *(unsigned int *)raw;
    /* out_len is attacker-controlled, used to size buffer */
    char *output = (char *)alloca(out_len);
    memcpy(output, raw + 4, raw_len - 4);
    printf("Decoded %u bytes\n", out_len);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process_message(argv[1], atoi(argv[1]));
    return 0;
}
