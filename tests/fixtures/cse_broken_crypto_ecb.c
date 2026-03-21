/* CWE-327: Broken Cryptographic Algorithm (ECB mode / weak cipher)
 * Implements ECB-like encryption that preserves patterns. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple substitution cipher - trivially breakable */
void substitution_encrypt(const unsigned char *plain, unsigned char *cipher,
                          size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        cipher[i] = (plain[i] + key) % 256;  /* Caesar cipher on bytes */
    }
}

/* ECB-like: each block encrypted independently, patterns preserved */
void ecb_encrypt(const unsigned char *data, unsigned char *out,
                 size_t len, const unsigned char *key, size_t klen) {
    for (size_t i = 0; i < len; i++) {
        out[i] = data[i] ^ key[i % klen];
    }
}

/* MD5-strength custom hash */
unsigned long weak_digest(const unsigned char *data, size_t len) {
    unsigned long h = 5381;
    for (size_t i = 0; i < len; i++)
        h = ((h << 5) + h) + data[i];
    return h;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    unsigned char out[256];
    size_t len = strlen(argv[1]);
    if (len > 255) len = 255;
    ecb_encrypt((unsigned char *)argv[1], out, len, (unsigned char *)"key", 3);
    printf("Digest: %lu\n", weak_digest((unsigned char *)argv[1], len));
    return 0;
}
