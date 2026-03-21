/* CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 * Uses weak/broken algorithms (XOR, custom hash, hardcoded key). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Weak XOR "encryption" */
void xor_encrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= key;
}

/* Weak custom hash */
unsigned int weak_hash(const char *str) {
    unsigned int h = 0;
    while (*str) {
        h = h * 31 + (unsigned char)*str++;
    }
    return h;
}

/* Hardcoded encryption key */
static const char *SECRET_KEY = "SuperSecretKey123";

void encrypt_password(const char *password, char *output) {
    size_t klen = strlen(SECRET_KEY);
    size_t plen = strlen(password);
    for (size_t i = 0; i < plen; i++)
        output[i] = password[i] ^ SECRET_KEY[i % klen];
    output[plen] = '\0';
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char encrypted[256];
    encrypt_password(argv[1], encrypted);
    printf("Hash: %u\n", weak_hash(argv[1]));
    return 0;
}
