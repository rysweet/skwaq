/* CWE-338 Safe Variant: Cryptographically secure random
 * Uses /dev/urandom for security-sensitive random generation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int secure_random_bytes(unsigned char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

char *generate_session_token(void) {
    static char token[33];
    unsigned char raw[16];
    if (secure_random_bytes(raw, sizeof(raw)) != 0) return NULL;
    for (int i = 0; i < 16; i++) {
        snprintf(&token[i * 2], 3, "%02x", raw[i]);
    }
    return token;
}

unsigned int generate_nonce(void) {
    unsigned int nonce;
    if (secure_random_bytes((unsigned char *)&nonce, sizeof(nonce)) != 0)
        return 0;
    return nonce;
}

int main(void) {
    char *tok = generate_session_token();
    if (tok) printf("Token: %s\n", tok);
    printf("Nonce: %u\n", generate_nonce());
    return 0;
}
