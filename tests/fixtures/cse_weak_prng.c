/* CWE-338: Use of Cryptographically Weak PRNG
 * Uses rand() for security-sensitive token generation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *generate_session_token(void) {
    static char token[33];
    srand(time(NULL));  /* Weak seed */
    for (int i = 0; i < 32; i++) {
        int r = rand() % 62;  /* Weak PRNG */
        if (r < 26) token[i] = 'a' + r;
        else if (r < 52) token[i] = 'A' + (r - 26);
        else token[i] = '0' + (r - 52);
    }
    token[32] = '\0';
    return token;
}

int main(void) {
    printf("Session token: %s\n", generate_session_token());
    return 0;
}
