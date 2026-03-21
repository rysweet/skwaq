/* CWE-338: Weak PRNG (predictable seed pattern)
 * Uses PID and time as seed, making output predictable. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void generate_otp(char *otp, int len) {
    /* Predictable seed: pid + time */
    srand(getpid() ^ time(NULL));
    for (int i = 0; i < len; i++) {
        otp[i] = '0' + (rand() % 10);
    }
    otp[len] = '\0';
}

unsigned int generate_nonce(void) {
    srand(time(NULL));
    return (unsigned int)rand();
}

int main(void) {
    char otp[7];
    generate_otp(otp, 6);
    printf("OTP: %s\n", otp);
    printf("Nonce: %u\n", generate_nonce());
    return 0;
}
