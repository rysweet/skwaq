/*
 * CGC-style challenge: Stack buffer overflow with return address overwrite
 * CWE-121: Stack-based Buffer Overflow
 *
 * A service reads a "username" from stdin into a fixed-size stack buffer
 * without bounds checking, allowing overwrite of the saved return address.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USER_LEN 32

struct session {
    char username[MAX_USER_LEN];
    int  privilege_level;
};

static void grant_admin(void) {
    printf("ADMIN ACCESS GRANTED\n");
    exit(0);
}

static int authenticate(void) {
    struct session sess;
    char input[256];

    sess.privilege_level = 0;

    printf("Enter username: ");
    if (fgets(input, sizeof(input), stdin) == NULL)
        return -1;

    /* VULN: copies up to 256 bytes into a 32-byte buffer on the stack,
       overwriting privilege_level and the saved return address */
    strcpy(sess.username, input);

    if (sess.privilege_level == 0xdeadbeef)
        grant_admin();

    printf("Hello, %s (level %d)\n", sess.username, sess.privilege_level);
    return 0;
}

int main(void) {
    return authenticate();
}
