/*
 * CGC-style challenge: Use of uninitialized stack variable
 * CWE-457: Use of Uninitialized Variable
 *
 * An authentication routine reads credentials but only initialises the
 * "authenticated" flag on the success path.  On failure the flag retains
 * whatever value was previously on the stack, which an attacker can
 * influence via prior function calls.
 */
#include <stdio.h>
#include <string.h>

#define SECRET_PIN 1337

struct auth_ctx {
    int  user_id;
    int  authenticated;   /* never zeroed on failure path */
    char username[32];
};

static void spray_stack(void) {
    /* Attacker-controlled data left on the stack from a prior call frame.
       The value 1 at the right offset can satisfy the auth check. */
    volatile char buf[128];
    memset((char *)buf, 1, sizeof(buf));
}

static int do_login(void) {
    struct auth_ctx ctx;
    int pin;

    /* VULN: ctx.authenticated is NOT initialised here */

    printf("Username: ");
    if (!fgets(ctx.username, sizeof(ctx.username), stdin))
        return -1;

    printf("PIN: ");
    scanf("%d", &pin);

    if (pin == SECRET_PIN) {
        ctx.authenticated = 1;
        ctx.user_id = 0;
    }
    /* Missing: else { ctx.authenticated = 0; } */

    if (ctx.authenticated) {
        printf("Welcome, %s\n", ctx.username);
        return 0;
    }
    printf("Access denied\n");
    return -1;
}

int main(void) {
    spray_stack();
    return do_login();
}
