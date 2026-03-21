/*
 * CGC-style challenge: Format string write primitive
 * CWE-134: Use of Externally-Controlled Format String
 *
 * A logging service passes user-supplied text directly as the format
 * argument to printf.  An attacker can use %n to write to arbitrary
 * memory, or %x to leak stack contents.
 */
#include <stdio.h>
#include <string.h>

#define LOG_BUF 256

static int access_granted = 0;

static void log_event(const char *user_input) {
    char logbuf[LOG_BUF];
    snprintf(logbuf, sizeof(logbuf), "LOG: %s", user_input);

    /* VULN: logbuf contains attacker-controlled format specifiers.
       printf(logbuf) interprets %x, %n, etc. from user data.
       An attacker can use %n to overwrite access_granted. */
    printf(logbuf);
    printf("\n");
}

static void check_access(void) {
    if (access_granted) {
        printf("ACCESS GRANTED -- flag{fmt_str_win}\n");
    } else {
        printf("Access denied.\n");
    }
}

int main(void) {
    char input[LOG_BUF];

    printf("Enter log message: ");
    if (fgets(input, sizeof(input), stdin) == NULL)
        return 1;

    input[strcspn(input, "\n")] = '\0';

    log_event(input);
    check_access();
    return 0;
}
