/* CWE-134: Use of Externally-Controlled Format String (syslog-style)
 * Simulated syslog call with user-controlled format. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void my_syslog(int priority, const char *fmt, ...) {
    (void)priority;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void log_login_attempt(const char *username) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Login attempt by: %s", username);
    /* buf may contain format specifiers from username */
    my_syslog(3, buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_login_attempt(argv[1]);
    return 0;
}
