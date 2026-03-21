/* CWE-134: Use of Externally-Controlled Format String (logging pattern)
 * User input passed directly as format string to logging functions. */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void log_message(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[LOG] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void handle_request(const char *user_agent) {
    char msg[512];
    snprintf(msg, sizeof(msg), "Request from: %s", user_agent);
    /* User-controlled string used as format string */
    printf(msg);
    printf("\n");
}

void audit_log(const char *action) {
    /* Direct use of user input as format string */
    fprintf(stderr, action);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    handle_request(argv[1]);
    audit_log(argv[1]);
    return 0;
}
