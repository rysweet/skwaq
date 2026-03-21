/* CWE-134: Format String via snprintf/syslog-like patterns
 * User-controlled input used as format string in snprintf chain. */
#include <stdio.h>
#include <string.h>

void error_handler(const char *user_msg) {
    char buf[512];
    /* First snprintf is safe, embeds user_msg as data */
    snprintf(buf, sizeof(buf), "Error from user: %s", user_msg);
    /* But then buf (containing user data) used as format string */
    char final[1024];
    snprintf(final, sizeof(final), buf);
    printf("%s\n", final);
}

void log_with_prefix(const char *prefix, const char *message) {
    char logline[512];
    snprintf(logline, sizeof(logline), "%s: %s", prefix, message);
    /* logline used as format */
    fprintf(stderr, logline);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    error_handler(argv[1]);
    if (argc > 2) log_with_prefix(argv[1], argv[2]);
    return 0;
}
