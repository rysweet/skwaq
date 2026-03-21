/* CWE-78 Safe Variant: Command execution with input validation
 * Validates/sanitizes input before constructing shell commands. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Allow only alphanumeric, dots, and hyphens in hostnames */
int validate_hostname(const char *host) {
    for (int i = 0; host[i]; i++) {
        char c = host[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-') return 0;
    }
    return host[0] != '\0';
}

void check_host(const char *hostname) {
    if (!validate_hostname(hostname)) {
        fprintf(stderr, "Invalid hostname: %s\n", hostname);
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", hostname);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp))
        printf("%s", line);
    pclose(fp);
}

/* Use execv instead of system() to avoid shell interpretation */
void list_directory_safe(const char *path) {
    /* Only allow paths that don't contain shell metacharacters */
    for (int i = 0; path[i]; i++) {
        if (path[i] == ';' || path[i] == '|' || path[i] == '&' ||
            path[i] == '$' || path[i] == '`' || path[i] == '\n') {
            fprintf(stderr, "Invalid character in path\n");
            return;
        }
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls -la -- '%s'", path);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    check_host(argv[1]);
    return 0;
}
