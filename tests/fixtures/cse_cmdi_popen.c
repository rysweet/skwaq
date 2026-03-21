/* CWE-78: OS Command Injection (popen pattern)
 * Constructs shell command from user input without sanitization. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void check_host(const char *hostname) {
    char cmd[256];
    /* User input directly in shell command */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", hostname);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp))
        printf("%s", line);
    pclose(fp);
}

void list_directory(const char *path) {
    char cmd[512];
    sprintf(cmd, "ls -la %s", path);  /* Injection via path */
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    check_host(argv[1]);
    return 0;
}
