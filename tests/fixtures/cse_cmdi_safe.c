/* CWE-78 Safe Variant: Avoids shell execution entirely.
 * Uses direct process spawning via fork/exec. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>

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
    /* Safe: direct exec avoids shell interpretation */
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-c", "1", hostname, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

/* Safe: direct exec avoids shell interpretation */
void list_directory_safe(const char *path) {
    /* Validate path contains no control characters */
    for (int i = 0; path[i]; i++) {
        if ((unsigned char)path[i] < 0x20) {
            fprintf(stderr, "Invalid character in path\n");
            return;
        }
    }
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ls", "ls", "-la", "--", path, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    check_host(argv[1]);
    return 0;
}
