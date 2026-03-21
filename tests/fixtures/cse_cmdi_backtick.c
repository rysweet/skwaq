/* CWE-78: OS Command Injection (multi-vector pattern)
 * Several command injection vectors through different functions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dns_lookup(const char *domain) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nslookup %s 2>&1", domain);
    system(cmd);
}

void compress_file(const char *filename) {
    char cmd[512];
    /* Injection via filename containing shell metacharacters */
    snprintf(cmd, sizeof(cmd), "gzip -c '%s' > '%s.gz'", filename, filename);
    system(cmd);  /* Single quotes insufficient: filename can contain ' */
}

void check_url(const char *url) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "curl -sI %s", url);
    FILE *p = popen(cmd, "r");
    if (p) {
        char line[256];
        while (fgets(line, sizeof(line), p))
            printf("%s", line);
        pclose(p);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    dns_lookup(argv[1]);
    if (argc > 2) compress_file(argv[2]);
    return 0;
}
