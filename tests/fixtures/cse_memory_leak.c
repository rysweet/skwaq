/* CWE-401: Missing Release of Memory after Effective Lifetime
 * Memory allocated but never freed on error paths. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config {
    char *hostname;
    char *username;
    char *password;
    int port;
};

struct config *load_config(const char *path) {
    struct config *cfg = (struct config *)malloc(sizeof(struct config));
    if (!cfg) return NULL;

    cfg->hostname = (char *)malloc(256);
    if (!cfg->hostname) return NULL;  /* Leaks cfg */

    cfg->username = (char *)malloc(128);
    if (!cfg->username) return NULL;  /* Leaks cfg and hostname */

    cfg->password = (char *)malloc(128);
    if (!cfg->password) return NULL;  /* Leaks cfg, hostname, username */

    FILE *f = fopen(path, "r");
    if (!f) return NULL;  /* Leaks all allocated memory */

    fscanf(f, "%255s %127s %127s %d",
           cfg->hostname, cfg->username, cfg->password, &cfg->port);
    fclose(f);
    return cfg;
}

int main(int argc, char **argv) {
    struct config *c = load_config(argc > 1 ? argv[1] : "config.txt");
    if (c) {
        printf("Host: %s Port: %d\n", c->hostname, c->port);
        /* Only frees outer struct, not inner strings */
        free(c);
    }
    return 0;
}
