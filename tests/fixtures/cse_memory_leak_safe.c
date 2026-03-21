/* CWE-401 Safe Variant: Memory properly released on all paths
 * Uses goto-based cleanup pattern to avoid leaks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config {
    char *hostname;
    char *username;
    char *password;
    int port;
};

void free_config(struct config *cfg) {
    if (!cfg) return;
    free(cfg->hostname);
    free(cfg->username);
    free(cfg->password);
    free(cfg);
}

struct config *load_config(const char *path) {
    struct config *cfg = (struct config *)calloc(1, sizeof(struct config));
    if (!cfg) return NULL;

    cfg->hostname = (char *)malloc(256);
    if (!cfg->hostname) goto fail;

    cfg->username = (char *)malloc(128);
    if (!cfg->username) goto fail;

    cfg->password = (char *)malloc(128);
    if (!cfg->password) goto fail;

    FILE *f = fopen(path, "r");
    if (!f) goto fail;

    if (fscanf(f, "%255s %127s %127s %d",
               cfg->hostname, cfg->username, cfg->password, &cfg->port) != 4) {
        fclose(f);
        goto fail;
    }
    fclose(f);
    return cfg;

fail:
    free_config(cfg);
    return NULL;
}

int main(int argc, char **argv) {
    struct config *c = load_config(argc > 1 ? argv[1] : "config.txt");
    if (c) {
        printf("Host: %s Port: %d\n", c->hostname, c->port);
        free_config(c);
    }
    return 0;
}
