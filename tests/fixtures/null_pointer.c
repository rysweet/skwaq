#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config {
    char *host;
    int port;
};

struct config* load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    struct config *cfg = malloc(sizeof(struct config));
    cfg->host = malloc(256);
    fscanf(f, "%255s %d", cfg->host, &cfg->port);
    fclose(f);
    return cfg;
}

void connect_to_server(struct config *cfg) {
    /* CWE-476: cfg may be NULL if load_config failed */
    printf("Connecting to %s:%d\n", cfg->host, cfg->port);
}

int get_length(const char *s) {
    /* CWE-476: s may be NULL */
    return strlen(s);
}

int main(int argc, char *argv[]) {
    const char *path = argc > 1 ? argv[1] : "nonexistent.conf";
    struct config *cfg = load_config(path);
    connect_to_server(cfg);  /* NULL dereference if file doesn't exist */

    char *p = NULL;
    if (argc > 2) {
        p = argv[2];
    }
    printf("Length: %d\n", get_length(p));  /* NULL dereference */

    return 0;
}
