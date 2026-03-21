/* CWE-476: NULL Pointer Dereference (error handling / cast pattern)
 * NULL check present but on wrong variable, or check bypassed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct request {
    char method[16];
    char *path;
    char *body;
};

struct request *parse_request(const char *raw) {
    if (!raw) return NULL;
    struct request *req = (struct request *)malloc(sizeof(struct request));
    if (!req) return NULL;

    req->path = NULL;
    req->body = NULL;

    const char *space = strchr(raw, ' ');
    if (!space) { free(req); return NULL; }

    size_t mlen = space - raw;
    if (mlen >= sizeof(req->method)) mlen = sizeof(req->method) - 1;
    memcpy(req->method, raw, mlen);
    req->method[mlen] = '\0';

    req->path = strdup(space + 1);
    return req;
}

void handle_request(const char *raw) {
    struct request *req = parse_request(raw);
    /* Checks req but then unconditionally dereferences req->body */
    if (req) {
        printf("Method: %s Path: %s\n", req->method, req->path);
        printf("Body length: %zu\n", strlen(req->body));  /* body is NULL */
        free(req->path);
        free(req);
    }
}

int main(int argc, char **argv) {
    handle_request(argc > 1 ? argv[1] : "GET /index.html");
    return 0;
}
