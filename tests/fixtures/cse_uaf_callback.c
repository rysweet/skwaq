/* CWE-416: Use After Free (callback/function pointer pattern)
 * Freed struct still used via stale callback pointer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*handler_fn)(const char *msg);

struct handler {
    char name[32];
    handler_fn callback;
};

void default_handler(const char *msg) {
    printf("[default] %s\n", msg);
}

struct handler *create_handler(const char *name) {
    struct handler *h = (struct handler *)malloc(sizeof(struct handler));
    if (!h) return NULL;
    strncpy(h->name, name, sizeof(h->name) - 1);
    h->name[sizeof(h->name) - 1] = '\0';
    h->callback = default_handler;
    return h;
}

int main(void) {
    struct handler *h = create_handler("primary");
    handler_fn saved_cb = h->callback;
    free(h);
    /* Use after free: calling through saved reference to freed struct's fn ptr */
    saved_cb("test message");
    /* Also: accessing freed memory */
    printf("Handler name: %s\n", h->name);
    return 0;
}
