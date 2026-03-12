#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record {
    char name[64];
    int value;
};

struct record* create_record(const char *name, int value) {
    struct record *r = malloc(sizeof(struct record));
    if (!r) return NULL;
    strncpy(r->name, name, sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
    r->value = value;
    return r;
}

void process_and_free(struct record *r) {
    if (!r) return;
    printf("Processing: %s = %d\n", r->name, r->value);
    free(r);
}

int main() {
    struct record *r = create_record("test", 42);
    process_and_free(r);
    /* Safe: no access after free, pointer set to NULL */
    r = NULL;
    return 0;
}
