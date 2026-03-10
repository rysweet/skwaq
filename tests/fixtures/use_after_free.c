#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record {
    char name[64];
    int value;
};

struct record* create_record(const char *name, int value) {
    struct record *r = malloc(sizeof(struct record));
    strncpy(r->name, name, 63);
    r->value = value;
    return r;
}

void process_and_free(struct record *r) {
    printf("Processing: %s = %d\n", r->name, r->value);
    free(r);
}

int main() {
    struct record *r = create_record("test", 42);
    process_and_free(r);
    printf("After free: %s\n", r->name);  // Use after free
    return 0;
}
