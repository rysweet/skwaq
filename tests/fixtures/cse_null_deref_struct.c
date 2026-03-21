/* CWE-476: NULL Pointer Dereference (struct field access pattern)
 * Dereferences struct pointer without NULL check after failed lookup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
    char name[64];
    int role;
    struct user *next;
};

static struct user *user_list = NULL;

struct user *find_user(const char *name) {
    struct user *cur = user_list;
    while (cur) {
        if (strcmp(cur->name, name) == 0) return cur;
        cur = cur->next;
    }
    return NULL;  /* Not found */
}

void print_user_role(const char *name) {
    struct user *u = find_user(name);
    /* Missing NULL check */
    printf("User %s has role %d\n", u->name, u->role);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    print_user_role(argv[1]);
    return 0;
}
