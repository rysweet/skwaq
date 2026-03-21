/*
 * CGC-style challenge: Dangling pointer dereference
 * CWE-825: Expired Pointer Dereference
 *
 * A session manager caches a pointer to a user object.  After the
 * object is freed and the slot is reallocated with attacker-controlled
 * data, the stale cached pointer dereferences the new contents.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
    char name[32];
    int  role;          /* 0 = guest, 1 = admin */
    void (*greet)(struct user *);
};

static void greet_user(struct user *u) {
    printf("Hello, %s (role=%d)\n", u->name, u->role);
}

static struct user *create_user(const char *name) {
    struct user *u = malloc(sizeof(*u));
    if (!u) return NULL;
    strncpy(u->name, name, sizeof(u->name) - 1);
    u->name[sizeof(u->name) - 1] = '\0';
    u->role = 0;
    u->greet = greet_user;
    return u;
}

int main(void) {
    struct user *cached_ptr;
    char payload[sizeof(struct user)];

    /* Create and cache a pointer to the user */
    struct user *alice = create_user("alice");
    cached_ptr = alice;

    /* Free the user -- cached_ptr is now dangling */
    free(alice);
    alice = NULL;

    /* Reallocate the same region with attacker-controlled data.
       On most allocators, malloc returns the just-freed chunk. */
    char *evil = malloc(sizeof(struct user));
    memset(evil, 0, sizeof(struct user));
    printf("Enter payload: ");
    fgets(evil, sizeof(struct user), stdin);

    /* VULN: cached_ptr still points to the freed (now-reallocated) memory.
       The attacker controls the function pointer and role field. */
    cached_ptr->greet(cached_ptr);

    free(evil);
    return 0;
}
