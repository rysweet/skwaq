/* CWE-416: Use After Free (linked list removal)
 * Accesses node data after freeing during list traversal. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct item {
    int id;
    char name[32];
    struct item *next;
};

static struct item *head = NULL;

void add_item(int id, const char *name) {
    struct item *n = (struct item *)malloc(sizeof(struct item));
    if (!n) return;
    n->id = id;
    strncpy(n->name, name, sizeof(n->name) - 1);
    n->name[sizeof(n->name) - 1] = '\0';
    n->next = head;
    head = n;
}

void remove_all_matching(int target_id) {
    struct item *cur = head;
    struct item *prev = NULL;
    while (cur) {
        if (cur->id == target_id) {
            if (prev) prev->next = cur->next;
            else head = cur->next;
            free(cur);
            /* Bug: continues to use cur->next after free */
            cur = cur->next;
        } else {
            prev = cur;
            cur = cur->next;
        }
    }
}

int main(void) {
    add_item(1, "alpha");
    add_item(2, "bravo");
    add_item(1, "charlie");
    add_item(3, "delta");
    remove_all_matching(1);
    struct item *c = head;
    while (c) { printf("%d: %s\n", c->id, c->name); c = c->next; }
    return 0;
}
