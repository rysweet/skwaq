/* CWE-401: Memory Leak (linked list cleanup)
 * Partial cleanup of linked list nodes on error. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
    int value;
    char *label;
    struct node *next;
};

struct node *build_list(int count) {
    struct node *head = NULL;
    for (int i = 0; i < count; i++) {
        struct node *n = (struct node *)malloc(sizeof(struct node));
        if (!n) return head;  /* Leaks: caller gets partial list, may not free */

        n->label = (char *)malloc(64);
        if (!n->label) {
            free(n);
            return head;  /* Previous nodes leaked if caller doesn't walk list */
        }
        snprintf(n->label, 64, "item_%d", i);
        n->value = i;
        n->next = head;
        head = n;
    }
    return head;
}

void use_and_discard(int count) {
    struct node *list = build_list(count);
    if (!list) return;
    /* Only frees first node, leaks the rest */
    printf("First: %s\n", list->label);
    free(list->label);
    free(list);
}

int main(void) {
    use_and_discard(100);
    return 0;
}
