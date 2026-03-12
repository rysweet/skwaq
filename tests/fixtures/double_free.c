#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
    char *data;
    struct node *next;
};

struct node* create_node(const char *data) {
    struct node *n = malloc(sizeof(struct node));
    n->data = strdup(data);
    n->next = NULL;
    return n;
}

void destroy_node(struct node *n) {
    free(n->data);
    free(n);
}

void cleanup_list(struct node *head) {
    struct node *current = head;
    while (current) {
        struct node *next = current->next;
        destroy_node(current);
        current = next;
    }
}

int main() {
    struct node *a = create_node("first");
    struct node *b = create_node("second");
    a->next = b;

    /* CWE-415: destroy b separately, then cleanup_list frees it again */
    destroy_node(b);
    cleanup_list(a);  /* Double-free: a->next (b) already freed */

    /* CWE-415: explicit double free */
    char *buf = malloc(128);
    strcpy(buf, "hello");
    free(buf);
    free(buf);  /* Double-free */

    return 0;
}
