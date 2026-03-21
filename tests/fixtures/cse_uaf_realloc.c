/* CWE-416: Use After Free (realloc pattern)
 * Uses old pointer after realloc which may have moved the allocation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct entry {
    int id;
    char data[64];
};

int main(void) {
    size_t capacity = 2;
    struct entry *list = (struct entry *)malloc(capacity * sizeof(struct entry));
    if (!list) return 1;

    list[0].id = 1;
    strcpy(list[0].data, "first");

    struct entry *first = &list[0];  /* Save pointer into old allocation */

    /* Realloc may move the block, invalidating 'first' */
    capacity = 1000;
    list = (struct entry *)realloc(list, capacity * sizeof(struct entry));

    /* Use after free: 'first' may point to freed memory */
    printf("First entry: %d %s\n", first->id, first->data);

    free(list);
    return 0;
}
