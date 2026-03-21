/* CWE-843: Type Confusion
 * Interprets data as wrong type through void pointer misuse. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum obj_type { TYPE_INT, TYPE_STRING, TYPE_FLOAT };

struct object {
    enum obj_type type;
    void *data;
};

struct object *create_int(int val) {
    struct object *o = (struct object *)malloc(sizeof(struct object));
    if (!o) return NULL;
    o->type = TYPE_INT;
    o->data = malloc(sizeof(int));
    *(int *)o->data = val;
    return o;
}

struct object *create_string(const char *val) {
    struct object *o = (struct object *)malloc(sizeof(struct object));
    if (!o) return NULL;
    o->type = TYPE_STRING;
    o->data = strdup(val);
    return o;
}

void print_as_string(struct object *o) {
    /* Assumes string type without checking, causes type confusion */
    printf("Value: %s\n", (char *)o->data);
}

int get_as_int(struct object *o) {
    /* Assumes int type without checking */
    return *(int *)o->data;
}

int main(void) {
    struct object *num = create_int(42);
    struct object *str = create_string("hello");
    /* Type confusion: treating int as string */
    print_as_string(num);
    /* Type confusion: treating string as int */
    printf("Int value: %d\n", get_as_int(str));
    free(num->data); free(num);
    free(str->data); free(str);
    return 0;
}
