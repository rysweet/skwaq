#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

/* CWE-122: Heap overflow — fixed-size allocation, unbounded copy */
char* parse_input(const char *raw_input) {
    char *buf = malloc(128);
    if (!buf) return NULL;
    strcpy(buf, raw_input);  /* Heap overflow if raw_input > 128 bytes */
    return buf;
}

/* CWE-190: Integer overflow in length calculation */
int get_parsed_length(const char *parsed) {
    int len = (int)strlen(parsed);
    return len + 1;  /* Could overflow on very long strings */
}
