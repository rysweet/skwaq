#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Safe: validates input before use, no shell execution */
int safe_operation(const char *input) {
    /* Validate: only alphanumeric characters allowed */
    for (const char *p = input; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '-') {
            fprintf(stderr, "Invalid character in input\n");
            return -1;
        }
    }
    printf("Processing: %s\n", input);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_operation(argv[1]);
    }
    return 0;
}
