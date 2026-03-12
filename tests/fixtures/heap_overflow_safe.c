#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Safe: bounds-checked heap copy */
char* process_message(const char *input, size_t max_len) {
    size_t len = strlen(input);
    if (len >= max_len) len = max_len - 1;
    char *buf = malloc(max_len);
    if (!buf) return NULL;
    memcpy(buf, input, len);
    buf[len] = '\0';
    return buf;
}

/* Safe: correct allocation with NUL terminator */
char* duplicate_string(const char *s) {
    size_t len = strlen(s);
    char *copy = malloc(len + 1);  /* Correct: includes NUL byte */
    if (!copy) return NULL;
    memcpy(copy, s, len + 1);
    return copy;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        char *msg = process_message(argv[1], 64);
        if (msg) {
            printf("Message: %s\n", msg);
            free(msg);
        }
        char *dup = duplicate_string(argv[1]);
        if (dup) {
            printf("Duplicate: %s\n", dup);
            free(dup);
        }
    }
    return 0;
}
