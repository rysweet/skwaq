#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-122: Heap-based buffer overflow */
char* process_message(const char *input) {
    /* Allocate fixed size but copy unbounded input */
    char *buf = malloc(64);
    strcpy(buf, input);  /* Heap overflow if input > 64 bytes */
    return buf;
}

/* CWE-122: Off-by-one heap overflow */
char* duplicate_string(const char *s) {
    size_t len = strlen(s);
    char *copy = malloc(len);  /* Off-by-one: should be len + 1 for NUL */
    memcpy(copy, s, len + 1); /* Writes one byte past allocation */
    return copy;
}

/* CWE-122: Integer-controlled allocation */
void process_records(int count, const char *data) {
    /* count could be attacker-controlled */
    char *buf = malloc(count * sizeof(int));  /* Integer overflow in size calc */
    memcpy(buf, data, count * sizeof(int));   /* Heap overflow */
    free(buf);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        char *msg = process_message(argv[1]);
        printf("Message: %s\n", msg);
        free(msg);

        char *dup = duplicate_string(argv[1]);
        printf("Duplicate: %s\n", dup);
        free(dup);
    }
    return 0;
}
