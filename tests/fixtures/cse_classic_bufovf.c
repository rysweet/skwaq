/* CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
 * Uses strcpy with no bounds checking. */
#include <stdio.h>
#include <string.h>

void process_username(const char *input) {
    char username[32];
    strcpy(username, input);  /* No bounds check */
    printf("Welcome, %s\n", username);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    process_username(argv[1]);
    return 0;
}
