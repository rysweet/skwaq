/* CWE-121: Stack-based Buffer Overflow
 * Local buffer overflowed via unbounded read/copy. */
#include <stdio.h>
#include <string.h>

void process_input(void) {
    char buffer[64];
    char overflow_target[16] = "SAFE";

    printf("Enter data: ");
    /* reads unlimited input into 64-byte buffer */
    scanf("%s", buffer);

    printf("Buffer: %s\n", buffer);
    printf("Target: %s\n", overflow_target);
}

void copy_argv(const char *arg) {
    char local[32];
    /* Unbounded copy from command line */
    strcpy(local, arg);
    printf("Copied: %s\n", local);
}

int main(int argc, char **argv) {
    if (argc > 1)
        copy_argv(argv[1]);
    else
        process_input();
    return 0;
}
