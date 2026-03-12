#include <stdio.h>
#include <string.h>

/* Safe: uses strncpy with bounds check */
void safe_copy(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Copied: %s\n", buffer);
}

/* Safe: uses snprintf with size limit */
int process_input(const char *data) {
    char temp[32];
    snprintf(temp, sizeof(temp), "Processing: %s", data);
    return (int)strlen(temp);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_copy(argv[1]);
        process_input(argv[1]);
    }
    return 0;
}
