#include <stdio.h>
#include <string.h>

void vulnerable_copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds check
    printf("Copied: %s\n", buffer);
}

int process_input(char *data) {
    char temp[32];
    sprintf(temp, "Processing: %s", data);  // Format + overflow
    return strlen(temp);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_copy(argv[1]);
        process_input(argv[1]);
    }
    return 0;
}
