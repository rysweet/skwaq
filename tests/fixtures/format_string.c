#include <stdio.h>
#include <string.h>

void log_message(char *msg) {
    printf(msg);  // Format string vuln
}

void safe_log(char *msg) {
    printf("%s\n", msg);  // Safe
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        log_message(argv[1]);
        safe_log(argv[1]);
    }
    return 0;
}
