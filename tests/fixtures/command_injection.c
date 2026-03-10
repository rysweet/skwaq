#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_command(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    system(cmd);  // Command injection
}

void safe_operation() {
    system("ls -la /tmp");  // Hardcoded - safe
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        run_command(argv[1]);
    }
    safe_operation();
    return 0;
}
