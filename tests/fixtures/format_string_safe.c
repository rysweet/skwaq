#include <stdio.h>
#include <string.h>

/* Safe: uses format specifier, not raw user string */
void safe_log(const char *msg) {
    printf("%s\n", msg);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_log(argv[1]);
    }
    return 0;
}
