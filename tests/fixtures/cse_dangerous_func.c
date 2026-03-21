/* CWE-676: Use of Potentially Dangerous Function
 * Uses gets(), sprintf(), strcat() and other banned functions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_input(void) {
    char buf[128];
    printf("Enter command: ");
    gets(buf);  /* Dangerous: no bounds check */
    printf("Got: %s\n", buf);
}

void build_path(const char *dir, const char *file) {
    char path[256];
    strcpy(path, dir);     /* Dangerous if dir > 256 */
    strcat(path, "/");     /* Dangerous: no bounds check */
    strcat(path, file);    /* Dangerous: can overflow */
    printf("Path: %s\n", path);
}

void format_message(const char *user, const char *msg) {
    char output[256];
    sprintf(output, "User %s says: %s", user, msg);  /* No bounds check */
    printf("%s\n", output);
}

int main(int argc, char **argv) {
    if (argc >= 3) {
        build_path(argv[1], argv[2]);
    }
    if (argc >= 5) {
        format_message(argv[3], argv[4]);
    }
    return 0;
}
