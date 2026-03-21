/* CWE-457: Use of Uninitialized Variable
 * Variables used before being assigned a value. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_access(int user_id) {
    int authorized;  /* Uninitialized */
    if (user_id == 0) {
        authorized = 1;
    }
    /* If user_id != 0, authorized is uninitialized */
    return authorized;
}

void process_data(int mode) {
    char *buffer;  /* Uninitialized pointer */
    int length;    /* Uninitialized */

    if (mode == 1) {
        buffer = (char *)malloc(256);
        length = 256;
    } else if (mode == 2) {
        buffer = (char *)malloc(512);
        length = 512;
    }
    /* mode == 0: buffer and length are uninitialized */
    memset(buffer, 0, length);
    printf("Buffer at %p, length %d\n", (void *)buffer, length);
    free(buffer);
}

int main(int argc, char **argv) {
    int uid = argc > 1 ? atoi(argv[1]) : 5;
    if (check_access(uid))
        printf("Access granted\n");
    else
        printf("Access denied\n");
    process_data(argc > 2 ? atoi(argv[2]) : 0);
    return 0;
}
