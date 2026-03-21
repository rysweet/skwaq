/* CWE-120: Buffer Copy without Checking Size (gets + scanf patterns)
 * Multiple classic buffer overflow patterns. */
#include <stdio.h>
#include <string.h>

struct credentials {
    char username[32];
    char password[32];
    int is_admin;
};

void login(void) {
    struct credentials cred;
    cred.is_admin = 0;

    printf("Username: ");
    scanf("%s", cred.username);  /* No width limit: overflow overwrites password/is_admin */

    printf("Password: ");
    scanf("%s", cred.password);  /* No width limit */

    if (cred.is_admin)
        printf("Admin access granted!\n");
}

void copy_header(const char *raw_header) {
    char local[64];
    /* No size check */
    memcpy(local, raw_header, strlen(raw_header));
    local[63] = '\0';
    printf("Header: %s\n", local);
}

int main(void) {
    login();
    return 0;
}
