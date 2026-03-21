/* CWE-476 Safe Variant: Null pointer checks on all paths
 * Validates pointers before dereference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
    char name[64];
    int role;
    struct user *next;
};

static struct user *user_list = NULL;

struct user *find_user(const char *name) {
    struct user *cur = user_list;
    while (cur) {
        if (strcmp(cur->name, name) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

int print_user_role(const char *name) {
    struct user *u = find_user(name);
    if (!u) {
        fprintf(stderr, "User '%s' not found\n", name);
        return -1;
    }
    printf("User %s has role %d\n", u->name, u->role);
    return 0;
}

void process_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f))
        printf("%s", line);
    fclose(f);
}

void copy_data(size_t size) {
    char *buf = (char *)malloc(size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return;
    }
    memset(buf, 0, size);
    strcpy(buf, "initialized");
    printf("Data: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1) process_file(argv[1]);
    copy_data(1024);
    return 0;
}
