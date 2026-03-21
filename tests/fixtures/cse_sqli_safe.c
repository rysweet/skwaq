/* CWE-89 Safe Variant: SQL query with parameterized input
 * Uses proper escaping/validation instead of concatenation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Escape single quotes for safe SQL string literal */
int escape_sql_string(const char *input, char *output, size_t outsize) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < outsize - 2; i++) {
        if (input[i] == '\'') {
            if (j + 2 >= outsize) return -1;
            output[j++] = '\'';
            output[j++] = '\'';
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
    return 0;
}

/* Validate that id is numeric only */
int validate_numeric(const char *input) {
    for (int i = 0; input[i]; i++) {
        if (!isdigit((unsigned char)input[i])) return 0;
    }
    return 1;
}

int execute_query(const char *sql) {
    printf("Executing: %s\n", sql);
    return 0;
}

int lookup_user(const char *username) {
    char escaped[256];
    if (escape_sql_string(username, escaped, sizeof(escaped)) != 0)
        return -1;
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE username = '%s'", escaped);
    return execute_query(query);
}

int delete_record(const char *id) {
    if (!validate_numeric(id)) {
        fprintf(stderr, "Invalid ID: must be numeric\n");
        return -1;
    }
    char query[256];
    snprintf(query, sizeof(query), "DELETE FROM records WHERE id = %s", id);
    return execute_query(query);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    lookup_user(argv[1]);
    if (argc > 2) delete_record(argv[2]);
    return 0;
}
