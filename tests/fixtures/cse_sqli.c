/* CWE-89: SQL Injection in C
 * Constructs SQL query via string concatenation with user input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simulated DB query function */
int execute_query(const char *sql) {
    printf("Executing: %s\n", sql);
    return 0;
}

int lookup_user(const char *username) {
    char query[512];
    /* Direct concatenation of user input into SQL */
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE username = '%s'", username);
    return execute_query(query);
}

int delete_record(const char *id) {
    char query[256];
    sprintf(query, "DELETE FROM records WHERE id = %s", id);
    return execute_query(query);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    lookup_user(argv[1]);
    if (argc > 2) delete_record(argv[2]);
    return 0;
}
