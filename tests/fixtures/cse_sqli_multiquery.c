/* CWE-89: SQL Injection (multi-statement / UNION pattern)
 * Concatenates user input into SQL with multiple injection points. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int execute_query(const char *sql) {
    printf("SQL: %s\n", sql);
    return 0;
}

int search_products(const char *category, const char *sort_col) {
    char query[1024];
    /* Both category and sort_col are injectable */
    snprintf(query, sizeof(query),
             "SELECT name, price FROM products WHERE category = '%s' ORDER BY %s",
             category, sort_col);
    return execute_query(query);
}

int authenticate(const char *user, const char *pass) {
    char query[512];
    sprintf(query,
            "SELECT id FROM users WHERE name='%s' AND password='%s'",
            user, pass);
    return execute_query(query);
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    search_products(argv[1], argc > 2 ? argv[2] : "name");
    if (argc > 3) authenticate(argv[1], argv[3]);
    return 0;
}
