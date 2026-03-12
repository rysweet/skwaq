#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include "processor.h"

/*
 * Multi-file vulnerability test case.
 *
 * The vulnerability chain spans files:
 *   main.c: reads argv[1] (user input)
 *   parser.c: parse_input() heap-overflows (CWE-122)
 *   processor.c: process_data() command-injects (CWE-78)
 *
 * This tests inter-procedural analysis across compilation units.
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    /* User input enters here */
    char *parsed = parse_input(argv[1]);
    if (!parsed) {
        fprintf(stderr, "Parse failed\n");
        return 1;
    }

    int len = get_parsed_length(parsed);
    printf("Parsed %d bytes\n", len);

    /* Tainted data flows to command execution */
    int result = process_data(parsed);

    free(parsed);
    return result;
}
