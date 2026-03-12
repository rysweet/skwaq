#ifndef PARSER_H
#define PARSER_H

/* Parse user input and return allocated buffer. Caller must free. */
char* parse_input(const char *raw_input);

/* Get the length of parsed data */
int get_parsed_length(const char *parsed);

#endif
