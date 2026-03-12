#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "processor.h"

/* CWE-78: Command injection — user input flows from parser through to system() */
int process_data(const char *parsed) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo %s | process_tool", parsed);
    return system(cmd);  /* Injection: parsed contains unsanitized user input */
}
