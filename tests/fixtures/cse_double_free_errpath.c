/* CWE-415: Double Free (error path pattern)
 * Same pointer freed in both normal and error cleanup paths. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int process_data(const char *input) {
    char *buf = (char *)malloc(strlen(input) + 1);
    if (!buf) return -1;
    strcpy(buf, input);

    char *processed = (char *)malloc(1024);
    if (!processed) {
        free(buf);
        return -1;
    }

    if (strlen(buf) > 512) {
        free(buf);
        free(processed);
        /* Falls through instead of returning */
    }

    snprintf(processed, 1024, "Processed: %s", buf);
    printf("%s\n", processed);

    free(buf);       /* Double free if len > 512 */
    free(processed); /* Double free if len > 512 */
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return process_data(argv[1]);
}
