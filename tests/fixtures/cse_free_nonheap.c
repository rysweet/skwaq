/* CWE-590: Free of Memory not on the Heap
 * Frees stack and global memory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char global_buf[128] = "global data";

void process_data(int use_heap) {
    char stack_buf[128];
    char *ptr;

    if (use_heap) {
        ptr = (char *)malloc(128);
        if (!ptr) return;
        strcpy(ptr, "heap data");
    } else {
        strcpy(stack_buf, "stack data");
        ptr = stack_buf;  /* Points to stack */
    }

    printf("Data: %s\n", ptr);
    free(ptr);  /* Bug: frees stack memory when use_heap == 0 */
}

void free_global(void) {
    char *p = global_buf;
    free(p);  /* Bug: frees global/static memory */
}

int main(int argc, char **argv) {
    process_data(argc > 1 ? atoi(argv[1]) : 0);
    return 0;
}
