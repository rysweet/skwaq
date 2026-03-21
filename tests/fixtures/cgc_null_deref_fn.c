/*
 * CGC-style challenge: NULL function pointer call
 * CWE-476: NULL Pointer Dereference
 *
 * A plugin system loads handler callbacks from a table.  If a plugin
 * slot is unregistered (NULL), the dispatcher still calls through the
 * pointer.  On systems where page 0 is mappable, an attacker can place
 * shellcode at address 0 and gain execution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PLUGINS 8

typedef void (*plugin_fn)(const char *arg);

static plugin_fn plugin_table[MAX_PLUGINS];

static void builtin_echo(const char *arg) {
    printf("ECHO: %s\n", arg);
}

static void builtin_upper(const char *arg) {
    printf("UPPER: ");
    for (size_t i = 0; arg[i]; i++)
        putchar(arg[i] >= 'a' && arg[i] <= 'z' ? arg[i] - 32 : arg[i]);
    putchar('\n');
}

static void register_plugins(void) {
    /* Only some slots are initialized -- the rest remain NULL */
    plugin_table[0] = builtin_echo;
    plugin_table[1] = builtin_upper;
    /* slots 2..7 are NULL */
}

static void dispatch_plugin(int id, const char *arg) {
    if (id < 0 || id >= MAX_PLUGINS) {
        printf("Invalid plugin id\n");
        return;
    }

    /* VULN: no NULL check before call.  If plugin_table[id] is NULL,
       this jumps to address 0x0. */
    plugin_table[id](arg);
}

int main(void) {
    int id;
    char arg[128];

    register_plugins();

    printf("Plugin ID (0-%d): ", MAX_PLUGINS - 1);
    scanf("%d", &id);
    getchar();

    printf("Argument: ");
    if (!fgets(arg, sizeof(arg), stdin))
        return 1;
    arg[strcspn(arg, "\n")] = '\0';

    dispatch_plugin(id, arg);
    return 0;
}
