/*
 * Safe cookie parser based on curl's lib/cookie.c patterns.
 *
 * Uses bounded string operations and proper validation.
 * No known vulnerabilities.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_COOKIE_NAME  256
#define MAX_COOKIE_VALUE 4096
#define MAX_DOMAIN       256

struct cookie {
    char name[MAX_COOKIE_NAME];
    char value[MAX_COOKIE_VALUE];
    char domain[MAX_DOMAIN];
    time_t expires;
    int secure;
    int httponly;
};

/* Safe: all operations are bounded, no unchecked copies */
int parse_set_cookie(const char *header, struct cookie *out)
{
    if (!header || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    /* Find name=value pair */
    const char *eq = strchr(header, '=');
    if (!eq || eq == header)
        return -1;

    size_t name_len = (size_t)(eq - header);
    if (name_len >= MAX_COOKIE_NAME)
        return -1;

    memcpy(out->name, header, name_len);
    out->name[name_len] = '\0';

    /* Extract value (up to ';' or end) */
    const char *val_start = eq + 1;
    const char *val_end = strchr(val_start, ';');
    if (!val_end)
        val_end = val_start + strlen(val_start);

    size_t val_len = (size_t)(val_end - val_start);
    if (val_len >= MAX_COOKIE_VALUE)
        return -1;

    memcpy(out->value, val_start, val_len);
    out->value[val_len] = '\0';

    /* Parse attributes safely */
    const char *attr = val_end;
    while (*attr == ';') {
        attr++;
        while (*attr == ' ')
            attr++;

        if (strncmp(attr, "Secure", 6) == 0) {
            out->secure = 1;
        } else if (strncmp(attr, "HttpOnly", 8) == 0) {
            out->httponly = 1;
        } else if (strncmp(attr, "Domain=", 7) == 0) {
            const char *dom = attr + 7;
            const char *dom_end = strchr(dom, ';');
            if (!dom_end)
                dom_end = dom + strlen(dom);
            size_t dom_len = (size_t)(dom_end - dom);
            if (dom_len < MAX_DOMAIN) {
                memcpy(out->domain, dom, dom_len);
                out->domain[dom_len] = '\0';
            }
        }

        /* Advance to next ';' */
        const char *next = strchr(attr, ';');
        if (!next)
            break;
        attr = next;
    }

    return 0;
}

int main(void)
{
    struct cookie c;
    const char *header = "session=abc123; Domain=example.com; Secure; HttpOnly";
    if (parse_set_cookie(header, &c) == 0) {
        return c.secure ? 0 : 1;
    }
    return 1;
}
