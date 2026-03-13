/*
 * Safe URL parser based on curl's lib/urlapi.c patterns.
 *
 * This code uses bounded operations and validates all input lengths
 * before copying. No known vulnerabilities.
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_URL_LEN 4096
#define MAX_SCHEME_LEN 32

struct parsed_url {
    char scheme[MAX_SCHEME_LEN];
    char host[256];
    int port;
    char path[2048];
};

/* Safe: all copies are bounded and inputs validated */
int parse_url(const char *url, struct parsed_url *out)
{
    if (!url || !out)
        return -1;

    size_t url_len = strlen(url);
    if (url_len == 0 || url_len >= MAX_URL_LEN)
        return -1;

    memset(out, 0, sizeof(*out));

    /* Extract scheme */
    const char *colon = strchr(url, ':');
    if (!colon || colon == url)
        return -1;

    size_t scheme_len = (size_t)(colon - url);
    if (scheme_len >= MAX_SCHEME_LEN)
        return -1;

    memcpy(out->scheme, url, scheme_len);
    out->scheme[scheme_len] = '\0';

    /* Validate scheme is alphabetic */
    for (size_t i = 0; i < scheme_len; i++) {
        if (!isalpha((unsigned char)out->scheme[i]))
            return -1;
    }

    /* Skip "://" */
    const char *rest = colon + 1;
    if (rest[0] != '/' || rest[1] != '/')
        return -1;
    rest += 2;

    /* Extract host (up to '/' or ':' or end) */
    const char *host_end = rest;
    while (*host_end && *host_end != '/' && *host_end != ':')
        host_end++;

    size_t host_len = (size_t)(host_end - rest);
    if (host_len == 0 || host_len >= sizeof(out->host))
        return -1;

    memcpy(out->host, rest, host_len);
    out->host[host_len] = '\0';

    out->port = 0;
    if (*host_end == ':') {
        out->port = atoi(host_end + 1);
        host_end = strchr(host_end, '/');
        if (!host_end)
            host_end = url + url_len;
    }

    /* Path */
    if (*host_end == '/') {
        size_t path_len = strlen(host_end);
        if (path_len >= sizeof(out->path))
            return -1;
        memcpy(out->path, host_end, path_len);
        out->path[path_len] = '\0';
    }

    return 0;
}

int main(void)
{
    struct parsed_url url;
    if (parse_url("https://example.com:443/path", &url) == 0) {
        /* Use parsed result safely */
        return (url.port == 443) ? 0 : 1;
    }
    return 1;
}
