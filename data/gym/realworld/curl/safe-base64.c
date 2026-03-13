/*
 * Safe base64 encoder based on curl's lib/base64.c patterns.
 *
 * Uses calculated output sizes and bounded operations.
 * No known vulnerabilities.
 */
#include <stdlib.h>
#include <string.h>

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Safe: output buffer is pre-calculated to exact required size */
int base64_encode(const unsigned char *src, size_t src_len,
                  char **out, size_t *out_len)
{
    if (!src || !out || !out_len)
        return -1;

    /* Calculate exact output size: 4 chars per 3 bytes, plus padding, plus NUL */
    size_t encoded_len = ((src_len + 2) / 3) * 4;
    char *result = malloc(encoded_len + 1);
    if (!result)
        return -1;

    size_t i = 0;
    size_t j = 0;

    while (i + 2 < src_len) {
        unsigned int triple = ((unsigned int)src[i] << 16) |
                              ((unsigned int)src[i + 1] << 8) |
                              (unsigned int)src[i + 2];
        result[j++] = base64_table[(triple >> 18) & 0x3F];
        result[j++] = base64_table[(triple >> 12) & 0x3F];
        result[j++] = base64_table[(triple >> 6) & 0x3F];
        result[j++] = base64_table[triple & 0x3F];
        i += 3;
    }

    /* Handle remaining 1 or 2 bytes */
    if (i < src_len) {
        unsigned int val = (unsigned int)src[i] << 16;
        if (i + 1 < src_len)
            val |= (unsigned int)src[i + 1] << 8;

        result[j++] = base64_table[(val >> 18) & 0x3F];
        result[j++] = base64_table[(val >> 12) & 0x3F];
        result[j++] = (i + 1 < src_len) ? base64_table[(val >> 6) & 0x3F] : '=';
        result[j++] = '=';
    }

    result[j] = '\0';
    *out = result;
    *out_len = j;
    return 0;
}

int main(void)
{
    const char *input = "Hello, curl!";
    char *encoded = NULL;
    size_t encoded_len = 0;

    if (base64_encode((const unsigned char *)input, strlen(input),
                      &encoded, &encoded_len) == 0) {
        /* encoded is properly NUL-terminated and correctly sized */
        free(encoded);
        return 0;
    }
    return 1;
}
