/*
 * CGC-style challenge: Off-by-one error leading to overflow
 * CWE-193: Off-by-one Error
 *
 * A string canonicalization routine has an off-by-one in its length
 * check, allowing one byte past the buffer to be written.  This
 * corrupts an adjacent stack variable controlling access.
 */
#include <stdio.h>
#include <string.h>

#define PATH_MAX_LEN 128

struct request {
    char path[PATH_MAX_LEN];
    int  is_admin;
};

static int normalize_path(struct request *req, const char *input) {
    size_t len = strlen(input);

    /* VULN: off-by-one -- should be < PATH_MAX_LEN, not <= PATH_MAX_LEN.
       When len == PATH_MAX_LEN, the null terminator is written one byte
       past req->path, which on common layouts zeroes the low byte of
       is_admin or corrupts adjacent stack data. */
    if (len <= PATH_MAX_LEN) {
        memcpy(req->path, input, len);
        req->path[len] = '\0';
        return 0;
    }
    return -1;
}

static void handle_request(const char *raw_path) {
    struct request req;
    req.is_admin = 0;

    if (normalize_path(&req, raw_path) < 0) {
        printf("Path too long\n");
        return;
    }

    printf("Serving %s (admin=%d)\n", req.path, req.is_admin);
    if (req.is_admin)
        printf("ADMIN OVERRIDE ACTIVE\n");
}

int main(void) {
    char input[256];
    printf("Path: ");
    if (fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = '\0';
        handle_request(input);
    }
    return 0;
}
