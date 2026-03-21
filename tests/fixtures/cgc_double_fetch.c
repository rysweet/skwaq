/*
 * CGC-style challenge: TOCTOU / double fetch race condition
 * CWE-367: Time-of-Check Time-of-Use Race Condition
 *
 * A service validates a shared-memory request length, then copies data
 * using the same field a second time.  A concurrent thread can change
 * the length between check and use, causing a buffer overflow.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define BUF_SIZE 64

struct shared_req {
    volatile size_t length;
    char data[256];
};

static struct shared_req *g_req;

static void *racer_thread(void *arg) {
    (void)arg;
    /* Spin and flip the length between safe and dangerous values */
    for (int i = 0; i < 100000; i++) {
        g_req->length = 200;   /* larger than BUF_SIZE */
        g_req->length = 16;    /* passes the check */
    }
    return NULL;
}

static void process_request(struct shared_req *req) {
    char local_buf[BUF_SIZE];

    /* CHECK: length appears safe */
    if (req->length > BUF_SIZE) {
        printf("Request too large\n");
        return;
    }

    /* VULN: second fetch of req->length -- a concurrent writer may have
       changed it to a value > BUF_SIZE between the check and this copy */
    memcpy(local_buf, req->data, req->length);
    local_buf[req->length < BUF_SIZE ? req->length : BUF_SIZE - 1] = '\0';
    printf("Processed: %s\n", local_buf);
}

int main(void) {
    pthread_t tid;

    g_req = calloc(1, sizeof(*g_req));
    g_req->length = 16;
    strcpy(g_req->data, "hello world");

    pthread_create(&tid, NULL, racer_thread, NULL);

    for (int i = 0; i < 1000; i++)
        process_request(g_req);

    pthread_join(tid, NULL);
    free(g_req);
    return 0;
}
