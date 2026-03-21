/* CWE-362: Race Condition (shared file descriptor in threads)
 * Multiple threads read/write shared state without synchronization. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static int shared_counter = 0;
static char shared_buffer[256];

void *increment_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        /* No mutex: concurrent read-modify-write */
        int tmp = shared_counter;
        tmp++;
        shared_counter = tmp;
    }
    return NULL;
}

void *writer_worker(void *arg) {
    const char *msg = (const char *)arg;
    for (int i = 0; i < 1000; i++) {
        /* No synchronization on shared_buffer */
        strcpy(shared_buffer, msg);
    }
    return NULL;
}

int main(void) {
    pthread_t t1, t2, t3, t4;
    pthread_create(&t1, NULL, increment_worker, NULL);
    pthread_create(&t2, NULL, increment_worker, NULL);
    pthread_create(&t3, NULL, writer_worker, (void *)"Thread A data");
    pthread_create(&t4, NULL, writer_worker, (void *)"Thread B data!!");
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);
    printf("Counter: %d (expected 200000)\n", shared_counter);
    printf("Buffer: %s\n", shared_buffer);
    return 0;
}
