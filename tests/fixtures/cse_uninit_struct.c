/* CWE-457: Use of Uninitialized Variable (struct fields)
 * Struct fields read before all paths initialize them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct connection {
    int fd;
    int is_ssl;
    char *hostname;
    int timeout;
};

struct connection *new_connection(const char *host, int ssl) {
    struct connection *conn = (struct connection *)malloc(sizeof(struct connection));
    if (!conn) return NULL;
    /* Only partially initializes struct */
    conn->hostname = strdup(host);
    if (ssl) {
        conn->is_ssl = 1;
    }
    /* conn->fd uninitialized */
    /* conn->timeout uninitialized */
    /* conn->is_ssl uninitialized when ssl == 0 */
    return conn;
}

void use_connection(struct connection *conn) {
    printf("FD: %d, SSL: %d, Host: %s, Timeout: %d\n",
           conn->fd, conn->is_ssl, conn->hostname, conn->timeout);
}

int main(void) {
    struct connection *c = new_connection("example.com", 0);
    if (c) {
        use_connection(c);
        free(c->hostname);
        free(c);
    }
    return 0;
}
