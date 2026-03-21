/* CWE-772: Missing Release of Resource (socket leak)
 * Sockets opened but not closed on error paths. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int connect_to_server(const char *host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
        return -1;  /* Leaks sockfd */

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;  /* Leaks sockfd */

    return sockfd;
}

int send_request(const char *host, int port, const char *data) {
    int fd = connect_to_server(host, port);
    if (fd < 0) return -1;

    if (write(fd, data, strlen(data)) < 0)
        return -1;  /* Leaks fd */

    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0)
        return -1;  /* Leaks fd */

    buf[n] = '\0';
    printf("Response: %s\n", buf);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    send_request(argv[1], atoi(argv[2]), "GET / HTTP/1.0\r\n\r\n");
    return 0;
}
