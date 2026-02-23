#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include "net_utils.h"

int send_exact(int sock, const uint8_t *buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(sock, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }

    return 0;
}

int recv_exact(int sock, uint8_t *buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = recv(sock, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }

    return 0;
}