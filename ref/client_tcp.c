#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "net_utils.h"

#define PORT 8080

int main() {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    uint32_t received;
    recv_exact(sock, (uint8_t *)&received, sizeof(received));

    printf("Received number: %u\n", received);

    uint32_t reply = 987654321;
    send_exact(sock, (uint8_t *)&reply, sizeof(reply));

    close(sock);

    return 0;
}