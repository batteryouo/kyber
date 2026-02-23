#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "net_utils.h"

#define PORT 8080

int main() {

    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    printf("Server waiting on port %d...\n", PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    printf("Client connected\n");

    uint32_t number = 123456789;

    send_exact(client_fd, (uint8_t *)&number, sizeof(number));

    uint32_t received;
    recv_exact(client_fd, (uint8_t *)&received, sizeof(received));

    printf("Received number: %u\n", received);

    close(client_fd);
    close(server_fd);

    return 0;
}