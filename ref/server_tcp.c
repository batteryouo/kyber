#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "api.h"
#include "net_utils.h"
#include "handshake.h"

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

    uint8_t shared_secret[pqcrystals_kyber768_BYTES];

    if (server_handshake(client_fd, shared_secret) != 0) {
        printf("Handshake failed\n");
        return -1;
    }
    printf("Handshake complete (server)\n");
    printf("SS[0..3] = %02x %02x %02x %02x\n",
        shared_secret[0],
        shared_secret[1],
        shared_secret[2],
        shared_secret[3]);

    close(client_fd);
    close(server_fd);

    return 0;
}