#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "api.h"
#include "net_utils.h"
#include "handshake.h"

#define PORT 8080

int main() {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    uint8_t shared_secret[pqcrystals_kyber768_BYTES];

    if (client_handshake(sock, shared_secret) != 0) {
        printf("Handshake failed\n");
        return -1;
    }

    printf("Handshake complete (client)\n");

    close(sock);

    return 0;
}