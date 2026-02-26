#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "api.h"
#include "net_utils.h"
#include "handshake.h"
#include "crypto_utils.h"
#include "secure_channel.h"

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

    /* ---------------- Handshake ---------------- */

    uint8_t shared_secret[pqcrystals_kyber768_BYTES];

    if (server_handshake(client_fd, shared_secret) != 0) {
        printf("Handshake failed\n");
        return -1;
    }

    printf("Handshake complete (server)\n");

    /* -------- Secure Channel Init -------- */

    secure_channel_t ch;

    secure_channel_init(&ch, client_fd, 1, shared_secret);/* is_server = 1 */

    /* -------- Receive Message -------- */

    uint8_t buffer[1024];
    uint32_t len;
    while (1) {

        if (secure_recv(&ch, buffer, &len) != 0) {
            printf("Secure receive failed\n");
            break;
        }

        if (len < sizeof(buffer))
            buffer[len] = '\0';

        printf("Client: %s\n", buffer);

        printf("Server reply: ");
        fgets((char*)buffer, sizeof(buffer), stdin);

        size_t reply_len = strlen((char*)buffer);

        if (secure_send(&ch, buffer, reply_len) != 0) {
            printf("Secure send failed\n");
            break;
        }
    }


    close(client_fd);
    close(server_fd);

    return 0;
}