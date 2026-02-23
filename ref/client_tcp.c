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

    /* -------- Secure Channel Init -------- */

    secure_channel_t ch;

    secure_channel_init(&ch, sock, 0, shared_secret); /* is_server = 0 */
    /* -------- Send Message -------- */
    char message[] = "Hello PQC secure world";

    if (secure_send(&ch, (uint8_t*)message, strlen(message)) != 0) {
        printf("Secure send failed\n");
        return -1;
    }

    printf("Message sent\n");
    /* -------- Receive Reply -------- */

    uint8_t buffer[1024];
    uint32_t len;

    if (secure_recv(&ch, buffer, &len) != 0) {
        printf("Secure receive failed\n");
        return -1;
    }

    buffer[len] = '\0';
    printf("Reply from server: %s\n", buffer);

    close(sock);

    return 0;
}

