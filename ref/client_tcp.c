#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "api.h"
#include "net_utils.h"
#include "handshake.h"
#include "crypto_utils.h"

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
    printf("SS[0..3] = %02x %02x %02x %02x\n", shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[3]);

    uint8_t client_key[32];
    uint8_t server_key[32];
    uint8_t base_nonce[12];

    derive_keys(shared_secret, client_key, server_key, base_nonce);
    /* ---------------- Encrypt Message ---------------- */

    uint8_t plaintext[] = "Hello PQC Secure Channel!";
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint8_t nonce[12];

    memcpy(nonce, base_nonce, 12);
    nonce[11] ^= 1;  /* simple demo counter */

    int plaintext_len = strlen((char*)plaintext);

    aes_gcm_encrypt(client_key,
                    nonce,
                    plaintext,
                    plaintext_len,
                    ciphertext,
                    tag);

    /* ---------------- Send ---------------- */

    uint32_t msg_len = plaintext_len;

    send_exact(sock, (uint8_t *)&msg_len, sizeof(msg_len));
    send_exact(sock, ciphertext, msg_len);
    send_exact(sock, tag, 16);

    printf("Encrypted message sent\n");

    close(sock);

    return 0;
}