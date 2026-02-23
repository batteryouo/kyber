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

    /* ---------------- Key Derivation ---------------- */

    uint8_t client_key[32];
    uint8_t server_key[32];
    uint8_t base_nonce[12];

    derive_keys(shared_secret, client_key, server_key, base_nonce);

    /* ---------------- Encrypted Receive ---------------- */
    uint64_t send_counter = 1;
    uint64_t recv_counter = 1;
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint8_t plaintext[1024];
    uint8_t nonce[12];

    make_nonce(nonce, base_nonce, recv_counter);


    /* first receive length */
    uint32_t msg_len;
    recv_exact(client_fd, (uint8_t *)&msg_len, sizeof(msg_len));
    /* receive ciphertext */
    recv_exact(client_fd, ciphertext, msg_len);
    /* receive tag */
    recv_exact(client_fd, tag, 16);

    if (aes_gcm_decrypt(client_key,
                        nonce,
                        ciphertext,
                        msg_len,
                        tag,
                        plaintext) != 0) {
        printf("Decrypt failed\n");
        return -1;
    }
    recv_counter++;
    plaintext[msg_len] = '\0';

    printf("Decrypted message from client: %s\n", plaintext);

    uint8_t reply[] = "Message received securely!";
    uint8_t reply_cipher[1024];
    uint8_t reply_tag[16];
    uint8_t reply_nonce[12];

    make_nonce(reply_nonce, base_nonce, send_counter);

    int reply_len = strlen((char*)reply);

    aes_gcm_encrypt(server_key,
                    reply_nonce,
                    reply,
                    reply_len,
                    reply_cipher,
                    reply_tag);
    send_counter++;
    uint32_t send_len = reply_len;

    send_exact(client_fd, (uint8_t *)&send_len, sizeof(send_len));
    send_exact(client_fd, reply_cipher, send_len);
    send_exact(client_fd, reply_tag, 16);

    printf("Encrypted reply sent to client\n");

    close(client_fd);
    close(server_fd);

    return 0;
}