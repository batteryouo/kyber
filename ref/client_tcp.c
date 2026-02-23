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
    uint64_t send_counter = 1;
    uint64_t recv_counter = 1;
    
    uint8_t plaintext[] = "Hello PQC Secure Channel!";
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint8_t nonce[12];

    make_nonce(nonce, base_nonce, send_counter);

    int plaintext_len = strlen((char*)plaintext);

    aes_gcm_encrypt(client_key,
                    nonce,
                    plaintext,
                    plaintext_len,
                    ciphertext,
                    tag);
    send_counter++;
    /* ---------------- Send ---------------- */

    uint32_t msg_len = plaintext_len;

    send_exact(sock, (uint8_t *)&msg_len, sizeof(msg_len));
    send_exact(sock, ciphertext, msg_len);
    send_exact(sock, tag, 16);

    printf("Encrypted message sent\n");
    uint8_t reply_cipher[1024];
    uint8_t reply_tag[16];
    uint8_t reply_plain[1024];
    uint8_t reply_nonce[12];

    make_nonce(reply_nonce, base_nonce, recv_counter);
    uint32_t reply_len;

    recv_exact(sock, (uint8_t *)&reply_len, sizeof(reply_len));
    recv_exact(sock, reply_cipher, reply_len);
    recv_exact(sock, reply_tag, 16);

    if (aes_gcm_decrypt(server_key,
                        reply_nonce,
                        reply_cipher,
                        reply_len,
                        reply_tag,
                        reply_plain) != 0) {
        printf("Reply decrypt failed\n");
        return -1;
    }
    recv_counter++;
    reply_plain[reply_len] = '\0';

    printf("Decrypted reply from server: %s\n", reply_plain);
    close(sock);

    return 0;
}

