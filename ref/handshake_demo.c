#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

int main() {

    uint8_t server_pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    uint8_t server_sk[pqcrystals_kyber768_SECRETKEYBYTES];

    uint8_t ciphertext[pqcrystals_kyber768_CIPHERTEXTBYTES];

    uint8_t client_ss[pqcrystals_kyber768_BYTES];
    uint8_t server_ss[pqcrystals_kyber768_BYTES];

    printf("=== Kyber768 Handshake Demo ===\n");

    /* Server generates keypair */
    if (pqcrystals_kyber768_ref_keypair(server_pk, server_sk) != 0) {
        printf("Keypair generation failed\n");
        return -1;
    }

    printf("Server keypair generated\n");

    /* Client encapsulates */
    if (pqcrystals_kyber768_ref_enc(ciphertext, client_ss, server_pk) != 0) {
        printf("Encapsulation failed\n");
        return -1;
    }

    printf("Client encapsulation done\n");

    /* Server decapsulates */
    if (pqcrystals_kyber768_ref_dec(server_ss, ciphertext, server_sk) != 0) {
        printf("Decapsulation failed\n");
        return -1;
    }

    printf("Server decapsulation done\n");

    if (memcmp(client_ss, server_ss, pqcrystals_kyber768_BYTES) == 0) {
        printf("Handshake successful: shared secrets match\n");
    } else {
        printf("Handshake failed: shared secrets do NOT match\n");
        return -1;
    }

    return 0;
}