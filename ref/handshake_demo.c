#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

/* Server side handshake */
void server_handshake(
    uint8_t *server_pk,
    uint8_t *server_sk,
    uint8_t *received_ct,
    uint8_t *shared_secret_out){
    /* Generate keypair */
    pqcrystals_kyber768_ref_keypair(server_pk, server_sk);

    /* Decapsulate ciphertext */
    pqcrystals_kyber768_ref_dec(shared_secret_out, received_ct, server_sk);
}

/* Client side handshake */
void client_handshake(
    uint8_t *server_pk,
    uint8_t *ciphertext_out,
    uint8_t *shared_secret_out){
    /* Encapsulate */
    pqcrystals_kyber768_ref_enc(ciphertext_out, shared_secret_out, server_pk);
}

int main() {

    uint8_t server_pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    uint8_t server_sk[pqcrystals_kyber768_SECRETKEYBYTES];

    uint8_t ciphertext[pqcrystals_kyber768_CIPHERTEXTBYTES];

    uint8_t client_ss[pqcrystals_kyber768_BYTES];
    uint8_t server_ss[pqcrystals_kyber768_BYTES];

    printf("=== Split Handshake Demo ===\n");

    /* ---- Step 1: Server generates keypair ---- */
    pqcrystals_kyber768_ref_keypair(server_pk, server_sk);

    /* ---- Step 2: Client encapsulates ---- */
    client_handshake(server_pk, ciphertext, client_ss);

    /* ---- Step 3: Server decapsulates ---- */
    pqcrystals_kyber768_ref_dec(server_ss, ciphertext, server_sk);

    /* ---- Step 4: Compare ---- */
    if (memcmp(client_ss, server_ss, pqcrystals_kyber768_BYTES) == 0) {
        printf("Handshake successful: shared secrets match\n");
    }
    else {
        printf("Handshake failed\n");
    }

    return 0;
}