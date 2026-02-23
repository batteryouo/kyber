#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "api.h"
#include "net_utils.h"
#include "handshake.h"

/* Server side handshake */
int server_handshake(int sock, uint8_t *shared_secret) {

    uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];

    /* Generate keypair */
    if (pqcrystals_kyber768_ref_keypair(pk, sk) != 0)
        return -1;

    /* Send public key to client */
    if (send_exact(sock, pk, sizeof(pk)) != 0)
        return -1;

    /* Receive ciphertext */
    if (recv_exact(sock, ct, sizeof(ct)) != 0)
        return -1;

    /* Decapsulate */
    if (pqcrystals_kyber768_ref_dec(shared_secret, ct, sk) != 0)
        return -1;

    return 0;
}

/* Client side handshake */
int client_handshake(int sock, uint8_t *shared_secret) {

    uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];

    /* Receive public key */
    if (recv_exact(sock, pk, sizeof(pk)) != 0)
        return -1;

    /* Encapsulate */
    if (pqcrystals_kyber768_ref_enc(ct, shared_secret, pk) != 0)
        return -1;

    /* Send ciphertext */
    if (send_exact(sock, ct, sizeof(ct)) != 0)
        return -1;

    return 0;
}