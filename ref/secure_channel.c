#include <string.h>
#include <stdio.h>

#include "secure_channel.h"
#include "crypto_utils.h"
#include "net_utils.h"

int secure_channel_init(secure_channel_t *ch, int sock, int is_server, const uint8_t *shared_secret){
    ch->sock = sock;
    ch->is_server = is_server;

    // derive_keys must now output c2s_key and s2c_key
    derive_keys(shared_secret, ch->c2s_key, ch->s2c_key, ch->base_nonce);

    ch->send_counter = 1;
    ch->recv_counter = 1;

    return 0;
}

int secure_send(secure_channel_t *ch, const uint8_t *data, uint32_t len){
    uint8_t nonce[12];
    uint8_t ciphertext[4096];
    uint8_t tag[16];

    if (len > sizeof(ciphertext))
        return -1;

    make_nonce(nonce, ch->base_nonce, ch->send_counter);

    const uint8_t *key;

    // Direction selection
    if (ch->is_server){
        key = ch->s2c_key;   // server sending
    }
    else{
        key = ch->c2s_key;   // client sending
    }

    if (aes_gcm_encrypt(key, nonce, data, len, ciphertext, tag) != 0)
        return -1;

    ch->send_counter++;

    if (send_exact(ch->sock, (uint8_t *)&len, sizeof(len)) != 0)
        return -1;

    if (send_exact(ch->sock, ciphertext, len) != 0)
        return -1;

    if (send_exact(ch->sock, tag, 16) != 0)
        return -1;

    return 0;
}

int secure_recv(secure_channel_t *ch, uint8_t *buffer, uint32_t *out_len){
    uint8_t nonce[12];
    uint8_t ciphertext[4096];
    uint8_t tag[16];
    uint32_t len;

    if (recv_exact(ch->sock, (uint8_t *)&len, sizeof(len)) != 0)
        return -1;

    if (len > sizeof(ciphertext))
        return -1;

    if (recv_exact(ch->sock, ciphertext, len) != 0)
        return -1;

    if (recv_exact(ch->sock, tag, 16) != 0)
        return -1;

    make_nonce(nonce, ch->base_nonce, ch->recv_counter);

    const uint8_t *key;

    // Reverse direction
    if (ch->is_server)
        key = ch->c2s_key;   // server receiving from client
    else
        key = ch->s2c_key;   // client receiving from server

    if (aes_gcm_decrypt(key, nonce, ciphertext, len, tag, buffer) != 0)
        return -1;

    ch->recv_counter++;

    *out_len = len;
    return 0;
}