#include <string.h>
#include <stdio.h>

#include "secure_channel.h"
#include "crypto_utils.h"
#include "net_utils.h"

int secure_channel_init(secure_channel_t *ch,
                        int sock,
                        int is_server,
                        const uint8_t *shared_secret){
    ch->sock = sock;
    ch->is_server = is_server;

    derive_keys(shared_secret,
                ch->client_key,
                ch->server_key,
                ch->base_nonce);

    ch->send_counter = 1;
    ch->recv_counter = 1;

    return 0;
}

int secure_send(secure_channel_t *ch,
                const uint8_t *data,
                uint32_t len){
    uint8_t nonce[12];
    uint8_t ciphertext[2048];
    uint8_t tag[16];

    make_nonce(nonce, ch->base_nonce, ch->send_counter);

    const uint8_t *key =
        ch->is_server ? ch->server_key : ch->client_key;

    aes_gcm_encrypt(key, nonce, data, len, ciphertext, tag);

    ch->send_counter++;

    send_exact(ch->sock, (uint8_t *)&len, sizeof(len));
    send_exact(ch->sock, ciphertext, len);
    send_exact(ch->sock, tag, 16);

    return 0;
}

int secure_recv(secure_channel_t *ch,
                uint8_t *buffer,
                uint32_t *out_len){
    uint8_t nonce[12];
    uint8_t ciphertext[2048];
    uint8_t tag[16];

    uint32_t len;

    recv_exact(ch->sock, (uint8_t *)&len, sizeof(len));

    if (len > sizeof(ciphertext))
        return -1;

    recv_exact(ch->sock, ciphertext, len);
    recv_exact(ch->sock, tag, 16);

    make_nonce(nonce, ch->base_nonce, ch->recv_counter);

    const uint8_t *key =
        ch->is_server ? ch->client_key : ch->server_key;

    if (aes_gcm_decrypt(key,
                        nonce,
                        ciphertext,
                        len,
                        tag,
                        buffer) != 0)
        return -1;

    ch->recv_counter++;

    *out_len = len;
    return 0;
}