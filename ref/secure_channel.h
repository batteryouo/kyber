#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int sock;
    int is_server;

    uint8_t c2s_key[32];   // client -> server
    uint8_t s2c_key[32];   // server -> client
    uint8_t base_nonce[12];

    uint64_t send_counter;
    uint64_t recv_counter;

} secure_channel_t;

int secure_channel_init(secure_channel_t *ch, int sock, int is_server, const uint8_t *shared_secret);

int secure_send(secure_channel_t *ch, const uint8_t *data, uint32_t len);

int secure_recv(secure_channel_t *ch, uint8_t *buffer, uint32_t *out_len);

#endif