#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>

int server_handshake(int sock, uint8_t *shared_secret);
int client_handshake(int sock, uint8_t *shared_secret);

#endif