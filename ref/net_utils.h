#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stdint.h>
#include <stddef.h>

int send_exact(int sock, const uint8_t *buf, size_t len);
int recv_exact(int sock, uint8_t *buf, size_t len);

#endif