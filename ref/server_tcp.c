#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "api.h"
#include "net_utils.h"
#include "handshake.h"
#include "crypto_utils.h"
#include "secure_channel.h"

#define PORT 8080


void* handle_client(void* arg) {
  int client_fd = *(int*)arg;
  free(arg);

  printf("Client connected (fd=%d)\n", client_fd);

  /* ---------------- Handshake ---------------- */
  uint8_t shared_secret[pqcrystals_kyber768_BYTES];

  if (server_handshake(client_fd, shared_secret) != 0) {
    printf("Handshake failed (fd=%d)\n", client_fd);
    close(client_fd);
    return NULL;
  }

  printf("Handshake complete (fd=%d)\n", client_fd);

  /* -------- Secure Channel Init -------- */
  secure_channel_t ch;
  secure_channel_init(&ch, client_fd, 1, shared_secret);

  /* -------- Receive Loop -------- */
  uint8_t buffer[1024];
  uint32_t len;

  while (1) {
    if (secure_recv(&ch, buffer, &len) != 0) {
      printf("Client disconnected (fd=%d)\n", client_fd);
      break;
    }

    if (len < sizeof(buffer))
      buffer[len] = '\0';

    printf("Client(%d): %s\n", client_fd, buffer);

    /*
    if (secure_send(&ch, buffer, len) != 0) {
      printf("Send failed (fd=%d)\n", client_fd);
      break;
    }
    */
  }

  close(client_fd);
  return NULL;
}

int main() {
  int server_fd;
  struct sockaddr_in address;
  socklen_t addrlen = sizeof(address);

  server_fd = socket(AF_INET, SOCK_STREAM, 0);

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  bind(server_fd, (struct sockaddr *)&address, sizeof(address));

  listen(server_fd, 10);  // backlog must not be too small

  printf("Server waiting on port %d...\n", PORT);

  while (1) {
    int *client_fd = malloc(sizeof(int));
    if (!client_fd) continue;

    *client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);

    if (*client_fd < 0) {
      free(client_fd);
      continue;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, handle_client, client_fd);
    pthread_detach(tid);  // do not need join
  }

  close(server_fd);
  return 0;
}
