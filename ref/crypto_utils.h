#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>

#define AES_KEY_LEN 32
#define NONCE_LEN 12

int derive_keys(const uint8_t *shared_secret,
                uint8_t *client_key,
                uint8_t *server_key,
                uint8_t *base_nonce);

int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *plaintext,
                    int plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *ciphertext,
                    int ciphertext_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);


#endif