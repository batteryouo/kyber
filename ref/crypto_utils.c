#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include "crypto_utils.h"

int derive_keys(const uint8_t *shared_secret,
                uint8_t *client_key,
                uint8_t *server_key,
                uint8_t *base_nonce){
    uint8_t derived[76]; 
    /* 32 + 32 + 12 = 76 bytes */

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0) return -1;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) return -1;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "kyber-demo", 10) <= 0) return -1;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, 32) <= 0) return -1;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "handshake data", 14) <= 0) return -1;

    size_t outlen = sizeof(derived);
    if (EVP_PKEY_derive(pctx, derived, &outlen) <= 0) return -1;

    memcpy(client_key, derived, 32);
    memcpy(server_key, derived + 32, 32);
    memcpy(base_nonce, derived + 64, 12);

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *plaintext,
                    int plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *ciphertext,
                    int ciphertext_len,
                    const uint8_t *tag,
                    uint8_t *plaintext){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return (ret > 0) ? 0 : -1;
}

void make_nonce(uint8_t *nonce,
                const uint8_t *base_nonce,
                uint64_t counter){
    memcpy(nonce, base_nonce, 12);

    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (counter >> (8 * i)) & 0xff;
    }
}