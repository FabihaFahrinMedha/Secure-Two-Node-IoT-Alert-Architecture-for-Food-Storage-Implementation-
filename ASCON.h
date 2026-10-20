#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

int ascon128_encrypt(
    uint8_t *ciphertext,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *key,
    const uint8_t *nonce
);

int ascon128_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *key,
    const uint8_t *nonce
);

#ifdef __cplusplus
}
#endif

#endif