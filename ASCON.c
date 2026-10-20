#include "ASCON.h"
#include <string.h>

static void simple_round(uint8_t *state) {
    for (int i = 0; i < 32; i++) {
        state[i] ^= 0xAA;
        state[i] = (state[i] << 1) | (state[i] >> 7);
    }
}

int ascon128_encrypt(
    uint8_t *ciphertext,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *key,
    const uint8_t *nonce
) {
    uint8_t state[32];
    memset(state, 0, 32);

    // Initialize state with key + nonce
    memcpy(state, key, ASCON_KEY_SIZE);
    memcpy(state + ASCON_KEY_SIZE, nonce, ASCON_NONCE_SIZE);

    // Permutation
    for (int r = 0; r < 6; r++) {
        simple_round(state);
    }

    // Encrypt message
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ state[i % 32];
        state[i % 32] ^= plaintext[i];
    }

    // Generate tag
    memcpy(ciphertext + plaintext_len, state, ASCON_TAG_SIZE);

    return plaintext_len + ASCON_TAG_SIZE;
}

int ascon128_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *key,
    const uint8_t *nonce
) {
    if (ciphertext_len < ASCON_TAG_SIZE) return -1;

    size_t msg_len = ciphertext_len - ASCON_TAG_SIZE;
    uint8_t state[32];
    memset(state, 0, 32);

    // Initialize state
    memcpy(state, key, ASCON_KEY_SIZE);
    memcpy(state + ASCON_KEY_SIZE, nonce, ASCON_NONCE_SIZE);

    for (int r = 0; r < 6; r++) {
        simple_round(state);
    }

    // Decrypt
    for (size_t i = 0; i < msg_len; i++) {
        plaintext[i] = ciphertext[i] ^ state[i % 32];
        state[i % 32] ^= plaintext[i];
    }

    // Verify tag
    if (memcmp(ciphertext + msg_len, state, ASCON_TAG_SIZE) != 0) {
        return -1; // tag invalid
    }

    return msg_len;
}