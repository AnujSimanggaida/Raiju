#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * crypto.h - AEAD encryption/decryption wrappers
 *
 * v1: static pre-shared key (PSK), loaded from config.
 * v2+ (stretch): replace key source with an X25519 handshake (handshake.h).
 *
 * Uses libsodium's crypto_aead_chacha20poly1305_ietf_* under the hood
 * (decision documented in the architecture doc).
 */

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_KEY_LEN    32   /* 256-bit key */
#define CRYPTO_NONCE_LEN   12  /* ChaCha20-Poly1305 IETF nonce size */
#define CRYPTO_TAG_LEN     16  /* Poly1305 auth tag size */

typedef struct {
    unsigned char key[CRYPTO_KEY_LEN];
} crypto_ctx_t;

/* Initializes the crypto subsystem (e.g. sodium_init()). Call once at
 * startup before any other crypto_* function. Returns 0 on success. */
int crypto_init(void);

/* Loads a pre-shared key into ctx, e.g. derived from a passphrase in config. */
int crypto_load_key(crypto_ctx_t *ctx, const unsigned char *key, size_t key_len);

/* Encrypts `plaintext` (len bytes) using a freshly generated nonce.
 * Writes the nonce to `nonce_out` (must be CRYPTO_NONCE_LEN bytes) and
 * the ciphertext+tag to `ciphertext_out` (must have room for
 * len + CRYPTO_TAG_LEN bytes). Returns ciphertext length, -1 on error. */
int crypto_encrypt(const crypto_ctx_t *ctx,
                    const unsigned char *plaintext, size_t len,
                    unsigned char *nonce_out,
                    unsigned char *ciphertext_out);

/* Decrypts `ciphertext` (len bytes, includes trailing auth tag) using
 * the given nonce. Writes plaintext to `plaintext_out` (must have room
 * for len - CRYPTO_TAG_LEN bytes). Returns plaintext length, -1 if
 * authentication fails or on error. */
int crypto_decrypt(const crypto_ctx_t *ctx,
                    const unsigned char *nonce,
                    const unsigned char *ciphertext, size_t len,
                    unsigned char *plaintext_out);

#endif /* CRYPTO_H */
