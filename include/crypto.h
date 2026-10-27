#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * crypto.h - AEAD encryption/decryption wrappers
 *
 * v1: static pre-shared key (PSK), loaded from config.
 * v2+ (stretch): replace key source with an X25519 handshake (handshake.h).
 *
 * Uses libsodium's crypto_aead_chacha20poly1305_ietf_* under the hood.
 *
 * "AEAD" = Authenticated Encryption with Associated Data:
 *   - the plaintext is encrypted AND authenticated (16-byte tag)
 *   - the "associated data" (ad) is NOT encrypted, only authenticated.
 *     We pass the packet header here, so an attacker can't change the
 *     sequence number without the tag check failing.
 */

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_KEY_LEN    32   /* 256-bit key */
#define CRYPTO_NONCE_LEN  12   /* ChaCha20-Poly1305 IETF nonce size */
#define CRYPTO_TAG_LEN    16   /* Poly1305 auth tag size */

typedef struct {
    unsigned char key[CRYPTO_KEY_LEN];
} crypto_ctx_t;

/* Initializes the crypto subsystem (sodium_init()). Call once at
 * startup before any other crypto_* function. Returns 0 on success. */
int crypto_init(void);

/* Copies a 32-byte pre-shared key into ctx. Returns 0 on success,
 * -1 if key_len is not CRYPTO_KEY_LEN. */
int crypto_load_key(crypto_ctx_t *ctx, const unsigned char *key, size_t key_len);

/* Wipes the key from memory. */
void crypto_wipe(crypto_ctx_t *ctx);

/* Encrypts `plaintext` (len bytes) using a freshly generated random nonce.
 * `ad` (ad_len bytes) is authenticated but not encrypted.
 * Writes the nonce to `nonce_out` (CRYPTO_NONCE_LEN bytes) and
 * ciphertext+tag to `ciphertext_out` (room for len + CRYPTO_TAG_LEN bytes).
 * Returns ciphertext length, -1 on error. */
int crypto_encrypt(const crypto_ctx_t *ctx,
                   const unsigned char *plaintext, size_t len,
                   const unsigned char *ad, size_t ad_len,
                   unsigned char *nonce_out,
                   unsigned char *ciphertext_out);

/* Decrypts `ciphertext` (len bytes, includes trailing tag) using `nonce`,
 * and checks that `ad` matches what was authenticated at encryption time.
 * Writes plaintext to `plaintext_out` (room for len - CRYPTO_TAG_LEN bytes).
 * Returns plaintext length, -1 if authentication fails (wrong key,
 * tampered packet, tampered header) or on error. */
int crypto_decrypt(const crypto_ctx_t *ctx,
                   const unsigned char *nonce,
                   const unsigned char *ad, size_t ad_len,
                   const unsigned char *ciphertext, size_t len,
                   unsigned char *plaintext_out);

#endif /* CRYPTO_H */
