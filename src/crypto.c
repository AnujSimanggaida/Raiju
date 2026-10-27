#include "crypto.h"

#include <sodium.h>
#include <string.h>

/* crypto.c - see include/crypto.h for the contract */

int crypto_init(void) {
    /* sodium_init() returns 0 on first success, 1 if already initialized. */
    return sodium_init() < 0 ? -1 : 0;
}

int crypto_load_key(crypto_ctx_t *ctx, const unsigned char *key, size_t key_len) {
    if (key_len != CRYPTO_KEY_LEN) {
        return -1;
    }
    memcpy(ctx->key, key, CRYPTO_KEY_LEN);
    return 0;
}

void crypto_wipe(crypto_ctx_t *ctx) {
    /* Unlike memset, sodium_memzero can't be optimized away by the compiler. */
    sodium_memzero(ctx->key, sizeof(ctx->key));
}

int crypto_encrypt(const crypto_ctx_t *ctx,
                   const unsigned char *plaintext, size_t len,
                   const unsigned char *ad, size_t ad_len,
                   unsigned char *nonce_out,
                   unsigned char *ciphertext_out) {
    /* Every packet must use a different nonce with the same key.
     * 96 random bits makes a repeat practically impossible. */
    randombytes_buf(nonce_out, CRYPTO_NONCE_LEN);

    unsigned long long ct_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext_out, &ct_len,
            plaintext, len,
            ad, ad_len,
            NULL,             /* nsec: unused by this algorithm */
            nonce_out, ctx->key) != 0) {
        return -1;
    }
    return (int)ct_len;
}

int crypto_decrypt(const crypto_ctx_t *ctx,
                   const unsigned char *nonce,
                   const unsigned char *ad, size_t ad_len,
                   const unsigned char *ciphertext, size_t len,
                   unsigned char *plaintext_out) {
    if (len < CRYPTO_TAG_LEN) {
        return -1;
    }

    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext_out, &pt_len,
            NULL,             /* nsec: unused */
            ciphertext, len,
            ad, ad_len,
            nonce, ctx->key) != 0) {
        return -1;            /* tag mismatch: forged, corrupted, or wrong key */
    }
    return (int)pt_len;
}
