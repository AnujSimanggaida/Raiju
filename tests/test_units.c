/*
 * test_units.c - unit tests for crypto, packet and session.
 * Run with: make -f MakeFile test
 */

#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "packet.h"
#include "session.h"

static int failures = 0;

#define CHECK(cond)                                                   \
    do {                                                              \
        if (!(cond)) {                                                \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                               \
        }                                                             \
    } while (0)

static void test_crypto(void) {
    printf("crypto\n");
    crypto_ctx_t ctx, other;
    unsigned char key[CRYPTO_KEY_LEN], key2[CRYPTO_KEY_LEN];
    memset(key, 0x11, sizeof(key));
    memset(key2, 0x22, sizeof(key2));
    CHECK(crypto_init() == 0);
    CHECK(crypto_load_key(&ctx, key, sizeof(key)) == 0);
    CHECK(crypto_load_key(&other, key2, sizeof(key2)) == 0);
    CHECK(crypto_load_key(&ctx, key, 16) == -1);

    const unsigned char msg[] = "hello through the tunnel";
    unsigned char ad[PACKET_AD_LEN] = {1, 1, 0, 0, 0, 0, 0, 0, 0, 42};
    unsigned char nonce[CRYPTO_NONCE_LEN], nonce2[CRYPTO_NONCE_LEN];
    unsigned char ct[sizeof(msg) + CRYPTO_TAG_LEN], ct2[sizeof(ct)];
    unsigned char pt[sizeof(msg)];

    int ct_len = crypto_encrypt(&ctx, msg, sizeof(msg), ad, sizeof(ad), nonce, ct);
    CHECK(ct_len == (int)(sizeof(msg) + CRYPTO_TAG_LEN));
    CHECK(memcmp(ct, msg, sizeof(msg)) != 0);  /* actually encrypted */

    /* round trip */
    CHECK(crypto_decrypt(&ctx, nonce, ad, sizeof(ad), ct, (size_t)ct_len, pt) == (int)sizeof(msg));
    CHECK(memcmp(pt, msg, sizeof(msg)) == 0);

    /* same plaintext twice -> different nonce and ciphertext */
    crypto_encrypt(&ctx, msg, sizeof(msg), ad, sizeof(ad), nonce2, ct2);
    CHECK(memcmp(nonce, nonce2, sizeof(nonce)) != 0);
    CHECK(memcmp(ct, ct2, sizeof(ct)) != 0);

    /* wrong key */
    CHECK(crypto_decrypt(&other, nonce, ad, sizeof(ad), ct, (size_t)ct_len, pt) == -1);

    /* flipped ciphertext bit */
    ct[3] ^= 0x01;
    CHECK(crypto_decrypt(&ctx, nonce, ad, sizeof(ad), ct, (size_t)ct_len, pt) == -1);
    ct[3] ^= 0x01;

    /* tampered header (associated data), e.g. attacker changes the seq */
    ad[9] = 43;
    CHECK(crypto_decrypt(&ctx, nonce, ad, sizeof(ad), ct, (size_t)ct_len, pt) == -1);
    ad[9] = 42;

    /* truncated */
    CHECK(crypto_decrypt(&ctx, nonce, ad, sizeof(ad), ct, 5, pt) == -1);
}

static void test_packet(void) {
    printf("packet\n");
    packet_header_t in = { .version = PACKET_VERSION, .type = PACKET_TYPE_DATA,
                           .seq = 0x0102030405060708ULL };
    for (int i = 0; i < CRYPTO_NONCE_LEN; i++) in.nonce[i] = (unsigned char)(0xA0 + i);

    unsigned char buf[PACKET_HEADER_LEN];
    CHECK(packet_header_write(&in, buf, sizeof(buf)) == 0);
    CHECK(buf[0] == 1 && buf[1] == 1);
    CHECK(buf[2] == 0x01 && buf[9] == 0x08);  /* big-endian seq */
    CHECK(buf[PACKET_NONCE_OFFSET] == 0xA0);

    packet_header_t out;
    CHECK(packet_header_read(buf, sizeof(buf), &out) == 0);
    CHECK(out.seq == in.seq && out.type == in.type);
    CHECK(memcmp(out.nonce, in.nonce, CRYPTO_NONCE_LEN) == 0);

    CHECK(packet_header_write(&in, buf, PACKET_HEADER_LEN - 1) == -1);
    CHECK(packet_header_read(buf, PACKET_HEADER_LEN - 1, &out) == -1);
    buf[0] = 9;
    CHECK(packet_header_read(buf, sizeof(buf), &out) == -1);  /* unknown version */
}

static void test_session(void) {
    printf("session\n");
    session_ctx_t s;
    session_init(&s);

    uint64_t a = session_next_send_seq(&s);
    uint64_t b = session_next_send_seq(&s);
    CHECK(a != 0 && b == a + 1);

    CHECK(session_check_replay(&s, 0) == 0);     /* 0 never valid */
    CHECK(session_check_replay(&s, 100) == 1);
    CHECK(session_check_replay(&s, 100) == 0);   /* exact replay */
    CHECK(session_check_replay(&s, 101) == 1);
    CHECK(session_check_replay(&s, 99) == 1);    /* late but new: reordering is fine */
    CHECK(session_check_replay(&s, 99) == 0);
    CHECK(session_check_replay(&s, 101 - 63) == 1);  /* oldest slot in window */
    CHECK(session_check_replay(&s, 101 - 64) == 0);  /* just outside window */

    CHECK(session_check_replay(&s, 1000) == 1);  /* big jump clears window */
    CHECK(session_check_replay(&s, 101) == 0);   /* now far too old */
    CHECK(session_check_replay(&s, 999) == 1);
    CHECK(session_check_replay(&s, 1000) == 0);
}

int main(void) {
    test_crypto();
    test_packet();
    test_session();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
