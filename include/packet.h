#ifndef PACKET_H
#define PACKET_H

/*
 * packet.h - On-wire packet framing format
 *
 * Layout of a single UDP datagram sent between peers:
 *
 *   +---------+----------+----------------+-------------------------+
 *   | version |  type    |  sequence num  |  nonce (12 bytes)       |
 *   | 1 byte  |  1 byte  |  8 bytes (BE)  |                         |
 *   +---------+----------+----------------+-------------------------+
 *   | ciphertext + auth tag (variable length, tag is last 16 bytes) |
 *   +-----------------------------------------------------------------+
 *
 * PACKET_HEADER_LEN = 1 + 1 + 8 + 12 = 22 bytes, followed by
 * (plaintext_len + CRYPTO_TAG_LEN) bytes of ciphertext+tag.
 *
 * The first PACKET_AD_LEN bytes (version, type, seq) are passed to the
 * AEAD as associated data, so they are authenticated: changing the
 * sequence number in transit makes decryption fail.
 *
 * This header is fixed for v1. Handshake packets (stretch goal) would
 * use a distinct `type` value and a different payload structure.
 */

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define PACKET_VERSION        1

#define PACKET_TYPE_DATA      0x01
#define PACKET_TYPE_HANDSHAKE 0x02  /* reserved for stretch goal */

#define PACKET_AD_LEN         (1 + 1 + 8)     /* version + type + seq */
#define PACKET_NONCE_OFFSET   PACKET_AD_LEN   /* nonce follows the seq */
#define PACKET_HEADER_LEN     (PACKET_AD_LEN + CRYPTO_NONCE_LEN)

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint64_t seq;
    unsigned char nonce[CRYPTO_NONCE_LEN];
} packet_header_t;

/* Serializes a header struct into the first PACKET_HEADER_LEN bytes of buf.
 * Returns 0 on success, -1 if buf_len is too small. */
int packet_header_write(const packet_header_t *hdr, unsigned char *buf, size_t buf_len);

/* Parses the first PACKET_HEADER_LEN bytes of buf into a header struct.
 * Returns 0 on success, -1 if buf_len is too small or version is unsupported. */
int packet_header_read(const unsigned char *buf, size_t buf_len, packet_header_t *hdr);

#endif /* PACKET_H */
