#include "packet.h"

#include <string.h>

/* packet.c - see include/packet.h for the contract */

int packet_header_write(const packet_header_t *hdr, unsigned char *buf, size_t buf_len) {
    if (buf_len < PACKET_HEADER_LEN) {
        return -1;
    }
    buf[0] = hdr->version;
    buf[1] = hdr->type;

    /* Sequence number in big-endian (network) order: most significant byte first. */
    for (int i = 0; i < 8; i++) {
        buf[2 + i] = (unsigned char)((hdr->seq >> (56 - 8 * i)) & 0xFF);
    }

    memcpy(buf + PACKET_NONCE_OFFSET, hdr->nonce, CRYPTO_NONCE_LEN);
    return 0;
}

int packet_header_read(const unsigned char *buf, size_t buf_len, packet_header_t *hdr) {
    if (buf_len < PACKET_HEADER_LEN) {
        return -1;
    }
    if (buf[0] != PACKET_VERSION) {
        return -1;
    }
    hdr->version = buf[0];
    hdr->type = buf[1];

    hdr->seq = 0;
    for (int i = 0; i < 8; i++) {
        hdr->seq = (hdr->seq << 8) | buf[2 + i];
    }

    memcpy(hdr->nonce, buf + PACKET_NONCE_OFFSET, CRYPTO_NONCE_LEN);
    return 0;
}
