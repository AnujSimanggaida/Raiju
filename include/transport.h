#ifndef TRANSPORT_H
#define TRANSPORT_H

/*
 * transport.h - UDP socket transport
 *
 * Responsible for:
 *   - Creating/binding a UDP socket
 *   - Sending/receiving raw framed packets to/from a peer
 *
 * NOT responsible for:
 *   - Encryption (see crypto.h)
 *   - Packet framing/header layout (see session.h / packet format doc)
 */

#include <stddef.h>
#include <netinet/in.h>

typedef struct {
    int fd;
    struct sockaddr_in peer_addr;   /* set once peer is known/configured */
    int peer_known;                 /* 0 until first packet or config sets it */
} transport_ctx_t;

/* Creates a UDP socket bound to local_port (0 = ephemeral/client mode).
 * Sets the socket non-blocking. Returns 0 on success, -1 on error. */
int transport_init(transport_ctx_t *ctx, int local_port);

/* Sets the known peer address (used by clients that already know
 * the server's address/port from config). */
int transport_set_peer(transport_ctx_t *ctx, const char *peer_ip, int peer_port);

/* Sends a raw buffer to the configured peer.
 * Returns bytes sent, -1 on error. */
int transport_send(transport_ctx_t *ctx, const unsigned char *buf, size_t len);

/* Receives a raw buffer from any sender. On first receive (server mode),
 * updates ctx->peer_addr to the sender so replies can be routed back.
 * Returns bytes received, 0 if nothing available (non-blocking), -1 on error. */
int transport_recv(transport_ctx_t *ctx, unsigned char *buf, size_t buf_len);

/* Closes the underlying socket. */
int transport_close(transport_ctx_t *ctx);

#endif /* TRANSPORT_H */
