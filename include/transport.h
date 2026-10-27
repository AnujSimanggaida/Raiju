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
 *   - Packet framing/header layout (see packet.h)
 *   - Deciding who the peer is. transport_recv reports the sender, and the
 *     caller updates the peer only after the packet passes authentication,
 *     so an attacker can't redirect our traffic with a fake packet.
 */

#include <stddef.h>
#include <netinet/in.h>

typedef struct {
    int fd;
    struct sockaddr_in peer_addr;   /* where transport_send sends to */
    int peer_known;                 /* 0 until config or an authenticated packet sets it */
} transport_ctx_t;

/* Creates a UDP socket bound to local_port (0 = ephemeral, for clients).
 * Sets the socket non-blocking. Returns 0 on success, -1 on error. */
int transport_init(transport_ctx_t *ctx, int local_port);

/* Sets the peer from an IP string and port (client: from config).
 * Returns 0 on success, -1 if peer_ip isn't a valid IPv4 address. */
int transport_set_peer(transport_ctx_t *ctx, const char *peer_ip, int peer_port);

/* Sets the peer from a socket address (server: the sender of the
 * latest authenticated packet). */
void transport_update_peer(transport_ctx_t *ctx, const struct sockaddr_in *addr);

/* Sends a raw buffer to the peer.
 * Returns bytes sent, -1 on error (errno = ENOTCONN if no peer yet). */
int transport_send(transport_ctx_t *ctx, const unsigned char *buf, size_t len);

/* Receives one datagram from any sender, and stores the sender's address
 * in `from`. Returns bytes received, 0 if nothing available, -1 on error. */
int transport_recv(transport_ctx_t *ctx, unsigned char *buf, size_t buf_len,
                   struct sockaddr_in *from);

/* Closes the underlying socket. */
int transport_close(transport_ctx_t *ctx);

#endif /* TRANSPORT_H */
