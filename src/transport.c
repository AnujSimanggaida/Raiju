#define _DEFAULT_SOURCE

#include "transport.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

/* transport.c - see include/transport.h for the contract */

int transport_init(transport_ctx_t *ctx, int local_port) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ctx->fd < 0) {
        return -1;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);  /* listen on every address */
    local.sin_port = htons((uint16_t)local_port);

    if (bind(ctx->fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        int saved = errno;
        close(ctx->fd);
        errno = saved;
        return -1;
    }
    return 0;
}

int transport_set_peer(transport_ctx_t *ctx, const char *peer_ip, int peer_port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)peer_port);
    if (inet_pton(AF_INET, peer_ip, &addr.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    transport_update_peer(ctx, &addr);
    return 0;
}

void transport_update_peer(transport_ctx_t *ctx, const struct sockaddr_in *addr) {
    ctx->peer_addr = *addr;
    ctx->peer_known = 1;
}

int transport_send(transport_ctx_t *ctx, const unsigned char *buf, size_t len) {
    if (!ctx->peer_known) {
        errno = ENOTCONN;
        return -1;
    }
    ssize_t n = sendto(ctx->fd, buf, len, 0,
                       (const struct sockaddr *)&ctx->peer_addr, sizeof(ctx->peer_addr));
    return n < 0 ? -1 : (int)n;
}

int transport_recv(transport_ctx_t *ctx, unsigned char *buf, size_t buf_len,
                   struct sockaddr_in *from) {
    socklen_t from_len = sizeof(*from);
    ssize_t n = recvfrom(ctx->fd, buf, buf_len, 0, (struct sockaddr *)from, &from_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return (int)n;
}

int transport_close(transport_ctx_t *ctx) {
    return close(ctx->fd);
}
