#define _DEFAULT_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "tun.h"
#include "transport.h"
#include "crypto.h"
#include "session.h"
#include "config.h"
#include "log.h"
#include "packet.h"

/*
 * raiju.c - wires the modules together and runs the event loop.
 *
 *   tun0 --(tun_read)--> encrypt + frame --(transport_send)--> peer
 *   peer --(transport_recv)--> parse + decrypt + replay check --(tun_write)--> tun0
 */

#define TUN_BUF_LEN  2048  /* larger than any MTU we allow (max 1500) */
#define WIRE_BUF_LEN (PACKET_HEADER_LEN + TUN_BUF_LEN + CRYPTO_TAG_LEN)

static volatile sig_atomic_t running = 1;

/* Counters printed at shutdown, handy for checking what happened. */
static struct {
    unsigned long sent, received, bad_header, bad_auth, replayed, no_peer;
} stats;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-v] <config-file-path>\n", prog);
    fprintf(stderr, "  -v   verbose: log every packet\n");
}

static void print_banner(void) {
    printf("\033[33m                                  GOD\033[0m\n");
    printf("\033[33m              *      .            dZZZZZ,       .          *\033[0m\n");
    printf("\033[33m                                 dZZZZ  ZZ,\033[0m\n");
    printf("\033[33m     *         .         ,AZZZZZZZZZZZ  `ZZ,_          *\033[0m\n");
    printf("\033[33m                    ,ZZZZZZV'      ZZZZ   `Z,`\\\033[0m\n");
    printf("\033[33m                  ,ZZZ    ZZ   .    ZZZZ   `V\033[0m\n");
    printf("\033[33m        *      ZZZZV'     ZZ         ZZZZ    \\_              .\033[0m\n");
    printf("\033[33m.              V   l   .   ZZ        ZZZZZZ          .\n");
    printf("\033[33m               l    \\       ZZ,     ZZZ  ZZZZZZ,\033[0m\n");
    printf("\033[33m   .          /            ZZ l    ZZZ    ZZZ `Z,\033[0m\n");
    printf("\033[33m                          ZZ  l   ZZZ     Z Z, `Z,            *\033[0m\n");
    printf("\033[33m                .        ZZ      ZZZ      Z  Z, `lv\n");
    printf("\033[33m                         Z        ZZ      V  `Z   \033[0m\\\n");
    printf("\033[33m                         V        ZZC     l   V\033[0m\n");
    printf("\033[33m           Z             l        V ZR        l      .\033[0m\n");
    printf("\033[33m            \\             \\       l  ZA\033[0m\n");
    printf("\033[33m                            \\         C          C\033[0m\n");
    printf("\033[33m                                  \\   K   /    /             K\033[0m\n");
    printf("\033[33m                          A    \\   \\  |  /  /              /\033[0m\n");
    printf("\033[33m                           \\        \\\\|/ /  /v\n");
    printf("\033[33m   __________________________________\\|/_________________________\033[0m\n");
    printf("Art From: cv666@cleveland.Freenet.Edu (Gary G. Nass)\n\n");
    printf("Welcome to RajiuVPN, a free open-source mini VPN service\n");
}

/* Outgoing path: one plaintext IP packet from tun0 -> one encrypted UDP datagram. */
static void handle_tun_packet(int tun_fd, transport_ctx_t *transport,
                              const crypto_ctx_t *crypto, session_ctx_t *session) {
    unsigned char plain[TUN_BUF_LEN];
    unsigned char wire[WIRE_BUF_LEN];

    int n = tun_read(tun_fd, plain, sizeof(plain));
    if (n <= 0) {
        if (n < 0) LOG_ERRORF("tun_read: %s", strerror(errno));
        return;
    }

    if (!transport->peer_known) {
        /* Server only: we don't know where the client is until it sends us something. */
        stats.no_peer++;
        LOG_DEBUGF("dropping %d-byte packet: no peer yet", n);
        return;
    }

    /* 1. Header first (nonce left as zeros), so version/type/seq can be
     *    authenticated as associated data. */
    packet_header_t hdr = {
        .version = PACKET_VERSION,
        .type = PACKET_TYPE_DATA,
        .seq = session_next_send_seq(session),
    };
    packet_header_write(&hdr, wire, sizeof(wire));

    /* 2. Encrypt the IP packet straight into the wire buffer after the
     *    header, and let crypto write the fresh nonce into its header slot. */
    int ct_len = crypto_encrypt(crypto, plain, (size_t)n,
                                wire, PACKET_AD_LEN,
                                wire + PACKET_NONCE_OFFSET,
                                wire + PACKET_HEADER_LEN);
    if (ct_len < 0) {
        LOG_ERRORF("crypto_encrypt failed");
        return;
    }

    /* 3. Send header + ciphertext + tag as one UDP datagram. */
    size_t wire_len = PACKET_HEADER_LEN + (size_t)ct_len;
    if (transport_send(transport, wire, wire_len) < 0) {
        LOG_WARNF("transport_send: %s", strerror(errno));
        return;
    }
    stats.sent++;
    LOG_DEBUGF("tun -> peer: %d bytes plaintext, %zu bytes on the wire, seq %llu",
               n, wire_len, (unsigned long long)hdr.seq);
}

/* Incoming path: one UDP datagram -> verify + decrypt -> one IP packet into tun0. */
static void handle_udp_packet(int tun_fd, transport_ctx_t *transport,
                              const crypto_ctx_t *crypto, session_ctx_t *session,
                              vpn_mode_t mode) {
    unsigned char wire[WIRE_BUF_LEN];
    unsigned char plain[TUN_BUF_LEN];
    struct sockaddr_in from;

    int n = transport_recv(transport, wire, sizeof(wire), &from);
    if (n <= 0) {
        if (n < 0) LOG_ERRORF("transport_recv: %s", strerror(errno));
        return;
    }

    /* 1. Parse the header. */
    packet_header_t hdr;
    if (packet_header_read(wire, (size_t)n, &hdr) < 0 || hdr.type != PACKET_TYPE_DATA) {
        stats.bad_header++;
        LOG_DEBUGF("dropping %d bytes: bad header", n);
        return;
    }

    /* 2. Verify the tag and decrypt. Anything forged, corrupted or encrypted
     *    with a different key fails here. */
    size_t ct_len = (size_t)n - PACKET_HEADER_LEN;
    if (ct_len > TUN_BUF_LEN + CRYPTO_TAG_LEN) {
        stats.bad_header++;
        return;
    }
    int pt_len = crypto_decrypt(crypto, hdr.nonce,
                                wire, PACKET_AD_LEN,
                                wire + PACKET_HEADER_LEN, ct_len,
                                plain);
    if (pt_len < 0) {
        stats.bad_auth++;
        LOG_DEBUGF("dropping %d bytes from %s: authentication failed",
                   n, inet_ntoa(from.sin_addr));
        return;
    }

    /* 3. Replay check, only now that we know the packet is genuine. */
    if (!session_check_replay(session, hdr.seq)) {
        stats.replayed++;
        LOG_DEBUGF("dropping seq %llu: replay or too old", (unsigned long long)hdr.seq);
        return;
    }

    /* 4. Server: reply to wherever the client's genuine packets come from.
     *    (Handles the client's address/port changing, e.g. behind NAT.) */
    if (mode == MODE_SERVER) {
        if (!transport->peer_known ||
            transport->peer_addr.sin_addr.s_addr != from.sin_addr.s_addr ||
            transport->peer_addr.sin_port != from.sin_port) {
            LOG_INFOF("peer is now %s:%d", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        }
        transport_update_peer(transport, &from);
    }

    /* 5. Inject the original IP packet into tun0. */
    if (tun_write(tun_fd, plain, (size_t)pt_len) < 0) {
        LOG_WARNF("tun_write: %s", strerror(errno));
        return;
    }
    stats.received++;
    LOG_DEBUGF("peer -> tun: %d bytes on the wire, %d bytes plaintext, seq %llu",
               n, pt_len, (unsigned long long)hdr.seq);
}

int main(int argc, char *argv[]) {
    print_banner();

    int verbose = 0;
    const char *config_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (!config_path) {
            config_path = argv[i];
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (!config_path) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    log_set_level(verbose ? LOG_DEBUG : LOG_INFO);
    LOG_INFOF("raiju starting, config: %s", config_path);

    /* Config */
    vpn_config_t cfg;
    if (config_load(config_path, &cfg) != 0) {
        return EXIT_FAILURE;
    }

    /* Crypto */
    crypto_ctx_t crypto;
    if (crypto_init() != 0 || crypto_load_key(&crypto, cfg.psk, sizeof(cfg.psk)) != 0) {
        LOG_ERRORF("crypto setup failed");
        return EXIT_FAILURE;
    }
    memset(cfg.psk, 0, sizeof(cfg.psk));  /* the key now lives only in `crypto` */

    /* TUN interface */
    char dev[TUN_IFACE_NAME_MAX] = "tun0";
    int tun_fd = tun_create(dev);
    if (tun_fd < 0) {
        LOG_ERRORF("tun_create: %s (need root or CAP_NET_ADMIN)", strerror(errno));
        return EXIT_FAILURE;
    }
    if (tun_configure_addr(dev, cfg.tun_addr, cfg.tun_prefix) < 0 ||
        tun_set_mtu(dev, cfg.mtu) < 0) {
        LOG_ERRORF("configuring %s: %s", dev, strerror(errno));
        tun_close(tun_fd);
        return EXIT_FAILURE;
    }
    LOG_INFOF("%s up at %s/%d, mtu %d", dev, cfg.tun_addr, cfg.tun_prefix, cfg.mtu);

    /* UDP transport */
    transport_ctx_t transport;
    if (transport_init(&transport, cfg.listen_port) < 0) {
        LOG_ERRORF("transport_init on port %d: %s", cfg.listen_port, strerror(errno));
        tun_close(tun_fd);
        return EXIT_FAILURE;
    }
    if (cfg.mode == MODE_CLIENT) {
        if (transport_set_peer(&transport, cfg.peer_addr, cfg.peer_port) < 0) {
            LOG_ERRORF("bad peer_addr '%s'", cfg.peer_addr);
            transport_close(&transport);
            tun_close(tun_fd);
            return EXIT_FAILURE;
        }
        LOG_INFOF("client mode, peer %s:%d", cfg.peer_addr, cfg.peer_port);
    } else {
        LOG_INFOF("server mode, listening on UDP port %d", cfg.listen_port);
    }

    /* Session (sequence numbers + replay window) */
    session_ctx_t session;
    session_init(&session);

    /* Ctrl+C / kill: stop the loop and clean up. No SA_RESTART, so poll()
     * returns with EINTR and we notice `running` changed. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Event loop: sleep until either fd has data, then handle it. */
    struct pollfd fds[2] = {
        { .fd = tun_fd,       .events = POLLIN },
        { .fd = transport.fd, .events = POLLIN },
    };

    while (running) {
        int ready = poll(fds, 2, -1);  /* -1 = wait forever */
        if (ready < 0) {
            if (errno == EINTR) continue;
            LOG_ERRORF("poll: %s", strerror(errno));
            break;
        }
        if (fds[0].revents & POLLIN) {
            handle_tun_packet(tun_fd, &transport, &crypto, &session);
        }
        if (fds[1].revents & POLLIN) {
            handle_udp_packet(tun_fd, &transport, &crypto, &session, cfg.mode);
        }
    }

    LOG_INFOF("shutting down: sent %lu, received %lu, dropped %lu bad header, "
              "%lu failed auth, %lu replayed, %lu with no peer",
              stats.sent, stats.received, stats.bad_header,
              stats.bad_auth, stats.replayed, stats.no_peer);

    crypto_wipe(&crypto);
    transport_close(&transport);
    tun_close(tun_fd);
    return EXIT_SUCCESS;
}
