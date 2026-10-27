/*
 * tun_demo.c - Phase 1 sanity check for src/tun.c
 *
 * Creates a virtual interface named tun0, gives it 10.8.0.1/24, and then:
 *   - RECEIVES: prints every raw IP packet the kernel routes into tun0
 *   - INJECTS:  for each ICMP echo request (ping), builds an echo reply
 *               and writes it back into tun0, so the kernel delivers it
 *               to the ping program as if a real host had answered.
 *
 * No UDP, no crypto - just the TUN plumbing.
 *
 * Try it (in a second terminal while this runs):
 *   ping 10.8.0.2        # any address in 10.8.0.0/24 except 10.8.0.1
 *
 * Note: pinging 10.8.0.1 itself will NOT reach this program. That address
 * belongs to this machine, so the kernel answers it over loopback.
 *
 * Needs root or CAP_NET_ADMIN:  sudo ./tun_demo
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "tun.h"

#define DEMO_ADDR   "10.8.0.1"
#define DEMO_PREFIX 24
#define DEMO_MTU    1400
#define BUF_SIZE    2048  /* bigger than the MTU, so a packet always fits */

static volatile sig_atomic_t running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

/* Standard Internet checksum (RFC 1071), used by IPv4 and ICMP headers. */
static uint16_t inet_checksum(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)(data[i] << 8 | data[i + 1]);
    }
    if (len & 1) {
        sum += (uint32_t)(data[len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static const char *proto_name(uint8_t proto) {
    switch (proto) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    default: return "other";
    }
}

/* Prints a one-line summary of a packet plus a short hex dump. */
static void print_packet(const unsigned char *pkt, int len) {
    int version = pkt[0] >> 4;
    if (version != 4) {
        printf("[recv] %d bytes, IPv%d (not decoded)\n", len, version);
        return;
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, pkt + 12, src, sizeof(src));
    inet_ntop(AF_INET, pkt + 16, dst, sizeof(dst));
    printf("[recv] %d bytes, IPv4 %s -> %s, proto %s\n",
           len, src, dst, proto_name(pkt[9]));

    int show = len < 32 ? len : 32;
    printf("       ");
    for (int i = 0; i < show; i++) {
        printf("%02x%s", pkt[i], (i % 16 == 15) ? "\n       " : " ");
    }
    printf("%s\n", len > show ? "..." : "");
}

/*
 * If pkt is an IPv4 ICMP echo request, rewrite it in place into an echo
 * reply and return 1. Otherwise leave it alone and return 0.
 */
static int make_echo_reply(unsigned char *pkt, int len) {
    if (len < 20 || (pkt[0] >> 4) != 4 || pkt[9] != 1) {
        return 0;  /* not IPv4 ICMP */
    }
    int ihl = (pkt[0] & 0x0F) * 4;  /* IP header length in bytes */
    if (ihl < 20 || len < ihl + 8) {
        return 0;
    }
    unsigned char *icmp = pkt + ihl;
    if (icmp[0] != 8) {
        return 0;  /* not an echo request */
    }

    /* Swap source and destination IP addresses. */
    unsigned char tmp[4];
    memcpy(tmp, pkt + 12, 4);
    memcpy(pkt + 12, pkt + 16, 4);
    memcpy(pkt + 16, tmp, 4);

    /* Recompute the IP header checksum. */
    pkt[10] = pkt[11] = 0;
    uint16_t ip_sum = inet_checksum(pkt, (size_t)ihl);
    pkt[10] = (unsigned char)(ip_sum >> 8);
    pkt[11] = (unsigned char)(ip_sum & 0xFF);

    /* ICMP type 8 (request) -> 0 (reply), then recompute ICMP checksum. */
    icmp[0] = 0;
    icmp[2] = icmp[3] = 0;
    uint16_t icmp_sum = inet_checksum(icmp, (size_t)(len - ihl));
    icmp[2] = (unsigned char)(icmp_sum >> 8);
    icmp[3] = (unsigned char)(icmp_sum & 0xFF);
    return 1;
}

int main(void) {
    char dev[TUN_IFACE_NAME_MAX] = "tun0";

    int fd = tun_create(dev);
    if (fd < 0) {
        perror("tun_create (are you root?)");
        return EXIT_FAILURE;
    }
    if (tun_configure_addr(dev, DEMO_ADDR, DEMO_PREFIX) < 0) {
        perror("tun_configure_addr");
        tun_close(fd);
        return EXIT_FAILURE;
    }
    if (tun_set_mtu(dev, DEMO_MTU) < 0) {
        perror("tun_set_mtu");
        tun_close(fd);
        return EXIT_FAILURE;
    }

    /* Use sigaction without SA_RESTART so Ctrl+C interrupts the blocking read. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("%s is up at %s/%d (mtu %d)\n", dev, DEMO_ADDR, DEMO_PREFIX, DEMO_MTU);
    printf("In another terminal, try:  ping 10.8.0.2\n");
    printf("Ctrl+C to quit.\n\n");

    unsigned char buf[BUF_SIZE];
    while (running) {
        int n = tun_read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* signal arrived; loop checks `running` */
            }
            perror("tun_read");
            break;
        }
        if (n == 0) {
            continue;
        }

        print_packet(buf, n);

        if (make_echo_reply(buf, n)) {
            if (tun_write(fd, buf, (size_t)n) < 0) {
                perror("tun_write");
            } else {
                printf("[inject] %d bytes, ICMP echo reply\n\n", n);
            }
        }
    }

    printf("\nShutting down, removing %s\n", dev);
    tun_close(fd);  /* not persistent, so the kernel deletes tun0 */
    return EXIT_SUCCESS;
}
