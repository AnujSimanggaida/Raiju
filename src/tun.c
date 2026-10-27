#define _DEFAULT_SOURCE  /* for ifreq/IFF_* definitions under -std=c11 */

#include "tun.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/*
 * tun.c - TUN device handling (see include/tun.h for the contract)
 *
 * A TUN device is a virtual network interface backed by a file descriptor.
 * When the kernel routes an IP packet to the interface, we can read() it
 * from the fd. When we write() an IP packet to the fd, the kernel treats it
 * as if it had arrived on that interface.
 *
 * We open with IFF_NO_PI so each read/write is exactly one raw IP packet,
 * with no extra 4-byte "packet info" header in front.
 */

/* Opens a throwaway UDP socket. Interface ioctls (address, MTU, flags)
 * have to be issued on a socket, not on the TUN fd itself. */
static int ctl_socket(void) {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

/* Copies an interface name into ifr, always NUL-terminated. */
static void set_ifr_name(struct ifreq *ifr, const char *dev_name) {
    memset(ifr, 0, sizeof(*ifr));
    strncpy(ifr->ifr_name, dev_name, IFNAMSIZ - 1);
}

int tun_create(char *dev_name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    set_ifr_name(&ifr, dev_name ? dev_name : "");
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* layer 3, raw IP only */

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    /* Report back the name the kernel actually gave us. */
    if (dev_name) {
        strncpy(dev_name, ifr.ifr_name, TUN_IFACE_NAME_MAX - 1);
        dev_name[TUN_IFACE_NAME_MAX - 1] = '\0';
    }
    return fd;
}

int tun_configure_addr(const char *dev_name, const char *ip_addr, int prefix_len) {
    if (prefix_len < 0 || prefix_len > 32) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }

    int sock = ctl_socket();
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    int rc = -1;

    /* 1. Set the IPv4 address. */
    set_ifr_name(&ifr, dev_name);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        goto out;
    }

    /* 2. Set the netmask (e.g. /24 -> 255.255.255.0). */
    uint32_t mask = prefix_len == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix_len));
    addr.sin_addr.s_addr = mask;
    set_ifr_name(&ifr, dev_name);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        goto out;
    }

    /* 3. Bring the interface up (read flags, add IFF_UP, write back). */
    set_ifr_name(&ifr, dev_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        goto out;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        goto out;
    }

    rc = 0;
out:
    {
        int saved = errno;
        close(sock);
        errno = saved;
    }
    return rc;
}

int tun_set_mtu(const char *dev_name, int mtu) {
    int sock = ctl_socket();
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    set_ifr_name(&ifr, dev_name);
    ifr.ifr_mtu = mtu;

    int rc = ioctl(sock, SIOCSIFMTU, &ifr) < 0 ? -1 : 0;
    int saved = errno;
    close(sock);
    errno = saved;
    return rc;
}

int tun_read(int fd, unsigned char *buf, size_t buf_len) {
    ssize_t n = read(fd, buf, buf_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  /* non-blocking fd, nothing queued right now */
        }
        return -1;
    }
    return (int)n;
}

int tun_write(int fd, const unsigned char *buf, size_t len) {
    ssize_t n = write(fd, buf, len);
    return n < 0 ? -1 : (int)n;
}

int tun_close(int fd) {
    return close(fd);
}
