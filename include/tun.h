#ifndef TUN_H
#define TUN_H

/*
 * tun.h - Virtual network interface (TUN) handling
 *
 * Responsible for:
 *   - Opening /dev/net/tun and creating a TUN interface
 *   - Reading/writing raw IP packets to/from the interface
 *
 * NOT responsible for:
 *   - Assigning IP addresses / bringing the interface up
 *     (that's done via `ip` commands at startup, see tun_configure_addr)
 */

#include <stddef.h>

#define TUN_IFACE_NAME_MAX 16   /* matches IFNAMSIZ */

/* Opens /dev/net/tun and creates/attaches a TUN interface.
 * `dev_name` may be empty to let the kernel pick a name, or a
 * requested name (e.g. "tun0"). On success, `dev_name` is updated
 * in-place with the actual interface name assigned by the kernel.
 * Returns an open file descriptor on success, -1 on error (errno set). */
int tun_create(char *dev_name);

/* Assigns an IP/subnet to the interface and brings it up.
 * e.g. tun_configure_addr("tun0", "10.8.0.1", 24)
 * Returns 0 on success, -1 on error. */
int tun_configure_addr(const char *dev_name, const char *ip_addr, int prefix_len);

/* Sets the MTU on the given interface (e.g. to account for crypto overhead).
 * Returns 0 on success, -1 on error. */
int tun_set_mtu(const char *dev_name, int mtu);

/* Reads a single raw IP packet from the TUN fd into buf (max buf_len bytes).
 * Returns number of bytes read, 0 if nothing available (non-blocking mode),
 * -1 on error (errno set). */
int tun_read(int fd, unsigned char *buf, size_t buf_len);

/* Writes a single raw IP packet to the TUN fd.
 * Returns number of bytes written, -1 on error (errno set). */
int tun_write(int fd, const unsigned char *buf, size_t len);

/* Closes the TUN fd. Interface is torn down automatically unless
 * IFF_PERSIST was set (we don't set it). */
int tun_close(int fd);

#endif /* TUN_H */
