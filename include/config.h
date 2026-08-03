#ifndef CONFIG_H
#define CONFIG_H

/*
 * config.h - Config file loading
 *
 * v1 format (plain key=value, one per line, '#' comments), e.g.:
 *
 *   mode = client          # or "server"
 *   peer_addr = 203.0.113.5
 *   peer_port = 51820
 *   listen_port = 51820
 *   tun_addr = 10.8.0.2
 *   tun_prefix = 24
 *   mtu = 1400
 *   psk = <hex-encoded 32-byte key>
 */

#define CONFIG_MAX_STR 128

typedef enum {
    MODE_CLIENT,
    MODE_SERVER
} vpn_mode_t;

typedef struct {
    vpn_mode_t mode;
    char peer_addr[CONFIG_MAX_STR];
    int  peer_port;
    int  listen_port;
    char tun_addr[CONFIG_MAX_STR];
    int  tun_prefix;
    int  mtu;
    unsigned char psk[32];
} vpn_config_t;

/* Loads and parses a config file into `cfg`. Applies defaults for any
 * unset optional fields (e.g. mtu, listen_port). Returns 0 on success,
 * -1 on error (missing required field, unreadable file, bad psk, etc). */
int config_load(const char *path, vpn_config_t *cfg);

#endif /* CONFIG_H */
