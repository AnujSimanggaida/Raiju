#define _DEFAULT_SOURCE

#include "config.h"
#include "log.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* config.c - see include/config.h for the contract */

#define LINE_MAX_LEN 512

/* Removes leading and trailing whitespace in place; returns the new start. */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return s;
}

/* Parses a whole-string integer in [min, max]. Returns 0 on success. */
static int parse_int(const char *s, int min, int max, int *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < min || v > max) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes exactly out_len bytes of hex (2 chars per byte). Returns 0 on success. */
static int parse_hex(const char *s, unsigned char *out, size_t out_len) {
    if (strlen(s) != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value(s[2 * i]);
        int lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return 0;
}

/* Copies a string value into a fixed-size field. Returns 0 if it fit. */
static int copy_str(char *dst, const char *src) {
    if (strlen(src) >= CONFIG_MAX_STR) {
        return -1;
    }
    strcpy(dst, src);
    return 0;
}

int config_load(const char *path, vpn_config_t *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERRORF("config: can't open %s", path);
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->peer_port = 51820;
    cfg->listen_port = -1;  /* -1 = "not set", resolved after parsing */
    cfg->tun_prefix = 24;
    cfg->mtu = 1400;

    int have_mode = 0, have_tun_addr = 0, have_psk = 0;
    int rc = 0;
    char line[LINE_MAX_LEN];
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        char *hash = strchr(line, '#');  /* drop comments */
        if (hash) {
            *hash = '\0';
        }
        char *s = trim(line);
        if (*s == '\0') {
            continue;  /* blank line */
        }

        char *eq = strchr(s, '=');
        if (!eq) {
            LOG_ERRORF("config:%d: expected 'key = value'", lineno);
            rc = -1;
            break;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        int bad = 0;

        if (strcmp(key, "mode") == 0) {
            if (strcmp(val, "client") == 0)      cfg->mode = MODE_CLIENT;
            else if (strcmp(val, "server") == 0) cfg->mode = MODE_SERVER;
            else bad = 1;
            have_mode = !bad;
        } else if (strcmp(key, "peer_addr") == 0) {
            bad = copy_str(cfg->peer_addr, val);
        } else if (strcmp(key, "peer_port") == 0) {
            bad = parse_int(val, 1, 65535, &cfg->peer_port);
        } else if (strcmp(key, "listen_port") == 0) {
            bad = parse_int(val, 0, 65535, &cfg->listen_port);
        } else if (strcmp(key, "tun_addr") == 0) {
            bad = copy_str(cfg->tun_addr, val);
            have_tun_addr = !bad;
        } else if (strcmp(key, "tun_prefix") == 0) {
            bad = parse_int(val, 0, 32, &cfg->tun_prefix);
        } else if (strcmp(key, "mtu") == 0) {
            bad = parse_int(val, 576, 1500, &cfg->mtu);
        } else if (strcmp(key, "psk") == 0) {
            bad = parse_hex(val, cfg->psk, sizeof(cfg->psk));
            have_psk = !bad;
        } else {
            LOG_WARNF("config:%d: unknown key '%s' (ignored)", lineno, key);
        }

        if (bad) {
            LOG_ERRORF("config:%d: bad value for '%s'", lineno, key);
            rc = -1;
            break;
        }
    }
    fclose(f);

    if (rc == 0) {
        if (!have_mode)     { LOG_ERRORF("config: 'mode' is required"); rc = -1; }
        if (!have_tun_addr) { LOG_ERRORF("config: 'tun_addr' is required"); rc = -1; }
        if (!have_psk)      { LOG_ERRORF("config: 'psk' is required (64 hex chars, try: openssl rand -hex 32)"); rc = -1; }
        if (have_mode && cfg->mode == MODE_CLIENT && cfg->peer_addr[0] == '\0') {
            LOG_ERRORF("config: 'peer_addr' is required in client mode");
            rc = -1;
        }
    }

    /* Servers listen on a fixed port; clients default to any free port. */
    if (cfg->listen_port < 0) {
        cfg->listen_port = cfg->mode == MODE_SERVER ? 51820 : 0;
    }
    return rc;
}
