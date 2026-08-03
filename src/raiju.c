#include <stdio.h>
#include <stdlib.h>

#include "tun.h"
#include "transport.h"
#include "crypto.h"
#include "session.h"
#include "config.h"
#include "log.h"
#include "packet.h"
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <config-file-path>\n", prog);
}
int main(int argc, char *argv[]) {
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
if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    log_set_level(LOG_INFO);
    LOG_INFOF("mini-vpn starting, config: %s", argv[1]);

    /* TODO Phase 5: load config
     * vpn_config_t cfg;
     * if (config_load(argv[1], &cfg) != 0) { ... }
     */

    /* TODO Phase 1: create + configure TUN interface
     * char dev_name[TUN_IFACE_NAME_MAX] = "tun0";
     * int tun_fd = tun_create(dev_name);
     * tun_configure_addr(dev_name, cfg.tun_addr, cfg.tun_prefix);
     * tun_set_mtu(dev_name, cfg.mtu);
     */

    /* TODO Phase 2: set up UDP transport
     * transport_ctx_t transport;
     * transport_init(&transport, cfg.listen_port);
     * if (cfg.mode == MODE_CLIENT) transport_set_peer(&transport, cfg.peer_addr, cfg.peer_port);
     */

    /* TODO Phase 3: init crypto + load PSK
     * crypto_init();
     * crypto_ctx_t crypto;
     * crypto_load_key(&crypto, cfg.psk, sizeof(cfg.psk));
     */

    /* TODO Phase 4: init session state, then main event loop
     * session_ctx_t session;
     * session_init(&session);
     *
     * poll()/epoll() over tun_fd and transport.fd:
     *   - on tun_fd readable: tun_read -> crypto_encrypt -> packet_header_write -> transport_send
     *   - on transport.fd readable: transport_recv -> packet_header_read -> session_check_replay
     *       -> crypto_decrypt -> tun_write
     */

    LOG_INFOF("mini-vpn shutting down (not yet implemented)");
    return EXIT_SUCCESS;


}