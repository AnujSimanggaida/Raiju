# Raiju

Raiju is a small point-to-point VPN written in C. It takes IP packets from a
virtual network interface, encrypts them, and sends them over UDP to a peer,
which decrypts them and hands them to its own virtual interface.

## Requirements

- Linux (native, VM, or WSL2). TUN devices and network namespaces are Linux-only.
- `gcc`, `make`
- `libsodium` development headers (not needed for the TUN demo)
- `libasan` / `libubsan` for `make debug` only
- `tcpdump` and `openssl` for the end-to-end test
- Root or `CAP_NET_ADMIN` to create TUN interfaces

```bash
sudo apt install build-essential libsodium-dev tcpdump           # Debian / Ubuntu
sudo dnf install gcc make libsodium-devel libasan libubsan tcpdump  # Fedora
```

## Build

The build file is named `MakeFile` (capital F), so `make` needs `-f`:

```bash
make -f MakeFile release      # optimized build -> build/mini-vpn
make -f MakeFile debug        # with AddressSanitizer + UBSan, for development
make -f MakeFile test         # unit tests
make -f MakeFile netns-test   # full encrypted tunnel test on one machine
make -f MakeFile clean
```

## Run

One machine is the **server** (10.8.0.1 in the tunnel), the other is the
**client** (10.8.0.2).

1. Generate one key and paste it into the `psk =` line of **both**
   `config/server.conf` and `config/client.conf`:
   ```bash
   openssl rand -hex 32
   ```
2. In `config/client.conf`, set `peer_addr` to the server's real IP.
3. Start the server, then the client:
   ```bash
   sudo ./build/mini-vpn config/server.conf     # on the server
   sudo ./build/mini-vpn config/client.conf     # on the client
   ```
4. From the client: `ping 10.8.0.1`. From the server: `ping 10.8.0.2`
   (works once the client has sent at least one packet).

Add `-v` to log every packet. Ctrl+C prints counters (sent, received,
dropped) and removes `tun0`.

To try it without two machines, run `make -f MakeFile netns-test`
(see [Testing](#testing)).

---

## How the code works

### The big picture

Each peer runs one Raiju process. That process sits between two "ends":

- **The TUN interface** (`tun0`): a virtual network card. Programs on the
  machine send traffic to it like any other interface, but instead of going
  out a cable, the packets are handed to Raiju through a file descriptor.
- **A UDP socket**: the real network connection to the other peer.

Raiju's job is to move packets between those two ends, encrypting on the way
out and decrypting on the way in.

```
 Outgoing (this machine -> peer)

   app (ping, curl, ...)
        |
        v
   kernel routes packet to tun0
        |
        v
   tun_read()                      raw IP packet
        |
        v
   session_next_send_seq()         pick sequence number
   packet_header_write()           write version/type/seq into the header
   crypto_encrypt()                fresh nonce into the header, then
                                   ciphertext + auth tag after it
                                   (header is authenticated too)
        |
        v
   transport_send()                UDP datagram to peer
```

```
 Incoming (peer -> this machine)

   transport_recv()                UDP datagram from peer
        |
        v
   packet_header_read()            parse version/type/seq/nonce
   crypto_decrypt()                verify tag (body AND header),
                                   recover raw IP packet
   session_check_replay()          drop duplicates / old packets
   transport_update_peer()         server only: reply to this sender
        |
        v
   tun_write()                     inject packet into tun0
        |
        v
   kernel delivers packet to the app
```

`raiju.c` ties this together with a single `poll()` loop that waits on both
file descriptors (the TUN fd and the UDP socket) and runs whichever path is
ready: `handle_tun_packet()` for outgoing, `handle_udp_packet()` for incoming.

**Why this order on the incoming side?** Each check runs only after the
packet has passed the one before it:

- The replay check comes *after* decryption. Otherwise an attacker could
  send a fake packet with a huge sequence number, push the replay window
  forward, and make every real packet look "too old".
- The server only updates its peer address *after* a packet authenticates.
  Otherwise one spoofed UDP packet could redirect all your traffic.
- The header (version, type, seq) is fed to the cipher as "associated data".
  It travels in plaintext, but changing even one bit makes decryption fail.

### What each file does

Every module has a header in `include/` that is the contract (what each
function promises) and a matching `.c` file in `src/` that implements it.
Read the headers first.

| File | Role | Depends on |
|------|------|------------|
| `src/raiju.c` | `main()`: loads config, sets up every module, runs the event loop | all modules |
| `include/tun.h`, `src/tun.c` | Creates the virtual interface and reads/writes raw IP packets | Linux kernel only |
| `include/transport.h`, `src/transport.c` | UDP socket: send/receive bytes to/from the peer | Linux sockets |
| `include/crypto.h`, `src/crypto.c` | Encrypt/decrypt with ChaCha20-Poly1305 using a pre-shared key | libsodium |
| `include/packet.h`, `src/packet.c` | Writes/parses the on-wire header in front of each encrypted packet | `crypto.h` (for nonce size) |
| `include/session.h`, `src/session.c` | Sequence numbers and replay protection | nothing |
| `include/config.h`, `src/config.c` | Reads the `key = value` config file | nothing |
| `include/log.h`, `src/log.c` | Leveled logging (`LOG_INFOF(...)` etc.) | nothing |
| `config/server.conf`, `config/client.conf` | Example settings for each side | |
| `tests/test_units.c` | Unit tests for crypto, packet and session | those modules |
| `tests/netns_test.sh` | End-to-end test: two namespaces, real tunnel, tcpdump check | built binary |
| `demo/tun_demo.c`, `demo/Makefile` | Standalone test of `tun.c` with no networking or crypto | `tun.c` |

The modules don't call each other. Only `raiju.c` calls them, and it passes
data from one to the next. That keeps each module testable on its own.

### Functions, module by module

#### `tun` (implemented)

| Function | What it does |
|----------|--------------|
| `tun_create(dev_name)` | Opens `/dev/net/tun` and asks the kernel (ioctl `TUNSETIFF`) for a TUN interface with that name, e.g. `"tun0"`. Uses `IFF_NO_PI` so every read/write is exactly one raw IP packet with no extra header. Writes the final name back into `dev_name` and returns the fd. |
| `tun_configure_addr(dev, ip, prefix)` | Gives the interface an IPv4 address and netmask and marks it UP, using ioctls on a temporary socket (`SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`). Same effect as `ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up`. |
| `tun_set_mtu(dev, mtu)` | Sets the interface MTU (`SIOCSIFMTU`). The VPN needs a smaller MTU than the real network because each packet gains a 22-byte header and a 16-byte auth tag, plus UDP/IP headers. |
| `tun_read(fd, buf, len)` | Reads one packet that the kernel routed to the interface. Returns 0 if the fd is non-blocking and nothing is waiting. |
| `tun_write(fd, buf, len)` | Injects one packet. The kernel treats it as if it arrived on the interface from the network. |
| `tun_close(fd)` | Closes the fd. Because the interface isn't persistent, the kernel deletes it. |

#### `transport`

| Function | What it does |
|----------|--------------|
| `transport_init(ctx, port)` | Creates a non-blocking UDP socket and binds it on all addresses (port 0 = let the OS pick, for clients). |
| `transport_set_peer(ctx, ip, port)` | Client side: records the server's address from config. |
| `transport_update_peer(ctx, addr)` | Server side: called after a packet authenticates, so replies go to wherever the client really is (handles the client's port changing behind NAT). |
| `transport_send(ctx, buf, len)` | Sends one datagram to the peer. Fails with `ENOTCONN` if there's no peer yet. |
| `transport_recv(ctx, buf, len, from)` | Receives one datagram and reports who sent it in `from`. It does **not** trust the sender; that's the caller's job after decryption. |
| `transport_close(ctx)` | Closes the socket. |

#### `crypto`

Uses ChaCha20-Poly1305, an AEAD cipher: it encrypts the data and also
produces a 16-byte tag that proves nobody changed it. It can also
authenticate extra bytes without encrypting them (the "associated data"),
which is how the header is protected.

| Function | What it does |
|----------|--------------|
| `crypto_init()` | Calls `sodium_init()`. Must run once before any other crypto call. |
| `crypto_load_key(ctx, key, len)` | Stores the 32-byte pre-shared key. |
| `crypto_wipe(ctx)` | Erases the key from memory at shutdown. |
| `crypto_encrypt(ctx, pt, len, ad, ad_len, nonce_out, ct_out)` | Makes a random 12-byte nonce and encrypts. Output is ciphertext followed by the tag. `ad` (the header) is authenticated but stays readable. |
| `crypto_decrypt(ctx, nonce, ad, ad_len, ct, len, pt_out)` | Checks the tag and decrypts. Returns -1 for a wrong key, a changed packet or a changed header. |

#### `packet`

Each UDP datagram looks like this (22-byte header, then the encrypted packet):

```
| version (1) | type (1) | seq (8, big-endian) | nonce (12) | ciphertext + tag |
|<------- authenticated (PACKET_AD_LEN) ------>|
```

A 1400-byte IP packet becomes 1400 + 22 + 16 = 1438 bytes of UDP payload,
plus 28 bytes of UDP/IP headers = 1466, which fits in a normal 1500 MTU.

| Function | What it does |
|----------|--------------|
| `packet_header_write(hdr, buf, len)` | Serializes the header struct into bytes (seq as big-endian, using shifts). |
| `packet_header_read(buf, len, hdr)` | Parses bytes into the struct. Rejects short buffers and unknown versions. |

#### `session`

| Function | What it does |
|----------|--------------|
| `session_init(sess)` | Starts the send counter at `unix_time << 32` and clears the replay window. Because of the clock, a restarted peer keeps using higher numbers instead of starting at 0, which the other side would reject as replays. |
| `session_next_send_seq(sess)` | Returns the next outgoing sequence number. |
| `session_check_replay(sess, seq)` | Uses a 64-bit sliding window to accept each sequence number once. Out-of-order packets inside the window are fine (UDP can reorder); duplicates and anything older than 64 packets are dropped. |

#### `config`

| Function | What it does |
|----------|--------------|
| `config_load(path, cfg)` | Parses lines like `peer_port = 51820`, skips `#` comments, fills defaults (port 51820, prefix 24, MTU 1400), decodes the hex PSK. Required: `mode`, `tun_addr`, `psk`, plus `peer_addr` for clients. Prints the line number of any bad value. |

#### `log`

| Function | What it does |
|----------|--------------|
| `log_set_level(level)` | Messages below this level are not printed. Default `LOG_INFO`. |
| `log_write(level, fmt, ...)` | printf-style output with a level tag. Usually called through `LOG_ERRORF`, `LOG_WARNF`, `LOG_INFOF`, `LOG_DEBUGF`. |

---

## TUN demo (phase 1)

`demo/tun_demo.c` checks that the TUN layer works before any networking or
crypto exists. It:

1. creates `tun0`, gives it `10.8.0.1/24` and MTU 1400,
2. prints every packet the kernel sends into `tun0` (source, destination,
   protocol, first bytes in hex),
3. for each ping (ICMP echo request), swaps the source and destination,
   turns it into an echo reply, fixes the checksums, and writes it back
   into `tun0`.

Step 3 is how the demo shows packet injection: `ping` receives replies from
an address that doesn't exist, because the demo made them up.

```bash
cd demo
make
sudo ./tun_demo          # terminal 1
ping 10.8.0.2            # terminal 2 (any 10.8.0.x except .1)
```

Pinging `10.8.0.1` will not reach the demo. That address belongs to your
machine, so the kernel answers it over loopback without touching `tun0`.

You may also see IPv6 packets show up. Those are normal: the kernel sends
router solicitations on any new interface.

To try it without sudo, run it in a private network namespace:

```bash
unshare -rn sh -c 'ip link set lo up; ./tun_demo & sleep 1; ping -c 3 10.8.0.2; kill -INT $!'
```

---

## Project structure

```
Raiju/
├── src/            # implementations
├── include/        # module headers (the contracts, read these first)
├── demo/           # standalone demos (tun_demo.c + its own Makefile)
├── config/         # example server/client configs
├── tests/          # unit tests + end-to-end namespace test
├── MakeFile
└── readme.md
```

## Build phases (see include/*.h for each module's contract)

1. **TUN plumbing** (done): `tun.c`: open device, configure IP, confirm raw
   packet read/write works. Verified with `demo/tun_demo.c`.
2. **Transport** (done): `transport.c`: UDP send/recv between peers
3. **Crypto** (done): `crypto.c`: AEAD encrypt/decrypt with a PSK
4. **Framing & replay** (done): `packet.c` + `session.c`: header format,
   sequence numbers, sliding replay window
5. **Config & CLI** (done): `config.c`: peer/key/subnet settings per side
6. **(Stretch)**: `handshake.c`: X25519 key exchange, multi-peer support

## Testing

**Unit tests** (`make -f MakeFile test`): `tests/test_units.c` checks:
- crypto round trip
- that wrong keys, flipped bits, a changed header and truncated packets
  are all rejected
- header byte layout
- replay window edge cases

**End-to-end** (`make -f MakeFile netns-test`): `tests/netns_test.sh`
needs no root. It runs inside an unprivileged user namespace and builds
this:

```
[ server namespace ]                          [ client namespace ]
tun0  10.8.0.1                                tun0  10.8.0.2
veth0 192.168.50.1  <--- encrypted UDP --->   veth1 192.168.50.2
```

It then:
1. pings in both directions through the tunnel, with a recognizable
   payload (`c0ffee`)
2. captures traffic on `tun0` and on the cable
3. checks that the pattern is visible on `tun0` (plaintext) but not on
   the cable (ciphertext), and prints a packet as an eavesdropper sees it

Next step: two VMs or machines over a real network.

## Threat model / known limitations (v1)

- Static pre-shared key: no per-session key exchange yet, no forward
  secrecy (X25519 handshake is future work)
- Single peer only: no multi-user auth (RADIUS/Kerberos are explicitly
  out of scope for this project)
- No NAT traversal robustness, no DoS resistance: out of scope
- Confidentiality/integrity via AEAD: in scope
- Replay protection via sequence window: in scope
