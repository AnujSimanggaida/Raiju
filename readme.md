Welcome to Raiju, a mini VPN service
# Requirements

- Linux (native, VM, or WSL2) — TUN and network namespaces are Linux-specific
- `gcc`, `make`
- `libsodium-dev`
- Root or `CAP_NET_ADMIN` for TUN interface creation

```bash
sudo apt install build-essential libsodium-dev
```

## Build

```bash
make debug     # with AddressSanitizer + UBSan, for development
make release   # optimized build
make clean
```

## Run

```bash
sudo ./build/mini-vpn config/example.conf
```

Copy `config/example.conf` per peer, generate a real PSK with
`openssl rand -hex 32`, and make sure both peers use the same key.

## Project structure

```
mini-vpn/
├── src/            # implementations
├── include/        # module headers (the contracts — read these first)
├── config/         # example config
├── tests/          # unit + integration tests
├── Makefile
└── README.md
```

## Build phases (see include/*.h for each module's contract)

1. **TUN plumbing** — `tun.c`: open device, configure IP, confirm raw
   packet read/write works (test before touching transport/crypto)
2. **Transport** — `transport.c`: UDP send/recv between two TUN
   devices, *no encryption yet*
3. **Crypto** — `crypto.c`: AEAD encrypt/decrypt with a hardcoded PSK
4. **Framing & replay** — `packet.c` + `session.c`: header format,
   sequence numbers, sliding replay window
5. **Config & CLI** — `config.c`: externalize peer/key/subnet settings
6. **(Stretch)** — `handshake.c`: X25519 key exchange, multi-peer support

## Testing

- Unit tests: crypto roundtrip, tamper detection, replay window logic
  (see `tests/`)
- Integration: `ip netns` + `veth` isolated topology (two isolated
  namespaces, no other route between them — forces traffic through
  the tunnel)
- Verify with `tcpdump`/Wireshark that UDP payloads are ciphertext,
  not visible plaintext IP/ICMP
- Progression: network namespaces → local VMs → two cloud
  instances/physical machines over the real internet

## Threat model / known limitations (v1)

- Static pre-shared key — no per-session key exchange yet, no forward
  secrecy (X25519 handshake is future work)
- Single peer only — no multi-user auth (RADIUS/Kerberos are explicitly
  out of scope for this project)
- No NAT traversal robustness, no DoS resistance — out of scope
- Confidentiality/integrity via AEAD: in scope
- Replay protection via sequence window: in scope
