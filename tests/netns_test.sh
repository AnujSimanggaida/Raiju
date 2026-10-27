#!/usr/bin/env bash
#
# netns_test.sh - end-to-end test of the encrypted tunnel on one machine.
#
# Builds two isolated network "machines" (network namespaces) joined by a
# virtual cable (veth pair), then runs Raiju on each side:
#
#   [ server ns ]                                [ client ns ]
#   tun0 10.8.0.1                                tun0 10.8.0.2
#   veth0 192.168.50.1  <--- encrypted UDP --->  veth1 192.168.50.2
#
# It pings 10.8.0.2 <-> 10.8.0.1 through the tunnel, and captures traffic
# on both the cable and tun0 to show the ping payload is readable inside
# the tunnel but NOT on the wire.
#
# No root needed: everything runs inside an unprivileged user namespace.
#
# Usage:  tests/netns_test.sh [path-to-binary]     (default: build/mini-vpn)

set -euo pipefail

BIN=$(realpath "${1:-build/mini-vpn}")
PATTERN=c0ffee                       # bytes ping will fill its payload with
TCPDUMP="tcpdump -Z root"          # stay root inside the namespace (no "tcpdump" user there)

# Re-run this script inside a fresh user + network namespace, where we
# are "root" and can create interfaces without affecting the real system.
if [[ "${RAIJU_INSIDE_NS:-}" != 1 ]]; then
    [[ -x "$BIN" ]] || { echo "binary not found: $BIN (build it first)"; exit 1; }
    RAIJU_INSIDE_NS=1 exec unshare --user --map-root-user --net "$0" "$BIN"
fi

WORK=$(mktemp -d)
PIDS=()   # every background process we start, so we can stop them all
stop_all() {
    [[ ${#PIDS[@]} -gt 0 ]] && kill "${PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    PIDS=()
}
cleanup() {
    stop_all
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- Shared key and one config per side ---------------------------------
PSK=$(openssl rand -hex 32)
cat > "$WORK/server.conf" <<EOF
mode = server
listen_port = 51820
tun_addr = 10.8.0.1
psk = $PSK
EOF
cat > "$WORK/client.conf" <<EOF
mode = client
peer_addr = 192.168.50.1
peer_port = 51820
tun_addr = 10.8.0.2
psk = $PSK
EOF

# --- Network: this namespace is the server, a child one is the client ---
ip link set lo up
unshare --net sleep infinity &      # holds the client namespace open
CLIENT_PID=$!; PIDS+=($!)
sleep 0.3
in_client() { nsenter --target "$CLIENT_PID" --net "$@"; }

ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$CLIENT_PID"
ip addr add 192.168.50.1/24 dev veth0
ip link set veth0 up
in_client ip link set lo up
in_client ip addr add 192.168.50.2/24 dev veth1
in_client ip link set veth1 up

# --- Start both peers ----------------------------------------------------
# (nsenter is called directly, not via in_client, so $! is Raiju's own PID)
"$BIN" -v "$WORK/server.conf" > "$WORK/server.log" 2>&1 &
PIDS+=($!)
nsenter --target "$CLIENT_PID" --net "$BIN" -v "$WORK/client.conf" > "$WORK/client.log" 2>&1 &
PIDS+=($!)
sleep 1

# --- Capture on the cable (ciphertext) and on the server's tun0 (plaintext)
$TCPDUMP -i veth0 -nn -U -w "$WORK/wire.pcap" udp 2>/dev/null &
PIDS+=($!)
$TCPDUMP -i tun0  -nn -U -w "$WORK/tun.pcap" icmp 2>/dev/null &
PIDS+=($!)
sleep 1

echo "=== client (10.8.0.2) pings server (10.8.0.1) through the tunnel"
in_client ping -c 3 -W 2 -p "$PATTERN" 10.8.0.1
echo
echo "=== server (10.8.0.1) pings client (10.8.0.2) through the tunnel"
ping -c 3 -W 2 -p "$PATTERN" 10.8.0.2
sleep 0.5

# Stop everything so logs and captures are flushed.
stop_all

# Flatten a capture into one hex string and look for the ping pattern.
hex_of() { $TCPDUMP -nn -x -r "$1" 2>/dev/null | grep -o '0x[0-9a-f]*: .*' | cut -d' ' -f2- | tr -d ' \n'; }
seen() { [[ "$(hex_of "$1")" == *"$PATTERN$PATTERN"* ]]; }

echo
echo "=== what an eavesdropper sees on the cable (first UDP packet)"
$TCPDUMP -nn -X -r "$WORK/wire.pcap" -c 1 2>/dev/null

echo
seen "$WORK/tun.pcap"  && echo "tun0  : ping pattern '$PATTERN' visible (plaintext, as expected)" \
                       || { echo "tun0  : pattern missing?"; FAIL=1; }
seen "$WORK/wire.pcap" && { echo "cable : ping pattern visible - NOT ENCRYPTED"; FAIL=1; } \
                       || echo "cable : ping pattern not found (encrypted)"

echo
echo "=== server log";  grep -E '\[(INFO|WARN|ERROR)' "$WORK/server.log"
echo "=== client log";  grep -E '\[(INFO|WARN|ERROR)' "$WORK/client.log"

[[ -z "${FAIL:-}" ]] && echo && echo "PASS"
