#!/bin/bash
#
# End-to-end test of the ip64 NAT64 service against real host software, over a
# Linux TAP device:
#   1. Start a Python IPv4 echo server on the host (reused from
#      tests/17-tun-rpl-br).
#   2. Run a native node that runs ip64 with its IPv4 side on a TAP device.
#      The node creates the device, gives the host end 192.0.2.1, answers to
#      192.0.2.50 itself, and sends UDP to the echo server through the NAT64
#      prefix.
#   3. Start a small DNS server on the host, which the node is pointed at
#      through the NAT64 prefix.
#   4. Rebuild the node with IP64_CONF_DHCP=1 and run it again against a DHCP
#      server on the host, so that the address comes from a lease, as it does
#      on the Orion border router.
#   5. Assert that the echo server, which knows nothing about NAT64, received
#      IPv4 from 192.0.2.50 (the IPv6->IPv4 leg), that the node received the
#      reflected datagram back over IPv6 (the return leg), that the host can
#      ping 192.0.2.50 (inbound ICMP translation, and ip64 answering the
#      host's ARP request), and that the name lookup worked in both
#      directions: the IPv4 DNS server saw an A query although the node asked
#      for AAAA, and the node ended up with the A record's address behind the
#      NAT64 prefix. For the DHCP run, assert that the server handed out the
#      lease, that the node reports the leased address and router, and that
#      UDP and ping still work with the address it was given.
#
# Creating and configuring the TAP device needs CAP_NET_ADMIN. Without it the
# test fails, unless IP64_TAP_ALLOW_SKIP=1 is set for a local run.
#
# Author: Nicolas Tsiftes <nicolas.tsiftes@ri.se>

set -u

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTIKI="$THIS_DIR/../.."
NODE_DIR="$THIS_DIR/code-ip64-tap"
ECHO_SERVER="$CONTIKI/tests/17-tun-rpl-br/nat64-echo-server.py"

UDP_PORT=5557
TCP_PORT=5558
NODE_IPV4=192.0.2.50
HOST_IPV4=192.0.2.1
TAP_DEV="${IP64_TAP_DEV:-tap0}"
DNS_PORT=53
LOOKUP_NAME=ip64-test.example
# The answer differs from the DNS server's own address, so the address the
# node reports can only have come from the A record.
LOOKUP_ANSWER=192.0.2.99
LOOKUP_EXPECTED="64:ff9b::192.0.2.99"
RUN_TIME=60

NODE_BIN="$NODE_DIR/build/native/ip64-tap-node.native"
BUILD_LOG="$THIS_DIR/ip64-tap.buildlog"
NODE_LOG="$THIS_DIR/ip64-tap.nodelog"
ECHO_LOG="$THIS_DIR/ip64-tap.echo.log"
ECHO_PIDFILE="$THIS_DIR/ip64-tap.echo.pid"
DNS_LOG="$THIS_DIR/ip64-tap.dns.log"
DNS_PIDFILE="$THIS_DIR/ip64-tap.dns.pid"
DHCP_LOG="$THIS_DIR/ip64-tap.dhcp.log"
DHCP_PIDFILE="$THIS_DIR/ip64-tap.dhcp.pid"
DHCP_NODE_LOG="$THIS_DIR/ip64-tap.dhcp.nodelog"
DHCP_PING_LOG="$THIS_DIR/ip64-tap.dhcp.ping.log"
DHCP_ECHO_LOG="$THIS_DIR/ip64-tap.dhcp.echo.log"
DHCP_ECHO_PIDFILE="$THIS_DIR/ip64-tap.dhcp.echo.pid"
PING_LOG="$THIS_DIR/ip64-tap.ping.log"

NODE_PID=
WATCHDOG_PID=

# The node runs directly rather than under timeout(1), so that NODE_PID is
# the node itself. Killing a timeout(1) wrapper does not reach the process it
# runs on every implementation, and a node that survives keeps the TAP device
# open, which the second phase then cannot create. The watchdog that enforces
# RUN_TIME goes first when the node is stopped, so that it cannot fire at a
# reused pid once the next node has started.
start_node() {
  local log=$1

  "$NODE_BIN" >"$log" 2>&1 &
  NODE_PID=$!
  ( sleep "$RUN_TIME"; kill "$NODE_PID" 2>/dev/null ) &
  WATCHDOG_PID=$!
}

stop_node() {
  if [ -n "$WATCHDOG_PID" ]; then
    kill "$WATCHDOG_PID" 2>/dev/null
    WATCHDOG_PID=
  fi
  if [ -n "$NODE_PID" ]; then
    kill "$NODE_PID" 2>/dev/null
    wait "$NODE_PID" 2>/dev/null
    NODE_PID=
  fi
}

stop_pidfile() {
  local pidfile=$1
  local pid

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null || true)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
    rm -f "$pidfile"
  fi
}

cleanup() {
  stop_node
  for PIDFILE in "$ECHO_PIDFILE" "$DNS_PIDFILE" "$DHCP_PIDFILE" \
                 "$DHCP_ECHO_PIDFILE"; do
    if [ -f "$PIDFILE" ]; then
      PID=$(cat "$PIDFILE" 2>/dev/null || true)
      [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
  done
  # The TAP device is not persistent: it disappears with the node's fd.
}
trap cleanup EXIT INT TERM

rm -f "$BUILD_LOG" "$NODE_LOG" "$ECHO_LOG" "$ECHO_PIDFILE" "$PING_LOG" \
      "$DNS_LOG" "$DNS_PIDFILE" "$DHCP_LOG" "$DHCP_PIDFILE" \
      "$DHCP_NODE_LOG" "$DHCP_PING_LOG" "$DHCP_ECHO_LOG" \
      "$DHCP_ECHO_PIDFILE"

# Creating the TAP device needs CAP_NET_ADMIN. CI runs this in a privileged
# container, but as an ordinary user with passwordless sudo, so take that
# route when it is there rather than refusing to run.
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true 2>/dev/null; then
    echo "Not running as root; continuing under sudo"
    exec sudo -E "$0" "$@"
  fi

  if [ "${IP64_TAP_ALLOW_SKIP:-0}" = "1" ]; then
    echo "SKIP: no way to get CAP_NET_ADMIN, and IP64_TAP_ALLOW_SKIP=1 is set"
    exit 0
  fi

  echo "FAIL: this test needs CAP_NET_ADMIN to create the TAP device."
  echo "      Run it as root, arrange passwordless sudo, or set"
  echo "      IP64_TAP_ALLOW_SKIP=1 to skip it."
  exit 1
fi

# With the capability in hand, the device node still has to be there. In a
# container that means the host's /dev, which is what --privileged gives.
if [ ! -c /dev/net/tun ]; then
  echo "FAIL: /dev/net/tun is missing, so no TAP device can be created."
  echo "      A container needs --privileged, or at least this device."
  exit 1
fi

echo "Building the ip64 TAP node"
# Build as the invoking user where there is one, so that a local run under
# sudo does not leave root-owned files in the build directory.
BUILD_CMD=(make -C "$NODE_DIR" -B TARGET=native ip64-tap-node)
if [ -n "${SUDO_USER:-}" ] && command -v sudo >/dev/null 2>&1; then
  BUILD_CMD=(sudo -u "$SUDO_USER" "${BUILD_CMD[@]}")
fi
if ! "${BUILD_CMD[@]}" >"$BUILD_LOG" 2>&1; then
  echo "FAIL: node build failed"
  tail -n 40 "$BUILD_LOG"
  exit 1
fi

echo "Running the node (up to ${RUN_TIME}s)"
start_node "$NODE_LOG"

for _ in $(seq 1 10); do
  grep -q "IP64_TAP_READY" "$NODE_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "IP64_TAP_READY" "$NODE_LOG" 2>/dev/null; then
  echo "FAIL: the node did not come up"
  cat "$NODE_LOG" 2>/dev/null || true
  exit 1
fi

# Both servers bind the TAP address rather than every address, so that they
# do not collide with a resolver or another service already on this machine.
# That address exists only once the node has created the device, which is why
# they start here rather than before it. The node retransmits, so the first
# few requests going nowhere costs nothing.
echo "Starting IPv4 echo server on $HOST_IPV4 (UDP $UDP_PORT)"
python3 "$ECHO_SERVER" \
  --host "$HOST_IPV4" \
  --udp-port "$UDP_PORT" \
  --tcp-port "$TCP_PORT" \
  --log "$ECHO_LOG" \
  --pidfile "$ECHO_PIDFILE" &

for _ in 1 2 3 4 5; do
  grep -q "UDP_LISTEN" "$ECHO_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "UDP_LISTEN" "$ECHO_LOG" 2>/dev/null; then
  echo "FAIL: echo server did not start"
  cat "$ECHO_LOG" 2>/dev/null || true
  exit 1
fi

echo "Starting DNS server on $HOST_IPV4 (UDP $DNS_PORT), $LOOKUP_NAME"
python3 "$THIS_DIR/dns-server.py" \
  --host "$HOST_IPV4" \
  --port "$DNS_PORT" \
  --name "$LOOKUP_NAME" \
  --answer "$LOOKUP_ANSWER" \
  --log "$DNS_LOG" \
  --pidfile "$DNS_PIDFILE" &

for _ in 1 2 3 4 5; do
  grep -q "DNS_LISTEN" "$DNS_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "DNS_LISTEN" "$DNS_LOG" 2>/dev/null; then
  echo "FAIL: DNS server did not start"
  cat "$DNS_LOG" 2>/dev/null || true
  exit 1
fi

# The node retransmits every two seconds, so a few seconds are enough for the
# round trip and for the ARP exchange that precedes it.
for _ in $(seq 1 10); do
  grep -q "IP64_TAP_ECHO_OK" "$NODE_LOG" 2>/dev/null && \
    grep -q "IP64_TAP_DNS_OK" "$NODE_LOG" 2>/dev/null && break
  sleep 1
done

echo "Pinging the node at $NODE_IPV4 from the host"
ping -c 3 -W 2 "$NODE_IPV4" >"$PING_LOG" 2>&1
PING_STATUS=$?

STATUS=0

if grep -q "UDP_ECHO from=$NODE_IPV4:.*payload=b'PING-IP64-TAP'" \
   "$ECHO_LOG" 2>/dev/null; then
  echo "PASS: echo server received translated IPv4 from $NODE_IPV4"
else
  echo "FAIL: echo server saw no IPv4 datagram from the node (IPv6->IPv4 leg)"
  STATUS=1
fi

if grep -q "IP64_TAP_ECHO_OK" "$NODE_LOG" 2>/dev/null; then
  echo "PASS: node received the reflected datagram back over IPv6"
else
  echo "FAIL: node did not log IP64_TAP_ECHO_OK (IPv4->IPv6 return leg)"
  STATUS=1
fi

if [ $PING_STATUS -eq 0 ]; then
  echo "PASS: the host can ping the node at $NODE_IPV4"
else
  echo "FAIL: the host could not ping the node (inbound ICMP or ARP)"
  STATUS=1
fi

# The node asks for AAAA (resolv.c queries NATIVE_DNS_TYPE), so an A query
# arriving at an IPv4-only server is the DNS64 rewrite doing its work.
if grep -q "DNS_QUERY .*name=$LOOKUP_NAME qtype=1" "$DNS_LOG" 2>/dev/null; then
  echo "PASS: DNS server received an A query for $LOOKUP_NAME"
elif grep -q "qtype=28" "$DNS_LOG" 2>/dev/null; then
  echo "FAIL: DNS server saw the AAAA query unrewritten (DNS64 outbound)"
  STATUS=1
else
  echo "FAIL: DNS server saw no query for $LOOKUP_NAME"
  STATUS=1
fi

if grep -q "IP64_TAP_DNS_OK $LOOKUP_NAME $LOOKUP_EXPECTED" \
   "$NODE_LOG" 2>/dev/null; then
  echo "PASS: node resolved $LOOKUP_NAME to $LOOKUP_EXPECTED"
else
  echo "FAIL: node did not resolve $LOOKUP_NAME to $LOOKUP_EXPECTED"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# Second phase: the same node, but taking its address from DHCP, as the Orion
# border router does.
# ---------------------------------------------------------------------------

# The servers of the first phase are bound to an address that goes away with
# the device, and their ports would collide with the ones started below.
echo "Stopping the first node and its servers"
stop_node
stop_pidfile "$ECHO_PIDFILE"
stop_pidfile "$DNS_PIDFILE"

echo "Rebuilding the node with IP64_CONF_DHCP=1"
BUILD_CMD=(make -C "$NODE_DIR" -B TARGET=native DEFINES=IP64_CONF_DHCP=1
           ip64-tap-node)
if [ -n "${SUDO_USER:-}" ] && command -v sudo >/dev/null 2>&1; then
  BUILD_CMD=(sudo -u "$SUDO_USER" "${BUILD_CMD[@]}")
fi
if ! "${BUILD_CMD[@]}" >>"$BUILD_LOG" 2>&1; then
  echo "FAIL: DHCP node build failed"
  tail -n 40 "$BUILD_LOG"
  exit 1
fi

echo "Running the node again, this time without a configured address"
start_node "$DHCP_NODE_LOG"

for _ in $(seq 1 10); do
  grep -q "IP64_TAP_DEVICE_UP" "$DHCP_NODE_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "IP64_TAP_DEVICE_UP" "$DHCP_NODE_LOG" 2>/dev/null; then
  echo "FAIL: the node did not bring up the TAP device"
  cat "$DHCP_NODE_LOG" 2>/dev/null || true
  exit 1
fi

# Bound to the TAP device, so serving 0.0.0.0:67, which is what receiving a
# broadcast takes, cannot disturb the rest of the machine.
echo "Starting DHCP server on $TAP_DEV, offering $NODE_IPV4"
python3 "$THIS_DIR/dhcp-server.py" \
  --device "$TAP_DEV" \
  --offer "$NODE_IPV4" \
  --server "$HOST_IPV4" \
  --router "$HOST_IPV4" \
  --log "$DHCP_LOG" \
  --pidfile "$DHCP_PIDFILE" &

for _ in 1 2 3 4 5; do
  grep -q "DHCP_LISTEN" "$DHCP_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "DHCP_LISTEN" "$DHCP_LOG" 2>/dev/null; then
  echo "FAIL: DHCP server did not start"
  cat "$DHCP_LOG" 2>/dev/null || true
  exit 1
fi

# The echo server from the first phase lost its interface when the first node
# exited, so it is restarted for this one.
echo "Restarting the echo server on $HOST_IPV4 for the DHCP run"
python3 "$ECHO_SERVER" \
  --host "$HOST_IPV4" \
  --udp-port "$UDP_PORT" \
  --tcp-port "$TCP_PORT" \
  --log "$DHCP_ECHO_LOG" \
  --pidfile "$DHCP_ECHO_PIDFILE" &

for _ in 1 2 3 4 5; do
  grep -q "UDP_LISTEN" "$DHCP_ECHO_LOG" 2>/dev/null && break
  sleep 1
done
if ! grep -q "UDP_LISTEN" "$DHCP_ECHO_LOG" 2>/dev/null; then
  echo "FAIL: echo server did not restart"
  cat "$DHCP_ECHO_LOG" 2>/dev/null || true
  exit 1
fi

for _ in $(seq 1 15); do
  grep -q "IP64_TAP_ECHO_OK" "$DHCP_NODE_LOG" 2>/dev/null && break
  sleep 1
done

echo "Pinging the leased address $NODE_IPV4 from the host"
ping -c 3 -W 2 "$NODE_IPV4" >"$DHCP_PING_LOG" 2>&1
DHCP_PING_STATUS=$?

if grep -q "DHCP_ACK ip=$NODE_IPV4" "$DHCP_LOG" 2>/dev/null; then
  echo "PASS: DHCP server leased $NODE_IPV4 to the node"
else
  echo "FAIL: DHCP server did not get to acknowledge a lease"
  STATUS=1
fi

if grep -q "IP64_TAP_LEASE $NODE_IPV4 router $HOST_IPV4" \
   "$DHCP_NODE_LOG" 2>/dev/null; then
  echo "PASS: node configured itself from the lease"
else
  echo "FAIL: node did not report the leased address and router"
  STATUS=1
fi

if grep -q "IP64_TAP_ECHO_OK" "$DHCP_NODE_LOG" 2>/dev/null; then
  echo "PASS: UDP works with the leased address"
else
  echo "FAIL: no UDP round trip after the lease"
  STATUS=1
fi

if [ $DHCP_PING_STATUS -eq 0 ]; then
  echo "PASS: the host can ping the leased address"
else
  echo "FAIL: the host could not ping the leased address"
  STATUS=1
fi

if [ $STATUS -ne 0 ]; then
  echo "==== DHCP node log ===="
  cat "$DHCP_NODE_LOG" 2>/dev/null || true
  echo "==== DHCP server log ===="
  cat "$DHCP_LOG" 2>/dev/null || true
  echo "==== DHCP echo server log ===="
  cat "$DHCP_ECHO_LOG" 2>/dev/null || true
  echo "==== DHCP ping log ===="
  cat "$DHCP_PING_LOG" 2>/dev/null || true
  echo "==== node log ===="
  cat "$NODE_LOG" 2>/dev/null || true
  echo "==== echo server log ===="
  cat "$ECHO_LOG" 2>/dev/null || true
  echo "==== ping log ===="
  cat "$PING_LOG" 2>/dev/null || true
  echo "==== DNS server log ===="
  cat "$DNS_LOG" 2>/dev/null || true
fi

exit $STATUS
