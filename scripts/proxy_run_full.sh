#!/bin/bash
# Proxy-side SLAC (AcCCS, both roles) + HLC (proxy01.py) launcher.
#
# Runs two AcCCS SLAC_ONLY handshakes concurrently -- one per HLC leg -- so
# the proxy also intercepts SLAC, not just HLC:
#   - PEV role on proxy_net1 (SECC-facing): SECC's own EVSE.py completes
#     SLAC against the proxy, believing it's talking to the real EVCC.
#   - EVSE role on proxy_net2 (EVCC-facing): EVCC's own PEV.py completes
#     SLAC against the proxy, believing it's talking to the real SECC.
#
# Both mod_acccs SLACHandlers already retry a timed-out SLAC_PARM.REQ up to
# twice (8s timeout each, ~24s worst case), the same budget the bounded
# `timeout 20` below assumes -- matching the pattern already used in
# secc_run_full.sh/evcc_run_full.sh. Run both roles concurrently (one
# backgrounded) rather than sequentially (like AcCCS's own MIM.py reference
# does) since SECC and EVCC each start their own SLAC step independently
# and don't wait for each other.
#
# EVSE.py/PEV.py default sourceMAC/sourceIP to the interface's own MAC/
# link-local IPv6 when not passed explicitly, so each role naturally
# assumes the proxy's own identity on that leg -- no hardcoded MAC/IP
# needed (unlike AcCCS's MIM.py reference, which hardcodes both).
#
# Once both SLAC roles finish (or time out), hands off to proxy01.py for
# the existing HLC MITM (SDP hijack + TCP/TLS/EXI relay) -- unchanged.
#
# Which of this container's interfaces (eth0/eth1) is which is resolved by
# subnet at runtime, NOT assumed by name, same as proxy01.py's own
# discover_secc_evcc_interfaces() and the other *_run_full.sh scripts.
set -uo pipefail

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

PROXY_NET1_IFACE="$(resolve_iface '172\.20\.' '2001:db8:1:')"   # SECC-facing
PROXY_NET2_IFACE="$(resolve_iface '172\.19\.' '2001:db8:2:')"   # EVCC-facing

if [ -z "$PROXY_NET1_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net1 (172.20.0.0/16 / 2001:db8:1::/64), falling back to eth0" >&2
    PROXY_NET1_IFACE="eth0"
fi
if [ -z "$PROXY_NET2_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net2 (172.19.0.0/16 / 2001:db8:2::/64), falling back to eth1" >&2
    PROXY_NET2_IFACE="eth1"
fi

echo "=== [1/2] AcCCS SLAC, both roles, concurrently ==="
echo "    PEV role  (vs. real SECC) on $PROXY_NET1_IFACE (proxy_net1)"
echo "    EVSE role (vs. real EVCC) on $PROXY_NET2_IFACE (proxy_net2)"
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I "$PROXY_NET1_IFACE" &
PEV_PID=$!
SLAC_ONLY=1 timeout 20 python EVSE.py -I "$PROXY_NET2_IFACE" &
EVSE_PID=$!
wait "$PEV_PID"
echo "=== proxy PEV-role SLAC exited with code $? ==="
wait "$EVSE_PID"
echo "=== proxy EVSE-role SLAC exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] HLC MITM (proxy01.py) ==="
cd /usr/src/app/iso15118
exec python3 proxy01.py --capture --show-hex
