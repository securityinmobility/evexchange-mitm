#!/bin/bash
# Combined SLAC (AcCCS EVSE role) + HLC (EcoG iso15118 SECC) launcher.
#
# Runs the AcCCS SLAC handshake first (SLAC_ONLY=1, so AcCCS stops right
# after SLAC_MATCH_CNF instead of continuing into its own DIN/TCP code),
# then hands off to the real ISO 15118 stack for the HLC session. Both
# steps run on the same interface, proxy_net1 -- SECC no longer talks
# directly to EVCC for SLAC either: the Evil_EVSE_Evil_PEV proxy runs a
# PEV-role SLAC handler of its own on its proxy_net1 leg (see
# proxy_run_full.sh) so SECC's SLAC handshake completes against the proxy,
# same as its HLC session already does.
#
# Pass `noslac` as the first argument to skip the SLAC step entirely and go
# straight to HLC -- for when real MITM hardware (not our Docker proxy) is
# doing the interception, including SLAC, outside this container's view.
# See README "Bringing your own MITM hardware".
#
# Which of this container's interfaces (eth0/eth1) is proxy_net1 is
# resolved by subnet at runtime, NOT assumed by name. Docker does not
# guarantee eth0/eth1 map to the same network across container restarts or
# `docker network connect`/`disconnect` calls. Same principle as the
# proxy01.py fix: match on the interface's actual assigned subnet.
#
# The bounded `timeout` below is a safety net: AcCCS's own idle-timeout
# thread should stop the SLAC handler once SLAC_MATCH_CNF is sent, but if
# something goes wrong we don't want this to block the HLC step forever.
set -uo pipefail

SLAC_MODE="${1:-slac}"
case "$SLAC_MODE" in
    slac|noslac) ;;
    *) echo "Usage: $0 [noslac]" >&2; exit 1 ;;
esac

# Resolve which local interface has an address in a given subnet, by
# matching `ip -br a` output against IPv4 and/or IPv6 prefixes. Prints the
# interface name (without the "@ifNN" peer-index suffix Docker adds) or
# nothing if no match was found.
resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

HLC_IFACE="$(resolve_iface '172\.20\.' '2001:db8:1:')"   # proxy_net1 = SECC's HLC-facing network, now also SLAC

if [ -z "$HLC_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net1 (172.20.0.0/16 / 2001:db8:1::/64), falling back to eth0" >&2
    HLC_IFACE="eth0"
fi

if [ "$SLAC_MODE" = "noslac" ]; then
    echo "=== SLAC skipped (noslac) -- assuming it's handled by real MITM hardware outside Docker ==="
    HLC_STEP_LABEL="[1/1]"
else
    echo "=== [1/2] AcCCS SLAC (EVSE role) on $HLC_IFACE (proxy_net1), SLAC_ONLY=1 ==="
    cd /usr/src/app/mod_acccs
    SLAC_ONLY=1 timeout 20 python EVSE.py -I "$HLC_IFACE"
    echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="
    HLC_STEP_LABEL="[2/2]"
fi

echo "=== $HLC_STEP_LABEL EcoG iso15118 SECC (HLC layer) on $HLC_IFACE (proxy_net1) ==="
cd /usr/src/app/iso15118
exec env NETWORK_INTERFACE="$HLC_IFACE" make run-secc
