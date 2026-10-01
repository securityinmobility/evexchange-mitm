#!/bin/bash
# Combined SLAC (AcCCS EVSE role) + HLC (EcoG iso15118 SECC) launcher for
# SECC_Attacker -- the attacker's own real charger, part of the EVExchange
# cross-session relay attack (see README "EVExchange cross-session relay",
# evexchange_attack.pdf).
#
# Identical in every way to secc_run_full.sh except which subnet it
# resolves its interface against: proxy_net3 (SECC_Attacker's own leg,
# facing Dev2) instead of proxy_net1 (SECC's leg, facing Dev1). A separate
# script rather than parameterizing secc_run_full.sh because the subnet
# prefixes are baked into a simple grep pattern -- same reason
# evil_secc_run_full.sh etc. are their own scripts rather than variants of
# proxy_run_full.sh.
#
# Which of this container's interfaces is proxy_net3 is resolved by subnet
# at runtime, NOT assumed by name -- same principle as everywhere else in
# this repo.
set -uo pipefail

SLAC_MODE="${1:-slac}"
case "$SLAC_MODE" in
    slac|noslac) ;;
    *) echo "Usage: $0 [noslac]" >&2; exit 1 ;;
esac

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

HLC_IFACE="$(resolve_iface '172\.29\.' '2001:db8:4:')"   # proxy_net3 = SECC_Attacker's HLC-facing network, now also SLAC

if [ -z "$HLC_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net3 (172.29.0.0/16 / 2001:db8:4::/64), falling back to eth0" >&2
    HLC_IFACE="eth0"
fi

if [ "$SLAC_MODE" = "noslac" ]; then
    echo "=== SLAC skipped (noslac) -- assuming it's handled by real MITM hardware outside Docker ==="
    HLC_STEP_LABEL="[1/1]"
else
    echo "=== [1/2] AcCCS SLAC (EVSE role) on $HLC_IFACE (proxy_net3), SLAC_ONLY=1 ==="
    cd /usr/src/app/mod_acccs
    SLAC_ONLY=1 timeout 20 python EVSE.py -I "$HLC_IFACE"
    echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="
    HLC_STEP_LABEL="[2/2]"
fi

echo "=== $HLC_STEP_LABEL EcoG iso15118 SECC (HLC layer) on $HLC_IFACE (proxy_net3) ==="
cd /usr/src/app/iso15118
exec env NETWORK_INTERFACE="$HLC_IFACE" make run-secc
