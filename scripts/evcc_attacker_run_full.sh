#!/bin/bash
# Combined SLAC (AcCCS PEV role) + HLC (EcoG iso15118 EVCC) launcher for
# EVCC_Attacker -- the attacker's own real EV, part of the EVExchange
# cross-session relay attack (see README "EVExchange cross-session relay",
# evexchange_attack.pdf).
#
# Identical in every way to evcc_run_full.sh except which subnet it
# resolves its interface against: proxy_net4 (EVCC_Attacker's own leg,
# facing Dev2) instead of proxy_net2 (EVCC's leg, facing Dev1). A separate
# script rather than parameterizing evcc_run_full.sh because the subnet
# prefixes are baked into a simple grep pattern -- same reason
# evil_evcc_run_full.sh etc. are their own scripts rather than variants of
# proxy_run_full.sh.
#
# EVCC_MODE selects the HLC config, same three values as evcc_run_full.sh
# (tls/notls/iso20) -- see that script's header comment for the full
# explanation, including the iso20-runs-plaintext-by-default note.
#
# Which of this container's interfaces is proxy_net4 is resolved by subnet
# at runtime, NOT assumed by name -- same principle as everywhere else in
# this repo.
set -uo pipefail

EVCC_MODE="${EVCC_MODE:-tls}"

SLAC_MODE="${1:-slac}"
case "$SLAC_MODE" in
    slac|noslac) ;;
    *) echo "Usage: $0 [noslac]" >&2; exit 1 ;;
esac

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

HLC_IFACE="$(resolve_iface '172\.30\.' '2001:db8:5:')"   # proxy_net4 = EVCC_Attacker's HLC-facing network, now also SLAC

if [ -z "$HLC_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net4 (172.30.0.0/16 / 2001:db8:5::/64), falling back to eth0" >&2
    HLC_IFACE="eth0"
fi

if [ "$SLAC_MODE" = "noslac" ]; then
    echo "=== SLAC skipped (noslac) -- assuming it's handled by real MITM hardware outside Docker ==="
    HLC_STEP_LABEL="[1/1]"
else
    echo "=== [1/2] AcCCS SLAC (PEV role) on $HLC_IFACE (proxy_net4), SLAC_ONLY=1 ==="
    cd /usr/src/app/mod_acccs
    SLAC_ONLY=1 timeout 20 python PEV.py -I "$HLC_IFACE"
    echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="
    HLC_STEP_LABEL="[2/2]"
fi

cd /usr/src/app/iso15118
case "$EVCC_MODE" in
    tls)
        echo "=== $HLC_STEP_LABEL EcoG iso15118 EVCC (HLC layer, TLS/PnC) on $HLC_IFACE (proxy_net4) ==="
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_pnc_ac.json
        ;;
    notls)
        echo "=== $HLC_STEP_LABEL EcoG iso15118 EVCC (HLC layer, plaintext EIM) on $HLC_IFACE (proxy_net4) ==="
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_eim_ac.json
        ;;
    iso20)
        echo "=== $HLC_STEP_LABEL EcoG iso15118 EVCC (HLC layer, ISO 15118-20 AC) on $HLC_IFACE (proxy_net4) ==="
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_20/evcc_config_ac.json
        ;;
    *)
        echo "Unknown EVCC_MODE '$EVCC_MODE' (expected 'tls', 'notls', or 'iso20')" >&2
        exit 1
        ;;
esac
