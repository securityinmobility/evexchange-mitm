#!/bin/bash
# Combined SLAC (AcCCS PEV role) + HLC (EcoG iso15118 EVCC) launcher.
#
# Runs the AcCCS SLAC handshake first (SLAC_ONLY=1, so AcCCS stops right
# after SLAC_MATCH_CNF instead of continuing into its own DIN/TCP code),
# then hands off to the real ISO 15118 stack for the HLC session. Both
# steps run on the same interface, proxy_net2 -- EVCC no longer talks
# directly to SECC for SLAC either: the Evil_EVSE_Evil_PEV proxy runs an
# EVSE-role SLAC handler of its own on its proxy_net2 leg (see
# proxy_run_full.sh) so EVCC's SLAC handshake completes against the proxy,
# same as its HLC session already does.
#
# Pass `noslac` as the first argument to skip the SLAC step entirely and go
# straight to HLC -- for when real MITM hardware (not our Docker proxy) is
# doing the interception, including SLAC, outside this container's view.
# See README "Bringing your own MITM hardware". Independent of EVCC_MODE
# below -- the two toggles don't interact.
#
# Which of this container's interfaces (eth0/eth1) is proxy_net2 is
# resolved by subnet at runtime, NOT assumed by name. Docker does not
# guarantee eth0/eth1 map to the same network across container restarts or
# `docker network connect`/`disconnect` calls. Same principle as the
# proxy01.py fix: match on the interface's actual assigned subnet.
#
# The bounded `timeout` below is a safety net: AcCCS's own idle-timeout
# thread should stop the SLAC handler once SLAC_MATCH_CNF is sent, but if
# something goes wrong we don't want this to block the HLC step forever.
#
# EVCC_MODE selects the HLC config: "tls" (default) negotiates a real
# TLS/PnC session with a full cert chain; "notls" negotiates plaintext
# EIM/AC. SECC needs no corresponding change -- it follows whatever the
# EVCC's SDP request asks for.
set -uo pipefail

EVCC_MODE="${EVCC_MODE:-tls}"

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

HLC_IFACE="$(resolve_iface '172\.19\.' '2001:db8:2:')"   # proxy_net2 = EVCC's HLC-facing network, now also SLAC

if [ -z "$HLC_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net2 (172.19.0.0/16 / 2001:db8:2::/64), falling back to eth0" >&2
    HLC_IFACE="eth0"
fi

if [ "$SLAC_MODE" = "noslac" ]; then
    echo "=== SLAC skipped (noslac) -- assuming it's handled by real MITM hardware outside Docker ==="
    HLC_STEP_LABEL="[1/1]"
else
    echo "=== [1/2] AcCCS SLAC (PEV role) on $HLC_IFACE (proxy_net2), SLAC_ONLY=1 ==="
    cd /usr/src/app/mod_acccs
    SLAC_ONLY=1 timeout 20 python PEV.py -I "$HLC_IFACE"
    echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="
    HLC_STEP_LABEL="[2/2]"
fi

cd /usr/src/app/iso15118
case "$EVCC_MODE" in
    tls)
        echo "=== $HLC_STEP_LABEL EcoG iso15118 EVCC (HLC layer, TLS/PnC) on $HLC_IFACE (proxy_net2) ==="
        # PnC config (useTls: true), so the session negotiates TLS + a real
        # cert chain like the original Dec-10 run (CPOSubCA2/SECCCert/
        # CPOSubCA1/VGRoot CA) instead of plaintext EXI.
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_pnc_ac.json
        ;;
    notls)
        echo "=== $HLC_STEP_LABEL EcoG iso15118 EVCC (HLC layer, plaintext EIM) on $HLC_IFACE (proxy_net2) ==="
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_eim_ac.json
        ;;
    *)
        echo "Unknown EVCC_MODE '$EVCC_MODE' (expected 'tls' or 'notls')" >&2
        exit 1
        ;;
esac
