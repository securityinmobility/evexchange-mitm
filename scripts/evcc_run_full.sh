#!/bin/bash
# Combined SLAC (AcCCS PEV role) + HLC (EcoG iso15118 EVCC) launcher.
#
# Runs the AcCCS SLAC handshake first (SLAC_ONLY=1, so AcCCS stops right
# after SLAC_MATCH_CNF instead of continuing into its own DIN/TCP code),
# then hands off to the real ISO 15118 stack for the HLC session.
#
# Two separate networks, two separate purposes:
#   - slac_net: a dedicated L2 segment shared ONLY by EVCC and SECC (the
#     proxy is not on it). This is where the real SLAC handshake runs,
#     since SLAC needs a genuine adjacent peer to exchange
#     CM_SLAC_PARM.REQ/CNF, CM_MNBC_SOUND.IND, CM_ATTEN_CHAR.IND/RSP and
#     CM_SLAC_MATCH.REQ/CNF with -- it cannot work on the isolated
#     proxy_net1/proxy_net2 segments used for the HLC MITM relay.
#   - proxy_net2: used by the HLC (make run-evcc) step, which only ever
#     talks to the Evil_EVSE_Evil_PEV proxy, not directly to SECC.
#
# Which of this container's interfaces (eth0/eth1) is which is resolved by
# subnet at runtime, NOT assumed by name. Docker does not guarantee eth0/
# eth1 map to the same network across container restarts or `docker
# network connect`/`disconnect` calls (this bit us for real on SECC: it
# ended up with slac_net on eth0 and proxy_net1 on eth1 after some earlier
# reconnects, and since the HLC step never set NETWORK_INTERFACE, EcoG's
# default of eth0 silently pointed the SDP listener at slac_net instead of
# proxy_net1 -- "No SDP response from SECC" every time). Same principle as
# the proxy01.py fix: match on the interface's actual assigned subnet.
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

# Resolve which local interface has an address in a given subnet, by
# matching `ip -br a` output against IPv4 and/or IPv6 prefixes. Prints the
# interface name (without the "@ifNN" peer-index suffix Docker adds) or
# nothing if no match was found.
resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

SLAC_IFACE="$(resolve_iface '172\.18\.' '2001:db8:3:')"
HLC_IFACE="$(resolve_iface '172\.19\.' '2001:db8:2:')"   # proxy_net2 = EVCC's HLC-facing network

if [ -z "$SLAC_IFACE" ]; then
    echo "WARNING: no interface found on slac_net (172.18.0.0/16 / 2001:db8:3::/64), falling back to eth1" >&2
    SLAC_IFACE="eth1"
fi
if [ -z "$HLC_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net2 (172.19.0.0/16 / 2001:db8:2::/64), falling back to eth0" >&2
    HLC_IFACE="eth0"
fi

echo "=== [1/2] AcCCS SLAC (PEV role) on $SLAC_IFACE (slac_net), SLAC_ONLY=1 ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I "$SLAC_IFACE"
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

cd /usr/src/app/iso15118
case "$EVCC_MODE" in
    tls)
        echo "=== [2/2] EcoG iso15118 EVCC (HLC layer, TLS/PnC) on $HLC_IFACE (proxy_net2) ==="
        # PnC config (useTls: true), so the session negotiates TLS + a real
        # cert chain like the original Dec-10 run (CPOSubCA2/SECCCert/
        # CPOSubCA1/VGRoot CA) instead of plaintext EXI.
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_pnc_ac.json
        ;;
    notls)
        echo "=== [2/2] EcoG iso15118 EVCC (HLC layer, plaintext EIM) on $HLC_IFACE (proxy_net2) ==="
        exec env NETWORK_INTERFACE="$HLC_IFACE" make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_eim_ac.json
        ;;
    *)
        echo "Unknown EVCC_MODE '$EVCC_MODE' (expected 'tls' or 'notls')" >&2
        exit 1
        ;;
esac
