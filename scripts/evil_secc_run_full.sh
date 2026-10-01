#!/bin/bash
# Evil_SECC-side SLAC (AcCCS EVSE role) + HLC (proxy/evil_secc.py) launcher.
#
# Counterpart to scripts/evil_evcc_run_full.sh -- together they replace
# proxy_run_full.sh's single dual-role proxy with two containers, one role
# each (see README "Split proxy (Evil_SECC + Evil_EVCC)"). Evil_SECC
# plays the EVSE role at the SLAC layer and the fake-SECC role at the HLC
# layer, both facing the real EVCC on proxy_net2 -- same leg,
# same reasoning as proxy_run_full.sh's own EVSE-role half.
#
# Which of this container's interfaces is proxy_net2 is resolved by subnet
# at runtime, NOT assumed by name -- same principle as proxy01.py/
# evil_secc.py's own discover_secc_evcc_interfaces().
set -uo pipefail

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

PROXY_NET2_IFACE="$(resolve_iface '172\.19\.' '2001:db8:2:')"   # EVCC-facing

if [ -z "$PROXY_NET2_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net2 (172.19.0.0/16 / 2001:db8:2::/64), falling back to eth0" >&2
    PROXY_NET2_IFACE="eth0"
fi

echo "=== [1/2] AcCCS SLAC (EVSE role, vs. real EVCC) on $PROXY_NET2_IFACE (proxy_net2) ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python EVSE.py -I "$PROXY_NET2_IFACE"
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] HLC fake-SECC (evil_secc.py) ==="
cd /usr/src/app/iso15118
# /venv/bin/python3, not bare python3: evil_secc.py imports
# iso15118.shared.messages.{enums,sdp,v2gtp} and iso15118.shared.security,
# which need pydantic -- only present in /venv (where the iso15118 wheel's
# own dependencies were installed), not the base image's system python3.
exec /venv/bin/python3 evil_secc.py --capture --show-hex
