#!/bin/bash
# Evil_EVCC-side SLAC (AcCCS PEV role) + HLC (proxy/evil_evcc.py) launcher.
#
# Counterpart to scripts/evil_secc_run_full.sh -- together they replace
# proxy_run_full.sh's single dual-role proxy with two containers, one role
# each (see README "Split proxy (Evil_SECC + Evil_EVCC)"). Evil_EVCC
# plays the PEV role at the SLAC layer and the fake-EVCC role at the HLC
# layer, both facing the real SECC on proxy_net1 -- same leg,
# same reasoning as proxy_run_full.sh's own PEV-role half.
#
# TAMPER=1 (env var, see docker-compose.yml) enables EVSEMaxCurrent
# tampering -- unlike proxy01.py's single-relay tamper, this works in TLS/
# PnC mode too (and ISO 15118-20), not just notls, since Evil_EVCC
# genuinely terminates TLS with the real SECC instead of relaying it
# opaquely.
#
# Which of this container's interfaces is proxy_net1 is resolved by subnet
# at runtime, NOT assumed by name -- same principle as proxy01.py/
# evil_evcc.py's own discover_secc_evcc_interfaces().
set -uo pipefail

resolve_iface() {
    local v4_prefix="$1" v6_prefix="$2"
    ip -br a | grep -E "${v4_prefix}|${v6_prefix}" | awk '{print $1}' | cut -d@ -f1 | head -n1
}

PROXY_NET1_IFACE="$(resolve_iface '172\.20\.' '2001:db8:1:')"   # SECC-facing

if [ -z "$PROXY_NET1_IFACE" ]; then
    echo "WARNING: no interface found on proxy_net1 (172.20.0.0/16 / 2001:db8:1::/64), falling back to eth0" >&2
    PROXY_NET1_IFACE="eth0"
fi

echo "=== [1/2] AcCCS SLAC (PEV role, vs. real SECC) on $PROXY_NET1_IFACE (proxy_net1) ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I "$PROXY_NET1_IFACE"
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] HLC fake-EVCC (evil_evcc.py), listening for Evil_SECC on bridge_net ==="
cd /usr/src/app/iso15118
# TAMPER=1 is read directly from the environment by evil_evcc.py itself
# (same as proxy01.py), so no --tamper flag needs adding here.
#
# /venv/bin/python3, not bare python3: evil_evcc.py imports
# iso15118.shared.messages.{enums,sdp,v2gtp} and iso15118.shared.security,
# which need pydantic -- only present in /venv (where the iso15118 wheel's
# own dependencies were installed), not the base image's system python3.
exec /venv/bin/python3 evil_evcc.py --capture --show-hex
