#!/bin/bash
# Combined SLAC (AcCCS EVSE role) + HLC (EcoG iso15118 SECC) launcher.
#
# Runs the AcCCS SLAC handshake first (SLAC_ONLY=1, so AcCCS stops right
# after SLAC_MATCH_CNF instead of continuing into its own DIN/TCP code),
# then hands off to the real ISO 15118 stack for the HLC session.
#
# SLAC is best-effort here, not a hard gate: in the isolated proxy_net1/
# proxy_net2 MITM topology there is no SLAC peer on this container's
# network segment (SLAC needs direct L2 adjacency with the other role's
# container, which the MITM topology deliberately isolates), so SLAC will
# time out after ~8-10s. That mirrors how this was actually run before
# (SLAC and the HLC MITM demo were separate, independent demonstrations)
# rather than a chained precondition. The bounded `timeout` below is a
# safety net in case AcCCS's own timeout thread doesn't fire.
set -uo pipefail

echo "=== [1/2] AcCCS SLAC (EVSE role) on eth0, SLAC_ONLY=1 ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python EVSE.py -I eth0
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] EcoG iso15118 SECC (HLC layer) ==="
cd /usr/src/app/iso15118
exec make run-secc
