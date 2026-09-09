#!/bin/bash
# Combined SLAC (AcCCS PEV role) + HLC (EcoG iso15118 EVCC) launcher.
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

echo "=== [1/2] AcCCS SLAC (PEV role) on eth0, SLAC_ONLY=1 ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I eth0
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] EcoG iso15118 EVCC (HLC layer, TLS/PnC) ==="
cd /usr/src/app/iso15118
# PnC config (useTls: true) instead of the plaintext EIM default, so the
# session negotiates TLS + a real cert chain like the original Dec-10 run
# (CPOSubCA2/SECCCert/CPOSubCA1/VGRoot CA) instead of plaintext EXI.
exec make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_pnc_ac.json
