#!/bin/bash
# Combined SLAC (AcCCS PEV role) + HLC (EcoG iso15118 EVCC) launcher.
#
# Runs the AcCCS SLAC handshake first (SLAC_ONLY=1, so AcCCS stops right
# after SLAC_MATCH_CNF instead of continuing into its own DIN/TCP code),
# then hands off to the real ISO 15118 stack for the HLC session.
#
# Two separate interfaces, two separate purposes:
#   - eth1 (slac_net): a dedicated L2 segment shared ONLY by EVCC and SECC
#     (the proxy is not on it). This is where the real SLAC handshake runs,
#     since SLAC needs a genuine adjacent peer to exchange
#     CM_SLAC_PARM.REQ/CNF, CM_MNBC_SOUND.IND, CM_ATTEN_CHAR.IND/RSP and
#     CM_SLAC_MATCH.REQ/CNF with -- it cannot work on the isolated
#     proxy_net1/proxy_net2 segments used for the HLC MITM relay.
#   - eth0 (proxy_net2): unchanged, used by the HLC (make run-evcc) step,
#     which only ever talks to the Evil_EVSE_Evil_PEV proxy, not directly
#     to SECC.
#
# The bounded `timeout` below is a safety net: AcCCS's own idle-timeout
# thread should stop the SLAC handler once SLAC_MATCH_CNF is sent, but if
# something goes wrong we don't want this to block the HLC step forever.
set -uo pipefail

echo "=== [1/2] AcCCS SLAC (PEV role) on eth1 (slac_net), SLAC_ONLY=1 ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python PEV.py -I eth1
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] EcoG iso15118 EVCC (HLC layer, TLS/PnC) on eth0 (proxy_net2) ==="
cd /usr/src/app/iso15118
# PnC config (useTls: true) instead of the plaintext EIM default, so the
# session negotiates TLS + a real cert chain like the original Dec-10 run
# (CPOSubCA2/SECCCert/CPOSubCA1/VGRoot CA) instead of plaintext EXI.
exec make run-evcc config=iso15118/shared/examples/evcc/iso15118_2/evcc_config_pnc_ac.json
