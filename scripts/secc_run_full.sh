#!/bin/bash
# Combined SLAC (AcCCS EVSE role) + HLC (EcoG iso15118 SECC) launcher.
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
#   - eth0 (proxy_net1): unchanged, used by the HLC (make run-secc) step,
#     which only ever talks to the Evil_EVSE_Evil_PEV proxy, not directly
#     to EVCC.
#
# The bounded `timeout` below is a safety net: AcCCS's own idle-timeout
# thread should stop the SLAC handler once SLAC_MATCH_CNF is sent, but if
# something goes wrong we don't want this to block the HLC step forever.
set -uo pipefail

echo "=== [1/2] AcCCS SLAC (EVSE role) on eth1 (slac_net), SLAC_ONLY=1 ==="
cd /usr/src/app/mod_acccs
SLAC_ONLY=1 timeout 20 python EVSE.py -I eth1
echo "=== SLAC step exited with code $? — proceeding to HLC regardless ==="

echo "=== [2/2] EcoG iso15118 SECC (HLC layer) on eth0 (proxy_net1) ==="
cd /usr/src/app/iso15118
exec make run-secc
