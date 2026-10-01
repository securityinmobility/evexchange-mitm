#!/bin/bash
# compose `command` entrypoint for EVCC_Attacker (the "evexchange" profile).
#
# Mirrors compose_evcc_entry.sh: clean up leftover processes, start a
# packet capture, then hand off to evcc_attacker_run_full.sh. Output goes
# straight to this process's own stdout/stderr (compose shows it live,
# labeled/colored per-service) and is also tee'd into /captures.
#
# EVCC_MODE (compose `environment:`, default tls) picks TLS/PnC vs.
# plaintext EIM vs. iso20 -- passed straight through to
# evcc_attacker_run_full.sh, same env var EVCC already uses.
#
# The 4s sleep staggers this behind SECC_Attacker's own 2s, same reasoning
# as compose_evcc_entry.sh's stagger behind SECC.
#
# On SIGTERM/SIGINT (`docker compose down`/stop, or Ctrl-C on `up`),
# tcpdump gets SIGINT specifically so its pcap trailer is written cleanly.
set -uo pipefail

TS="$(date +%Y%m%d_%H%M%S)"
CAPDIR=/captures
mkdir -p "$CAPDIR"

CLEANUP_DONE=0
cleanup() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then return; fi
    CLEANUP_DONE=1
    echo "--- EVCC_Attacker: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- EVCC_Attacker: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f "iso15118/evcc/main.py" 2>/dev/null
pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- EVCC_Attacker: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/evcc_attacker_run_${TS}.pcap" &

sleep 4

echo "--- EVCC_Attacker: starting (SLAC then HLC, mode=${EVCC_MODE:-tls}) ---"
/usr/src/app/evcc_attacker_run_full.sh 2>&1 | tee "${CAPDIR}/evcc_attacker_demo_${TS}.log" &

wait -n
