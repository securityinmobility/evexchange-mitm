#!/bin/bash
# compose `command` entrypoint for SECC_Attacker (the "evexchange" profile).
#
# Mirrors compose_secc_entry.sh: clean up leftover processes, start a
# packet capture, then hand off to secc_b_run_full.sh. Output goes
# straight to this process's own stdout/stderr (compose shows it live,
# labeled/colored per-service) and is also tee'd into /captures.
#
# The 2s sleep roughly staggers this after Dev1/Dev2 (which have no
# sleep of their own), same reasoning as compose_secc_entry.sh's stagger
# ahead of EVCC -- best-effort, not a real ordering guarantee.
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
    echo "--- SECC_Attacker: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- SECC_Attacker: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f "iso15118/secc/main.py" 2>/dev/null
pkill -f "mod_acccs/EVSE.py" 2>/dev/null
sleep 1

echo "--- SECC_Attacker: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/secc_b_run_${TS}.pcap" &

sleep 2

echo "--- SECC_Attacker: starting (SLAC then HLC) ---"
/usr/src/app/secc_b_run_full.sh 2>&1 | tee "${CAPDIR}/secc_b_demo_${TS}.log" &

wait -n
