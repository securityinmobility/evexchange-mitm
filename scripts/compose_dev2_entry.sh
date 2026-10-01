#!/bin/bash
# compose `command` entrypoint for Dev2 (the "evexchange" profile).
#
# Mirrors compose_dev1_entry.sh. ATTACKER_STOP_AFTER_S (compose
# `environment:`) is read directly by dev_relay.py itself -- see
# docker-compose.yml and dev_relay.py's own docstring.
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
    echo "--- Dev2: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- Dev2: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f dev_relay.py 2>/dev/null
pkill -f "mod_acccs/EVSE.py" 2>/dev/null
pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- Dev2: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/dev2_run_${TS}.pcap" &

echo "--- Dev2: starting (SLAC, both roles, then cross-session relay, ATTACKER_STOP_AFTER_S=${ATTACKER_STOP_AFTER_S:-unset}) ---"
/usr/src/app/dev2_run_full.sh 2>&1 | tee "${CAPDIR}/dev2_demo_${TS}.log" &

wait -n
