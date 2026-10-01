#!/bin/bash
# compose `command` entrypoint for Dev1 (the "evexchange" profile).
#
# Mirrors compose_proxy_entry.sh: clean up leftover processes, start a
# packet capture, then hand off to dev1_run_full.sh. No stagger sleep,
# same as compose_proxy_entry.sh -- Dev1/Dev2 need to be up and listening
# before SECC/EVCC/SECC_Attacker/EVCC_Attacker (which do sleep) start
# their own SDP attempts.
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
    echo "--- Dev1: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- Dev1: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f dev_relay.py 2>/dev/null
pkill -f "mod_acccs/EVSE.py" 2>/dev/null
pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- Dev1: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/dev1_run_${TS}.pcap" &

echo "--- Dev1: starting (SLAC, both roles, then cross-session relay) ---"
/usr/src/app/dev1_run_full.sh 2>&1 | tee "${CAPDIR}/dev1_demo_${TS}.log" &

wait -n
