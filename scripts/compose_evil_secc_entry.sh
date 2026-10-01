#!/bin/bash
# compose `command` entrypoint for Evil_SECC (the "split" profile).
#
# Mirrors compose_proxy_entry.sh: clean up leftover processes, start a
# packet capture, then hand off to evil_secc_run_full.sh. Output goes
# straight to this process's own stdout/stderr (compose shows it live,
# labeled/colored per-service) and is also tee'd into /captures.
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
    echo "--- Evil_SECC: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- Evil_SECC: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f evil_secc.py 2>/dev/null
pkill -f "mod_acccs/EVSE.py" 2>/dev/null
sleep 1

echo "--- Evil_SECC: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/evil_secc_run_${TS}.pcap" &

echo "--- Evil_SECC: starting (SLAC EVSE role, then fake-SECC HLC) ---"
/usr/src/app/evil_secc_run_full.sh 2>&1 | tee "${CAPDIR}/evil_secc_demo_${TS}.log" &

# Waits for either job -- tcpdump or the evil_secc pipeline -- so a crash of
# either one ends the container instead of hanging forever.
wait -n
