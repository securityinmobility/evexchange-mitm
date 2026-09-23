#!/bin/bash
# compose `command` entrypoint for Evil_EVSE_Evil_PEV.
#
# Rebuilds, inside the container itself, what run_live_demo.sh used to do
# for this container from the host via `docker exec`: clean up leftover
# processes, start a packet capture, then hand off to proxy_run_full.sh.
# Output goes straight to this process's own stdout/stderr, so
# `docker compose up` shows it live, already labeled/colored per-service --
# no more manual `tail -F | sed` pipe on the host for this role. It's also
# tee'd into /captures so a log file still lands next to the pcap, same
# artifacts run_live_demo.sh used to produce in captures/.
#
# TAMPER=1 (compose `environment:`) enables EVSEMaxCurrent tampering in
# notls sessions, same as run_live_demo.sh's `tamper` argument -- see
# proxy01.py.
#
# On SIGTERM/SIGINT (`docker compose down`/stop, or Ctrl-C on `up`),
# tcpdump gets SIGINT specifically so its pcap trailer is written cleanly,
# same reasoning as run_live_demo.sh's own cleanup().
set -uo pipefail

TS="$(date +%Y%m%d_%H%M%S)"
CAPDIR=/captures
mkdir -p "$CAPDIR"

CLEANUP_DONE=0
cleanup() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then return; fi
    CLEANUP_DONE=1
    echo "--- Evil_EVSE_Evil_PEV: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- Evil_EVSE_Evil_PEV: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f proxy01.py 2>/dev/null
pkill -f "mod_acccs/EVSE.py" 2>/dev/null
pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- Evil_EVSE_Evil_PEV: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/full_run_${TS}.pcap" &

echo "--- Evil_EVSE_Evil_PEV: starting proxy (SLAC, both roles, then SDP/TCP relay) ---"
/usr/src/app/proxy_run_full.sh 2>&1 | tee "${CAPDIR}/proxy_demo_${TS}.log" &

# Waits for either job -- tcpdump or the proxy pipeline -- so a crash of
# either one ends the container instead of hanging forever. Normal finish
# falls through to the EXIT trap above, same cleanup as a signal.
wait -n
