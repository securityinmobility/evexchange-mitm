#!/bin/bash
# compose `command` entrypoint for EVCC.
#
# Rebuilds, inside the container itself, what run_live_demo.sh used to do
# for this container from the host via `docker exec`: clean up leftover
# processes, start a packet capture, then hand off to evcc_run_full.sh.
# Output goes straight to this process's own stdout/stderr, so
# `docker compose up` shows it live, already labeled/colored per-service --
# no more manual `tail -F | sed` pipe on the host for this role. It's also
# tee'd into /captures so a log file still lands next to the pcap, same
# artifacts run_live_demo.sh used to produce in captures/.
#
# EVCC_MODE (compose `environment:`, default tls) picks TLS/PnC vs.
# plaintext EIM -- passed straight through to evcc_run_full.sh, same env
# var run_live_demo.sh used.
#
# The 4s sleep before starting roughly reproduces run_live_demo.sh's
# proxy-then-SECC-then-EVCC stagger (2s behind SECC's own 2s, so EVCC
# starts after both). It's best-effort, not a real ordering guarantee --
# compose starts all three containers together, so actual timing still
# depends on how fast each one's earlier steps (leftover-process cleanup,
# tcpdump startup) finish.
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
    echo "--- EVCC: stopping capture (SIGINT, for a clean pcap trailer) ---"
    pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5
    exit
}
trap cleanup EXIT INT TERM

echo "--- EVCC: cleaning up leftover processes from a previous run ---"
pkill -x tcpdump 2>/dev/null
pkill -f "iso15118/evcc/main.py" 2>/dev/null
pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- EVCC: starting packet capture ---"
tcpdump -i any -w "${CAPDIR}/evcc_run_${TS}.pcap" &

sleep 4

echo "--- EVCC: starting EVCC (SLAC then HLC, mode=${EVCC_MODE:-tls}) ---"
/usr/src/app/evcc_run_full.sh 2>&1 | tee "${CAPDIR}/evcc_demo_${TS}.log" &

# Waits for either job -- tcpdump or the EVCC pipeline -- so a crash of
# either one ends the container instead of hanging forever. Normal finish
# falls through to the EXIT trap above, same cleanup as a signal.
wait -n
