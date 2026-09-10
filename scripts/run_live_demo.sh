#!/bin/bash
# Host-side orchestrator for LIVE demos: runs the same SLAC + HLC MITM flow
# as run_full_demo.sh, but streams proxy/SECC/EVCC output live, interleaved
# and labeled, into this terminal as it happens -- instead of hiding
# everything in background log files until the run is over. Still produces
# the same pcap/log artifacts in captures/ at the end.
#
# Usage:
#   ./run_live_demo.sh [tls|notls]
#   tls   (default) -- EVCC negotiates a real TLS/PnC session with a full
#                       certificate chain.
#   notls           -- EVCC negotiates a plaintext EIM/AC session.
#
# Ctrl+C at any point triggers the same cleanup as a normal finish: capture
# streamers and tcpdump are stopped, and whatever was captured so far is
# copied out to captures/.
#
# Requires: EVCC, SECC, Evil_EVSE_Evil_PEV containers already created, same
# as run_full_demo.sh.
set -uo pipefail

MODE="${1:-tls}"
case "$MODE" in
    tls|notls) ;;
    *) echo "Usage: $0 [tls|notls]" >&2; exit 1 ;;
esac

TS="$(date +%Y%m%d_%H%M%S)"
HOST_CAPDIR="/home/vasu/newtest001/captures"
mkdir -p "$HOST_CAPDIR"

# Color-code the three sources if stdout is a real terminal; degrade to
# plain labels (no escape codes) when piped/redirected/not a tty.
if [ -t 1 ]; then
    C_PROXY=$'\033[1;36m'  # cyan
    C_SECC=$'\033[1;33m'   # yellow
    C_EVCC=$'\033[1;32m'   # green
    C_RESET=$'\033[0m'
else
    C_PROXY=''; C_SECC=''; C_EVCC=''; C_RESET=''
fi

CLEANUP_DONE=0

cleanup() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then return; fi
    CLEANUP_DONE=1
    echo
    echo "--- Stopping live output streamers ---"
    # Note: `docker exec ... tail -F ... | sed ... &` backgrounds a pipeline,
    # and `$!` after that only captures sed's PID (the last command in the
    # pipeline), not docker exec's -- killing just sed leaves the local
    # `docker exec` client (and the `tail -F` it drives inside the
    # container) running indefinitely, since it has no more output to write
    # and so never gets SIGPIPE. Kill by matching the actual command line
    # instead, which is unique to this run via $TS.
    pkill -f "tail -F -n \+1 /tmp/proxy_demo_${MODE}_${TS}.log" 2>/dev/null
    pkill -f "tail -F -n \+1 /tmp/secc_demo_${MODE}_${TS}.log" 2>/dev/null
    pkill -f "tail -F -n \+1 /tmp/evcc_demo_${MODE}_${TS}.log" 2>/dev/null

    echo "--- Stopping captures cleanly (SIGINT, so pcap trailers are written) ---"
    docker exec Evil_EVSE_Evil_PEV pkill -INT -x tcpdump 2>/dev/null
    docker exec SECC pkill -INT -x tcpdump 2>/dev/null
    docker exec EVCC pkill -INT -x tcpdump 2>/dev/null
    sleep 1.5   # give tcpdump a moment to flush and close the file

    echo "--- Copying pcaps and logs out to the host ---"
    docker cp "Evil_EVSE_Evil_PEV:/tmp/full_run_${MODE}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
    docker cp "SECC:/tmp/secc_run_${MODE}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
    docker cp "EVCC:/tmp/evcc_run_${MODE}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
    docker cp "Evil_EVSE_Evil_PEV:/tmp/proxy_demo_${MODE}_${TS}.log" "$HOST_CAPDIR/" 2>&1
    docker cp "SECC:/tmp/secc_demo_${MODE}_${TS}.log" "$HOST_CAPDIR/" 2>&1
    docker cp "EVCC:/tmp/evcc_demo_${MODE}_${TS}.log" "$HOST_CAPDIR/" 2>&1

    echo
    echo "=== Done. Captures for this run: ==="
    ls -la "$HOST_CAPDIR"/*"${MODE}_${TS}"* 2>/dev/null

    # Unlike EXIT, bash's INT/TERM traps do NOT stop the script after the
    # handler returns -- without this, a Ctrl+C here would run cleanup and
    # then resume the rest of the script from wherever it was interrupted.
    # This exit is what actually stops it; it re-enters this function via
    # the EXIT trap, but CLEANUP_DONE makes that second entry a no-op.
    exit
}
trap cleanup EXIT INT TERM

echo "=== Live run $TS (mode: $MODE) ==="

echo "--- Ensuring containers are up ---"
docker start EVCC SECC Evil_EVSE_Evil_PEV >/dev/null

echo "--- Ensuring slac_net exists and EVCC/SECC are attached to it ---"
docker network create --ipv6 --subnet 2001:db8:3::/64 slac_net >/dev/null 2>&1 || true
docker network connect slac_net EVCC >/dev/null 2>&1 || true
docker network connect slac_net SECC >/dev/null 2>&1 || true

echo "--- Cleaning up any leftover processes from a previous run ---"
docker exec Evil_EVSE_Evil_PEV pkill -x tcpdump 2>/dev/null
docker exec Evil_EVSE_Evil_PEV pkill -f proxy01.py 2>/dev/null
docker exec SECC pkill -x tcpdump 2>/dev/null
docker exec SECC pkill -f "iso15118/secc/main.py" 2>/dev/null
docker exec SECC pkill -f "mod_acccs/EVSE.py" 2>/dev/null
docker exec EVCC pkill -x tcpdump 2>/dev/null
docker exec EVCC pkill -f "iso15118/evcc/main.py" 2>/dev/null
docker exec EVCC pkill -f "mod_acccs/PEV.py" 2>/dev/null
sleep 1

echo "--- Starting packet captures ---"
docker exec -d Evil_EVSE_Evil_PEV tcpdump -i any -w "/tmp/full_run_${MODE}_${TS}.pcap"
docker exec -d SECC tcpdump -i any -w "/tmp/secc_run_${MODE}_${TS}.pcap"
docker exec -d EVCC tcpdump -i any -w "/tmp/evcc_run_${MODE}_${TS}.pcap"
sleep 1.5

echo "--- Attaching live output streams (labeled, color-coded) ---"
# Pre-create the log files so `tail -F` can attach before the processes
# that write them even start -- -F (not -f) retries/re-opens across the
# truncate that happens when the process's own `> file` redirection opens.
docker exec Evil_EVSE_Evil_PEV touch "/tmp/proxy_demo_${MODE}_${TS}.log"
docker exec SECC touch "/tmp/secc_demo_${MODE}_${TS}.log"
docker exec EVCC touch "/tmp/evcc_demo_${MODE}_${TS}.log"

docker exec Evil_EVSE_Evil_PEV tail -F -n +1 "/tmp/proxy_demo_${MODE}_${TS}.log" 2>/dev/null \
    | sed -u "s/^/${C_PROXY}[PROXY]${C_RESET} /" &
docker exec SECC tail -F -n +1 "/tmp/secc_demo_${MODE}_${TS}.log" 2>/dev/null \
    | sed -u "s/^/${C_SECC}[SECC]${C_RESET}  /" &
docker exec EVCC tail -F -n +1 "/tmp/evcc_demo_${MODE}_${TS}.log" 2>/dev/null \
    | sed -u "s/^/${C_EVCC}[EVCC]${C_RESET}  /" &
sleep 0.5

echo "--- Starting proxy (SDP/TCP relay) ---"
docker exec -d Evil_EVSE_Evil_PEV bash -c "cd /usr/src/app/iso15118 && python3 proxy01.py --capture --show-hex > /tmp/proxy_demo_${MODE}_${TS}.log 2>&1"
sleep 2

echo "--- Starting SECC (SLAC then HLC) ---"
docker exec -d SECC bash -c "/usr/src/app/secc_run_full.sh > /tmp/secc_demo_${MODE}_${TS}.log 2>&1"
sleep 2

echo "--- Starting EVCC (SLAC then HLC, mode=$MODE) ---"
docker exec -d -e EVCC_MODE="$MODE" EVCC bash -c "/usr/src/app/evcc_run_full.sh > /tmp/evcc_demo_${MODE}_${TS}.log 2>&1"
echo "=== Live output below (Ctrl+C to stop and save captures at any point) ==="
echo

echo "--- Waiting for EVCC's HLC process to start (SLAC step takes up to ~20s first) ---" >&2
for i in $(seq 1 30); do
    sleep 1
    if docker exec EVCC pgrep -f "iso15118/evcc/main.py" >/dev/null 2>&1; then
        break
    fi
done

for i in $(seq 1 20); do
    sleep 1
    if ! docker exec EVCC pgrep -f "iso15118/evcc/main.py" >/dev/null 2>&1; then
        break
    fi
done
sleep 2   # grace period so the last relayed packets land in the log/capture

# cleanup() runs automatically via the EXIT trap from here (normal finish
# or Ctrl+C).
