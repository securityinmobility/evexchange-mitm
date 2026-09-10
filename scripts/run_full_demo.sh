#!/bin/bash
# Host-side orchestrator: runs the full evexchange MITM demo
# (proxy + SECC + EVCC, each with SLAC-then-HLC via *_run_full.sh) and
# captures packets throughout, on the host side, into timestamped pcaps.
#
# Usage:
#   ./run_full_demo.sh [tls|notls] [tamper]
#   tls   (default) -- EVCC negotiates a real TLS/PnC session with a full
#                       certificate chain.
#   notls           -- EVCC negotiates a plaintext EIM/AC session.
#   tamper          -- proxy tampers with EVSEMaxCurrent in
#                       ChargeParameterDiscoveryRes (SECC->EVCC). Only takes
#                       effect in notls mode -- see README "Content
#                       tampering" section for why TLS can't be tampered
#                       with by this proxy. Off by default.
#
# Requires: EVCC, SECC, Evil_EVSE_Evil_PEV containers already created
# (docker create/run once, with proxy_net1/proxy_net2 attached as set up
# previously). This script only starts/stops/execs into them.
set -uo pipefail

MODE="${1:-tls}"
case "$MODE" in
    tls|notls) ;;
    *) echo "Usage: $0 [tls|notls] [tamper]" >&2; exit 1 ;;
esac

TAMPER_ARG="${2:-}"
case "$TAMPER_ARG" in
    ""|tamper) ;;
    *) echo "Usage: $0 [tls|notls] [tamper]" >&2; exit 1 ;;
esac
PROXY_ENV_ARGS=()
RUN_TAG="$MODE"
if [ "$TAMPER_ARG" = "tamper" ]; then
    PROXY_ENV_ARGS=(-e TAMPER=1)
    RUN_TAG="${MODE}_tamper"
    if [ "$MODE" = "tls" ]; then
        echo "NOTE: tamper has no effect in tls mode (the proxy can't see inside" >&2
        echo "      TLS-protected content) -- proceeding anyway, but expect no" >&2
        echo "      [TAMPER] line. Use './run_full_demo.sh notls tamper' to see it." >&2
    fi
fi

TS="$(date +%Y%m%d_%H%M%S)"
HOST_CAPDIR="/home/vasu/newtest001/captures"
mkdir -p "$HOST_CAPDIR"

echo "=== Run $TS (mode: $MODE${TAMPER_ARG:+, $TAMPER_ARG}) ==="

echo "--- Ensuring containers are up ---"
docker start EVCC SECC Evil_EVSE_Evil_PEV >/dev/null

echo "--- Ensuring slac_net exists and EVCC/SECC are attached to it ---"
# slac_net is a dedicated L2 segment shared ONLY by EVCC and SECC (not the
# proxy), for the real SLAC handshake -- eth0 stays on proxy_net1/proxy_net2
# for the isolated HLC MITM relay, untouched. Idempotent: safe to re-run.
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
# Primary: proxy container sees both legs (proxy_net1 + proxy_net2) via -i any.
docker exec -d Evil_EVSE_Evil_PEV tcpdump -i any -w "/tmp/full_run_${RUN_TAG}_${TS}.pcap"
# Secondary/per-leg: EVCC and SECC each see their own SLAC attempt + HLC leg.
docker exec -d SECC tcpdump -i any -w "/tmp/secc_run_${RUN_TAG}_${TS}.pcap"
docker exec -d EVCC tcpdump -i any -w "/tmp/evcc_run_${RUN_TAG}_${TS}.pcap"
sleep 1.5   # let tcpdump finish binding before traffic starts

echo "--- Starting proxy (SDP/TCP relay) ---"
docker exec -d "${PROXY_ENV_ARGS[@]}" Evil_EVSE_Evil_PEV bash -c "cd /usr/src/app/iso15118 && python3 proxy01.py --capture --show-hex > /tmp/proxy_demo_${RUN_TAG}_${TS}.log 2>&1"
sleep 2

echo "--- Starting SECC (SLAC then HLC) ---"
docker exec -d SECC bash -c "/usr/src/app/secc_run_full.sh > /tmp/secc_demo_${RUN_TAG}_${TS}.log 2>&1"
sleep 2

echo "--- Starting EVCC (SLAC then HLC, mode=$MODE) ---"
docker exec -d -e EVCC_MODE="$MODE" EVCC bash -c "/usr/src/app/evcc_run_full.sh > /tmp/evcc_demo_${RUN_TAG}_${TS}.log 2>&1"

echo "--- Waiting for EVCC's HLC process to start (SLAC step takes up to ~20s first) ---"
for i in $(seq 1 30); do
    sleep 1
    if docker exec EVCC pgrep -f "iso15118/evcc/main.py" >/dev/null 2>&1; then
        echo "    EVCC HLC process started after ${i}s"
        break
    fi
done

echo "--- Waiting for EVCC's HLC process to finish ---"
for i in $(seq 1 20); do
    sleep 1
    if ! docker exec EVCC pgrep -f "iso15118/evcc/main.py" >/dev/null 2>&1; then
        echo "    EVCC HLC process has exited after ${i}s"
        break
    fi
done
sleep 2   # grace period so the last relayed packets land in the capture

echo "--- Stopping captures cleanly (SIGINT, so pcap trailers are written) ---"
docker exec Evil_EVSE_Evil_PEV pkill -INT -x tcpdump 2>/dev/null
docker exec SECC pkill -INT -x tcpdump 2>/dev/null
docker exec EVCC pkill -INT -x tcpdump 2>/dev/null
sleep 1.5   # give tcpdump a moment to flush and close the file

echo "--- Copying pcaps and logs out to the host ---"
docker cp "Evil_EVSE_Evil_PEV:/tmp/full_run_${RUN_TAG}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
docker cp "SECC:/tmp/secc_run_${RUN_TAG}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
docker cp "EVCC:/tmp/evcc_run_${RUN_TAG}_${TS}.pcap" "$HOST_CAPDIR/" 2>&1
docker cp "Evil_EVSE_Evil_PEV:/tmp/proxy_demo_${RUN_TAG}_${TS}.log" "$HOST_CAPDIR/" 2>&1
docker cp "SECC:/tmp/secc_demo_${RUN_TAG}_${TS}.log" "$HOST_CAPDIR/" 2>&1
docker cp "EVCC:/tmp/evcc_demo_${RUN_TAG}_${TS}.log" "$HOST_CAPDIR/" 2>&1

echo
echo "=== Done. Captures for this run: ==="
ls -la "$HOST_CAPDIR"/*"${RUN_TAG}_${TS}"*
