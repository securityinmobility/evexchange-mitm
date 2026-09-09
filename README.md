# evexchange-mitm

A working man-in-the-middle setup between an ISO 15118 EVCC (EV / car side) and
SECC (charger side), fully virtualized in Docker. The proxy hijacks the SDP
(SECC Discovery Protocol) handshake so the EVCC connects to it instead of the
real charger, then transparently relays the full charging session — SLAC,
TCP/TLS, and EXI-encoded ISO 15118-2 messages — including a real Plug & Charge
TLS handshake with a full certificate chain.

> **Research use only.** This repo intercepts and relays ISO 15118 charging
> sessions between EV and EVSE. Use it only against your own test rigs /
> simulators / authorized lab environments — never against a real vehicle,
> real charging station, or any system you don't own or have explicit written
> authorization to test.

## What's actually happening

Two independent layers, both virtualized as Docker containers:

- **SLAC** (HomePlug GreenPHY link establishment) — via
  [AcCCS](https://github.com/securityinmobility/AcCCS) (this repo uses the
  [mod_acccs](https://github.com/vvvasu/mod_acccs) fork, which adds a
  `SLAC_ONLY=1` mode: AcCCS does the `SLAC_PARM`/`SLAC_MATCH_REQ`/`SLAC_MATCH_CNF`
  exchange and then stops, instead of continuing into its own (unrelated,
  weaker) DIN 70121 code path).
- **HLC** (High-Level Communication — the actual ISO 15118 TCP/TLS/EXI session)
  — via [EcoG's `iso15118`](https://github.com/EcoG-io/iso15118) stack, real
  EVCC and SECC implementations.

SLAC and HLC are **not chained** in this setup — and can't be, given the
topology below (see [Why SLAC doesn't gate HLC here](#why-slac-doesnt-gate-hlc-here)).
Each container runs its SLAC step best-effort, then unconditionally starts its
HLC process. This matches how the underlying demo was actually built and run.

The MITM proxy (`proxy/proxy01.py`) sits at the HLC layer only: it intercepts
the EVCC's SDP multicast request, learns the real SECC's address from the
SECC's own SDP response, rewrites that response so the EVCC connects to the
proxy instead, opens its own connection to the real SECC, and relays
everything between them — including passing through a real TLS handshake
unmodified (it distinguishes TLS from plaintext by sniffing the first byte of
the stream: `0x16` = TLS ClientHello) and printing decoded EXI messages for
plaintext sessions via `--debug`.

## Topology

```
   EVCC container                proxy container                 SECC container
 (EcoG iso15118 EVCC,       (proxy01.py — SDP hijack           (EcoG iso15118 SECC,
   AcCCS PEV role)            + transparent relay)                AcCCS EVSE role)
        eth0 ─────── proxy_net2 ─────── eth1    eth0 ─────── proxy_net1 ─────── eth0
    172.19.0.x/2001:db8:2::x        172.19.0.2/2001:db8:2::2  172.20.0.2/2001:db8:1::2   172.20.0.x/2001:db8:1::x
```

- `proxy_net1`: `172.20.0.0/16`, `2001:db8:1::/64`
- `proxy_net2`: `172.19.0.0/16`, `2001:db8:2::/64`
- `EVCC` and `SECC` are **never on the same network** — they can only reach
  each other through the proxy, which is the only container dual-homed on
  both. `proxy01.py` auto-discovers its own addresses via `ip a` and assumes
  its *first* interface (`eth0`) faces SECC's network and its *second*
  (`eth1`) faces EVCC's — so container placement matters:
  - `SECC` → `proxy_net1`
  - `EVCC` → `proxy_net2`
  - `Evil_EVSE_Evil_PEV` (the proxy) → both

### Why SLAC doesn't gate HLC here

SLAC requires direct L2 adjacency between exactly two peers on the same
segment. The MITM topology deliberately isolates EVCC and SECC from each
other at L2/L3 (that's the whole point — it forces both sides through the
proxy). So neither container has a real SLAC peer to match against; SLAC
always times out here. SLAC and the HLC MITM are genuinely two separate
demonstrations of the same containers/images, not stages of one pipeline.

## Prerequisites

- Docker (with IPv6-enabled bridge networking).
- The `proxy-proxy` image, built from
  [`virtual-charging-station/Proxy`](https://github.com/securityinmobility/virtual-charging-station)'s
  `Dockerfile.proxytest` — this image bundles the EcoG `iso15118` stack,
  [`mod_acccs`](https://github.com/vvvasu/mod_acccs) (AcCCS), and
  `HomePlugPWN`/`V2GInjector` all together. All three containers below
  (`EVCC`, `SECC`, `Evil_EVSE_Evil_PEV`) run this same image, just started
  with different names/networks/entrypoints.

```bash
git clone git@github.com:securityinmobility/virtual-charging-station.git
cd virtual-charging-station/Proxy
docker compose build --no-cache   # -> image `proxy-proxy`
```

## One-time setup

```bash
# Networks
docker network create --ipv6 --subnet 172.20.0.0/16 --subnet 2001:db8:1::/64 proxy_net1
docker network create --ipv6 --subnet 172.19.0.0/16 --subnet 2001:db8:2::/64 proxy_net2

# Containers (no extra --cap-add needed — Docker's default caps already
# include NET_RAW, enough for both AcCCS's raw SLAC sockets and tcpdump)
docker run -dit --network proxy_net1 --name SECC proxy-proxy /bin/bash
docker run -dit --network proxy_net2 --name EVCC proxy-proxy /bin/bash
docker run -dit --network proxy_net1 --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker network connect proxy_net2 Evil_EVSE_Evil_PEV   # dual-home the proxy

# Copy this repo's scripts into each container
docker cp proxy/proxy01.py            Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker cp scripts/secc_run_full.sh    SECC:/usr/src/app/secc_run_full.sh
docker cp scripts/evcc_run_full.sh    EVCC:/usr/src/app/evcc_run_full.sh
docker exec SECC chmod +x /usr/src/app/secc_run_full.sh
docker exec EVCC chmod +x /usr/src/app/evcc_run_full.sh

# Generate a fresh, valid PKI (see "Certificate expiry" below)
./scripts/regen_certs.sh
```

## Running it

The easiest path is the orchestrator, which starts everything, captures
packets, and copies the results back to the host:

```bash
./scripts/run_full_demo.sh
```

This starts all three containers, launches `tcpdump -i any` inside the proxy
(the only container that sees *both* legs of the relay in one capture) plus
per-leg captures on `SECC`/`EVCC`, runs `proxy01.py --capture --show-hex`,
then `secc_run_full.sh` and `evcc_run_full.sh` in sequence, waits for the HLC
session to actually finish, stops all captures cleanly (`SIGINT`, so the pcap
trailer is written properly), and drops everything into
`captures/` on the host, timestamped so repeated runs never clobber each
other:

```
captures/
  full_run_<ts>.pcap    # proxy's view — both relay legs, the authoritative capture
  secc_run_<ts>.pcap    # SECC's own leg + its SLAC attempt
  evcc_run_<ts>.pcap    # EVCC's own leg + its SLAC attempt
  proxy_demo_<ts>.log   # proxy01.py's relay/decode log
  secc_demo_<ts>.log    # SECC-side SLAC + HLC stdout
  evcc_demo_<ts>.log    # EVCC-side SLAC + HLC stdout
```

Or run each step manually, one shell per container:

```bash
# 1. Proxy
docker exec -it Evil_EVSE_Evil_PEV bash
cd /usr/src/app/iso15118 && python3 proxy01.py --capture --show-hex

# 2. SECC (wait for the proxy to be listening)
docker exec -it SECC bash
/usr/src/app/secc_run_full.sh

# 3. EVCC (wait a couple seconds after SECC)
docker exec -it EVCC bash
/usr/src/app/evcc_run_full.sh
```

### TLS / Plug & Charge vs. plaintext

`evcc_run_full.sh` runs with the PnC config
(`evcc_config_pnc_ac.json`, `useTls: true`) by default, so the session
negotiates a real TLS handshake with a full cert chain
(`CPOSubCA2 → SECCCert`, `CPOSubCA2 → CPOSubCA1 → V2GRootCA`). SECC needs no
corresponding change — it already advertises both `EIM` and `PNC` auth modes
and follows whatever the EVCC's SDP request asks for. To run the plaintext
EIM/AC session instead, drop the `config=...` argument from `make run-evcc`
in `evcc_run_full.sh` (or point it at `evcc_config_eim_ac.json`).

An example captured TLS/PnC session is included in
[`examples/`](./examples): `full_run_tls_pnc.pcap` (202 packets — SDP, TLS
Handshake/ApplicationData/Alert records visible) and
`proxy_demo_tls_pnc.log` (the proxy's relay/decode log for that same run —
45 relayed messages, `SupportedAppProtocol` through `SessionStop`).

### Certificate expiry

`iso15118`'s own `create_certs.sh` hardcodes short validity windows (the SECC
leaf cert defaults to **60 days**). Certs baked into the image at build time
*will* expire; when they do, TLS/PnC runs fail with
`ssl.SSLCertVerificationError: certificate has expired`. Run
`./scripts/regen_certs.sh` to regenerate the whole chain in `SECC` and sync it
into `EVCC` (both sides must share the identical regenerated chain — CA keys
are random per run, so regenerating independently on each side breaks trust).
This is a container-filesystem-only fix: if `EVCC`/`SECC` are ever recreated
fresh from the `proxy-proxy` image (not just stopped/started), the
short-lived certs baked into the image come back and `regen_certs.sh` needs
to be re-run.

## The proxy fix (`proxy01.py`)

The version of `proxy01.py` in this repo fixes a framing bug in the original:
the original peeked exactly 5 bytes of the incoming stream to sniff for TLS
(`first_bytes[0] == 0x16`) and forwarded those 5 bytes immediately, before
handing off to the generic relay loop — which split the first V2GTP message
across two separate TCP writes. `iso15118`'s SECC-side parser doesn't buffer
partial reads, so it rejected the truncated first fragment
(`InvalidV2GTPMessageError: only 5 bytes`) and the session died immediately.

Fixed version: peek only **1** byte to distinguish TLS (`0x16`) from
plaintext. For plaintext, read the full 8-byte V2GTP header (1B version, 1B
inverse version, 2B payload type, 4B payload length), parse the real payload
length, then read exactly that many more bytes — so SECC always receives one
complete V2GTP message per write. TLS framing is left to the TLS layer
itself, same as before.

## Repo layout

```
proxy/proxy01.py         The MITM relay (SDP hijack + transparent TCP/TLS relay)
scripts/secc_run_full.sh  SLAC (AcCCS EVSE role) then HLC (EcoG SECC) in one command
scripts/evcc_run_full.sh  SLAC (AcCCS PEV role) then HLC (EcoG EVCC, TLS/PnC) in one command
scripts/run_full_demo.sh  Host-side orchestrator: runs everything + captures pcaps
scripts/regen_certs.sh    Regenerates the ISO 15118-2 PKI and syncs it SECC -> EVCC
examples/                 Sample capture + log from a working TLS/PnC run
```
