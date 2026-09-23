# evexchange-mitm

A working man-in-the-middle setup between an ISO 15118 EVCC (EV / car side) and
SECC (charger side), fully virtualized in Docker. The proxy sits in the middle
at **both** layers: it completes its own SLAC (HomePlug GreenPHY)
link-establishment handshake with each real endpoint (impersonating the SECC
to the real EVCC, and the EVCC to the real SECC), then hijacks the SDP (SECC
Discovery Protocol) handshake at the HLC layer so the EVCC connects to it
instead of the real charger, and transparently relays the rest of the charging
session — TCP/TLS and EXI-encoded ISO 15118-2 messages — including a real
Plug & Charge TLS handshake with a full certificate chain. EVCC and SECC never
share a network segment at either layer — every step of the session, from
SLAC onward, only ever reaches the other side through the proxy.

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

SLAC and HLC are not chained within a single container process (see
[Topology](#topology) below): each container runs its SLAC step first, then
unconditionally starts its HLC process regardless of the SLAC outcome (the
bounded `timeout` in each `*_run_full.sh` is just a safety net). But at the
network layer, both now run over `proxy_net1`/`proxy_net2` — the same two
segments used for HLC — with the proxy present on both, so both layers are
intercepted:

- **SLAC**: the proxy (`scripts/proxy_run_full.sh`) runs two AcCCS
  `SLAC_ONLY=1` instances of its own, concurrently — a `PEV.py` (PEV role) on
  its `proxy_net1` leg, facing the real `SECC`, and an `EVSE.py` (EVSE role)
  on its `proxy_net2` leg, facing the real `EVCC`. Each is a genuine,
  protocol-conformant handshake (real `CM_SLAC_PARM.REQ`/`CNF`,
  `CM_MNBC_SOUND.IND` rounds, `CM_ATTEN_CHAR.IND`/`RSP`, and
  `CM_SLAC_MATCH.REQ`/`CNF`) — the real `SECC`/`EVCC` each believe they
  completed SLAC with each other, when they actually each completed it with
  the proxy impersonating the other side. This mirrors the identity-swap
  pattern in AcCCS's own `MIM.py` reference class, just invoked as two plain
  `EVSE.py`/`PEV.py` processes (same as `secc_run_full.sh`/`evcc_run_full.sh`
  already do) rather than `MIM.py` itself, which is stale against this fork's
  `argparse`-based `EVSE`/`PEV` constructors.
- **HLC**: unchanged — see below.

The MITM proxy (`proxy/proxy01.py`) handles the HLC layer: it intercepts
the EVCC's SDP multicast request, learns the real SECC's address from the
SECC's own SDP response, rewrites that response so the EVCC connects to the
proxy instead, opens its own connection to the real SECC, and relays
everything between them — including passing through a real TLS handshake
unmodified (it distinguishes TLS from plaintext by sniffing the first byte of
the stream: `0x16` = TLS ClientHello) and printing decoded EXI messages for
plaintext sessions via `--debug`.

## Topology

Just two networks — `EVCC` and `SECC` each have a single interface, and never
share a segment with each other at any layer:

```
   EVCC container                                             SECC container
 (EcoG iso15118 EVCC,                                       (EcoG iso15118 SECC,
   AcCCS PEV role)                                             AcCCS EVSE role)
             ─────────── proxy_net2 ───────────         ─────── proxy_net1 ───────
                                        proxy container
                        (proxy_run_full.sh — AcCCS EVSE role vs. EVCC,
                          AcCCS PEV role vs. SECC, then proxy01.py —
                                SDP hijack + transparent HLC relay)
```

- `proxy_net1`: `172.20.0.0/16`, `2001:db8:1::/64` — SECC's network, carrying
  both its SLAC and HLC traffic.
- `proxy_net2`: `172.19.0.0/16`, `2001:db8:2::/64` — EVCC's network, same.
  Both are created with `--ipv6` — AcCCS's `PEV.py`/`EVSE.py` require a
  link-local IPv6 address on the interface they're given at startup (without
  it, AcCCS crashes immediately with `IndexError: list index out of range`),
  which `--ipv6` already satisfies for both networks.
- `EVCC` and `SECC` are **never on the same network, at any layer** — they
  can only reach each other through the proxy, which is the only container on
  both `proxy_net1` and `proxy_net2`:
  - `SECC` → `proxy_net1` only
  - `EVCC` → `proxy_net2` only
  - `Evil_EVSE_Evil_PEV` (the proxy) → `proxy_net1` + `proxy_net2`

SLAC frames (HomePlug GreenPHY, EtherType `0x88E1`) and HLC traffic (SDP/UDP,
TCP/TLS — both IP-based) coexist on the same two bridges without interfering:
scapy's raw `AF_PACKET` SLAC handlers only ever see/inject `0x88E1` frames,
completely independent of the UDP/TCP sockets `proxy01.py` has open on the
same interfaces.

**Nothing in this repo assumes `eth0`/`eth1` map to a particular network.**
Docker does not guarantee that mapping stays stable across container
restarts or `docker network connect`/`disconnect` calls — confirmed twice in
practice, in two different places:

- `proxy01.py` identifies which of its own interfaces faces SECC vs. EVCC by
  matching each interface's assigned subnet against the known `proxy_net1`/
  `proxy_net2` ranges (see `discover_secc_evcc_interfaces()` in
  `proxy/proxy01.py` for the implementation), and pins the SDP multicast
  relay's outgoing interface the same way (`IPV6_MULTICAST_IF`) instead of
  trusting the kernel's default-route pick.
- `secc_run_full.sh`/`evcc_run_full.sh`/`proxy_run_full.sh` all use the same
  `resolve_iface()` shell function, which greps `ip -br a` for the interface
  whose address falls in a given subnet (`proxy_net1` for SECC/the proxy's
  SECC-facing leg, `proxy_net2` for EVCC/the proxy's EVCC-facing leg),
  passed to AcCCS's `-I <iface>` and to the EcoG stack via the
  `NETWORK_INTERFACE` env var it already reads, rather than left to its
  `eth0` default. This was hit for real (back when SLAC ran on a separate
  `slac_net` segment): `SECC` ended up with that segment on `eth0` and
  `proxy_net1` on `eth1` after some earlier reconnects, and since the HLC
  step never set `NETWORK_INTERFACE`, EcoG's default of `eth0` silently
  pointed the SDP listener at the wrong network — the proxy's SDP relay had
  a real destination, SECC's listener was real too, they were just on two
  different networks, so every run failed with `No SDP response from SECC`.
  Resolving every interface by subnet, everywhere, is what makes that class
  of bug impossible regardless of how many networks are in play.

## Prerequisites

- Docker (with IPv6-enabled bridge networking).
- The `proxy-proxy` image, built from this repo's own
  [`docker/Dockerfile.proxytest`](./docker/Dockerfile.proxytest) — it
  bundles the EcoG `iso15118` stack,
  [`mod_acccs`](https://github.com/vvvasu/mod_acccs) (AcCCS), and
  `HomePlugPWN`/`V2GInjector` all together. All three containers below
  (`EVCC`, `SECC`, `Evil_EVSE_Evil_PEV`) run this same image, just started
  with different names/networks/entrypoints.

```bash
git clone git@github.com:securityinmobility/evexchange-mitm.git
cd evexchange-mitm
docker build -f docker/Dockerfile.proxytest -t proxy-proxy .
```

⚠️ Don't confuse this with `virtual-charging-station/Proxy`'s own
`docker compose build` — that builds a *different*, older Dockerfile
(`Dockerfile.proxy`) that also happens to produce an image named
`proxy-proxy`, but without any of the AcCCS/SLAC/mod_acccs integration this
repo needs. Building the wrong one looks identical (succeeds, same image
name) until the `docker cp`/setup steps below fail with "Could not find the
file `/usr/src/app`" — if you hit that, this is why.

### Tested versions 📌

`docker/Dockerfile.proxytest` pins all four dependencies below to specific
commits — unpinned clones (whatever's HEAD at build time) are exactly what
let this setup silently drift out of sync with itself once before. They're
what every result in this README (`examples/`, the live-demo output, the
SLAC/HLC captures) was actually produced against:

| Dependency | Pinned at | Last verified working |
|---|---|---|
| [`EcoG-io/iso15118`](https://github.com/EcoG-io/iso15118) | [`b256f9b`](https://github.com/EcoG-io/iso15118/commit/b256f9b379d3c0acbea24258c4a184f5264950a2) (2025-10-02) | 2026-09-10 |
| [`vvvasu/mod_acccs`](https://github.com/vvvasu/mod_acccs) | [`fa1d08e`](https://github.com/vvvasu/mod_acccs/commit/fa1d08ea4c679cb37562c26a8775b0c86aab0d99) (2025-10-29) | 2026-09-10 |
| [`JakeMG-INL/HomePlugPWN`](https://github.com/JakeMG-INL/HomePlugPWN) | [`ff840e7`](https://github.com/JakeMG-INL/HomePlugPWN/commit/ff840e707b0c54e06b1c836ed47112daffefd200) (2025-05-01) | 2026-09-10 |
| [`JakeMG-INL/V2GInjector`](https://github.com/JakeMG-INL/V2GInjector) | [`1823d05`](https://github.com/JakeMG-INL/V2GInjector/commit/1823d055fe72f2613e3052736e3fc9071cba5f9f) (2024-01-10) | 2026-09-10 |

If you bump any of these, re-run the full `run_full_demo.sh`/`run_live_demo.sh`
flow (both `tls` and `notls`) before updating this table — a pin that's gone
stale without re-verification is barely better than no pin.

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
docker cp scripts/proxy_run_full.sh   Evil_EVSE_Evil_PEV:/usr/src/app/proxy_run_full.sh
docker cp scripts/secc_run_full.sh    SECC:/usr/src/app/secc_run_full.sh
docker cp scripts/evcc_run_full.sh    EVCC:/usr/src/app/evcc_run_full.sh
docker exec Evil_EVSE_Evil_PEV chmod +x /usr/src/app/proxy_run_full.sh
docker exec SECC chmod +x /usr/src/app/secc_run_full.sh
docker exec EVCC chmod +x /usr/src/app/evcc_run_full.sh

# Generate a fresh, valid PKI (see "Certificate expiry" below)
./scripts/regen_certs.sh
```

## Running it

The easiest path is the orchestrator, which starts everything, captures
packets, and copies the results back to the host:

```bash
./scripts/run_full_demo.sh                # TLS/PnC session (default)
./scripts/run_full_demo.sh notls           # plaintext EIM/AC session — see below
./scripts/run_full_demo.sh notls tamper    # plaintext + live content tampering — see "Content tampering"
```

This starts all three containers, launches `tcpdump -i any` inside the proxy
(the only container that sees *both* legs, SLAC and HLC alike, in one
capture) plus per-leg captures on `SECC`/`EVCC`, runs `proxy_run_full.sh`
(the proxy's two SLAC roles, then `proxy01.py --capture --show-hex`), then
`secc_run_full.sh` and `evcc_run_full.sh` in sequence, waits for the HLC
session to actually finish, stops all captures cleanly (`SIGINT`, so the pcap
trailer is written properly), and drops everything into `captures/` on the
host, timestamped so repeated runs never clobber each other:

```
captures/
  full_run_<mode>_<ts>.pcap    # proxy's view — SLAC (both roles) + both HLC relay legs, the authoritative capture
  secc_run_<mode>_<ts>.pcap    # SECC's own SLAC + HLC leg (now against the proxy, not EVCC directly)
  evcc_run_<mode>_<ts>.pcap    # EVCC's own SLAC + HLC leg (now against the proxy, not SECC directly)
  proxy_demo_<mode>_<ts>.log   # proxy_run_full.sh's SLAC output + proxy01.py's relay/decode log
  secc_demo_<mode>_<ts>.log    # SECC-side SLAC + HLC stdout
  evcc_demo_<mode>_<ts>.log    # EVCC-side SLAC + HLC stdout
```

Or run each step manually, one shell per container:

```bash
# 1. Proxy (SLAC, both roles, then SDP/TCP relay)
docker exec -it Evil_EVSE_Evil_PEV bash
/usr/src/app/proxy_run_full.sh

# 2. SECC (wait for the proxy to be listening)
docker exec -it SECC bash
/usr/src/app/secc_run_full.sh

# 3. EVCC (wait a couple seconds after SECC)
docker exec -it EVCC bash
/usr/src/app/evcc_run_full.sh
```

## Live demo

For presenting this live (a talk, someone watching over your shoulder),
`run_full_demo.sh` isn't great — it backgrounds everything and only shows
progress messages like `--- Starting SECC (SLAC then HLC) ---`, with the
actual SLAC/SDP/TLS/EXI output invisible until you read the log files
afterward. `run_live_demo.sh` runs the identical flow (same setup, same
`tls`/`notls` mode argument, same capture files at the end) but streams
`proxy01.py`'s and both `*_run_full.sh`'s output live, interleaved and
labeled, into the terminal as it happens:

```bash
./scripts/run_live_demo.sh        # TLS/PnC session (default)
./scripts/run_live_demo.sh notls  # plaintext EIM/AC session
```

Each line is prefixed `[PROXY]`, `[SECC]`, or `[EVCC]` (color-coded cyan/
yellow/green if the terminal supports it, plain text otherwise), so a viewer
can follow SLAC happening on both sides, then the SDP hijack, then the
TLS handshake or plaintext EXI messages, in the order they actually occur:

```
[PROXY] INFO (PEV) : Starting SLAC
[SECC]  INFO (EVSE): Recieved SLAC_PARM_REQ
[SECC]  INFO (EVSE): Sending CM_SLAC_PARM_CNF
[PROXY] INFO (EVSE): Sending 10 MNBC_SOUND_IND
[SECC]  INFO (EVSE): Sending SLAC_MATCH_CNF
[SECC]  INFO (EVSE): Done SLAC
[PROXY] INFO (PEV) : Done SLAC
[EVCC]  INFO (PEV) : Done SLAC
[PROXY] SECC SDP Response: 01fe900100000014fe800000000000006c57defffecc1954edcf0000
[PROXY]   SECC IP: fe80::6c57:deff:fecc:1954
[PROXY] Sent modified SDP response to EVCC at ('fe80::74bb:eff:fe7d:a415', 35019, 0, 3)
[PROXY] Accepted TCP connection from EVCC: ('fe80::74bb:eff:fe7d:a415', 35472, 0, 3)
[EVCC]  INFO    ... comm_session_handler (416): Starting TLS client, trying to connect to ...
```

Implementation: each source still logs to its own file in the container
(same as `run_full_demo.sh`), and the script attaches `docker exec ...
tail -F -n +1 <logfile> | sed -u 's/^/[LABEL] /'` to each one in the
background *before* starting proxy/SECC/EVCC, so nothing is missed. `tail
-F` (not `-f`) is what makes this work across the log file being truncated
when the actual process's own `> logfile` redirection opens.

Ctrl+C at any point is safe: it stops the streamers and `tcpdump`
(`SIGINT`, so the pcap trailer is still written correctly) and copies out
whatever was captured so far, same as letting it finish normally — you just
get a shorter/partial capture. Two things worth knowing if you're modifying
this script: `$!` right after `cmd1 | cmd2 &` only captures `cmd2`'s PID
(here, `sed`) — killing that leaves the `docker exec ... tail -F` process
orphaned indefinitely, since it has nothing left to write to and never gets
`SIGPIPE`, so cleanup instead kills by matching the actual command line
(`pkill -f`). And unlike an `EXIT` trap, bash's `INT`/`TERM` traps don't
stop the script after the handler returns on their own — the cleanup
function ends with an explicit `exit` to actually stop it.

### TLS / Plug & Charge vs. plaintext

The orchestrator takes a mode argument, so the two demos you actually run are:

```bash
./scripts/run_full_demo.sh tls      # (or no arg — default) real TLS/PnC session
./scripts/run_full_demo.sh notls    # plaintext EIM/AC session
```

This selects `EVCC_CONFIG_PATH` on the EVCC side only — `evcc_run_full.sh`
reads an `EVCC_MODE` env var (`tls` by default) and picks
`evcc_config_pnc_ac.json` (`useTls: true`) or `evcc_config_eim_ac.json`
(`useTls: false`) accordingly; `run_full_demo.sh` passes the mode through via
`docker exec -e EVCC_MODE=... EVCC ...`. `SECC` needs no corresponding
change — it already advertises both `EIM` and `PNC` auth modes and follows
whatever the EVCC's SDP request asks for, so `secc_run_full.sh` is identical
in both modes. The SLAC step (see [Topology](#topology)) is also identical
in both modes.

`tls` mode negotiates a real TLS handshake with a full cert chain
(`CPOSubCA2 → SECCCert`, `CPOSubCA2 → CPOSubCA1 → V2GRootCA`). `notls` mode
negotiates a plaintext EXI session and completes the same state sequence
(`SupportedAppProtocol` → `SessionSetup` → `ServiceDiscovery` →
`PaymentServiceSelection` → `Authorization` → `ChargeParameterDiscovery` →
`PowerDelivery` → `ChargingStatus` → `SessionStop`) with no TLS records at
all. Capture filenames from `run_full_demo.sh` are tagged with the mode,
e.g. `full_run_tls_<ts>.pcap` / `full_run_notls_<ts>.pcap`, so results from
both never collide.

If you're driving the containers manually instead of through the
orchestrator, set `EVCC_MODE=notls` before calling `evcc_run_full.sh`:

```bash
docker exec -it -e EVCC_MODE=notls EVCC bash -c /usr/src/app/evcc_run_full.sh
```

Example captures from a single, real run are included in
[`examples/`](./examples):
- `full_run_tls_pnc.pcap` (201 packets — SDP, TLS Handshake/ApplicationData/
  Alert records visible) and `proxy_demo_tls_pnc.log` (the proxy's
  relay/decode log for that same run — 45 relayed messages,
  `SupportedAppProtocol` through `SessionStop`): the HLC/TLS side, captured
  on the proxy.
- `secc_run_slac_handshake.pcap` and `secc_demo_slac_handshake.log`: the SLAC
  handshake from the same run — `CM_SET_KEY.REQ` → `CM_SLAC_PARM.REQ`/`CNF` →
  `CM_START_ATTEN_CHAR.IND` → repeated `CM_MNBC_SOUND.IND` →
  `CM_ATTEN_CHAR.IND`/`RSP` → `CM_SLAC_MATCH.REQ`/`CNF`, ending in
  `EVSE: Done SLAC`. Captured on `SECC`'s dedicated `slac_net` interface from
  before the proxy also intercepted SLAC (see [Topology](#topology)) — SECC's
  SLAC counterpart in this particular capture is the real `EVCC`, not the
  proxy; the message sequence itself is unchanged.

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

## Content tampering

Up to this point the proxy only *observes* the session — every byte it
relays is exactly what SECC or EVCC sent. `TAMPER=1` (or `--tamper` on
`proxy01.py` directly) makes it actually alter content in flight, to
demonstrate the MITM can tamper with a session, not just watch it:

```bash
./scripts/run_full_demo.sh notls tamper
./scripts/run_live_demo.sh notls tamper
```

**What it tampers with, and why it's safety-relevant**: `ChargeParameterDiscoveryRes`
(SECC → EVCC) carries `AC_EVSEChargeParameter.EVSEMaxCurrent` — the charger
telling the car how much current the physical hookup can safely supply. The
proxy decodes this message as it passes through, changes
`EVSEMaxCurrent.Value` from the demo EVSE's real `32` (Amps) to `63`, and
re-encodes it before forwarding — a real EVSE overstating its own supply
capacity in transit, which is a genuine electrical-safety-relevant
falsification (as opposed to e.g. tampering with pricing or a status
string), and it's the SECC→EVCC direction rather than the EVCC→SECC
direction the old `virtual-charging-station/Proxy/mod_proxy.py`'s
`EVMaxVoltage` example used. When it fires, the proxy prints a loud, `grep`-able
line regardless of `--debug`/`--show-hex`:

```
[TAMPER] EVSEMaxCurrent: 32A -> 63A (ChargeParameterDiscoveryRes, SECC→EVCC)
```

**Only takes effect in `notls` mode.** The proxy relays TLS as an opaque
encrypted byte stream without terminating it itself — tampering TLS-protected content would need a full TLS-interception
MITM (present the proxy's own certificate to EVCC, open a separate TLS
connection to SECC, decrypt/modify/re-encrypt in the middle), which this
does not implement. `tls tamper` runs without error but has no effect
(a `NOTE:` line says so up front); use `notls tamper` to actually see it.

**Verified: EVCC accepts the tampered value with no validation, but this
particular reference simulator doesn't act on it.** Confirmed live, both
ends:
- EVCC's own decoded-message log shows it received and logged
  `"EVSEMaxCurrent":{"Multiplier":0,"Unit":"A","Value":63}` verbatim — the
  tampered value, not the real `32` — and proceeded straight into
  `PowerDelivery`/`ChargingStatus` with no rejection, clamping, or warning.
  This is the actual point of the demo: the EV trusted a falsified claim
  about the charger's electrical capacity with zero pushback.
- However, `grep -rn EVSEMaxCurrent iso15118/evcc/` inside the EVCC
  container returns nothing: this EcoG reference simulator (`SimEVController`)
  never reads `EVSEMaxCurrent` anywhere in its own logic. Its charging
  profile (`PowerDeliveryReq.ChargingProfile`) is instead driven by
  `PMaxSchedule` (a power/Watts figure, part of the same
  `ChargeParameterDiscoveryRes` but a different field, left untampered), so
  the EV's own requested profile doesn't visibly change in this specific
  code path. A real vehicle's onboard charger hardware would be expected to
  treat `EVSEMaxCurrent` as a hard current ceiling independent of the power
  schedule — this reference simulator just doesn't model that, so the
  "did it get used" question splits into "accepted, yes" / "acted on
  *this specific way*, not observably, in this simulator." Reported
  honestly rather than claiming a dramatic behavioral change that isn't
  actually there.

An example capture is included in [`examples/`](./examples):
`full_run_tamper.pcap`, `proxy_demo_tamper.log` (shows the `[TAMPER]` line),
and `evcc_demo_tamper.log` (shows EVCC decoding the tampered `63A` value).

## Running with your own MITM hardware (HLC-only)

For demonstrating this on real hardware: `SECC` and `EVCC` stay exactly as
the rest of this README builds them — Docker containers, unchanged. SLAC is
assumed to be handled by your own separate setup, outside this repo's
scope, so the containers skip it. The MITM itself is your own device,
replacing the `Evil_EVSE_Evil_PEV` container — but it needs *this repo's*
HLC MITM software (`proxy01.py`) actually running on it; owning the
hardware doesn't include the interception logic, that's what this section
sets up.

**Topology.** The MITM device needs **two** physical network interfaces —
one wired to each Docker container's network (a direct cable, or its own
small switch per leg) — *not* one shared switch with everything on it. A
real switch would forward `EVCC`'s and `SECC`'s traffic straight to each
other once it learns their MAC addresses, bypassing the MITM device
entirely — same "two separate physical links" reasoning as
[Topology](#topology) above, just with the Docker host's own two NICs
standing in for the proxy container's two interfaces:

```
EVCC container  ──(host NIC A)── real MITM device ──(host NIC B)──  SECC container
```

**Expose `proxy_net1`/`proxy_net2` to those NICs.** Docker bridge networks
(what the rest of this README uses) are host-internal and never reach a
real wire. Recreate them as `macvlan` networks instead, each bound to one
of the host's physical NICs via `-o parent=`, keeping the same subnets so
nothing else in the repo needs to change:

```bash
docker network create -d macvlan --ipv6 \
  --subnet 172.20.0.0/16 --subnet 2001:db8:1::/64 \
  -o parent=<host NIC facing SECC>   proxy_net1

docker network create -d macvlan --ipv6 \
  --subnet 172.19.0.0/16 --subnet 2001:db8:2::/64 \
  -o parent=<host NIC facing EVCC>   proxy_net2
```

Replace the `<...>` placeholders with your actual NIC names (`ip -br a` on
the host). If the host's real LAN already uses `172.19.0.0/16`/
`172.20.0.0/16`, pick different subnets for both `docker network create`
calls here and for the `resolve_iface()` prefixes in
`secc_run_full.sh`/`evcc_run_full.sh` — otherwise interface auto-detection
won't match. **Untested here** (no multi-NIC hardware to verify against) —
try this against your actual host before relying on it for a live
demonstration. Skip `Evil_EVSE_Evil_PEV` entirely — don't create or start
that container; the real device takes its place on the wire.

**Skip SLAC in the containers.** Both `secc_run_full.sh` and
`evcc_run_full.sh` take an optional `noslac` argument that skips the AcCCS
SLAC step and goes straight to HLC — use it here, since SLAC is your own
setup's job, not this container's:

```bash
# SECC
docker exec -it SECC bash -c "/usr/src/app/secc_run_full.sh noslac"

# EVCC (tls/PnC by default; set EVCC_MODE=notls same as normal)
docker exec -it EVCC bash -c "/usr/src/app/evcc_run_full.sh noslac"
```

`run_full_demo.sh`/`run_live_demo.sh` don't apply here — they assume all
three containers including the Docker proxy — so drive `SECC`/`EVCC`
manually as above, same pattern as the "run each step manually" steps in
[Running it](#running-it).

**Build and run the proxy software on the MITM device itself** (building
there, rather than cross-compiling, so Docker picks the right base image
automatically):

```bash
git clone git@github.com:securityinmobility/evexchange-mitm.git
cd evexchange-mitm
docker build -f docker/Dockerfile.proxytest -t proxy-proxy .
```

Run just `proxy01.py` — not `proxy_run_full.sh`, which also runs the AcCCS
SLAC roles that aren't needed here — with the container sharing the
device's real network stack (`--network host`) so it can see the two
physical interfaces directly, and tell it which interface faces which side
by name instead of by Docker subnet (`--secc-iface`/`--evcc-iface` — see
`proxy01.py`'s `discover_secc_evcc_interfaces()`; auto-detect-by-subnet is
what the rest of this README's Docker demo uses, and doesn't apply here
since these are real interfaces, not `proxy_net1`/`proxy_net2`):

```bash
docker run -dit --network host --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker cp proxy/proxy01.py Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker exec -it Evil_EVSE_Evil_PEV bash -c \
  "cd /usr/src/app/iso15118 && python3 proxy01.py --capture --show-hex \
     --secc-iface eth0 --evcc-iface eth1"
```

Replace `eth0`/`eth1` with whatever `ip -br a` on the device actually shows
for the two links. `--tamper`, `--debug`, `--capture`, `--show-hex` all
work the same as in the Docker demo (see
[Content tampering](#content-tampering) above) — nothing about the
relay/tamper/decode logic changed, only how the two interfaces are
identified.

**What this doesn't assume**: `proxy01.py` only needs to speak standard
ISO 15118 SDP (UDP multicast to `ff02::1`, port `15118`) and TCP/TLS/EXI on
the wire — it has no dependency on `SECC`/`EVCC` running any particular
software beyond that, Dockerized or not. It does still import
`iso15118.shared.exificient_exi_codec` at startup for EXI decode/encode
(used by `--debug`/`--tamper`), which is why it still needs to run from
inside the `proxy-proxy` image (or any environment with that package
installed) even in this HLC-only mode.

## Repo layout

```
docker/Dockerfile.proxytest  Builds the proxy-proxy image (iso15118 + mod_acccs + HomePlugPWN/V2GInjector)
proxy/proxy01.py         The HLC MITM relay (SDP hijack + transparent TCP/TLS relay)
scripts/proxy_run_full.sh SLAC (AcCCS, both roles, concurrently) then HLC (proxy01.py) in one command
scripts/secc_run_full.sh  SLAC (AcCCS EVSE role, vs. the proxy) then HLC (EcoG SECC) in one command
scripts/evcc_run_full.sh  SLAC (AcCCS PEV role, vs. the proxy) then HLC (EcoG EVCC, TLS/PnC) in one command
scripts/run_full_demo.sh  Host-side orchestrator: runs everything + captures pcaps
scripts/run_live_demo.sh  Same flow, streamed live/labeled to the terminal -- see "Live demo"
scripts/regen_certs.sh    Regenerates the ISO 15118-2 PKI and syncs it SECC -> EVCC
examples/                 Sample captures + logs from a working SLAC + TLS/PnC run
```
