# evexchange-mitm

A working man-in-the-middle setup between an ISO 15118 EVCC (EV / car side)
and SECC (charger side), fully virtualized in Docker. A proxy sits in the
middle at **both** protocol layers — SLAC (HomePlug GreenPHY link
establishment) and HLC (the TCP/TLS/EXI charging session) — so the real EV
and real charger never share a network segment at any point; every step of
a session only ever reaches the other side through the proxy.

> **Research use only.** This repo intercepts and relays ISO 15118 charging
> sessions between EV and EVSE. Use it only against your own test rigs /
> simulators / authorized lab environments — never against a real vehicle,
> real charging station, or any system you don't own or have explicit
> written authorization to test.

## Two proxy modes

This repo ships two different MITM designs, both running the same Docker
image, picked with a `docker compose` flag:

| | **Single relay** (default) | **Split proxy** (`--profile split`) |
|---|---|---|
| Containers | `Evil_EVSE_Evil_PEV` (one) | `Evil_SECC` + `Evil_EVCC` (two) |
| TLS-protected sessions | Passed through as opaque bytes — can't see or alter content | Genuinely terminated on both legs — full visibility |
| `--debug` / `--tamper` on TLS | No effect | Works |
| Good for | Quick demo, plaintext (`notls`) tampering | Inspecting/tampering any session, including real ISO 15118-20 |

Start with the single relay — it's the default and the simplest to reason
about. Reach for the split proxy ([details below](#split-proxy-evil_secc--evil_evcc))
once you need to see inside a TLS session.

## Topology

```
   EVCC container                                             SECC container
             ─────────── proxy_net2 ───────────         ─────── proxy_net1 ───────
                                   MITM container(s)
                      (single relay: Evil_EVSE_Evil_PEV, dual-homed
                       split: Evil_SECC on proxy_net2, Evil_EVCC on proxy_net1,
                              bridged by a private bridge_net)
```

`EVCC` and `SECC` are **never on the same network, at any layer** (SLAC or
HLC) — they only ever reach each other through whichever proxy container is
on both `proxy_net1` and `proxy_net2`. Interfaces are always identified by
which subnet they're actually on (`proxy_net1` = `172.20.0.0/16`,
`proxy_net2` = `172.19.0.0/16`), never by assuming `eth0`/`eth1` map to a
particular network — Docker doesn't guarantee that stays stable across
restarts, and this bit the project for real once (see `discover_secc_evcc_interfaces()`
in `proxy/common.py` / `resolve_iface()` in the shell scripts).

## Quick start

```bash
git clone git@github.com:securityinmobility/evexchange-mitm.git
cd evexchange-mitm
docker build -f docker/Dockerfile.proxytest -t proxy-proxy .
```

> ⚠️ Don't confuse this with `virtual-charging-station/Proxy`'s own
> `docker compose build` — that builds a *different*, older Dockerfile that
> also happens to produce an image named `proxy-proxy`. Building the wrong
> one looks identical until setup fails with "Could not find the file
> `/usr/src/app`".

Then just:

```bash
docker compose up --build
```

This brings up `SECC`, `EVCC`, and `Evil_EVSE_Evil_PEV` (the single relay),
runs SLAC then a full TLS/PnC charging session, streams everything live and
labeled per-container, and drops pcaps + logs into `./captures/` when done
(Ctrl-C any time for a clean, partial capture).

**Modes**, via env vars:

```bash
EVCC_MODE=tls    docker compose up --build   # (default) ISO 15118-2 TLS/PnC
EVCC_MODE=notls  docker compose up --build   # ISO 15118-2 plaintext EIM/AC
EVCC_MODE=iso20  docker compose up --build   # ISO 15118-20 AC
TAMPER=1 EVCC_MODE=notls docker compose up --build   # + live tampering, see below
DEBUG=1 EVCC_MODE=notls docker compose up --build    # + print decoded EXI as messages are relayed
```

`--show-hex`/`--capture` (always on) only ever show raw hex — **`DEBUG=1`
is what actually prints decoded EXI content**, and it's off by default, so
without it you're only ever seeing hex, not translated message content.

**The split proxy** uses the same image/modes, just a different profile —
name the services explicitly so you don't also start the single relay
against the same `SECC`/`EVCC`:

```bash
docker compose --profile split up --build SECC EVCC Evil_SECC Evil_EVCC
```

See "[Split proxy](#split-proxy-evil_secc--evil_evcc)" below for what this buys you.

<details>
<summary>Manual / non-compose setup (one container per shell)</summary>

If you'd rather drive each container yourself instead of through compose:

```bash
# Networks
docker network create --ipv6 --subnet 172.20.0.0/16 --subnet 2001:db8:1::/64 proxy_net1
docker network create --ipv6 --subnet 172.19.0.0/16 --subnet 2001:db8:2::/64 proxy_net2

# Containers
docker run -dit --network proxy_net1 --name SECC proxy-proxy /bin/bash
docker run -dit --network proxy_net2 --name EVCC proxy-proxy /bin/bash
docker run -dit --network proxy_net1 --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker network connect proxy_net2 Evil_EVSE_Evil_PEV   # dual-home the proxy

# Copy scripts in
docker cp proxy/proxy01.py          Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker cp proxy/common.py           Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/common.py
docker cp scripts/proxy_run_full.sh Evil_EVSE_Evil_PEV:/usr/src/app/proxy_run_full.sh
docker cp scripts/secc_run_full.sh  SECC:/usr/src/app/secc_run_full.sh
docker cp scripts/evcc_run_full.sh  EVCC:/usr/src/app/evcc_run_full.sh

./scripts/regen_certs.sh   # fresh PKI — see "Certificate expiry" below
```

Then either the orchestrator (starts everything, captures pcaps, same
`[tls|notls|iso20] [tamper]` arguments as the `EVCC_MODE`/`TAMPER` env vars
above):

```bash
./scripts/run_full_demo.sh tls       # background, read logs after
./scripts/run_live_demo.sh tls       # streamed live, labeled [PROXY]/[SECC]/[EVCC]
```

or one shell per container:

```bash
docker exec -it Evil_EVSE_Evil_PEV bash -c /usr/src/app/proxy_run_full.sh
docker exec -it SECC bash -c /usr/src/app/secc_run_full.sh
docker exec -it EVCC bash -c /usr/src/app/evcc_run_full.sh
```

</details>

## Content tampering

By default the proxy only *observes* — every byte relayed is exactly what
was sent. `TAMPER=1` makes it actually alter content in flight: it targets
`ChargeParameterDiscoveryRes` (SECC → EVCC), which carries
`AC_EVSEChargeParameter.EVSEMaxCurrent` — the charger telling the car how
much current it can safely supply — and bumps it from the demo EVSE's real
`32` (Amps) to `63`, a genuine electrical-safety-relevant falsification.
When it fires:

```
[TAMPER] EVSEMaxCurrent: 32A -> 63A (ChargeParameterDiscoveryRes, SECC→EVCC)
```

**Verified live**: the EVCC reference simulator accepts the tampered value
with zero validation and proceeds straight into `PowerDelivery`/
`ChargingStatus` — but its own charging-profile logic is actually driven by
a different, untampered field (`PMaxSchedule`), so "accepted with no
pushback" and "visibly changed its own behavior" are two different claims;
only the first is demonstrated by this reference simulator.

**Only has an effect on sessions the proxy can actually decode**: `notls`
or `iso20` (which runs plaintext by default — see below) for the single
relay; any session for the split proxy. `tls` mode on the single relay
prints a `NOTE:` and does nothing — see "Two proxy modes" above for why.
Example captures are in [`examples/`](./examples).

### Modes in detail

- `tls` — real TLS handshake with a full cert chain
  (`CPOSubCA2 → SECCCert`, `CPOSubCA2 → CPOSubCA1 → V2GRootCA`).
- `notls` — plaintext EXI, same state sequence
  (`SupportedAppProtocol → SessionSetup → ServiceDiscovery →
  PaymentServiceSelection → Authorization → ChargeParameterDiscovery →
  PowerDelivery → ChargingStatus → SessionStop`), no TLS records.
- `iso20` — ISO 15118-20 AC. **Runs plaintext by default**, even though the
  standard itself mandates TLS: the pinned `iso15118` stack's own shipped
  example config (`evcc_config_ac.json`, and in fact all four of its
  `iso15118_20/` example configs) sets `"useTls": false`. So `--debug`
  shows decoded -20 content fine (EXI decode tries every -20 namespace,
  not just -2's), but `--tamper` still won't fire — -20 uses a
  differently-shaped `ACChargeParameterDiscoveryRes`, not the -2 message
  this proxy's tamper logic targets. To test a genuinely TLS-protected -20
  session, use your own copy of `evcc_config_ac.json` with
  `"useTls": true`, passed via `config=` to `make run-evcc` — not
  currently a canned `EVCC_MODE` option. An optional `ENABLE_TLS_1_3` env
  var (read directly by the `iso15118` stack) adds genuine TLS 1.3 +
  mutual-auth behavior on top of that.

### Certificate expiry

`iso15118`'s own cert-generation script hardcodes short validity windows
(SECC leaf: **60 days**). When certs expire, TLS/PnC runs fail with
`ssl.SSLCertVerificationError: certificate has expired` — run
`./scripts/regen_certs.sh` to regenerate and sync a fresh chain to every
container that needs it (`SECC` → `EVCC`/`Evil_SECC`/`Evil_EVCC`, if
present). This only patches the running containers' filesystems — if they
get recreated fresh from the image, the short-lived build-time certs come
back and `regen_certs.sh` needs to be re-run.

## Split proxy (`Evil_SECC` + `Evil_EVCC`)

The single relay (`Evil_EVSE_Evil_PEV`, `proxy/proxy01.py`) never
terminates TLS itself — for TLS-protected sessions it just forwards the
encrypted byte stream unmodified, so it can't see or tamper with content
once TLS is negotiated (confirmed above for `tls` mode; it would equally
apply to a genuinely TLS-protected `iso20` session, since this repo's
default `iso20` example just happens to run plaintext instead).

The split proxy closes that gap by using **two** containers, each
genuinely terminating its own TLS session as a real endpoint would,
instead of one relay that happens to forward bytes:

- **`Evil_SECC`** (`proxy/evil_secc.py`) sits on `proxy_net2`, next to the
  real `EVCC`. To the real EV it *is* the charger: answers SDP itself, and
  terminates TLS using the real SECC's own certificate/key
  (`iso15118.shared.security.get_ssl_context()` — the exact call the real
  SECC makes).
- **`Evil_EVCC`** (`proxy/evil_evcc.py`) sits on `proxy_net1`, next to the
  real `SECC`. To the real charger it *is* the EV: issues its own SDP
  request, and terminates TLS as a client trusting the real SECC's root CA.
- The two are bridged over a private `bridge_net` — never reachable by
  either real endpoint — carrying the relayed messages between them as
  length-prefixed JSON (`proxy/common.py`'s `write_json_frame`/
  `read_json_frame`).

```
            proxy_net2                                proxy_net1
 real EVCC ───────────── Evil_SECC          Evil_EVCC ───────────── real SECC
 (unchanged)            (fake charger)      (fake EV)               (unchanged)
                                │                  │
                                └──── bridge_net ──┘
                                 (private -- real EVCC/SECC never reach it)
```

Because TLS is genuinely terminated on both legs, `--debug`/`--tamper` now
work on **any** session, TLS or plaintext — the concrete capability this
buys over the single relay. `proxy/common.py` holds the decode/tamper/
framing logic shared by all three entry points, so the two designs can't
drift apart.

This is **additive, not a replacement**: `Evil_EVSE_Evil_PEV` and every
single-relay command above are unchanged, and the split containers are
gated behind the `split` compose profile so a plain `docker compose up`
behaves exactly as before. Run it with:

```bash
docker compose --profile split up --build SECC EVCC Evil_SECC Evil_EVCC
EVCC_MODE=iso20 docker compose --profile split up --build SECC EVCC Evil_SECC Evil_EVCC   # the mode that actually exercises the split's reason for existing
DEBUG=1 EVCC_MODE=tls docker compose --profile split up --build SECC EVCC Evil_SECC Evil_EVCC   # decoded EXI, even under real TLS
```

Don't run this alongside `Evil_EVSE_Evil_PEV` against the same `SECC`/
`EVCC` — both would try to answer the same SDP/SLAC requests. Captures land
in `./captures/` the same way (`evil_secc_run_*`/`evil_evcc_run_*`).

**Limitations**:
- One real `EVCC`/`SECC` pair and one session at a time, not a
  general-purpose multi-session proxy.
- `--tamper` stays ISO 15118-2 AC-specific here too.
- `bridge_net` carries the `Evil_SECC`↔`Evil_EVCC` control/relay protocol
  in plain, unauthenticated JSON — it relies entirely on network isolation
  (`internal: true`, no real EVCC/SECC ever attached) rather than being a
  hardened channel in its own right.
- Verified for one full session end to end (SDP → TLS handshake → relay →
  `SessionStop`), not stress-tested for back-to-back sessions, concurrent
  use, or recovery from a mid-session error.
- Not adapted for the "[Real hardware](#real-hardware-hlc-only)" setup
  below — that section only covers `proxy01.py`, the single relay.

## EVExchange cross-session relay

Neither of the two modes above is actually the attack this repo is named
after — both are single-session MITM designs. This section reproduces the
actual **EVExchange** attack: Conti, Donadel, Poovendran & Turrin,
*"EVExchange: A Relay Attack on Electric Vehicle Charging System"*
(arXiv:2203.05266).

### The scenario (what the paper describes)

Two real EVs each plug into one of two real, independent chargers at the
same site — both managed by the same back-end/charging network, so both
sides already trust each other's Plug & Charge certificates. One EV
belongs to a victim, one to the attacker. The attacker has pre-installed
two small relay devices, one inline at each charger's connector, wired
(or wirelessly linked) to each other.

Once both EVs are plugged in, the two relay devices **swap which
charger's communication each EV actually reaches** — the victim's EV ends
up negotiating its charging session with the *attacker's* charger, and
the attacker's EV ends up negotiating with the *victim's* charger. The
physical power cables never move: each charger still only ever energizes
whatever car is actually plugged into it. Since Plug & Charge bills
whoever's certificate/identity is in the negotiated session — not
whoever's car is physically drawing the current — the victim ends up
billed for charging the attacker's car, while the attacker can cut their
own (relayed) session short right after the victim walks away, paying
almost nothing for the energy that went into the victim's car instead.

Crucially, the relay devices **never decrypt anything** — the paper is
explicit that they only need to stop/forward the byte stream, even when
it's TLS-protected, since the attack works at the level of *which session
reaches which charger*, not by reading or altering content.

### How we reproduce it

This maps directly onto the existing building blocks in this repo,
blind-relay-only (no TLS termination anywhere, closer to `proxy01.py`'s
opaque pass-through than to the split proxy's content-visible design,
which exists for a different reason this attack doesn't need):

```
EVCC (victim) ──proxy_net2── Dev1 ──proxy_net1── SECC (victim's charger)
                              │
                         relay_link
                      (two raw TCP pipes,
                       Dev1<->Dev2 -- nothing
                       is ever decoded)
                              │
EVCC_Attacker ──proxy_net4── Dev2 ──proxy_net3── SECC_Attacker (attacker's charger)
```

`Dev1`/`Dev2` (`proxy/dev_relay.py`, one shared script) are mirror images
of each other, each a three-homed blind relay: a local-EVCC leg (SDP
responder, reusing the same SDP construction `evil_secc.py` uses), a
local-SECC leg (SDP initiator, same as `evil_evcc.py`), and a `relay_link`
connection to the other Dev. **The cross-wire**: each Dev's local-EVCC leg
bytes go out to the *other* Dev over `relay_link`, not back to its own
local-SECC leg — so `EVCC`'s (victim's) session actually reaches
`SECC_Attacker`, and `EVCC_Attacker`'s session actually reaches `SECC`
(victim's charger), while each charger's cable still only ever energizes
whatever's physically plugged into it. That data/energy split *is* the
attack — no decode or tamper logic exists anywhere in `dev_relay.py`.

`SECC_Attacker` needs the exact same cert chain as `SECC` (so the
cross-wired TLS handshake — victim's `EVCC` ending up talking to
`SECC_Attacker` — actually validates); `scripts/regen_certs.sh` already
syncs to it if present. `Dev1`/`Dev2` themselves need no certs at all,
since they never terminate TLS.

```bash
docker compose --profile evexchange up --build \
  SECC EVCC SECC_Attacker EVCC_Attacker Dev1 Dev2
```

Confirm the cross-wire actually happened by checking **identity, not just
traffic**: `SECC`'s own HLC log should show a session authenticated as the
*attacker's* contract cert, and `SECC_Attacker`'s log should show the
*victim's* — that mismatch between which charger and whose identity is the
actual proof, not just "bytes flowed." Then confirm energization stayed
physically correct: `EVCC`'s own charge-loop log should track `SECC`'s
power delivery, and `EVCC_Attacker`'s should track `SECC_Attacker`'s, each
physically paired, never swapped.

**`ATTACKER_STOP_AFTER_S`** (env var on `Dev2`, since `Dev2`'s local EVCC
is the attacker's) forcibly ends the attacker's relayed session N seconds
after it starts — reproducing the paper's billing asymmetry (attacker's
car charged in full and billed to the victim; victim's own car cut short,
billed to the attacker for almost nothing) without manual timing:

```bash
ATTACKER_STOP_AFTER_S=30 docker compose --profile evexchange up --build \
  SECC EVCC SECC_Attacker EVCC_Attacker Dev1 Dev2
```

**This is unverified** — built from the plan but not yet run end to end.
In particular: whether `SECC` actually stops energizing promptly on the
abrupt disconnect this produces (vs. hanging or retrying) hasn't been
confirmed against a real run. Verify before relying on it for a
demonstration, and update this note once confirmed.

**Limitations**: one victim pair + one attacker pair at a time (the
paper's own basic scenario, not its "more than two EVSEs" extension); no
TLS 1.3/mutual-auth variant explored yet (plain `tls`/`notls`/`iso20`
only); not adapted for the "[Real hardware](#real-hardware-hlc-only)"
section below, same as the split proxy.

## Real hardware (HLC-only)

For demonstrating this on physical hardware: `SECC`/`EVCC` stay as Docker
containers, unchanged, but SLAC is assumed handled by your own setup
outside this repo's scope. The MITM device itself needs **two** physical
NICs (one per leg — not one shared switch, which would let `SECC`/`EVCC`
reach each other directly once it learns their MACs) and runs this repo's
HLC software (currently only `proxy01.py`, the single relay — the split
proxy hasn't been adapted for bare-metal yet).

```
EVCC container  ──(host NIC A)── real MITM device ──(host NIC B)──  SECC container
```

1. Recreate `proxy_net1`/`proxy_net2` as `macvlan` networks bound to your
   physical NICs (`docker network create -d macvlan --ipv6 --subnet ... -o parent=<NIC> proxy_net1`,
   same for `proxy_net2`) — plain Docker bridge networks never reach a real
   wire. **Untested on real multi-NIC hardware** — verify before relying on
   it live.
2. Skip SLAC in `SECC`/`EVCC`: `secc_run_full.sh noslac` /
   `evcc_run_full.sh noslac`.
3. Build and run `proxy01.py` directly on the device, with `--network
   host` so it sees the physical interfaces, naming them explicitly since
   subnet auto-detection doesn't apply to real NICs:

```bash
docker run -dit --network host --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker cp proxy/proxy01.py Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker cp proxy/common.py Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/common.py
docker exec -it Evil_EVSE_Evil_PEV bash -c \
  "cd /usr/src/app/iso15118 && /venv/bin/python3 proxy01.py --capture --show-hex \
     --secc-iface eth0 --evcc-iface eth1"
```

Replace `eth0`/`eth1` with your device's actual link names. `--tamper`/
`--debug`/`--capture`/`--show-hex` all work the same as in the Docker demo.

## Repo layout

```
evexchange_attack.pdf           The EVExchange paper (Conti et al.) this repo is named after
docker/Dockerfile.proxytest     Builds the proxy-proxy image (iso15118 + mod_acccs + HomePlugPWN/V2GInjector)
docker-compose.yml               SECC/EVCC + three proxy modes: default (single relay), --profile split
                                 (Evil_SECC/Evil_EVCC), --profile evexchange (SECC_Attacker/EVCC_Attacker/Dev1/Dev2)
proxy/proxy01.py                Single-relay MITM (SDP hijack + transparent TCP/TLS relay)
proxy/common.py                 Decode/tamper/framing/interface-discovery helpers shared by every proxy entry point
proxy/evil_secc.py               Split-proxy fake-charger half
proxy/evil_evcc.py               Split-proxy fake-EV half
proxy/dev_relay.py               EVExchange cross-session relay (Dev1/Dev2, one shared script -- blind, no certs)
scripts/*_run_full.sh           SLAC then HLC, one command, per role (proxy/secc/evcc/evil_secc/evil_evcc/
                                 secc_b/evcc_attacker/dev1/dev2)
scripts/compose_*_entry.sh      compose `command:` entrypoints (cleanup, tcpdump, run the *_run_full.sh above)
scripts/run_full_demo.sh        Host-side orchestrator for the manual (non-compose) setup
scripts/run_live_demo.sh        Same, streamed live/labeled to the terminal
scripts/regen_certs.sh          Regenerates the ISO 15118-2 PKI and syncs it to every container that needs it
examples/                       Sample captures + logs from a working SLAC + TLS/PnC run
```

## Pinned versions

`docker/Dockerfile.proxytest` pins all four cloned dependencies to specific
commits — an unpinned build pulls whatever's HEAD at build time, which has
silently broken this setup before:

| Dependency | Pinned at |
|---|---|
| [`EcoG-io/iso15118`](https://github.com/EcoG-io/iso15118) | [`b256f9b`](https://github.com/EcoG-io/iso15118/commit/b256f9b379d3c0acbea24258c4a184f5264950a2) |
| [`vvvasu/mod_acccs`](https://github.com/vvvasu/mod_acccs) | [`fa1d08e`](https://github.com/vvvasu/mod_acccs/commit/fa1d08ea4c679cb37562c26a8775b0c86aab0d99) |
| [`JakeMG-INL/HomePlugPWN`](https://github.com/JakeMG-INL/HomePlugPWN) | [`ff840e7`](https://github.com/JakeMG-INL/HomePlugPWN/commit/ff840e707b0c54e06b1c836ed47112daffefd200) |
| [`JakeMG-INL/V2GInjector`](https://github.com/JakeMG-INL/V2GInjector) | [`1823d05`](https://github.com/JakeMG-INL/V2GInjector/commit/1823d055fe72f2613e3052736e3fc9071cba5f9f) |

If you bump any of these, re-run a full `tls`/`notls`/`iso20` pass on both
proxy modes before updating this table.
