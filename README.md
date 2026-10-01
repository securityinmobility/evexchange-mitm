# evexchange-mitm

ISO 15118 EV charging MITM toolkit. The main attack is a cross-session
relay: two EVs, two chargers, two relay devices that swap which EV's
session reaches which charger. Plug & Charge bills whoever's certificate
is in the session, not whoever's car is actually plugged in, so the
victim ends up paying for the attacker's charge.

The repo also has two simpler single-session MITM modes (one EV, one
charger, one proxy in between) that the cross-session relay is built on
top of.

> Research use only. Point this at your own test rigs and simulators —
> never a real vehicle or charging station you don't own or have written
> authorization to test.

## Build

```bash
git clone git@github.com:securityinmobility/evexchange-mitm.git
cd evexchange-mitm
docker build -f docker/Dockerfile.proxytest -t proxy-proxy .
```

## Cross-session relay

Two EV/charger pairs: `SECC`/`EVCC` on the victim's side,
`SECC_Attacker`/`EVCC_Attacker` on the attacker's. `Dev1` sits between the
victim's EV and the victim's charger; `Dev2` sits between the attacker's
EV and the attacker's charger.

```
EVCC (victim) ──proxy_net2── Dev1 ──proxy_net1── SECC (victim's charger)
                              │
                         relay_link
                              │
EVCC_Attacker ──proxy_net4── Dev2 ──proxy_net3── SECC_Attacker (attacker's charger)
```

Neither Dev relays its own two legs straight through. Dev1 takes what it
hears from the victim's EV and sends it to Dev2, which forwards it to the
attacker's charger. Dev2 does the same in reverse: what it hears from the
attacker's EV goes to Dev1, which forwards it to the victim's charger. End
result — the victim's EV runs its charging session against the attacker's
charger, and the attacker's EV runs its session against the victim's
charger, while the physical cables never move, so each charger still only
delivers power to whatever's actually plugged into it. Since billing
follows the session's certificate, not the cable, the victim ends up
paying for the attacker's charge.

`Dev1`/`Dev2` (`proxy/dev_relay.py`) are a blind byte relay — no TLS
termination, no decoding, no certs of their own.

```bash
docker compose --profile evexchange up --build \
  SECC EVCC SECC_Attacker EVCC_Attacker Dev1 Dev2
```

Check `SECC`'s log for a session authenticated with the attacker's
certificate, and `SECC_Attacker`'s for the victim's — that mismatch is the
proof it worked. Works for ISO 15118-20 too (`EVCC_MODE=iso20`), since the
relay never inspects content and has nothing version-specific to support.

`ATTACKER_STOP_AFTER_S` (set on `Dev2`) cuts the attacker's relayed
session short after N seconds, reproducing the billing asymmetry without
manual timing:

```bash
ATTACKER_STOP_AFTER_S=30 docker compose --profile evexchange up --build \
  SECC EVCC SECC_Attacker EVCC_Attacker Dev1 Dev2
```

Not yet tested end-to-end.

`SECC_Attacker` needs the same cert chain as `SECC` for the cross-wired
TLS handshake to validate — `regen_certs.sh` syncs it automatically. One
victim/attacker pair at a time; `--tamper`/`--debug` aren't available here
(see the single-session modes below for those).

## Single-session modes

One real EV, one real charger, one proxy in between — what the
cross-session relay is built out of.

| | Single relay (default) | Split proxy (`--profile split`) |
|---|---|---|
| Containers | `Evil_EVSE_Evil_PEV` | `Evil_SECC` + `Evil_EVCC` |
| TLS sessions | Opaque relay, no visibility | Terminated, full visibility |
| `--debug`/`--tamper` on TLS | No | Yes |

```bash
docker compose up --build                                                 # single relay
docker compose --profile split up --build SECC EVCC Evil_SECC Evil_EVCC   # split proxy
```

Both use the same `EVCC_MODE` values: `tls` (default, ISO 15118-2 PnC),
`notls` (plaintext), `iso20` (ISO 15118-20 — runs plaintext by default
since the stack's own example config sets `useTls: false`).

`TAMPER=1` rewrites `EVSEMaxCurrent` in `ChargeParameterDiscoveryRes` from
32A to 63A in flight. Only has an effect where the session can actually be
decoded: `notls`/`iso20` on the single relay, any mode on the split
proxy. The reference EVCC accepts the tampered value with no validation,
though its own charge-loop logic uses a different field (`PMaxSchedule`)
so it doesn't visibly act on it.

`DEBUG=1` prints decoded EXI content as messages are relayed. Off by
default — without it you only see hex.

Certs expire after 60 days (`ssl.SSLCertVerificationError`). Regenerate
and resync to every container that needs it:

```bash
./scripts/regen_certs.sh
```

<details>
<summary>Manual setup without compose</summary>

```bash
docker network create --ipv6 --subnet 172.20.0.0/16 --subnet 2001:db8:1::/64 proxy_net1
docker network create --ipv6 --subnet 172.19.0.0/16 --subnet 2001:db8:2::/64 proxy_net2

docker run -dit --network proxy_net1 --name SECC proxy-proxy /bin/bash
docker run -dit --network proxy_net2 --name EVCC proxy-proxy /bin/bash
docker run -dit --network proxy_net1 --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker network connect proxy_net2 Evil_EVSE_Evil_PEV

docker cp proxy/proxy01.py          Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker cp proxy/common.py           Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/common.py
docker cp scripts/proxy_run_full.sh Evil_EVSE_Evil_PEV:/usr/src/app/proxy_run_full.sh
docker cp scripts/secc_run_full.sh  SECC:/usr/src/app/secc_run_full.sh
docker cp scripts/evcc_run_full.sh  EVCC:/usr/src/app/evcc_run_full.sh

./scripts/regen_certs.sh
```

Then either the orchestrator:

```bash
./scripts/run_full_demo.sh tls    # background, read logs after
./scripts/run_live_demo.sh tls    # streamed live, labeled per container
```

or one shell per container:

```bash
docker exec -it Evil_EVSE_Evil_PEV bash -c /usr/src/app/proxy_run_full.sh
docker exec -it SECC bash -c /usr/src/app/secc_run_full.sh
docker exec -it EVCC bash -c /usr/src/app/evcc_run_full.sh
```

</details>

## Real hardware

HLC-only MITM on physical hardware — `SECC`/`EVCC` stay as containers,
SLAC is handled by your own setup, and the single relay runs on bare
metal with two NICs. Not adapted for the split proxy or cross-session
relay yet.

```bash
docker run -dit --network host --name Evil_EVSE_Evil_PEV proxy-proxy /bin/bash
docker cp proxy/proxy01.py Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/proxy01.py
docker cp proxy/common.py Evil_EVSE_Evil_PEV:/usr/src/app/iso15118/common.py
docker exec -it Evil_EVSE_Evil_PEV bash -c \
  "cd /usr/src/app/iso15118 && /venv/bin/python3 proxy01.py --secc-iface eth0 --evcc-iface eth1"
```

`secc_run_full.sh noslac` / `evcc_run_full.sh noslac` skip SLAC in the EV
and charger containers. Untested on real multi-NIC hardware.

## Repo layout

```
docker/Dockerfile.proxytest   Builds the proxy-proxy image
docker-compose.yml            Default profile (single relay), --profile split, --profile evexchange
proxy/dev_relay.py            Cross-session relay (Dev1/Dev2) -- blind, no certs
proxy/proxy01.py              Single relay -- SDP hijack + transparent TCP/TLS relay
proxy/common.py               Decode/tamper/framing/interface-discovery helpers
proxy/evil_secc.py            Split proxy, fake-charger half
proxy/evil_evcc.py            Split proxy, fake-EV half
scripts/*_run_full.sh         SLAC then HLC, one command, per role
scripts/compose_*_entry.sh    compose entrypoints (cleanup, tcpdump, run the *_run_full.sh above)
scripts/regen_certs.sh        Regenerates the PKI and syncs it to every container that needs it
examples/                     Sample captures and logs from a working run
```

## Pinned versions

| Dependency | Pinned at |
|---|---|
| [`EcoG-io/iso15118`](https://github.com/EcoG-io/iso15118) | [`b256f9b`](https://github.com/EcoG-io/iso15118/commit/b256f9b379d3c0acbea24258c4a184f5264950a2) |
| [`vvvasu/mod_acccs`](https://github.com/vvvasu/mod_acccs) | [`fa1d08e`](https://github.com/vvvasu/mod_acccs/commit/fa1d08ea4c679cb37562c26a8775b0c86aab0d99) |
| [`JakeMG-INL/HomePlugPWN`](https://github.com/JakeMG-INL/HomePlugPWN) | [`ff840e7`](https://github.com/JakeMG-INL/HomePlugPWN/commit/ff840e707b0c54e06b1c836ed47112daffefd200) |
| [`JakeMG-INL/V2GInjector`](https://github.com/JakeMG-INL/V2GInjector) | [`1823d05`](https://github.com/JakeMG-INL/V2GInjector/commit/1823d055fe72f2613e3052736e3fc9071cba5f9f) |
