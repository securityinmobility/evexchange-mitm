"""
ISO 15118 Pass-through Proxy (TLS-safe, Python 3.8+ compatible)
Author: Vishwa Vimukthi Vasu Ashoka

Features:
  • Forwards UDP (SDP) & TCP (TLS/non-TLS) traffic
  • Handles IPv6 link-local scope IDs correctly
  • Optional EXI decoding for cleartext sessions
  • Optional packet capture & hex preview
"""

import sys, os, json, socket, asyncio, datetime, argparse

# --------------------------------------------------------------------
# CLI options
# --------------------------------------------------------------------
parser = argparse.ArgumentParser(description="ISO15118 Pass-through Proxy")
parser.add_argument("--capture", action="store_true", help="Save packets to proxy_capture.log")
parser.add_argument("--show-hex", action="store_true", help="Print packet hex previews")
parser.add_argument("--debug", action="store_true", help="Enable EXI decoding for non-TLS")
parser.add_argument("--tamper", action="store_true",
                     help="Tamper with EVSEMaxCurrent in ChargeParameterDiscoveryRes "
                          "(non-TLS sessions only). Same effect as TAMPER=1.")
parser.add_argument("--secc-iface", metavar="IFACE",
                     help="Explicit interface name facing SECC (e.g. eth0), used instead "
                          "of auto-detecting by Docker subnet (proxy_net1). For real "
                          "hardware, where the physical NIC won't be on that subnet.")
parser.add_argument("--evcc-iface", metavar="IFACE",
                     help="Explicit interface name facing EVCC (e.g. eth1), used instead "
                          "of auto-detecting by Docker subnet (proxy_net2). See --secc-iface.")
args = parser.parse_args()

CAPTURE_FILE = "proxy_capture.log"
SHOW_PACKET_HEX = args.show_hex
ENABLE_CAPTURE = args.capture
DEBUG_EXI = args.debug

# Only active for plaintext (non-TLS) sessions: the proxy relays TLS as an
# opaque encrypted byte stream (see handle_client) without terminating it
# itself, so it has no way to see or modify TLS-protected content without a
# full TLS-interception MITM (present our own cert to EVCC, our own client
# connection to SECC) -- a much larger feature this does not implement.
TAMPER_ENABLED = args.tamper or os.environ.get("TAMPER") == "1"
TAMPER_NEW_CURRENT_A = int(os.environ.get("TAMPER_CURRENT_A", "63"))

# --------------------------------------------------------------------
# Project setup
# --------------------------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common import (
    SECC_NET_V4, SECC_NET_V6, EVCC_NET_V4, EVCC_NET_V6,
    ProxyCodec, decode_with_fallback,
    discover_secc_evcc_interfaces,
    parse_response, create_new_response_message,
    read_v2gtp_message, tamper_charge_parameter_discovery_res,
    MSG_DEF_NS,
)

LISTEN_HOST = '::'
UDP_PORT = 15118
SDP_MULTICAST_GROUP = 'ff02::1'
SDP_SERVER_PORT = 15118
proxy_port = 55000

# --------------------------------------------------------------------
# UDP SDP Proxy (Python 3.8 safe)
# --------------------------------------------------------------------
async def udp_listen_and_print(iface, start_event, local_ips):
    listen_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    listen_socket.bind((LISTEN_HOST, UDP_PORT))
    listen_socket.setblocking(True)
    print(f"\nUDP proxy listening on [{LISTEN_HOST}]:{UDP_PORT}")

    loop = asyncio.get_running_loop()
    def blocking_recv(): return listen_socket.recvfrom(4096)

    while True:
        data, client_addr = await loop.run_in_executor(None, blocking_recv)
        if client_addr[0] in local_ips:
            continue

        print(f"\nReceived SDP Request from {client_addr}")
        udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        # Pin the outgoing multicast interface to the SECC-facing one
        # (identified by subnet, see discover_secc_evcc_interfaces). Without
        # this, the kernel picks the interface for ff02::1 based on the
        # default route, which -- like interface list order -- Docker does
        # not guarantee stays pointed at proxy_net1 across reconnects.
        if secc_scope_id is not None:
            udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, secc_scope_id)
        udp_sock.sendto(data, (SDP_MULTICAST_GROUP, SDP_SERVER_PORT))

        udp_sock.settimeout(3)
        try:
            response, _ = udp_sock.recvfrom(4096)
        except socket.timeout:
            print("No SDP response from SECC")
            udp_sock.close()
            continue

        response_hex = response.hex()
        parsed = parse_response(response_hex)
        global secc_ip_address, secc_port
        secc_ip_address = parsed["SECC IP Address"]
        secc_port = parsed["SECC Port"]

        print(f"\nSECC SDP Response: {response_hex}")
        print(f"  SECC IP: {secc_ip_address}\n  Port: {secc_port}\n  Security: 0x{parsed['Security']:02x}")

        if evcc_ip:
            modified_msg = create_new_response_message(response, evcc_ip, proxy_port)
            listen_socket.sendto(modified_msg, client_addr)
            print(f"\nSent modified SDP response to EVCC at {client_addr}")
            start_event.set()
        udp_sock.close()

# --------------------------------------------------------------------
# TCP Proxy (TLS-safe, packet capture, full-duplex)
# --------------------------------------------------------------------
async def handle_client(client_reader, client_writer):
    addr = client_writer.get_extra_info('peername')
    print(f"\nAccepted TCP connection from EVCC: {addr}")

    try:
        print(f"Connecting to SECC at {secc_ip_address}%{secc_scope_id}:{secc_port}")
        try:
            server_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server_sock.bind((LISTEN_HOST, 0, 0, evcc_scope_id))
            server_sock.connect((secc_ip_address, secc_port, 0, secc_scope_id))
            server_sock.setblocking(False)
            server_reader, server_writer = await asyncio.open_connection(sock=server_sock)
            print(f"Connected to SECC at {secc_ip_address}%{secc_scope_id}:{secc_port}")
        except Exception as e:
            print(f"TCP connection error: {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Peek the first byte to distinguish a TLS ClientHello (0x16) from a
        # plaintext V2GTP message, without truncating the V2GTP frame the way
        # a blind 5-byte peek did (that split the first V2GTP message into two
        # TCP writes, which SECC's parser rejected as "too short").
        first_byte = await client_reader.readexactly(1)
        is_tls = first_byte[0] == 0x16

        if is_tls:
            # TLS framing is handled by the TLS layer itself downstream; just
            # forward the peeked byte and let the generic pipe() loop take over.
            server_writer.write(first_byte)
            await server_writer.drain()
        else:
            # V2GTP header is 8 bytes: 1B version, 1B inverse version,
            # 2B payload type, 4B payload length. Buffer the full header
            # plus its declared payload before the first forward, so SECC
            # always receives one complete V2GTP message per write.
            header_rest = await client_reader.readexactly(7)
            header = first_byte + header_rest
            payload_length = int.from_bytes(header[4:8], "big")
            payload = await client_reader.readexactly(payload_length)
            server_writer.write(header + payload)
            await server_writer.drain()

        # A codec is only needed for plaintext sessions, and only if
        # something's actually going to use it -- default pass-through stays
        # zero-overhead (no JVM decode round-trip per message).
        codec = ProxyCodec() if (not is_tls and (DEBUG_EXI or TAMPER_ENABLED)) else None
        if TAMPER_ENABLED and is_tls:
            print("\n[TAMPER] TAMPER is enabled but this session negotiated TLS -- "
                  "the proxy relays TLS as an opaque encrypted stream without "
                  "terminating it, so tampering is not possible here. Forwarding "
                  "unmodified. Use notls mode to see tampering take effect.\n")

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

        async def pipe_tls(reader, writer, direction):
            # Opaque byte relay -- the proxy never sees plaintext here.
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                log_and_capture(direction, data)

        async def pipe_plaintext(reader, writer, direction):
            # V2GTP-framed relay: one complete message per read/write, same
            # framing fix as the first message above. This also gives
            # tampering (and --debug decoding) reliable message boundaries
            # to work with, rather than whatever a raw `read(4096)` happens
            # to return.
            while True:
                try:
                    header, payload = await read_v2gtp_message(reader)
                except asyncio.IncompleteReadError:
                    break

                out_header, out_payload = header, payload

                if codec:
                    decoded, ns = await decode_with_fallback(codec, payload)
                    if decoded is not None:
                        if (TAMPER_ENABLED and direction == "SECC→EVCC"
                                and ns == MSG_DEF_NS):
                            original_value = tamper_charge_parameter_discovery_res(
                                decoded, TAMPER_NEW_CURRENT_A)
                            if original_value is not None:
                                new_payload = await codec.encode(json.dumps(decoded), MSG_DEF_NS)
                                out_header = header[0:4] + len(new_payload).to_bytes(4, "big")
                                out_payload = new_payload
                                print(f"\n[TAMPER] EVSEMaxCurrent: {original_value}A -> "
                                      f"{TAMPER_NEW_CURRENT_A}A (ChargeParameterDiscoveryRes, {direction})\n")
                        if DEBUG_EXI:
                            print(f"\n[{direction}] Decoded EXI (ns={ns}):\n"
                                  f"{json.dumps(decoded, indent=4)}\n")

                out_data = out_header + out_payload
                writer.write(out_data)
                await writer.drain()
                log_and_capture(direction, out_data)

        pipe = pipe_tls if is_tls else pipe_plaintext
        await asyncio.gather(
            pipe(client_reader, server_writer, "EVCC→SECC"),
            pipe(server_reader, client_writer, "SECC→EVCC"),
        )

    except Exception as e:
        print(f"TCP proxy error: {e}")
    finally:
        client_writer.close()
        await client_writer.wait_closed()
        print(f"Closed connection with {addr}")

async def start_tcp_proxy(start_event):
    await start_event.wait()
    server = await asyncio.start_server(handle_client, LISTEN_HOST, proxy_port)
    print(f"\nTCP proxy listening on port {proxy_port}")
    async with server:
        await server.serve_forever()

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    roles = loop.run_until_complete(
        discover_secc_evcc_interfaces(secc_iface=args.secc_iface, evcc_iface=args.evcc_iface)
    )

    detect_desc = ("explicit --secc-iface/--evcc-iface" if (args.secc_iface or args.evcc_iface)
                   else "Docker subnet auto-detect, not list order")
    print(f"\nSECC and EVCC network interfaces (identified by {detect_desc}):")
    local_ips = set()
    for role, (addr, scope) in roles.items():
        print(f"  {role}: {addr} -> scope {scope}")
        local_ips.add(addr)

    if "secc" in roles:
        secc_ip, secc_scope_id = roles["secc"]
    else:
        secc_ip, secc_scope_id = None, None
        if args.secc_iface:
            print(f"WARNING: --secc-iface {args.secc_iface} did not resolve to a usable "
                  f"interface -- SDP relay to SECC will fail.")
        else:
            print(f"WARNING: no interface found on the SECC subnet "
                  f"({SECC_NET_V4} / {SECC_NET_V6}) -- SDP relay to SECC will fail. "
                  f"On real hardware, pass --secc-iface instead.")

    if "evcc" in roles:
        evcc_ip, evcc_scope_id = roles["evcc"]
    else:
        evcc_ip, evcc_scope_id = None, None
        if args.evcc_iface:
            print(f"WARNING: --evcc-iface {args.evcc_iface} did not resolve to a usable "
                  f"interface -- EVCC will never get a usable SDP response.")
        else:
            print(f"WARNING: no interface found on the EVCC subnet "
                  f"({EVCC_NET_V4} / {EVCC_NET_V6}) -- EVCC will never get a "
                  f"usable SDP response. On real hardware, pass --evcc-iface instead.")

    start_event = asyncio.Event()
    udp_task = loop.create_task(udp_listen_and_print("eth0", start_event, local_ips))
    tcp_task = loop.create_task(start_tcp_proxy(start_event))
    loop.run_until_complete(asyncio.gather(udp_task, tcp_task))
