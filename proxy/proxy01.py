"""
ISO 15118 Pass-through Proxy (TLS-safe, Python 3.8+ compatible)
Author: Vishwa Vimukthi Vasu Ashoka

Features:
  • Forwards UDP (SDP) & TCP (TLS/non-TLS) traffic
  • Handles IPv6 link-local scope IDs correctly
  • Optional EXI decoding for cleartext sessions
  • Optional packet capture & hex preview
"""

import sys, os, json, socket, asyncio, struct, ipaddress, re, concurrent.futures, datetime, argparse

# --------------------------------------------------------------------
# CLI options
# --------------------------------------------------------------------
parser = argparse.ArgumentParser(description="ISO15118 Pass-through Proxy")
parser.add_argument("--capture", action="store_true", help="Save packets to proxy_capture.log")
parser.add_argument("--show-hex", action="store_true", help="Print packet hex previews")
parser.add_argument("--debug", action="store_true", help="Enable EXI decoding for non-TLS")
args = parser.parse_args()

CAPTURE_FILE = "proxy_capture.log"
SHOW_PACKET_HEX = args.show_hex
ENABLE_CAPTURE = args.capture
DEBUG_EXI = args.debug

# --------------------------------------------------------------------
# Project setup
# --------------------------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.settings import JAR_FILE_PATH

LISTEN_HOST = '::'
UDP_PORT = 15118
SDP_MULTICAST_GROUP = 'ff02::1'
SDP_SERVER_PORT = 15118
proxy_port = 55000

scope_id_pattern = re.compile(r'^(\d+):')
ipv6_pattern = re.compile(r'inet6 ([\da-fA-F:]+)\/\d+ scope link')
executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

# --------------------------------------------------------------------
# EXI Codec Wrapper
# --------------------------------------------------------------------
class ExificientEXICodec(IEXICodec):
    _gateway = None
    _exi_codec = None
    def __init__(self):
        if ExificientEXICodec._gateway is None:
            from py4j.java_gateway import JavaGateway
            ExificientEXICodec._gateway = JavaGateway.launch_gateway(
                classpath=JAR_FILE_PATH,
                die_on_exit=True,
                javaopts=["--add-opens", "java.base/java.lang=ALL-UNNAMED"],
            )
            ExificientEXICodec._exi_codec = (
                ExificientEXICodec._gateway.jvm.com.siemens.ct.exi.main.cmd.EXICodec()
            )
        self.gateway = ExificientEXICodec._gateway
        self.exi_codec = ExificientEXICodec._exi_codec

    async def decode(self, stream: bytes, namespace: str) -> str:
        loop = asyncio.get_running_loop()
        decoded = await loop.run_in_executor(None, self.exi_codec.decode, stream, namespace)
        if decoded is None:
            raise Exception(self.exi_codec.get_last_decoding_error())
        return decoded

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
async def get_ipv6_addresses_and_scope_ids():
    result = await asyncio.create_subprocess_shell('ip a', stdout=asyncio.subprocess.PIPE)
    stdout, _ = await result.communicate()
    lines = stdout.decode().splitlines()
    scope_ids, current_scope_id = {}, None
    for line in lines:
        scope_id_match = scope_id_pattern.match(line)
        if scope_id_match:
            current_scope_id = scope_id_match.group(1)
        ipv6_match = ipv6_pattern.search(line)
        if ipv6_match and current_scope_id:
            ipv6_address = ipv6_match.group(1)
            scope_ids[ipv6_address] = int(current_scope_id)
    return scope_ids

def parse_response(hex_data):
    data = bytes.fromhex(hex_data)
    return {
        'Version': data[0],
        'Message Type': data[1],
        'Message Length': int.from_bytes(data[2:4], 'big'),
        'Reserved': int.from_bytes(data[4:8], 'big'),
        'SECC IP Address': str(ipaddress.IPv6Address(data[8:24])),
        'SECC Port': int.from_bytes(data[24:26], 'big'),
        'Security': data[26],
        'Transport Protocol': data[27],
    }

def create_new_response_message(original_message, new_ip, new_port):
    new_ip_bytes = ipaddress.IPv6Address(new_ip).packed
    new_port_bytes = new_port.to_bytes(2, 'big')
    return original_message[:8] + new_ip_bytes + new_port_bytes + original_message[26:]

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

        codec = ExificientEXICodec() if (DEBUG_EXI and not is_tls) else None

        async def pipe(reader, writer, direction):
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()

                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                info = f"[{ts}] {direction} {len(data)} bytes"
                print(info)

                if SHOW_PACKET_HEX:
                    hex_preview = data.hex()
                    if len(hex_preview) > 128:
                        hex_preview = hex_preview[:128] + "..."
                    print(f"    {hex_preview}")

                if ENABLE_CAPTURE:
                    with open(CAPTURE_FILE, "a") as f:
                        f.write(f"{ts} {direction} len={len(data)} data={data.hex()}\n")

                if codec and len(data) > 8:
                    try:
                        decoded = await codec.decode(data[8:], "urn:iso:15118:2:2010:AppProtocol")
                        print(f"\n[{direction}] Decoded EXI:\n{json.dumps(json.loads(decoded), indent=4)}\n")
                    except Exception:
                        pass

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
    ipv6_scope_ids = loop.run_until_complete(get_ipv6_addresses_and_scope_ids())

    print("\nSECC and EVCC network interfaces:")
    local_ips = set()
    for ipv6, scope in ipv6_scope_ids.items():
        print(f"{ipv6} -> {scope}")
        local_ips.add(ipv6)

    if len(ipv6_scope_ids) > 1:
        evcc_ip = list(ipv6_scope_ids.keys())[1]
        evcc_scope_id = ipv6_scope_ids[evcc_ip]
    else:
        evcc_ip, evcc_scope_id = None, None

    if len(ipv6_scope_ids) > 0:
        secc_ip = list(ipv6_scope_ids.keys())[0]
        secc_scope_id = ipv6_scope_ids[secc_ip]
    else:
        secc_scope_id = None

    start_event = asyncio.Event()
    udp_task = loop.create_task(udp_listen_and_print("eth0", start_event, local_ips))
    tcp_task = loop.create_task(start_tcp_proxy(start_event))
    loop.run_until_complete(asyncio.gather(udp_task, tcp_task))
