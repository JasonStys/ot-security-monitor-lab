"""Jason Stys: bounded classic PCAP Ethernet/one-VLAN IPv4/TCP import; unsupported layers stay visible."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Segment — line 69
# variable: packet — line 72
# variable: time_ms — line 73
# variable: src — line 74
# variable: dst — line 75
# variable: sport — line 76
# variable: dport — line 77
# variable: sequence — line 78
# variable: flags — line 79
# variable: payload — line 80
# definition: ethernet — line 83
# parameter: data — line 83
# parameter: packet — line 83
# parameter: time_ms — line 83
# variable: kind — line 87
# variable: offset — line 88
# variable: kind — line 92
# variable: offset — line 93
# variable: ip — line 96
# variable: ihl — line 99
# variable: size — line 100
# variable: tcp — line 107
# variable: header — line 110
# variable: dport — line 113
# variable: sequence — line 113
# variable: sport — line 113
# definition: pcap — line 129
# parameter: data — line 129
# variable: formats — line 132
# variable: divisor — line 139
# variable: endian — line 139
# variable: link — line 140
# variable: major — line 140
# variable: minor — line 140
# variable: sigfigs — line 140
# variable: snaplen — line 140
# variable: zone — line 140
# variable: last — line 150
# variable: number — line 150
# variable: offset — line 150
# variable: segments — line 151
# variable: counts — line 152
# variable: fraction — line 155
# variable: included — line 155
# variable: original — line 155
# variable: sec — line 155
# variable: time_ms — line 165
# variable: last — line 167
# variable: number — line 168
# variable: raw — line 170
# variable: offset — line 171
# variable: reason — line 175
# variable: segment — line 175
# END CODE MAP

from __future__ import annotations

import ipaddress
import struct
from collections import Counter
from dataclasses import dataclass

from otmon.contracts import MAX_CAPTURE, MAX_PACKETS, require


@dataclass(frozen=True)
class Segment:
    """Captured TCP direction, absolute sequence and flags; payload is never transmitted or executed."""

    packet: int
    time_ms: int
    src: str
    dst: str
    sport: int
    dport: int
    sequence: int
    flags: int
    payload: bytes


def ethernet(data: bytes, packet: int, time_ms: int) -> tuple[Segment | None, str]:
    """Extract complete IPv4/TCP only; explicitly label short, fragmented and unsupported packets."""
    if len(data) < 14:
        return None, "short_ethernet"
    kind = struct.unpack(">H", data[12:14])[0]
    offset = 14
    if kind == 0x8100:
        if len(data) < 18:
            return None, "short_vlan"
        kind = struct.unpack(">H", data[16:18])[0]
        offset = 18
    if kind != 0x0800:
        return None, "unsupported_network"
    ip = data[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None, "invalid_ipv4"
    ihl = (ip[0] & 15) * 4
    size = struct.unpack(">H", ip[2:4])[0]
    if ihl < 20 or size < ihl or size > len(ip):
        return None, "invalid_ipv4_length"
    if struct.unpack(">H", ip[6:8])[0] & 0x3FFF:
        return None, "fragmented_ipv4"
    if ip[9] != 6:
        return None, "unsupported_transport"
    tcp = ip[ihl:size]
    if len(tcp) < 20:
        return None, "short_tcp"
    header = (tcp[12] >> 4) * 4
    if header < 20 or header > len(tcp):
        return None, "invalid_tcp_header"
    sport, dport, sequence = struct.unpack(">HHI", tcp[:8])
    if sport == 0 or dport == 0:
        return None, "invalid_tcp_port"
    return Segment(
        packet,
        time_ms,
        str(ipaddress.IPv4Address(ip[12:16])),
        str(ipaddress.IPv4Address(ip[16:20])),
        sport,
        dport,
        sequence,
        tcp[13],
        tcp[header:],
    ), "tcp"


def pcap(data: bytes) -> tuple[list[Segment], dict[str, int]]:
    """Read bounded uncompressed classic PCAP with monotonic timestamps; truncated records are fatal."""
    require(24 <= len(data) <= MAX_CAPTURE, "invalid capture size")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000),
        b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000),
    }
    require(data[:4] in formats, "unsupported capture format")
    endian, divisor = formats[data[:4]]
    major, minor, zone, sigfigs, snaplen, link = struct.unpack(
        endian + "HHIIII", data[4:24]
    )
    require(
        (major, minor) == (2, 4)
        and zone == sigfigs == 0
        and 54 <= snaplen <= 65535
        and link == 1,
        "unsupported PCAP header",
    )
    offset, number, last = 24, 0, -1
    segments = []
    counts: Counter[str] = Counter()
    while offset < len(data):
        require(offset + 16 <= len(data), "truncated PCAP record")
        sec, fraction, included, original = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        require(
            fraction < divisor * 1000
            and included <= snaplen
            and included <= original
            and offset + 16 + included <= len(data),
            "invalid PCAP record bounds",
        )
        time_ms = sec * 1000 + fraction // divisor
        require(time_ms >= last, "capture timestamps out of order")
        last = time_ms
        number += 1
        require(number <= MAX_PACKETS, "capture packet count exceeds cap")
        raw = data[offset + 16 : offset + 16 + included]
        offset += 16 + included
        if included != original:
            counts["snaplen_truncated"] += 1
            continue
        segment, reason = ethernet(raw, number, time_ms)
        counts[reason] += 1
        if segment is not None:
            segments.append(segment)
    counts["records"] = number
    return segments, dict(sorted(counts.items()))
