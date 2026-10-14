"""Jason Stys: classic PCAP endianness/resolution, truncation, layer visibility and adversarial length fuzzing."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_pcap_formats — line 46
# parameter: endian — line 46
# parameter: nano — line 46
# variable: record — line 48
# variable: segments — line 56
# variable: stats — line 56
# definition: test_capture_reject — line 75
# parameter: mutation — line 75
# variable: base — line 77
# variable: data — line 78
# variable: data — line 80
# variable: data — line 86
# variable: data — line 88
# variable: data — line 94
# definition: test_layer_visibility — line 121
# parameter: kind — line 121
# parameter: reason — line 121
# variable: data — line 123
# variable: data — line 134
# variable: data — line 137
# definition: test_snaplen_truncation — line 157
# variable: data — line 159
# definition: test_capture_fuzz — line 166
# parameter: data — line 166
# variable: _ — line 172
# variable: segment — line 172
# END CODE MAP

import struct
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from examples.scenarios import NOW, Conversation, capture, packet, read_request
from otmon.capture import ethernet, pcap
from otmon.contracts import Rejected


@pytest.mark.parametrize(
    "endian,nano", [("<", False), (">", False), ("<", True), (">", True)]
)
def test_pcap_formats(endian: str, nano: bool) -> None:
    """Decode the four classic PCAP magic/resolution variants without floating-point timestamps."""
    record = packet(
        read_request(),
        src="192.0.2.30",
        dst="192.0.2.10",
        sport=40000,
        dport=502,
        sequence=1,
    )
    segments, stats = pcap(capture([(NOW + 123, record)], endian=endian, nano=nano))
    assert segments[0].time_ms == NOW + 123 and stats == {"records": 1, "tcp": 1}


@pytest.mark.parametrize(
    "mutation",
    [
        "size",
        "magic",
        "header",
        "truncated-header",
        "truncated-record",
        "fraction",
        "length",
        "order",
        "count",
        "snaplen",
    ],
)
def test_capture_reject(mutation: str) -> None:
    """Bound malformed headers, records, timestamps and packet counts before any result publication."""
    base = Conversation().bytes()
    data = bytearray(base)
    if mutation == "size":
        data = bytearray(b"bad")
    elif mutation == "magic":
        data[:4] = b"ngpc"
    elif mutation == "header":
        struct.pack_into("<I", data, 20, 101)
    elif mutation == "truncated-header":
        data = data[:30]
    elif mutation == "truncated-record":
        data = data[:-1]
    elif mutation == "fraction":
        struct.pack_into("<I", data, 28, 1_000_000)
    elif mutation == "length":
        struct.pack_into("<I", data, 32, 65536)
    elif mutation == "order":
        data = bytearray(capture([(NOW, b"x" * 54), (NOW - 1, b"x" * 54)]))
    elif mutation == "snaplen":
        struct.pack_into("<I", data, 16, 1)
    if mutation == "count":
        with patch("otmon.capture.MAX_PACKETS", 1):
            with pytest.raises(Rejected):
                pcap(bytes(data))
    else:
        with pytest.raises(Rejected):
            pcap(bytes(data))


@pytest.mark.parametrize(
    "kind,reason",
    [
        ("ether", "short_ethernet"),
        ("vlan", "short_vlan"),
        ("ipv6", "unsupported_network"),
        ("ipv4", "invalid_ipv4"),
        ("ip-length", "invalid_ipv4_length"),
        ("fragment", "fragmented_ipv4"),
        ("udp", "unsupported_transport"),
        ("tcp-short", "short_tcp"),
        ("tcp-header", "invalid_tcp_header"),
        ("zero-port", "invalid_tcp_port"),
    ],
)
def test_layer_visibility(kind: str, reason: str) -> None:
    """Unsupported/incomplete packet layers remain classified instead of becoming clean OT frames."""
    data = bytearray(
        packet(
            read_request(),
            src="192.0.2.30",
            dst="192.0.2.10",
            sport=40000,
            dport=502,
            sequence=1,
        )
    )
    if kind == "ether":
        data = data[:10]
    elif kind == "vlan":
        data[12:14] = b"\x81\0"
        data = data[:15]
    elif kind == "ipv6":
        data[12:14] = b"\x86\xdd"
    elif kind == "ipv4":
        data[14] = 0x65
    elif kind == "ip-length":
        data[16:18] = b"\xff\xff"
    elif kind == "fragment":
        data[20:22] = b"\x20\0"
    elif kind == "udp":
        data[23] = 17
    elif kind == "tcp-short":
        data[16:18] = b"\0\x1e"
    elif kind == "tcp-header":
        data[46] = 0xF0
    elif kind == "zero-port":
        data[34:36] = b"\0\0"
    assert ethernet(bytes(data), 1, NOW) == (None, reason)


def test_snaplen_truncation() -> None:
    """A capture-truncated packet is counted as a visibility defect, never decoded as complete."""
    data = bytearray(capture([(NOW, b"x" * 54)]))
    struct.pack_into("<I", data, 36, 60)
    assert pcap(bytes(data))[1] == {"records": 1, "snaplen_truncated": 1}


@given(st.binary(max_size=2048))
@settings(max_examples=100, deadline=None)
def test_capture_fuzz(data: bytes) -> None:
    """Bounded random PCAP bytes fail safely; packet parser has no external/network side effects."""
    try:
        pcap(data)
    except Rejected:
        pass
    segment, _ = ethernet(data, 1, NOW)
    if segment is not None:
        assert segment.src and segment.dst
