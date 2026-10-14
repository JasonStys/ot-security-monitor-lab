"""Jason Stys: conservative TCP overlap/gap/SYN/FIN/reset/sequence-wrap and state-cap regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: segment — line 37
# parameter: flags — line 38
# parameter: payload — line 38
# parameter: response — line 38
# parameter: sequence — line 38
# definition: ready — line 54
# variable: transport — line 56
# definition: test_direction_and_control — line 62
# variable: transport — line 64
# definition: test_overlaps_conflicts_and_wrap — line 78
# variable: request — line 80
# variable: transport — line 81
# variable: old — line 90
# variable: wrap — line 92
# definition: test_fin_malformed_and_caps — line 98
# variable: partial — line 100
# variable: closed — line 103
# variable: full — line 106
# variable: immediate — line 108
# variable: malformed — line 112
# variable: syn — line 114
# END CODE MAP

from dataclasses import replace
from unittest.mock import patch

import pytest

from examples.scenarios import NOW, read_request
from otmon.capture import Segment
from otmon.contracts import Rejected
from otmon.transport import Transport


def segment(
    payload: bytes = b"", sequence: int = 1001, flags: int = 24, response: bool = False
) -> Segment:
    """Construct one synthetic typed segment for independent transport state-machine transitions."""
    return Segment(
        1,
        NOW,
        "192.0.2.10" if response else "192.0.2.30",
        "192.0.2.30" if response else "192.0.2.10",
        502 if response else 40000,
        40000 if response else 502,
        sequence,
        flags,
        payload,
    )


def ready() -> Transport:
    """Ground both directions with observed synthetic SYN and SYN-ACK."""
    transport = Transport(502)
    transport.feed(segment(sequence=1000, flags=2))
    transport.feed(segment(sequence=2000, flags=18, response=True))
    return transport


def test_direction_and_control() -> None:
    """Ignore other-service ACKs, classify ambiguous directions and require SYN for data."""
    transport = Transport(502)
    assert transport.feed(replace(segment(), dport=503))[0] is None
    assert transport.feed(replace(segment(), sport=502))[3] == ["ambiguous_direction"]
    assert transport.feed(segment())[3] == []
    assert transport.feed(segment(read_request()))[3] == ["missing_syn"]
    assert transport.feed(segment(sequence=1000, flags=2))[4] is False
    assert transport.feed(segment(sequence=1000, flags=2))[4] is False
    assert transport.feed(segment(sequence=1001, flags=16))[3] == []
    transport.feed(segment(read_request()))
    assert transport.feed(segment(sequence=1500, flags=2))[4] is True
    assert len(transport.streams) == 1
    assert transport.feed(segment(flags=4))[4] is True and not transport.streams


def test_overlaps_conflicts_and_wrap() -> None:
    """Accept only byte-verified contiguous overlaps and modular sequence wrap; reject conflicts/old unknown data."""
    request = read_request()
    transport = ready()
    assert transport.feed(segment(request[:7]))[2] == []
    assert transport.feed(segment(request[5:], sequence=1006))[2] == [request]
    assert transport.retransmissions == 1
    assert transport.feed(segment(request, sequence=1001))[2] == []
    assert transport.retransmissions == 2
    assert transport.feed(segment(b"bad", sequence=1001))[3] == ["tcp_gap_or_conflict"]
    assert transport.feed(segment(request, sequence=1013))[2] == []
    assert transport.blocked_payload_packets == 1
    old = ready()
    assert old.feed(segment(b"x", sequence=500))[3] == ["tcp_gap_or_conflict"]
    wrap = Transport(502)
    wrap.feed(segment(sequence=0xFFFFFFFC, flags=2))
    assert wrap.feed(segment(request[:3], sequence=0xFFFFFFFD))[2] == []
    assert wrap.feed(segment(request[3:], sequence=0))[2] == [request]


def test_fin_malformed_and_caps() -> None:
    """FIN never leaves reusable open state; malformed framing/SYN-data and resource caps stay explicit."""
    partial = ready()
    partial.feed(segment(read_request()[:5]))
    assert partial.feed(segment(flags=17, sequence=1006))[3] == ["incomplete_adu"]
    closed = ready()
    assert closed.feed(segment(read_request(), flags=25))[2] == [read_request()]
    assert closed.feed(segment(b"x", sequence=1013))[2] == []
    full = ready()
    assert full.feed(segment(flags=17))[3] == []
    immediate = ready()
    assert immediate.feed(segment(read_request()[:5], flags=25))[3] == [
        "incomplete_adu"
    ]
    malformed = ready()
    assert malformed.feed(segment(b"\0\x01\0\x01\0\x06"))[3] == ["malformed_mbap"]
    syn = Transport(502)
    assert syn.feed(segment(b"unexpected", sequence=1000, flags=2))[3] == [
        "syn_payload_unsupported"
    ]
    with patch("otmon.transport.MAX_STREAM", 1):
        with pytest.raises(Rejected, match="buffer"):
            ready().feed(segment(read_request()))
    with patch("otmon.transport.MAX_FLOWS", 0):
        with pytest.raises(Rejected, match="state cap"):
            Transport(502).feed(segment(sequence=1000, flags=2))
