"""Jason Stys: bounded analyst-state, exact connection correlation, reset/maintenance and rate-boundary tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_reset_and_other_ports — line 65
# parameter: config — line 65
# variable: conversation — line 67
# variable: report — line 70
# variable: restarted — line 72
# variable: monitor — line 76
# definition: test_write_response_mismatch_and_unit — line 84
# parameter: config — line 84
# variable: conversation — line 86
# variable: different — line 93
# variable: unknown — line 99
# definition: test_rate_expiration_and_scope — line 105
# parameter: config — line 105
# variable: conversation — line 107
# variable: transaction — line 108
# variable: transaction — line 113
# variable: report — line 116
# variable: other — line 118
# definition: test_monitor_caps — line 127
# parameter: config — line 127
# variable: _ — line 129
# variable: segments — line 129
# variable: request — line 130
# variable: limit — line 131
# variable: target — line 131
# variable: monitor — line 132
# variable: item — line 133
# variable: monitor — line 138
# definition: test_outside_value_unknown_address — line 144
# parameter: config — line 144
# variable: conversation — line 146
# variable: unsupported — line 152
# definition: test_connection_scope_and_internal_contract — line 160
# parameter: config — line 160
# variable: one — line 165
# variable: two — line 165
# variable: report — line 169
# parameter: item — line 170
# variable: monitor — line 173
# variable: observed — line 174
# variable: flow — line 175
# END CODE MAP

from dataclasses import replace
from unittest.mock import patch

import pytest
from test_transport import segment

from examples.scenarios import (
    Conversation,
    adu,
    read_request,
    read_response,
    write_request,
    write_response,
)
from otmon.capture import pcap
from otmon.contracts import Policy, Rejected
from otmon.monitor import Monitor, analyze


def test_reset_and_other_ports(config: Policy) -> None:
    """A connection reset invalidates only that connection's pending transactions; other service traffic is inert."""
    conversation = Conversation()
    conversation.add(read_request())
    conversation.add(b"", flags=4)
    report = analyze(conversation.bytes(), config)
    assert report["rule_counts"] == {"session_reset": 1}
    restarted = Conversation()
    restarted.add(read_request())
    restarted.add(b"", sequence=1500, flags=2)
    assert analyze(restarted.bytes(), config)["rule_counts"] == {"session_reset": 1}
    monitor = Monitor(config)
    monitor.feed(replace(segment(), dport=503))
    assert not monitor.alerts
    monitor.feed(replace(segment(), sport=502))
    assert monitor.alerts[0]["rule"] == "capture_gap"
    monitor.finish()


def test_write_response_mismatch_and_unit(config: Policy) -> None:
    """Wrong echoed value/unit/function cannot consume an expected pending request or imply process health."""
    conversation = Conversation(client="192.0.2.20")
    conversation.add(write_request())
    conversation.add(write_response(value=600), response=True)
    conversation.add(write_response(), response=True)
    assert analyze(conversation.bytes(), config)["rule_counts"] == {
        "response_mismatch": 1
    }
    different = Conversation()
    different.add(read_request())
    different.add(read_response(unit=2), response=True)
    different.add(read_response(function=4), response=True)
    different.add(read_response(), response=True)
    assert analyze(different.bytes(), config)["rule_counts"] == {"response_mismatch": 2}
    unknown = Conversation(server="192.0.2.11")
    unknown.add(read_request())
    unknown.add(read_response(), response=True)
    assert analyze(unknown.bytes(), config)["statistics"]["matched_responses"] == 1


def test_rate_expiration_and_scope(config: Policy) -> None:
    """One alert per sustained burst; window reset can produce a new crossing without blanket write suppression."""
    conversation = Conversation()
    for transaction in range(1, 7):
        conversation.add(read_request(transaction))
        conversation.add(read_response(transaction), response=True)
    conversation.add(read_request(7), delay=1000)
    conversation.add(read_response(7), response=True)
    for transaction in range(8, 11):
        conversation.add(read_request(transaction))
        conversation.add(read_response(transaction), response=True)
    report = analyze(conversation.bytes(), config)
    assert report["rule_counts"] == {"rate_burst": 2}
    other = Conversation(client="192.0.2.30")
    other.add(write_request())
    other.add(write_response(), response=True)
    assert analyze(other.bytes(), config)["rule_counts"] == {
        "outside_maintenance": 1,
        "unauthorized_write": 1,
    }


def test_monitor_caps(config: Policy) -> None:
    """Cap alerts, pending, rate and decoded-frame collections instead of silently losing evidence."""
    segments, _ = pcap(Conversation().bytes())
    request = segment(read_request())
    for target, limit in [("MAX_PENDING", 0), ("MAX_FLOWS", 0), ("MAX_PACKETS", 0)]:
        monitor = Monitor(config)
        for item in segments:
            monitor.feed(item)
        with patch("otmon.monitor." + target, limit):
            with pytest.raises(Rejected, match="cap"):
                monitor.feed(request)
    monitor = Monitor(config)
    with patch("otmon.monitor.MAX_ALERTS", 0):
        with pytest.raises(Rejected, match="cap"):
            monitor.alert("capture_gap", None, None)


def test_outside_value_unknown_address(config: Policy) -> None:
    """Do not guess an envelope for unconfigured registers or interpret unsupported function payloads."""
    conversation = Conversation(client="192.0.2.20")
    conversation.add(write_request(address=500, values=(65535,)))
    conversation.add(write_response(address=500, value=65535), response=True)
    assert analyze(conversation.bytes(), config)["rule_counts"] == {
        "register_outside_baseline": 1
    }
    unsupported = Conversation()
    unsupported.add(adu(1, b"\x2b\x0e\x01\x00"))
    unsupported.add(adu(1, b"\xab\x01"), response=True)
    assert analyze(unsupported.bytes(), config)["rule_counts"] == {
        "unsupported_function": 2
    }


def test_connection_scope_and_internal_contract(config: Policy) -> None:
    """A reset of one TCP connection cannot clear another; reject incomplete internal request shapes."""
    from examples.scenarios import capture
    from otmon.protocol import Message

    one, two = Conversation(), Conversation(port=40001)
    one.add(read_request())
    two.add(read_request())
    one.add(b"", flags=4)
    report = analyze(
        capture(sorted(one.records + two.records, key=lambda item: item[0])), config
    )
    assert report["rule_counts"] == {"session_reset": 1, "eof_unresolved": 1}
    monitor = Monitor(config)
    observed = segment()
    flow = ("192.0.2.30", 40000, "192.0.2.10", 502)
    with pytest.raises(Rejected, match="metadata"):
        monitor.request(Message(1, 1, 3), observed, flow, b"")
