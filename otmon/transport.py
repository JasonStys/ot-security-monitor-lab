"""Jason Stys: conservative bounded TCP sequence tracking and Modbus boundary extraction, no active sockets."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: Flow — line 68
# definition: Stream — line 72
# variable: expected — line 75
# variable: initial — line 76
# variable: history — line 77
# variable: buffer — line 78
# variable: blocked — line 79
# definition: Transport — line 83
# variable: port — line 86
# variable: streams — line 87
# variable: retransmissions — line 88
# variable: blocked_payload_packets — line 89
# definition: identity — line 91
# parameter: segment — line 91
# parameter: self — line 91
# definition: feed — line 101
# parameter: segment — line 102
# parameter: self — line 102
# variable: identity — line 105
# variable: flow — line 116
# variable: response — line 116
# variable: key — line 117
# variable: issues — line 118
# variable: reset — line 119
# variable: existing — line 125
# variable: reset — line 133
# variable: item — line 137
# variable: item — line 138
# attribute: blocked — line 145
# variable: stream — line 148
# attribute: blocked_payload_packets — line 155
# attribute: blocked — line 157
# attribute: buffer — line 159
# variable: payload — line 162
# variable: delta — line 163
# variable: behind — line 165
# variable: overlap — line 166
# attribute: blocked — line 177
# attribute: buffer — line 178
# attribute: retransmissions — line 180
# variable: payload — line 181
# attribute: expected — line 182
# attribute: history — line 183
# attribute: buffer — line 187
# variable: messages — line 188
# variable: length — line 190
# variable: protocol — line 190
# attribute: blocked — line 192
# attribute: buffer — line 193
# attribute: buffer — line 199
# attribute: blocked — line 201
# attribute: buffer — line 203
# definition: incomplete — line 207
# parameter: self — line 207
# variable: stream — line 209
# END CODE MAP

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from otmon.capture import Segment
from otmon.contracts import MAX_FLOWS, MAX_STREAM, require

Flow = tuple[str, int, str, int]


@dataclass
class Stream:
    """Directional sequence cursor, bounded retransmission history and pending ADU bytes."""

    expected: int
    initial: int
    history: bytes = b""
    buffer: bytes = b""
    blocked: bool = False


@dataclass
class Transport:
    """Per-analysis ordered-stream state; gaps/conflicts block that direction until a new SYN."""

    port: int
    streams: dict[tuple[Flow, bool], Stream] = field(default_factory=dict)
    retransmissions: int = 0
    blocked_payload_packets: int = 0

    def identity(self, segment: Segment) -> tuple[Flow, bool] | None:
        """Determine client/server direction from independent configured service port."""
        if segment.sport == self.port and segment.dport == self.port:
            return None
        if segment.dport == self.port:
            return (segment.src, segment.sport, segment.dst, segment.dport), False
        if segment.sport == self.port:
            return (segment.dst, segment.dport, segment.src, segment.sport), True
        return None

    def feed(
        self, segment: Segment
    ) -> tuple[Flow | None, bool, list[bytes], list[str], bool]:
        """Return complete raw ADUs/issues/reset; accept verified retransmissions, never guess after gaps."""
        identity = self.identity(segment)
        if identity is None:
            return (
                None,
                False,
                [],
                ["ambiguous_direction"]
                if segment.sport == segment.dport == self.port
                else [],
                False,
            )
        flow, response = identity
        key = (flow, response)
        issues: list[str] = []
        reset = False
        if segment.flags & 4:
            self.streams.pop((flow, False), None)
            self.streams.pop((flow, True), None)
            return flow, response, [], [], True
        if segment.flags & 2:
            existing = self.streams.get(key)
            if (
                existing is not None
                and existing.initial == segment.sequence
                and not existing.history
            ):
                return flow, response, [], [], False
            if not response:
                reset = (flow, False) in self.streams or (flow, True) in self.streams
                self.streams.pop((flow, False), None)
                self.streams.pop((flow, True), None)
            require(
                flow in {item[0] for item in self.streams}
                or len({item[0] for item in self.streams}) < MAX_FLOWS,
                "TCP flow state cap reached",
            )
            self.streams[key] = Stream(
                (segment.sequence + 1) & 0xFFFFFFFF, segment.sequence
            )
            if segment.payload:
                self.streams[key].blocked = True
                issues.append("syn_payload_unsupported")
            return flow, response, [], issues, reset
        stream = self.streams.get(key)
        if stream is None:
            if segment.payload:
                issues.append("missing_syn")
            return flow, response, [], issues, False
        if stream.blocked or not segment.payload:
            if stream.blocked and segment.payload:
                self.blocked_payload_packets += 1
            if not stream.blocked and segment.flags & 1:
                stream.blocked = True
                if stream.buffer:
                    stream.buffer = b""
                    issues.append("incomplete_adu")
            return flow, response, [], issues, False
        payload = segment.payload
        delta = (segment.sequence - stream.expected) & 0xFFFFFFFF
        if delta:
            behind = (stream.expected - segment.sequence) & 0xFFFFFFFF
            overlap = min(behind, len(payload))
            if (
                delta < 2**31
                or behind > len(stream.history)
                or stream.history[
                    len(stream.history) - behind : len(stream.history)
                    - behind
                    + overlap
                ]
                != payload[:overlap]
            ):
                stream.blocked = True
                stream.buffer = b""
                return flow, response, [], ["tcp_gap_or_conflict"], False
            self.retransmissions += 1
            payload = payload[overlap:]
        stream.expected = (stream.expected + len(payload)) & 0xFFFFFFFF
        stream.history = (stream.history + payload)[-MAX_STREAM:]
        require(
            len(stream.buffer) + len(payload) <= MAX_STREAM, "TCP buffer cap reached"
        )
        stream.buffer += payload
        messages = []
        while len(stream.buffer) >= 6:
            protocol, length = struct.unpack(">HH", stream.buffer[2:6])
            if protocol != 0 or not 2 <= length <= 254:
                stream.blocked = True
                stream.buffer = b""
                issues.append("malformed_mbap")
                break
            if len(stream.buffer) < length + 6:
                break
            messages.append(stream.buffer[: length + 6])
            stream.buffer = stream.buffer[length + 6 :]
        if segment.flags & 1:
            stream.blocked = True
            if stream.buffer:
                stream.buffer = b""
                issues.append("incomplete_adu")
        return flow, response, messages, issues, False

    def incomplete(self) -> int:
        """Count pending partial ADUs at capture end, not device health failures."""
        return sum(bool(stream.buffer) for stream in self.streams.values())
