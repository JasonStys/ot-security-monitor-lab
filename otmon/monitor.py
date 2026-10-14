"""Jason Stys: passive explainable OT detections, bounded correlation and explicit capture visibility limits."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: RULES — line 132
# definition: Monitor — line 227
# variable: policy — line 230
# variable: transport — line 231
# variable: pending — line 232
# variable: rates — line 235
# variable: bursting — line 236
# variable: alerts — line 237
# variable: frames — line 238
# variable: counts — line 239
# definition: __post_init__ — line 241
# parameter: self — line 241
# attribute: transport — line 243
# definition: alert — line 245
# parameter: self — line 246
# parameter: rule — line 247
# parameter: segment — line 248
# parameter: flow — line 249
# parameter: message — line 250
# parameter: raw — line 251
# variable: basis — line 255
# variable: reason — line 255
# variable: severity — line 255
# definition: asset — line 272
# parameter: flow — line 272
# parameter: self — line 272
# parameter: unit — line 272
# variable: asset — line 277
# definition: values — line 283
# parameter: self — line 284
# parameter: asset — line 285
# parameter: address — line 286
# parameter: values — line 287
# parameter: segment — line 288
# parameter: flow — line 289
# parameter: message — line 290
# parameter: raw — line 291
# variable: offset — line 294
# variable: value — line 294
# variable: reg — line 295
# variable: reg — line 298
# definition: request — line 307
# parameter: flow — line 308
# parameter: message — line 308
# parameter: raw — line 308
# parameter: segment — line 308
# parameter: self — line 308
# variable: address — line 318
# variable: quantity — line 318
# variable: asset — line 320
# variable: client — line 324
# variable: window — line 334
# variable: registers — line 337
# variable: reg — line 339
# variable: index — line 342
# variable: reg — line 344
# variable: reg — line 347
# variable: rate_key — line 351
# variable: times — line 356
# variable: key — line 368
# definition: response — line 375
# parameter: flow — line 376
# parameter: message — line 376
# parameter: raw — line 376
# parameter: segment — line 376
# parameter: self — line 376
# variable: key — line 383
# variable: pending — line 384
# variable: _ — line 388
# variable: request — line 388
# variable: matches — line 389
# variable: matches — line 391
# variable: matches — line 393
# variable: matches — line 395
# variable: asset — line 401
# definition: feed — line 412
# parameter: segment — line 412
# parameter: self — line 412
# variable: key — line 414
# variable: previous — line 414
# variable: request — line 414
# variable: flow — line 418
# variable: issues — line 418
# variable: raw_messages — line 418
# variable: reset — line 418
# variable: response — line 418
# variable: _ — line 420
# variable: key — line 420
# variable: request — line 420
# variable: issue — line 424
# variable: raw — line 429
# variable: message — line 431
# definition: finish — line 460
# parameter: self — line 460
# variable: _ — line 462
# variable: flow — line 462
# variable: request — line 462
# variable: segment — line 462
# definition: analyze — line 472
# parameter: config — line 472
# parameter: data — line 472
# variable: capture — line 474
# variable: segments — line 474
# variable: monitor — line 475
# variable: segment — line 476
# variable: alert — line 489
# END CODE MAP

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, cast

from otmon.capture import Segment, pcap
from otmon.contracts import (
    MAX_ALERTS,
    MAX_FLOWS,
    MAX_PACKETS,
    MAX_PENDING,
    Asset,
    Policy,
    Rejected,
    require,
    sha,
)
from otmon.protocol import Message, decode
from otmon.transport import Flow, Transport

RULES = {
    "unknown_asset": (
        "medium",
        "policy",
        "Server/unit has no reviewed asset baseline.",
    ),
    "unexpected_peer": (
        "high",
        "policy",
        "Observed source IP is not an expected reader or writer.",
    ),
    "unauthorized_write": (
        "high",
        "policy",
        "Observed write source IP is not an expected writer.",
    ),
    "outside_maintenance": (
        "medium",
        "policy",
        "Write has no matching asset/writer/time maintenance approval.",
    ),
    "readonly_write": (
        "high",
        "policy",
        "Write intersects a configured read-only register interval.",
    ),
    "register_outside_baseline": (
        "medium",
        "policy",
        "Request includes addresses outside reviewed register intervals.",
    ),
    "process_envelope": (
        "high",
        "process",
        "Observed raw uint16 value exceeds its configured engineering envelope.",
    ),
    "rate_burst": (
        "medium",
        "behavior",
        "Request count crossed the configured rolling-window threshold.",
    ),
    "transaction_reuse": (
        "medium",
        "correlation",
        "A transaction ID was reused on the same connection before resolution.",
    ),
    "unexpected_response": (
        "medium",
        "correlation",
        "No captured pending request matches this response transaction.",
    ),
    "response_mismatch": (
        "high",
        "correlation",
        "Unit/function/quantity or echoed write data differs from captured request.",
    ),
    "device_exception": (
        "medium",
        "protocol",
        "Device returned a valid Modbus exception; this alone is not proof of attack.",
    ),
    "unsupported_function": (
        "low",
        "visibility",
        "PDU function is outside this decoder's documented FC03/04/06/16 support.",
    ),
    "malformed_adu": (
        "high",
        "protocol",
        "A framed PDU failed exact protocol bounds/type validation.",
    ),
    "capture_gap": (
        "low",
        "visibility",
        "Stream continuity/direction/MBAP framing is incomplete or unsupported.",
    ),
    "observed_timeout": (
        "low",
        "correlation",
        "Later captured traffic shows a request older than the configured timeout.",
    ),
    "eof_unresolved": (
        "info",
        "visibility",
        "Capture ended with a pending request; device failure is not established.",
    ),
    "session_reset": (
        "info",
        "visibility",
        "Connection reset/restart ended unresolved captured transactions.",
    ),
}


@dataclass
class Monitor:
    """One deterministic analysis; input/state caps fail loudly rather than quietly evict evidence."""

    policy: Policy
    transport: Transport = field(init=False)
    pending: dict[tuple[Flow, int], tuple[Message, Segment]] = field(
        default_factory=dict
    )
    rates: dict[tuple[str, str], deque[int]] = field(default_factory=dict)
    bursting: set[tuple[str, str]] = field(default_factory=set)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    frames: list[dict[str, Any]] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)

    def __post_init__(self) -> None:
        """Initialize transport against independent configured service port."""
        self.transport = Transport(self.policy.service_port)

    def alert(
        self,
        rule: str,
        segment: Segment | None,
        flow: Flow | None,
        message: Message | None = None,
        raw: bytes = b"",
    ) -> None:
        """Append bounded fixed-reason evidence, never full payload bytes or guessed physical meaning."""
        require(len(self.alerts) < MAX_ALERTS, "alert evidence cap reached")
        severity, basis, reason = RULES[rule]
        self.alerts.append(
            dict(
                rule=rule,
                severity=severity,
                basis=basis,
                reason=reason,
                packet=None if segment is None else segment.packet,
                time_ms=None if segment is None else segment.time_ms,
                flow=flow,
                transaction=None if message is None else message.transaction,
                unit=None if message is None else message.unit,
                function=None if message is None else message.function,
                frame_sha256=sha(raw) if raw else None,
            )
        )

    def asset(self, flow: Flow, unit: int) -> Asset | None:
        """Lookup an exact configured server/unit pair; IP addresses are not authenticated identities."""
        return next(
            (
                asset
                for asset in self.policy.assets
                if asset.ip == flow[2] and asset.unit == unit
            ),
            None,
        )

    def values(
        self,
        asset: Asset,
        address: int,
        values: tuple[int, ...],
        segment: Segment,
        flow: Flow,
        message: Message,
        raw: bytes,
    ) -> None:
        """Check only captured matched register values using explicit raw uint16 policy envelopes."""
        for offset, value in enumerate(values):
            reg = next(
                (
                    reg
                    for reg in asset.registers
                    if reg.start <= address + offset <= reg.end
                ),
                None,
            )
            if reg is not None and not reg.minimum <= value <= reg.maximum:
                self.alert("process_envelope", segment, flow, message, raw)
                return

    def request(
        self, message: Message, segment: Segment, flow: Flow, raw: bytes
    ) -> None:
        """Evaluate peer/write/address/window/rate baselines and retain one bounded pending transaction."""
        require(
            message.address is not None
            and message.quantity is not None
            and message.exception is None
            and message.supported,
            "complete supported request metadata required",
        )
        address, quantity = cast(int, message.address), cast(int, message.quantity)
        self.counts["requests"] += 1
        asset = self.asset(flow, message.unit)
        if asset is None:
            self.alert("unknown_asset", segment, flow, message, raw)
        else:
            client = flow[0]
            if client not in asset.readers + asset.writers:
                self.alert("unexpected_peer", segment, flow, message, raw)
            if message.function in {6, 16}:
                if client not in asset.writers:
                    self.alert("unauthorized_write", segment, flow, message, raw)
                if not any(
                    window.asset == asset.name
                    and window.client == client
                    and window.start_ms <= segment.time_ms < window.end_ms
                    for window in self.policy.maintenance
                ):
                    self.alert("outside_maintenance", segment, flow, message, raw)
            registers = [
                next(
                    (reg for reg in asset.registers if reg.start <= index <= reg.end),
                    None,
                )
                for index in range(address, address + quantity)
            ]
            if any(reg is None for reg in registers):
                self.alert("register_outside_baseline", segment, flow, message, raw)
            if message.function in {6, 16} and any(
                reg is not None and not reg.writable for reg in registers
            ):
                self.alert("readonly_write", segment, flow, message, raw)
            self.values(asset, address, message.values, segment, flow, message, raw)
        rate_key = (flow[0], flow[2])
        require(
            rate_key in self.rates or len(self.rates) < MAX_FLOWS,
            "request rate state cap reached",
        )
        times = self.rates.setdefault(
            rate_key, deque(maxlen=self.policy.rate_limit + 1)
        )
        while times and times[0] <= segment.time_ms - self.policy.rate_window_ms:
            times.popleft()
        times.append(segment.time_ms)
        if len(times) > self.policy.rate_limit:
            if rate_key not in self.bursting:
                self.alert("rate_burst", segment, flow, message, raw)
            self.bursting.add(rate_key)
        else:
            self.bursting.discard(rate_key)
        key = (flow, message.transaction)
        if key in self.pending:
            self.alert("transaction_reuse", segment, flow, message, raw)
        else:
            require(len(self.pending) < MAX_PENDING, "pending transaction cap reached")
            self.pending[key] = message, segment

    def response(
        self, message: Message, segment: Segment, flow: Flow, raw: bytes
    ) -> None:
        """Correlate before interpreting addresses; mismatched responses do not consume a valid pending request."""
        self.counts["responses"] += 1
        if message.exception is not None:
            self.alert("device_exception", segment, flow, message, raw)
            self.counts["exceptions"] += 1
        key = (flow, message.transaction)
        pending = self.pending.get(key)
        if pending is None:
            self.alert("unexpected_response", segment, flow, message, raw)
            return
        request, _ = pending
        matches = request.unit == message.unit and request.function == message.function
        if message.exception is None:
            matches = matches and request.quantity == message.quantity
            if message.function in {6, 16}:
                matches = matches and request.address == message.address
            if message.function == 6:
                matches = matches and request.values == message.values
        if not matches:
            self.alert("response_mismatch", segment, flow, message, raw)
            return
        del self.pending[key]
        self.counts["matched_responses"] += 1
        asset = self.asset(flow, request.unit)
        if (
            asset is not None
            and request.address is not None
            and message.function in {3, 4}
            and message.exception is None
        ):
            self.values(
                asset, request.address, message.values, segment, flow, message, raw
            )

    def feed(self, segment: Segment) -> None:
        """Advance capture-time expirations, transport fidelity and complete-message analysis without network I/O."""
        for key, (request, previous) in list(self.pending.items()):
            if segment.time_ms - previous.time_ms >= self.policy.response_timeout_ms:
                self.alert("observed_timeout", segment, key[0], request)
                del self.pending[key]
        flow, response, raw_messages, issues, reset = self.transport.feed(segment)
        if reset:
            for key, (request, _) in list(self.pending.items()):
                if key[0] == flow:
                    self.alert("session_reset", segment, flow, request)
                    del self.pending[key]
        for issue in issues:
            self.counts["capture_issue_" + issue] += 1
            self.alert("capture_gap", segment, flow)
        if flow is None:
            return
        for raw in raw_messages:
            try:
                message = decode(raw, response)
            except Rejected:
                self.alert("malformed_adu", segment, flow, raw=raw)
                continue
            require(len(self.frames) < MAX_PACKETS, "decoded frame cap reached")
            self.frames.append(
                dict(
                    packet=segment.packet,
                    time_ms=segment.time_ms,
                    response=response,
                    flow=flow,
                    transaction=message.transaction,
                    unit=message.unit,
                    function=message.function,
                    address=message.address,
                    quantity=message.quantity,
                    exception=message.exception,
                    supported=message.supported,
                    frame_sha256=sha(raw),
                )
            )
            if not message.supported:
                self.alert("unsupported_function", segment, flow, message, raw)
                continue
            if response:
                self.response(message, segment, flow, raw)
            else:
                self.request(message, segment, flow, raw)

    def finish(self) -> None:
        """Label unresolved requests/partial ADUs at EOF; never manufacture a later device timeout."""
        for (flow, _), (request, segment) in self.pending.items():
            self.alert("eof_unresolved", segment, flow, request)
        self.counts["eof_unresolved_requests"] = len(self.pending)
        self.counts["eof_partial_adus"] = self.transport.incomplete()
        if self.counts["eof_partial_adus"]:
            self.alert("capture_gap", None, None)
        self.counts["verified_retransmissions"] = self.transport.retransmissions
        self.counts["blocked_payload_packets"] = self.transport.blocked_payload_packets


def analyze(data: bytes, config: Policy) -> dict[str, Any]:
    """Return deterministic evidence for an entire validated capture; output is not an enforcement decision."""
    segments, capture = pcap(data)
    monitor = Monitor(config)
    for segment in segments:
        monitor.feed(segment)
    monitor.finish()
    return dict(
        author="Jason Stys",
        schema=1,
        engine_version="1.0.0",
        site=config.site,
        source_sha256=sha(data),
        policy_sha256=config.digest,
        capture=capture,
        statistics=dict(sorted(monitor.counts.items())),
        rule_counts=dict(
            sorted(Counter(alert["rule"] for alert in monitor.alerts).items())
        ),
        alerts=monitor.alerts,
        frames=monitor.frames,
        limitations=[
            "offline passive lab, not a production IDS",
            "IP labels do not authenticate peers",
            "capture gaps/unsupported layers are not device health",
            "no physical-process safety verdict",
            "no automated blocking or PLC writes",
        ],
    )
