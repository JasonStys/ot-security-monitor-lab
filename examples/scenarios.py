"""Jason Stys: synthetic water-treatment PCAP scenarios with independent explicit expected rule counts."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: NOW — line 137
# definition: checksum — line 140
# parameter: data — line 140
# variable: data — line 143
# variable: total — line 144
# variable: total — line 146
# definition: packet — line 150
# parameter: payload — line 151
# parameter: src — line 153
# parameter: dst — line 154
# parameter: sport — line 155
# parameter: dport — line 156
# parameter: sequence — line 157
# parameter: ack — line 158
# parameter: flags — line 159
# parameter: vlan — line 160
# variable: source — line 163
# variable: target — line 163
# variable: tcp — line 167
# variable: pseudo — line 182
# variable: tcp — line 183
# variable: ip — line 184
# variable: ip — line 189
# variable: ethernet — line 190
# definition: capture — line 196
# parameter: endian — line 197
# parameter: nano — line 197
# parameter: records — line 197
# variable: magic — line 200
# variable: data — line 201
# variable: raw — line 202
# variable: timestamp — line 202
# variable: fraction — line 203
# variable: data — line 204
# definition: adu — line 213
# parameter: pdu — line 213
# parameter: transaction — line 213
# parameter: unit — line 213
# definition: read_request — line 218
# parameter: transaction — line 219
# parameter: function — line 220
# parameter: address — line 221
# parameter: quantity — line 222
# parameter: unit — line 223
# definition: read_response — line 229
# parameter: transaction — line 230
# parameter: function — line 231
# parameter: values — line 232
# parameter: unit — line 233
# definition: write_request — line 244
# parameter: transaction — line 245
# parameter: function — line 246
# parameter: address — line 247
# parameter: values — line 248
# variable: pdu — line 252
# variable: pdu — line 254
# definition: write_response — line 260
# parameter: address — line 261
# parameter: function — line 261
# parameter: transaction — line 261
# parameter: value — line 261
# definition: Conversation — line 268
# variable: client — line 271
# variable: server — line 272
# variable: port — line 273
# variable: start — line 274
# variable: vlan — line 275
# variable: records — line 276
# variable: client_sequence — line 277
# variable: server_sequence — line 278
# definition: __post_init__ — line 280
# parameter: self — line 280
# definition: add — line 286
# parameter: self — line 287
# parameter: payload — line 288
# parameter: response — line 290
# parameter: sequence — line 291
# parameter: ack — line 292
# parameter: flags — line 293
# parameter: delay — line 294
# variable: cursor — line 297
# variable: seq — line 298
# variable: raw — line 299
# variable: time — line 312
# attribute: server_sequence — line 316
# attribute: client_sequence — line 318
# definition: bytes — line 320
# parameter: self — line 320
# definition: scenarios — line 325
# variable: cases — line 327
# definition: save — line 329
# parameter: conversation — line 329
# parameter: expected — line 329
# parameter: name — line 329
# variable: normal — line 333
# variable: split — line 337
# variable: request — line 338
# variable: response — line 338
# variable: data — line 339
# variable: data — line 341
# variable: coalesced — line 344
# variable: retry — line 348
# variable: vlan — line 353
# variable: function — line 357
# variable: approved — line 358
# variable: outsider — line 369
# variable: readonly — line 377
# variable: late — line 381
# variable: dangerous — line 385
# variable: process — line 389
# variable: outside — line 393
# variable: unknown — line 397
# variable: burst — line 401
# variable: transaction — line 402
# variable: mismatch — line 406
# variable: exception — line 411
# variable: orphan — line 415
# variable: reuse — line 418
# variable: timeout — line 422
# variable: unresolved — line 426
# variable: partial — line 429
# variable: gap — line 432
# variable: bad — line 437
# variable: unsupported — line 440
# variable: missing — line 443
# attribute: records — line 444
# END CODE MAP

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

NOW = 1_700_000_000_000


def checksum(data: bytes) -> int:
    """Compute ordinary Internet checksum for synthetic IPv4/TCP fixture integrity."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(">" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(
    payload: bytes,
    *,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    sequence: int,
    ack: int = 0,
    flags: int = 24,
    vlan: bool = False,
) -> bytes:
    """Build synthetic Ethernet/IPv4/TCP bytes with valid checksums; this never sends packets."""
    source, target = (
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    tcp = (
        struct.pack(
            ">HHIIBBHHH",
            sport,
            dport,
            sequence & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            80,
            flags,
            8192,
            0,
            0,
        )
        + payload
    )
    pseudo = source + target + struct.pack(">BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", checksum(pseudo + tcp)) + tcp[18:]
    ip = (
        struct.pack(">BBHHHBBH", 69, 0, 20 + len(tcp), 1, 16384, 64, 6, 0)
        + source
        + target
    )
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("020000000010020000000030") + (
        bytes.fromhex("810000010800") if vlan else bytes.fromhex("0800")
    )
    return ethernet + ip + tcp


def capture(
    records: list[tuple[int, bytes]], *, endian: str = "<", nano: bool = False
) -> bytes:
    """Encode bounded synthetic classic PCAP micro/nanosecond timestamps without using runtime importers."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    data = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    for timestamp, raw in records:
        fraction = (timestamp % 1000) * (1_000_000 if nano else 1000)
        data += (
            struct.pack(
                endian + "IIII", timestamp // 1000, fraction, len(raw), len(raw)
            )
            + raw
        )
    return data


def adu(transaction: int, pdu: bytes, unit: int = 1) -> bytes:
    """Build independent MBAP fixture bytes; PDU structure is supplied explicitly by each scenario."""
    return struct.pack(">HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


def read_request(
    transaction: int = 1,
    function: int = 3,
    address: int = 100,
    quantity: int = 2,
    unit: int = 1,
) -> bytes:
    """Encode a read request golden fixture."""
    return adu(transaction, struct.pack(">BHH", function, address, quantity), unit)


def read_response(
    transaction: int = 1,
    function: int = 3,
    values: tuple[int, ...] = (100, 200),
    unit: int = 1,
) -> bytes:
    """Encode a read response with explicit independently chosen values."""
    return adu(
        transaction,
        bytes([function, len(values) * 2])
        + struct.pack(">" + "H" * len(values), *values),
        unit,
    )


def write_request(
    transaction: int = 1,
    function: int = 6,
    address: int = 200,
    values: tuple[int, ...] = (500,),
) -> bytes:
    """Encode write-single or write-multiple independent golden request bytes."""
    if function == 6:
        pdu = struct.pack(">BHH", function, address, values[0])
    else:
        pdu = struct.pack(
            ">BHHB", function, address, len(values), len(values) * 2
        ) + struct.pack(">" + "H" * len(values), *values)
    return adu(transaction, pdu)


def write_response(
    transaction: int = 1, function: int = 6, address: int = 200, value: int = 500
) -> bytes:
    """Encode an explicit write echo/quantity response, not by decoding the request."""
    return adu(transaction, struct.pack(">BHH", function, address, value))


@dataclass
class Conversation:
    """One in-memory synthetic TCP conversation; absolute sequence/ACK numbers mimic a captured handshake."""

    client: str = "192.0.2.30"
    server: str = "192.0.2.10"
    port: int = 40000
    start: int = NOW
    vlan: bool = False
    records: list[tuple[int, bytes]] = field(default_factory=list)
    client_sequence: int = 1001
    server_sequence: int = 2001

    def __post_init__(self) -> None:
        """Add a complete synthetic three-packet handshake to ground stream continuity."""
        self.add(b"", sequence=1000, ack=0, flags=2)
        self.add(b"", response=True, sequence=2000, ack=1001, flags=18)
        self.add(b"", sequence=1001, ack=2001, flags=16)

    def add(
        self,
        payload: bytes,
        *,
        response: bool = False,
        sequence: int | None = None,
        ack: int | None = None,
        flags: int = 24,
        delay: int = 1,
    ) -> None:
        """Append a captured-direction fixture, optionally controlling faults/timing without transmitting it."""
        cursor = self.server_sequence if response else self.client_sequence
        seq = cursor if sequence is None else sequence
        raw = packet(
            payload,
            src=self.server if response else self.client,
            dst=self.client if response else self.server,
            sport=502 if response else self.port,
            dport=self.port if response else 502,
            sequence=seq,
            ack=(self.client_sequence if response else self.server_sequence)
            if ack is None
            else ack,
            flags=flags,
            vlan=self.vlan,
        )
        time = self.records[-1][0] + delay if self.records else self.start
        self.records.append((time, raw))
        if sequence is None:
            if response:
                self.server_sequence = (cursor + len(payload)) & 0xFFFFFFFF
            else:
                self.client_sequence = (cursor + len(payload)) & 0xFFFFFFFF

    def bytes(self) -> bytes:
        """Return an inert PCAP snapshot, not a network operation."""
        return capture(self.records)


def scenarios() -> dict[str, tuple[bytes, dict[str, int]]]:
    """Return independent hand-authored expected detections; oracles never derive from the monitor output."""
    cases: dict[str, tuple[bytes, dict[str, int]]] = {}

    def save(name: str, conversation: Conversation, expected: dict[str, int]) -> None:
        """Store one complete synthetic conversation with its manually stated expected outcomes."""
        cases[name] = conversation.bytes(), expected

    normal = Conversation()
    normal.add(read_request())
    normal.add(read_response(), response=True)
    save("normal-poll", normal, {})
    split = Conversation()
    request, response = read_request(), read_response()
    for data in (request[:2], request[2:8], request[8:]):
        split.add(data)
    for data in (response[:6], response[6:]):
        split.add(data, response=True)
    save("segmented-poll", split, {})
    coalesced = Conversation()
    coalesced.add(read_request() + read_request(2, 4))
    coalesced.add(read_response() + read_response(2, 4), response=True)
    save("coalesced-polls", coalesced, {})
    retry = Conversation()
    retry.add(request)
    retry.add(request, sequence=1001)
    retry.add(response, response=True)
    save("verified-retransmission", retry, {})
    vlan = Conversation(vlan=True)
    vlan.add(request)
    vlan.add(response, response=True)
    save("vlan-poll", vlan, {})
    for function in (6, 16):
        approved = Conversation(client="192.0.2.20")
        approved.add(
            write_request(
                function=function, values=(500,) if function == 6 else (500, 600)
            )
        )
        approved.add(
            write_response(function=function, value=500 if function == 6 else 2),
            response=True,
        )
        save(f"approved-write-{function}", approved, {})
    outsider = Conversation(client="192.0.2.99")
    outsider.add(write_request())
    outsider.add(write_response(), response=True)
    save(
        "unknown-writer",
        outsider,
        dict(unexpected_peer=1, unauthorized_write=1, outside_maintenance=1),
    )
    readonly = Conversation(client="192.0.2.20")
    readonly.add(write_request(address=100))
    readonly.add(write_response(address=100), response=True)
    save("readonly-write", readonly, dict(readonly_write=1))
    late = Conversation(client="192.0.2.20", start=NOW + 5000)
    late.add(write_request())
    late.add(write_response(), response=True)
    save("outside-window", late, dict(outside_maintenance=1))
    dangerous = Conversation(client="192.0.2.20")
    dangerous.add(write_request(values=(1500,)))
    dangerous.add(write_response(value=1500), response=True)
    save("approved-writer-unsafe-value", dangerous, dict(process_envelope=1))
    process = Conversation()
    process.add(request)
    process.add(read_response(values=(1500, 100)), response=True)
    save("sensor-envelope", process, dict(process_envelope=1))
    outside = Conversation()
    outside.add(read_request(address=500))
    outside.add(response, response=True)
    save("unknown-registers", outside, dict(register_outside_baseline=1))
    unknown = Conversation(server="192.0.2.11")
    unknown.add(request)
    unknown.add(response, response=True)
    save("unknown-asset", unknown, dict(unknown_asset=1))
    burst = Conversation()
    for transaction in range(1, 5):
        burst.add(read_request(transaction))
        burst.add(read_response(transaction), response=True)
    save("poll-burst", burst, dict(rate_burst=1))
    mismatch = Conversation()
    mismatch.add(request)
    mismatch.add(read_response(values=(100,)), response=True)
    mismatch.add(response, response=True)
    save("mismatch-then-valid", mismatch, dict(response_mismatch=1))
    exception = Conversation()
    exception.add(request)
    exception.add(adu(1, b"\x83\x02"), response=True)
    save("device-exception", exception, dict(device_exception=1))
    orphan = Conversation()
    orphan.add(response, response=True)
    save("orphan-response", orphan, dict(unexpected_response=1))
    reuse = Conversation()
    reuse.add(request + request)
    reuse.add(response, response=True)
    save("transaction-reuse", reuse, dict(transaction_reuse=1))
    timeout = Conversation()
    timeout.add(request)
    timeout.add(response, response=True, delay=1000)
    save("observed-timeout", timeout, dict(observed_timeout=1, unexpected_response=1))
    unresolved = Conversation()
    unresolved.add(request)
    save("capture-ended-request", unresolved, dict(eof_unresolved=1))
    partial = Conversation()
    partial.add(request[:5])
    save("partial-adu-at-eof", partial, dict(capture_gap=1))
    gap = Conversation()
    gap.add(request[:5])
    gap.add(request[5:], sequence=1010)
    gap.add(b"ignored after gap")
    save("tcp-gap", gap, dict(capture_gap=1))
    bad = Conversation()
    bad.add(adu(1, b"\x03\x00"))
    save("malformed-pdu", bad, dict(malformed_adu=1))
    unsupported = Conversation()
    unsupported.add(adu(1, b"\x2b\x0e\x01\x00"))
    save("unsupported-identification", unsupported, dict(unsupported_function=1))
    missing = Conversation()
    missing.records = missing.records[3:]
    missing.add(request)
    save("missing-handshake", missing, dict(capture_gap=1))
    return cases
