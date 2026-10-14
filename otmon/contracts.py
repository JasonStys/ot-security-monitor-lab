"""Jason Stys: strict bounded asset/register/maintenance policy and fixed-message input validation."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_CAPTURE — line 108
# variable: MAX_PACKETS — line 109
# variable: MAX_FLOWS — line 110
# variable: MAX_PENDING — line 111
# variable: MAX_ALERTS — line 112
# variable: MAX_STREAM — line 113
# variable: ID — line 114
# definition: Rejected — line 117
# definition: require — line 121
# parameter: condition — line 121
# parameter: message — line 121
# definition: integer — line 127
# parameter: high — line 127
# parameter: low — line 127
# parameter: value — line 127
# definition: sha — line 132
# parameter: data — line 132
# definition: canonical — line 137
# parameter: value — line 137
# definition: read_file — line 144
# parameter: limit — line 144
# parameter: path — line 144
# variable: stream — line 153
# variable: data — line 154
# definition: object_pairs — line 159
# parameter: items — line 159
# variable: result — line 161
# variable: key — line 162
# variable: value — line 162
# definition: fields — line 168
# parameter: keys — line 168
# parameter: value — line 168
# definition: ipv4 — line 174
# parameter: value — line 174
# variable: address — line 178
# definition: clients — line 190
# parameter: value — line 190
# variable: item — line 193
# variable: result — line 193
# definition: Register — line 199
# variable: start — line 202
# variable: end — line 203
# variable: writable — line 204
# variable: minimum — line 205
# variable: maximum — line 206
# definition: Asset — line 210
# variable: name — line 213
# variable: ip — line 214
# variable: unit — line 215
# variable: readers — line 216
# variable: writers — line 217
# variable: registers — line 218
# definition: Maintenance — line 222
# variable: asset — line 225
# variable: client — line 226
# variable: start_ms — line 227
# variable: end_ms — line 228
# definition: Policy — line 232
# variable: site — line 235
# variable: service_port — line 236
# variable: response_timeout_ms — line 237
# variable: rate_window_ms — line 238
# variable: rate_limit — line 239
# variable: assets — line 240
# variable: maintenance — line 241
# variable: digest — line 242
# definition: policy — line 245
# parameter: data — line 245
# variable: raw — line 249
# variable: value — line 252
# variable: high — line 273
# variable: low — line 273
# variable: name — line 273
# variable: assets — line 284
# variable: names — line 285
# variable: endpoints — line 286
# variable: item — line 287
# variable: asset — line 288
# variable: ip — line 296
# variable: readers — line 300
# variable: writers — line 300
# variable: ranges — line 305
# variable: last — line 306
# variable: entry — line 307
# variable: reg — line 308
# variable: field — line 312
# variable: last — line 322
# variable: windows — line 330
# variable: entry — line 331
# variable: window — line 332
# variable: client — line 337
# variable: asset — line 338
# variable: owner — line 338
# END CODE MAP

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_CAPTURE = 8 * 1024 * 1024
MAX_PACKETS = 10000
MAX_FLOWS = 128
MAX_PENDING = 256
MAX_ALERTS = 10000
MAX_STREAM = 4096
ID = re.compile(r"[a-z][a-z0-9-]{0,47}")


class Rejected(ValueError):
    """Fixed-message input rejection; never echo captured bytes, credentials or submitted text."""


def require(condition: bool, message: str) -> None:
    """Reject a failed contract with a fixed public reason."""
    if not condition:
        raise Rejected(message)


def integer(value: Any, low: int, high: int) -> bool:
    """Accept bounded exact integers, excluding booleans/floats."""
    return type(value) is int and low <= value <= high


def sha(data: bytes) -> str:
    """Hash exact input/evidence bytes with SHA256."""
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    """Encode deterministic JSON report/policy identity with no nonfinite numbers."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def read_file(path: Path, limit: int) -> bytes:
    """Read only a bounded ordinary local file; trusted parent directories/ACLs are operator responsibility."""
    require(
        integer(limit, 0, MAX_CAPTURE)
        and path.is_file()
        and not path.is_symlink()
        and not path.is_junction(),
        "bounded regular file required",
    )
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file exceeds cap")
    return data


def object_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before their earlier values can be hidden."""
    result: dict[str, Any] = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def fields(value: Any, keys: set[str]) -> dict[str, Any]:
    """Require an exact dictionary field set; no ignored misspellings or coerced types."""
    require(isinstance(value, dict) and set(value) == keys, "invalid policy fields")
    return dict(value)


def ipv4(value: Any) -> str:
    """Parse a canonical unicast IPv4 label without resolving names or opening sockets."""
    require(isinstance(value, str), "invalid IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise Rejected("invalid IPv4 address") from error
    require(
        not address.is_multicast
        and not address.is_unspecified
        and str(address) == value,
        "invalid unicast IPv4 address",
    )
    return str(address)


def clients(value: Any) -> tuple[str, ...]:
    """Require a bounded distinct client-IP list; source IP is an observation, not authenticated identity."""
    require(isinstance(value, list) and len(value) <= 32, "invalid client list")
    result = tuple(ipv4(item) for item in value)
    require(len(set(result)) == len(result), "duplicate client address")
    return result


@dataclass(frozen=True)
class Register:
    """Inclusive zero-based address interval and raw uint16 engineering-value envelope."""

    start: int
    end: int
    writable: bool
    minimum: int
    maximum: int


@dataclass(frozen=True)
class Asset:
    """One server-IP/unit pair with expected peers and nonoverlapping register baseline."""

    name: str
    ip: str
    unit: int
    readers: tuple[str, ...]
    writers: tuple[str, ...]
    registers: tuple[Register, ...]


@dataclass(frozen=True)
class Maintenance:
    """Explicit half-open [start_ms,end_ms) approval for one asset and expected writer."""

    asset: str
    client: str
    start_ms: int
    end_ms: int


@dataclass(frozen=True)
class Policy:
    """Frozen typed detection configuration with exact semantic input fingerprint."""

    site: str
    service_port: int
    response_timeout_ms: int
    rate_window_ms: int
    rate_limit: int
    assets: tuple[Asset, ...]
    maintenance: tuple[Maintenance, ...]
    digest: str


def policy(data: bytes) -> Policy:
    """Decode strict bounded JSON, validate role/register/window relationships and return typed policy."""
    require(len(data) <= 65536, "policy exceeds cap")
    try:
        raw = json.loads(data, object_pairs_hook=object_pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid policy JSON") from error
    value = fields(
        raw,
        {
            "schema",
            "site",
            "service_port",
            "response_timeout_ms",
            "rate_window_ms",
            "rate_limit",
            "assets",
            "maintenance",
        },
    )
    require(
        type(value["schema"]) is int and value["schema"] == 1,
        "unsupported policy schema",
    )
    require(
        isinstance(value["site"], str) and bool(ID.fullmatch(value["site"])),
        "invalid site name",
    )
    for name, low, high in (
        ("service_port", 1, 65535),
        ("response_timeout_ms", 1, 60000),
        ("rate_window_ms", 1, 60000),
        ("rate_limit", 1, 1000),
    ):
        require(integer(value[name], low, high), "invalid policy numeric threshold")
    require(
        isinstance(value["assets"], list) and 1 <= len(value["assets"]) <= 16,
        "invalid asset count",
    )
    assets = []
    names: set[str] = set()
    endpoints: set[tuple[str, int]] = set()
    for item in value["assets"]:
        asset = fields(item, {"name", "ip", "unit", "readers", "writers", "registers"})
        require(
            isinstance(asset["name"], str)
            and bool(ID.fullmatch(asset["name"]))
            and asset["name"] not in names,
            "invalid/duplicate asset name",
        )
        require(integer(asset["unit"], 0, 255), "invalid unit identifier")
        ip = ipv4(asset["ip"])
        require((ip, asset["unit"]) not in endpoints, "duplicate asset endpoint")
        names.add(asset["name"])
        endpoints.add((ip, asset["unit"]))
        readers, writers = clients(asset["readers"]), clients(asset["writers"])
        require(
            isinstance(asset["registers"], list) and 1 <= len(asset["registers"]) <= 32,
            "invalid register baseline",
        )
        ranges = []
        last = -1
        for entry in asset["registers"]:
            reg = fields(entry, {"start", "end", "writable", "minimum", "maximum"})
            require(
                all(
                    integer(reg[field], 0, 65535)
                    for field in ("start", "end", "minimum", "maximum")
                )
                and type(reg["writable"]) is bool,
                "invalid register fields",
            )
            require(
                last < reg["start"] <= reg["end"] and reg["minimum"] <= reg["maximum"],
                "overlapping/invalid register intervals",
            )
            ranges.append(Register(**reg))
            last = reg["end"]
        assets.append(
            Asset(asset["name"], ip, asset["unit"], readers, writers, tuple(ranges))
        )
    require(
        isinstance(value["maintenance"], list) and len(value["maintenance"]) <= 64,
        "invalid maintenance count",
    )
    windows = []
    for entry in value["maintenance"]:
        window = fields(entry, {"asset", "client", "start_ms", "end_ms"})
        require(
            isinstance(window["asset"], str) and window["asset"] in names,
            "unknown maintenance asset",
        )
        client = ipv4(window["client"])
        owner = next(asset for asset in assets if asset.name == window["asset"])
        require(
            client in owner.writers, "maintenance client must be an expected writer"
        )
        require(
            integer(window["start_ms"], 0, 4_102_444_800_000)
            and integer(window["end_ms"], 0, 4_102_444_800_000)
            and window["start_ms"] < window["end_ms"],
            "invalid maintenance interval",
        )
        windows.append(
            Maintenance(window["asset"], client, window["start_ms"], window["end_ms"])
        )
    return Policy(
        value["site"],
        value["service_port"],
        value["response_timeout_ms"],
        value["rate_window_ms"],
        value["rate_limit"],
        tuple(assets),
        tuple(windows),
        sha(canonical(value)),
    )
