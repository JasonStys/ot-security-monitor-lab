"""Actual passive PCAP, policy and register-observation workflows for the native workbench. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 79
# variable: PRODUCT — line 80
# variable: PROFILE — line 80
# variable: TITLE — line 81
# variable: VERSION — line 81
# variable: COLUMNS — line 82
# variable: RESOURCES — line 88
# variable: RESOURCE_LIMITS — line 95
# variable: MODES — line 96
# variable: REVIEW_MODE — line 97
# variable: CHOICES — line 98
# variable: FIELDS — line 99
# variable: ACTIVE_FIELDS — line 111
# variable: SCENARIOS — line 121
# variable: HELP — line 132
# definition: scenario — line 137
# parameter: name — line 137
# variable: selected — line 141
# definition: effective_policy — line 163
# parameter: parameters — line 163
# parameter: raw — line 163
# variable: config — line 165
# variable: changed — line 168
# variable: maximum — line 169
# variable: name — line 169
# variable: value — line 174
# variable: result — line 184
# definition: analyze — line 189
# parameter: parameters — line 190
# parameter: stage — line 190
# parameter: state — line 190
# variable: mode — line 194
# variable: original — line 197
# variable: changed — line 198
# variable: effective — line 198
# variable: selected — line 200
# variable: capture — line 203
# variable: capture — line 205
# variable: result — line 206
# variable: output — line 207
# variable: notes — line 209
# variable: files — line 221
# variable: path — line 221
# variable: summary — line 229
# definition: views — line 233
# parameter: files — line 233
# variable: report — line 235
# variable: assets — line 236
# variable: spans — line 236
# variable: item — line 237
# variable: space — line 239
# variable: interval — line 240
# variable: row — line 251
# variable: row — line 253
# variable: row — line 259
# definition: cells — line 275
# parameter: row — line 275
# variable: kind — line 277
# END CODE MAP

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from examples.scenarios import scenarios

from .contracts import MAX_CAPTURE, policy
from .desktop_io import Rejected, canonical, json_value
from .desktop_state import Workspace
from .evidence import export
from .inputs import read_source
from .monitor import analyze as monitor

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "ot-security-monitor-lab", "OtSecurityMonitorLab"
TITLE, VERSION = "OT Security Monitor Workbench", "1.1.0"
COLUMNS = (
    "Packet / asset",
    "Rule / register space",
    "Observed evidence",
    "State / scope",
)
RESOURCES = (
    "examples/policy.json",
    "sql/evidence.sql",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
RESOURCE_LIMITS: dict[str, int] = {}
MODES = ("Analyze prepared synthetic capture", "Analyze authorized PCAP file")
REVIEW_MODE = None
CHOICES = {"capture_case": tuple(scenarios())}
FIELDS = (
    ("capture_case", "Inert prepared capture (never transmitted)", "choice"),
    ("pcap", "Authorized classic-PCAP file, at most 8 MiB", "file"),
    ("policy", "Authorized asset/register/maintenance policy JSON", "file"),
    (
        "response_timeout_ms",
        "Response timeout override in ms (blank uses file)",
        "text",
    ),
    ("rate_window_ms", "Poll-rate window override in ms (blank uses file)", "text"),
    ("rate_limit", "Poll-rate count override (blank uses file)", "text"),
)
ACTIVE_FIELDS = {
    MODES[0]: (
        "capture_case",
        "policy",
        "response_timeout_ms",
        "rate_window_ms",
        "rate_limit",
    ),
    MODES[1]: ("pcap", "policy", "response_timeout_ms", "rate_window_ms", "rate_limit"),
}
SCENARIOS = (
    "Normal water-treatment holding-register poll",
    "Unexpected writer and unauthorized maintenance",
    "Approved writer touches read-only registers",
    "Authorized writer outside maintenance window",
    "Sensor raw-value envelope needs engineering review",
    "Four polls exceed the supplied rate policy",
    "Same capture with an explicit higher rate limit",
    "TCP gap: observations remain incomplete",
    "Coalesced holding/input-register read coverage",
)
HELP = """Analyze authorized offline classic-PCAP bytes with this project's real conservative TCP/Modbus parser, policy/correlation engine and passive read-coverage calculator. No device connection, scan, socket, packet transmission, collector, live process, firewall or PLC write exists in this GUI. Prepared captures are inert synthetic bytes made by the original public fixture generator; choose your own supported capture and policy instead if authorized.
The selected policy specifies assets, readers/writers, register intervals, raw-value envelopes and scoped maintenance windows. Blank timeout/rate overrides preserve exact file bytes; explicit bounded overrides create a separately hashed effective policy alongside the original. Capture timestamps drive the original maintenance/correlation rules, not your PC wall clock. Altering a threshold changes an analysis assumption, not device behavior or safety.
Inspect original alerts, frames, correlated reads, separate FC03/FC04 coverage intervals and unfiltered visibility caveats. Unobserved registers are not a failed device or a required-polling verdict. IP peer labels do not authenticate identities; a timeout or exception alone does not prove attack. Literal search never changes original counts or the full export. Saved results contain private packet metadata and both policy snapshots, but not raw PCAP payload bytes; keep originals separately for reproduction. Owner-local history is plaintext, not encrypted or multiuser. Exit waits for the real worker and committed evidence."""


def scenario(name: str) -> dict[str, str]:
    """Fill normal editable settings; no selection runs or certifies the prepared capture."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared capture")
    selected = (
        "normal-poll",
        "unknown-writer",
        "readonly-write",
        "outside-window",
        "sensor-envelope",
        "poll-burst",
        "poll-burst",
        "tcp-gap",
        "coalesced-polls",
    )[SCENARIOS.index(name)]
    return {
        "mode": MODES[0],
        "capture_case": selected,
        "pcap": "",
        "policy": str(ROOT / "examples/policy.json"),
        "response_timeout_ms": "",
        "rate_window_ms": "",
        "rate_limit": "10" if SCENARIOS.index(name) == 6 else "",
    }


def effective_policy(raw: bytes, parameters: dict[str, str]) -> tuple[bytes, list[str]]:
    """Preserve the original policy exactly unless explicit bounded scalar overrides are supplied."""
    config = json_value(raw)
    if not isinstance(config, dict):
        raise Rejected("policy object required")
    changed = []
    for name, maximum in (
        ("response_timeout_ms", 60000),
        ("rate_window_ms", 60000),
        ("rate_limit", 10000),
    ):
        value = parameters.get(name, "").strip()
        if value:
            if (
                not value.isascii()
                or not value.isdecimal()
                or not 1 <= int(value) <= maximum
            ):
                raise Rejected("invalid policy override")
            config[name] = int(value)
            changed.append(name)
    result = canonical(config) if changed else raw
    policy(result)
    return result, changed


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Run the original complete passive engine before publishing bounded immutable private evidence."""
    del state
    mode = parameters.get("mode")
    if mode not in MODES:
        raise Rejected("unsupported capture operation")
    original = read_source(Path(parameters["policy"]), 65536)
    effective, changed = effective_policy(original, parameters)
    if mode == MODES[0]:
        selected = parameters.get("capture_case", "")
        if selected not in CHOICES["capture_case"]:
            raise Rejected("unknown inert capture")
        capture = scenarios()[selected][0]
    else:
        capture = read_source(Path(parameters["pcap"]), MAX_CAPTURE)
    result = monitor(capture, policy(effective))
    output = stage / "passive-evidence"
    export(output, result)
    notes = {
        "schema": 1,
        "capture_origin": "prepared-inert-synthetic"
        if mode == MODES[0]
        else "operator-authorized-file",
        "source_sha256": hashlib.sha256(capture).hexdigest(),
        "capture_bytes": len(capture),
        "original_policy_sha256": hashlib.sha256(original).hexdigest(),
        "effective_policy_sha256": hashlib.sha256(effective).hexdigest(),
        "explicit_overrides": changed,
        "scope": "Passive offline evidence. Original source bytes are not exported. No device access, enforcement or physical safety conclusion.",
    }
    files = {path.name: read_source(path, 32 * 1024**2) for path in output.iterdir()}
    files.update(
        {
            "original-policy.json": original,
            "effective-policy.json": effective,
            "input-scope.json": canonical(notes),
        }
    )
    summary = f"{len(result['frames'])} decoded ADUs; {len(result['alerts'])} findings; {len(result['read_coverage']['matched_read_evidence'])} exact matched reads; no device access"
    return "passive-modbus-review", summary, files


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Keep alerts, complete visibility and separate register-space observation denominators inspectable."""
    report = json_value(files["report.json"])
    assets, spans = [], []
    for item in report["read_coverage"]["assets"]:
        assets.append({"kind": "asset", **item})
        for space in item["spaces"]:
            for interval in space["baseline"]:
                spans.append(
                    {
                        "kind": "span",
                        "asset": item["asset"],
                        "register_space": space["register_space"],
                        "function": space["function"],
                        **interval,
                    }
                )
    return {
        "Original findings": [{"kind": "alert", **row} for row in report["alerts"]],
        "Captured protocol frames": [
            {"kind": "frame", **row} for row in report["frames"]
        ],
        "Passive asset coverage": assets,
        "Register observation intervals": spans,
        "Exact matched reads": [
            {"kind": "read", **row}
            for row in report["read_coverage"]["matched_read_evidence"]
        ],
        "Unfiltered capture and assumptions": [
            {
                "kind": "context",
                "capture": report["capture"],
                "statistics": report["statistics"],
                "rule_counts": report["rule_counts"],
                "limitations": report["limitations"],
                "coverage_scope": report["read_coverage"]["scope"],
                "input_scope": json_value(files["input-scope.json"]),
            }
        ],
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Render compact literal facts; selection retains the complete original structured evidence."""
    kind = row["kind"]
    if kind == "alert":
        return (
            str(row.get("packet", "")),
            str(row.get("rule", "")),
            str(row.get("basis", "")),
            str(row.get("severity", "")),
        )
    if kind == "frame":
        return (
            str(row["packet"]),
            f"FC{row['function']}",
            f"transaction {row['transaction']} / unit {row['unit']}",
            "response" if row["response"] else "request",
        )
    if kind == "asset":
        return (
            str(row["asset"]),
            str(row["server_ip"]),
            f"{row['matched_reads']} exact matched reads",
            str(row["state"]),
        )
    if kind == "span":
        return (
            str(row["asset"]),
            str(row["register_space"]),
            f"{row['start']}–{row['end']}: {row['observed_addresses']}/{row['configured_addresses']} observed",
            "capture observations only",
        )
    if kind == "read":
        return (
            str(row["asset"]),
            f"FC{row['function']}",
            f"request {row['request_packet']} → response {row['response_packet']}",
            f"{row['start']}–{row['end']}",
        )
    return (
        "Whole capture",
        "unfiltered visibility",
        str(row["rule_counts"]),
        "not device health or safety",
    )
