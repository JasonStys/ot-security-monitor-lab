"""Jason Stys: passive matched-read observation coverage, preserving asset/unit and register-space boundaries."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: intervals — line 46
# parameter: spans — line 46
# variable: result — line 48
# variable: end — line 49
# variable: start — line 49
# definition: summarize — line 57
# parameter: config — line 58
# parameter: observations — line 59
# parameter: capture — line 60
# parameter: rule_counts — line 61
# variable: assets — line 64
# variable: asset — line 65
# variable: matched — line 66
# variable: row — line 66
# variable: spaces — line 67
# variable: function — line 68
# variable: name — line 68
# variable: reads — line 69
# variable: row — line 71
# variable: baseline — line 74
# variable: register — line 75
# variable: observed — line 76
# variable: row — line 82
# variable: missing — line 86
# variable: cursor — line 87
# variable: end — line 88
# variable: start — line 88
# variable: cursor — line 91
# variable: end — line 100
# variable: start — line 100
# variable: row — line 121
# variable: row — line 124
# variable: count — line 137
# variable: name — line 137
# END CODE MAP

from __future__ import annotations

from typing import Any

from otmon.contracts import Policy


def intervals(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge inclusive observed address spans without expanding all addresses or double-counting overlaps."""
    result: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if result and start <= result[-1][1] + 1:
            result[-1] = result[-1][0], max(end, result[-1][1])
        else:
            result.append((start, end))
    return result


def summarize(
    config: Policy,
    observations: list[dict[str, Any]],
    capture: dict[str, int],
    rule_counts: dict[str, int],
) -> dict[str, Any]:
    """Count unique baseline addresses only from successful matched reads by expected peers; unobserved never means failed."""
    assets = []
    for asset in config.assets:
        matched = [row for row in observations if row["asset"] == asset.name]
        spaces = []
        for function, name in ((3, "holding_registers"), (4, "input_registers")):
            reads = [
                row
                for row in matched
                if row["function"] == function and row["expected_peer"]
            ]
            baseline = []
            for register in asset.registers:
                observed = intervals(
                    [
                        (
                            max(register.start, row["start"]),
                            min(register.end, row["end"]),
                        )
                        for row in reads
                        if row["start"] <= register.end and row["end"] >= register.start
                    ]
                )
                missing = []
                cursor = register.start
                for start, end in observed:
                    if cursor < start:
                        missing.append((cursor, start - 1))
                    cursor = end + 1
                if cursor <= register.end:
                    missing.append((cursor, register.end))
                baseline.append(
                    {
                        "start": register.start,
                        "end": register.end,
                        "configured_addresses": register.end - register.start + 1,
                        "observed_addresses": sum(
                            end - start + 1 for start, end in observed
                        ),
                        "observed_spans": observed,
                        "unobserved_spans": missing,
                    }
                )
            spaces.append(
                {
                    "function": function,
                    "register_space": name,
                    "expected_peer_matched_reads": len(reads),
                    "baseline": baseline,
                }
            )
        assets.append(
            {
                "asset": asset.name,
                "server_ip": asset.ip,
                "unit": asset.unit,
                "matched_reads": len(matched),
                "unexpected_peer_reads_excluded": sum(
                    not row["expected_peer"] for row in matched
                ),
                "state": "MATCHED_READS_OBSERVED"
                if any(row["expected_peer"] for row in matched)
                else "NO_EXPECTED_PEER_MATCHED_READS",
                "spaces": spaces,
            }
        )
    return {
        "kind": "passive_matched_read_coverage",
        "policy_sha256": config.digest,
        "assets": assets,
        "matched_read_evidence": observations,
        "capture_visibility_unfiltered": capture,
        "caveat_counts": {
            name: count
            for name, count in rule_counts.items()
            if name
            in {
                "capture_gap",
                "unsupported_function",
                "malformed_adu",
                "response_mismatch",
                "eof_unresolved",
                "observed_timeout",
                "session_reset",
            }
        },
        "scope": "FC03 holding and FC04 input register spaces are separate. Existing configured intervals are shown independently in each space; no expectation that every interval/space is polled is invented. Only exact successful correlated reads by expected IP peers count; IP is not identity. Writes, mismatches, exceptions, orphans and unresolved requests do not establish read coverage. Unobserved addresses are capture-observation gaps, not device failure or safety findings. No polling or OT device access occurs.",
    }
