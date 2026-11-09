"""Jason Stys: independent successful-read coverage and incomplete-observation regression oracles."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_unique_register_union_and_separate_spaces — line 59
# parameter: config — line 59
# variable: conversation — line 61
# variable: address — line 62
# variable: function — line 62
# variable: quantity — line 62
# variable: transaction — line 62
# variable: report — line 72
# variable: asset — line 73
# variable: holding — line 74
# variable: inputs — line 74
# variable: row — line 86
# definition: test_mismatch_exception_orphan_unresolved_and_write_not_coverage — line 94
# parameter: config — line 94
# variable: conversation — line 96
# variable: result — line 105
# definition: test_unknown_unit_unexpected_peer_and_absent_asset — line 115
# parameter: config — line 115
# variable: stranger — line 117
# variable: result — line 120
# variable: unknown — line 123
# variable: absent — line 129
# variable: extended — line 130
# definition: test_clipped_outside_baseline_and_actual_cli — line 137
# parameter: config — line 137
# parameter: tmp_path — line 137
# variable: conversation — line 139
# variable: report — line 142
# variable: source — line 150
# variable: out — line 152
# variable: stored — line 166
# definition: test_interior_unobserved_hole — line 173
# parameter: config — line 173
# variable: conversation — line 175
# variable: address — line 176
# variable: transaction — line 176
# variable: coverage — line 179
# END CODE MAP

import json
from dataclasses import replace
from pathlib import Path

from examples.scenarios import (
    Conversation,
    adu,
    read_request,
    read_response,
    write_request,
    write_response,
)
from otmon.cli import main
from otmon.coverage import intervals
from otmon.monitor import analyze


def test_unique_register_union_and_separate_spaces(config):
    """Overlapping read responses count each address once; FC04 cannot fill FC03 observation gaps."""
    conversation = Conversation()
    for transaction, address, quantity, function in [
        (1, 100, 2, 3),
        (2, 101, 3, 3),
        (3, 100, 2, 4),
        (4, 100, 2, 3),
    ]:
        conversation.add(read_request(transaction, function, address, quantity))
        conversation.add(
            read_response(transaction, function, tuple(range(quantity))), response=True
        )
    report = analyze(conversation.bytes(), config)
    asset = report["read_coverage"]["assets"][0]
    holding, inputs = asset["spaces"]
    assert (
        holding["baseline"][0]["observed_addresses"] == 4
        and holding["baseline"][0]["unobserved_spans"] == []
    )
    assert inputs["baseline"][0]["observed_addresses"] == 2 and inputs["baseline"][0][
        "unobserved_spans"
    ] == [(102, 103)]
    assert holding["baseline"][1]["unobserved_spans"] == [(200, 203)]
    assert len(report["read_coverage"]["matched_read_evidence"]) == 4
    assert all(
        row["request_packet"] < row["response_packet"]
        for row in report["read_coverage"]["matched_read_evidence"]
    )
    assert intervals([(100, 101), (101, 102), (103, 103), (200, 201)]) == [
        (100, 103),
        (200, 201),
    ]


def test_mismatch_exception_orphan_unresolved_and_write_not_coverage(config):
    """Only exact successful response correlation establishes reads; faults and write echoes cannot count."""
    conversation = Conversation(client="192.0.2.20")
    conversation.add(read_request(1))
    conversation.add(read_response(1, values=(100,)), response=True)
    conversation.add(read_request(2))
    conversation.add(adu(2, b"\x83\x02"), response=True)
    conversation.add(read_response(99), response=True)
    conversation.add(write_request(3))
    conversation.add(write_response(3), response=True)
    conversation.add(read_request(4))
    result = analyze(conversation.bytes(), config)
    assert result["read_coverage"]["matched_read_evidence"] == []
    assert (
        result["read_coverage"]["assets"][0]["state"]
        == "NO_EXPECTED_PEER_MATCHED_READS"
    )
    assert result["read_coverage"]["caveat_counts"]["response_mismatch"] == 1
    assert result["read_coverage"]["caveat_counts"]["eof_unresolved"] == 2


def test_unknown_unit_unexpected_peer_and_absent_asset(config):
    """Unknown units and unapproved IP readers cannot fabricate expected-peer baseline coverage; absent assets remain explicit."""
    stranger = Conversation(client="192.0.2.99")
    stranger.add(read_request())
    stranger.add(read_response(), response=True)
    result = analyze(stranger.bytes(), config)["read_coverage"]
    assert result["assets"][0]["unexpected_peer_reads_excluded"] == 1
    assert result["assets"][0]["spaces"][0]["baseline"][0]["observed_addresses"] == 0
    unknown = Conversation()
    unknown.add(read_request(unit=2))
    unknown.add(read_response(unit=2), response=True)
    assert (
        analyze(unknown.bytes(), config)["read_coverage"]["matched_read_evidence"] == []
    )
    absent = replace(config.assets[0], name="absent-skid", ip="192.0.2.11")
    extended = replace(config, assets=(*config.assets, absent))
    assert (
        analyze(stranger.bytes(), extended)["read_coverage"]["assets"][1]["state"]
        == "NO_EXPECTED_PEER_MATCHED_READS"
    )


def test_clipped_outside_baseline_and_actual_cli(config, tmp_path: Path):
    """Out-of-baseline addresses are not counted; the original detection remains while actual UI/SQL export includes coverage."""
    conversation = Conversation()
    conversation.add(read_request(address=99, quantity=3))
    conversation.add(read_response(values=(1, 2, 3)), response=True)
    report = analyze(conversation.bytes(), config)
    assert report["rule_counts"]["register_outside_baseline"] == 1
    assert (
        report["read_coverage"]["assets"][0]["spaces"][0]["baseline"][0][
            "observed_addresses"
        ]
        == 2
    )
    source = tmp_path / "synthetic.pcap"
    source.write_bytes(conversation.bytes())
    out = tmp_path / "review"
    assert (
        main(
            [
                "--pcap",
                str(source),
                "--policy",
                "examples/policy.json",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    stored = json.loads((out / "report.json").read_text())
    assert stored["read_coverage"]["matched_read_evidence"][0]["start"] == 99
    assert "Passive read observation coverage" in (out / "report.html").read_text(
        encoding="utf-8"
    )


def test_interior_unobserved_hole(config):
    """Sparse successful polls retain the exact interior blind interval instead of reporting all baseline addresses observed."""
    conversation = Conversation()
    for transaction, address in ((1, 100), (2, 103)):
        conversation.add(read_request(transaction, address=address, quantity=1))
        conversation.add(read_response(transaction, values=(1,)), response=True)
    coverage = analyze(conversation.bytes(), config)["read_coverage"]["assets"][0][
        "spaces"
    ][0]["baseline"][0]
    assert coverage["observed_addresses"] == 2 and coverage["unobserved_spans"] == [
        (101, 102)
    ]
