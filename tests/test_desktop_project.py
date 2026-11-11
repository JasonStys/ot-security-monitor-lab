"""Independent passive-capture GUI adapter oracles, threshold provenance and exact retained evidence. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: workspace — line 78
# parameter: tmp_path — line 78
# variable: state — line 80
# definition: execute — line 87
# parameter: changes — line 87
# parameter: index — line 87
# parameter: state — line 87
# parameter: tmp_path — line 87
# variable: values — line 89
# variable: stage — line 91
# definition: test_every_prepared_operation_uses_actual_independent_rules — line 110
# parameter: expected — line 111
# parameter: index — line 111
# parameter: tmp_path — line 111
# parameter: workspace — line 111
# variable: files — line 114
# variable: kind — line 114
# variable: summary — line 114
# variable: report — line 115
# variable: rows — line 128
# variable: row — line 129
# definition: test_exact_coverage_denominators_and_explicit_policy_change — line 133
# parameter: tmp_path — line 133
# parameter: workspace — line 133
# variable: _kind — line 135
# variable: _summary — line 135
# variable: files — line 135
# variable: report — line 136
# variable: asset — line 137
# variable: row — line 141
# variable: _kind — line 143
# variable: _summary — line 143
# variable: changed — line 143
# variable: notes — line 144
# definition: test_selected_external_capture_exact_hash_and_original_policy_survive — line 151
# parameter: tmp_path — line 152
# parameter: workspace — line 152
# variable: raw — line 157
# variable: selected — line 158
# variable: _kind — line 160
# variable: _summary — line 160
# variable: files — line 160
# variable: report — line 163
# variable: scope — line 164
# variable: name — line 177
# definition: test_bad_settings_do_not_create_or_replace_history — line 193
# parameter: change — line 193
# parameter: tmp_path — line 193
# parameter: workspace — line 193
# definition: test_policy_without_object_and_malformed_capture_refuse — line 200
# parameter: tmp_path — line 200
# parameter: workspace — line 200
# variable: selected — line 204
# definition: test_exact_all_frame_directions_and_unfiltered_context — line 214
# parameter: tmp_path — line 214
# parameter: workspace — line 214
# variable: _kind — line 216
# variable: _summary — line 216
# variable: files — line 216
# variable: views — line 217
# variable: frames — line 218
# variable: row — line 219
# END CODE MAP

import hashlib
import json

import pytest

from otmon import desktop_project as project
from otmon.desktop_io import Rejected
from otmon.desktop_state import Workspace


@pytest.fixture
def workspace(tmp_path):
    """Own only an isolated synthetic local SQLite profile."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    try:
        yield state
    finally:
        state.close()


def execute(state, tmp_path, index, changes=None):
    """Run actual original passive analysis; store no simulated monitor response."""
    values = project.scenario(project.SCENARIOS[index])
    values.update(changes or {})
    stage = tmp_path / ("analysis-" + str(index))
    stage.mkdir()
    return project.analyze(state, values, stage)


@pytest.mark.parametrize(
    "index,expected",
    [
        (0, {}),
        (1, {"unexpected_peer": 1, "unauthorized_write": 1, "outside_maintenance": 1}),
        (2, {"readonly_write": 1}),
        (3, {"outside_maintenance": 1}),
        (4, {"process_envelope": 1}),
        (5, {"rate_burst": 1}),
        (6, {}),
        (7, {"capture_gap": 1}),
        (8, {}),
    ],
)
def test_every_prepared_operation_uses_actual_independent_rules(
    workspace, tmp_path, index, expected
):
    """Literal scenario outcomes preserve ambiguity and scoped maintenance instead of deriving oracles from results."""
    kind, summary, files = execute(workspace, tmp_path, index)
    report = json.loads(files["report.json"])
    assert kind == "passive-modbus-review" and "no device access" in summary
    assert report["rule_counts"] == expected
    assert {
        "report.json",
        "report.html",
        "evidence.sqlite",
        "original-policy.json",
        "effective-policy.json",
        "input-scope.json",
    } == set(files)
    assert "no automated blocking or PLC writes" in report["limitations"]
    assert not workspace.history()
    for rows in project.views(files).values():
        for row in rows:
            assert len(project.cells(row)) == 4


def test_exact_coverage_denominators_and_explicit_policy_change(workspace, tmp_path):
    """A normal read observes only100–101 holding registers; input space and both other intervals remain unobserved."""
    _kind, _summary, files = execute(workspace, tmp_path, 0)
    report = json.loads(files["report.json"])
    asset = report["read_coverage"]["assets"][0]
    assert asset["matched_reads"] == 1
    assert asset["spaces"][0]["baseline"][0]["observed_spans"] == [[100, 101]]
    assert asset["spaces"][0]["baseline"][0]["unobserved_spans"] == [[102, 103]]
    assert all(row["observed_addresses"] == 0 for row in asset["spaces"][1]["baseline"])
    assert files["original-policy.json"] == files["effective-policy.json"]
    _kind, _summary, changed = execute(workspace, tmp_path, 6)
    notes = json.loads(changed["input-scope.json"])
    assert json.loads(changed["effective-policy.json"])["rate_limit"] == 10
    assert json.loads(changed["original-policy.json"])["rate_limit"] == 3
    assert notes["explicit_overrides"] == ["rate_limit"]
    assert notes["original_policy_sha256"] != notes["effective_policy_sha256"]


def test_selected_external_capture_exact_hash_and_original_policy_survive(
    workspace, tmp_path
):
    """A real selected file runs the same parser and retains metadata without copying raw PCAP into the bundle."""
    from examples.scenarios import scenarios

    raw = scenarios()["unknown-writer"][0]
    selected = tmp_path / "authorized.pcap"
    selected.write_bytes(raw)
    _kind, _summary, files = execute(
        workspace, tmp_path, 0, {"mode": project.MODES[1], "pcap": str(selected)}
    )
    report = json.loads(files["report.json"])
    scope = json.loads(files["input-scope.json"])
    assert (
        report["source_sha256"]
        == hashlib.sha256(raw).hexdigest()
        == scope["source_sha256"]
    )
    assert report["rule_counts"] == {
        "unexpected_peer": 1,
        "unauthorized_write": 1,
        "outside_maintenance": 1,
    }
    assert scope["capture_origin"] == "operator-authorized-file"
    assert selected.read_bytes() == raw and all(
        not name.endswith(".pcap") for name in files
    )


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "live capture"},
        {"capture_case": "unknown"},
        {"rate_limit": "0"},
        {"rate_limit": "10001"},
        {"rate_limit": "true"},
        {"rate_window_ms": "１２"},
        {"response_timeout_ms": "60001"},
    ],
)
def test_bad_settings_do_not_create_or_replace_history(workspace, tmp_path, change):
    """Wrong operation/threshold/source choices cannot fabricate a completed analysis."""
    with pytest.raises((Rejected, ValueError)):
        execute(workspace, tmp_path, 0, change)
    assert workspace.history() == []


def test_policy_without_object_and_malformed_capture_refuse(workspace, tmp_path):
    """Invalid input is not an empty clean observation."""
    with pytest.raises(Rejected):
        project.effective_policy(b"[]", {})
    selected = tmp_path / "bad.pcap"
    selected.write_bytes(b"not-a-capture")
    with pytest.raises(ValueError):
        execute(
            workspace, tmp_path, 0, {"mode": project.MODES[1], "pcap": str(selected)}
        )
    with pytest.raises(Rejected):
        project.scenario("missing")


def test_exact_all_frame_directions_and_unfiltered_context(workspace, tmp_path):
    """Literal display never drops whole-capture gaps or changes request/response meaning."""
    _kind, _summary, files = execute(workspace, tmp_path, 0)
    views = project.views(files)
    frames = views["Captured protocol frames"]
    assert [project.cells(row)[3] for row in frames] == ["request", "response"]
    assert (
        project.cells(views["Unfiltered capture and assumptions"][0])[3]
        == "not device health or safety"
    )
