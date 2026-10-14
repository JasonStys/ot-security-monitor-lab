"""Jason Stys: real CLI/export/SQLite lifecycle, idempotency/conflict rollback and inert report escaping."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_sqlite_and_escape — line 43
# parameter: config — line 43
# parameter: tmp_path — line 43
# variable: report — line 45
# variable: output — line 46
# variable: identity — line 47
# variable: connection — line 49
# variable: changed — line 58
# variable: connection — line 61
# variable: html — line 63
# definition: test_cli_and_errors — line 77
# parameter: capsys — line 78
# parameter: policy_data — line 78
# parameter: tmp_path — line 78
# variable: capture — line 81
# variable: policy — line 81
# variable: argv — line 84
# variable: report — line 93
# definition: test_module_entry — line 116
# parameter: tmp_path — line 116
# variable: result — line 133
# END CODE MAP

import json
import runpy
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from examples.scenarios import scenarios
from otmon.cli import main
from otmon.contracts import Policy, Rejected
from otmon.evidence import export, render, store
from otmon.monitor import analyze


def test_sqlite_and_escape(tmp_path: Path, config: Policy) -> None:
    """Persist exact findings with idempotency, indexed lookup, escaped HTML and no hidden payload execution."""
    report = analyze(scenarios()["unknown-writer"][0], config)
    output = tmp_path / "result"
    identity = export(output, report)
    assert store(output / "evidence.sqlite", report) == identity
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        assert connection.execute("SELECT count(*) FROM analyses").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 3
        assert (
            connection.execute(
                "SELECT count(*) FROM alerts WHERE rule=?", ("unauthorized_write",)
            ).fetchone()[0]
            == 1
        )
    changed = {**report, "site": "different"}
    with pytest.raises(Rejected, match="conflicting"):
        store(output / "evidence.sqlite", changed)
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        assert connection.execute("SELECT count(*) FROM alerts").fetchone()[0] == 3
    html = render({**report, "site": "<script>alert(1)</script>"})
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "default-src 'none'" in html and "Jason Stys" in html
    assert "https://github.com/JasonStys" in html and "<caption>" in html
    with pytest.raises(FileExistsError):
        export(output, report)
    with patch("otmon.evidence.canonical", return_value=b"x" * (16 * 1024 * 1024 + 1)):
        with pytest.raises(Rejected, match="cap"):
            store(tmp_path / "too-large.sqlite", report)
    with patch.object(Path, "is_junction", return_value=True):
        with pytest.raises(Rejected):
            store(tmp_path / "link.sqlite", report)


def test_cli_and_errors(
    tmp_path: Path, policy_data: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exercise actual input/report export and fixed-message malformed/IO/database errors."""
    capture, policy = tmp_path / "synthetic.pcap", tmp_path / "policy.json"
    capture.write_bytes(scenarios()["normal-poll"][0])
    policy.write_bytes(policy_data)
    argv = [
        "--pcap",
        str(capture),
        "--policy",
        str(policy),
        "--out",
        str(tmp_path / "result"),
    ]
    assert main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert (
        report["findings"] == 0
        and report["decoded_frames"] == 2
        and report["ok"] is True
    )
    assert main(argv) == 2
    assert (
        json.loads(capsys.readouterr().out)["error"]
        == "local filesystem operation failed"
    )
    with patch(
        "otmon.cli.export", side_effect=sqlite3.OperationalError("private path")
    ):
        assert main([*argv[:-1], str(tmp_path / "other")]) == 2
        assert "private path" not in capsys.readouterr().out
    capture.write_bytes(b"private invalid bytes")
    assert main([*argv[:-1], str(tmp_path / "bad")]) == 2
    assert "invalid capture size" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main([])


def test_module_entry(tmp_path: Path) -> None:
    """The standalone module entry forwards controlled failure rather than depending on imported UI state."""
    with patch.dict(sys.modules):
        sys.modules.pop("otmon.cli", None)
        with patch.object(
            sys,
            "argv",
            [
                "otmon",
                "--pcap",
                str(tmp_path / "missing"),
                "--policy",
                str(tmp_path / "missing"),
                "--out",
                str(tmp_path / "result"),
            ],
        ):
            with pytest.raises(SystemExit) as result:
                runpy.run_module("otmon.cli", run_name="__main__")
    assert result.value.code == 2
