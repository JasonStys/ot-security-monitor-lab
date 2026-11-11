"""Jason Stys: real bounded package files and fail-closed hosted-only independent-dissector setup."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_real_download_file_requires_exact_new_bytes_before_execution — line 34
# parameter: kind — line 34
# parameter: tmp_path — line 34
# variable: expected — line 36
# variable: raw — line 37
# variable: target — line 42
# definition: test_host_admission_precedes_any_network_or_process — line 65
# parameter: monkeypatch — line 66
# parameter: mutation — line 66
# parameter: tmp_path — line 66
# parameter: a — line 85
# parameter: k — line 85
# parameter: a — line 90
# parameter: k — line 90
# definition: test_actual_workflow_retains_the_original_independent_oracle_and_deadline — line 97
# variable: root — line 99
# variable: source — line 100
# variable: native — line 101
# variable: signature — line 121
# END CODE MAP

import hashlib
import io
from pathlib import Path

import pytest

from scripts import tshark_runner as installer


@pytest.mark.parametrize("kind", ["exact", "short", "long", "changed", "existing"])
def test_real_download_file_requires_exact_new_bytes_before_execution(tmp_path, kind):
    """Use real temporary files; incorrect packages never reach signature or installer execution."""
    expected = b"inert reviewed package fixture"
    raw = {
        "short": expected[:-1],
        "long": expected + b"x",
        "changed": expected[:-1] + b"!",
    }.get(kind, expected)
    target = tmp_path / "package.msi"
    if kind == "existing":
        target.write_bytes(b"retained")
    if kind == "exact":
        installer.verified_copy(
            io.BytesIO(raw), target, len(expected), hashlib.sha256(expected).hexdigest()
        )
        assert target.read_bytes() == expected
    else:
        with pytest.raises((ValueError, FileExistsError)):
            installer.verified_copy(
                io.BytesIO(raw),
                target,
                len(expected),
                hashlib.sha256(expected).hexdigest(),
            )
        if kind == "existing":
            assert target.read_bytes() == b"retained"


@pytest.mark.parametrize(
    "mutation", ["ordinary-pc", "linux", "machine", "missing-temp"]
)
def test_host_admission_precedes_any_network_or_process(
    monkeypatch, tmp_path, mutation
):
    """Only the fixed disposable Actions/Windows/AMD64 runner may acquire this dependency."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(installer.platform, "system", lambda: "Windows")
    monkeypatch.setattr(installer.platform, "machine", lambda: "AMD64")
    if mutation == "ordinary-pc":
        monkeypatch.delenv("GITHUB_ACTIONS")
    elif mutation == "linux":
        monkeypatch.setenv("RUNNER_OS", "Linux")
    elif mutation == "machine":
        monkeypatch.setattr(installer.platform, "machine", lambda: "ARM64")
    else:
        monkeypatch.setenv("RUNNER_TEMP", str(tmp_path / "absent"))
    monkeypatch.setattr(
        installer.urllib.request,
        "urlopen",
        lambda *a, **k: pytest.fail("Network before host admission"),
    )
    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda *a, **k: pytest.fail("Process before host admission"),
    )
    with pytest.raises(ValueError):
        installer.main()
    assert list(tmp_path.iterdir()) == []


def test_actual_workflow_retains_the_original_independent_oracle_and_deadline():
    """The environment changes, not the seven manually authored golden cases or offline-only dissector argv."""
    root = Path(__file__).resolve().parents[1]
    source = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    native = source.split("  native:\n", 1)[1].split("  security:\n", 1)[0]
    assert "runs-on: windows-latest" in native and "timeout-minutes: 15" in native
    assert (
        native.count("python scripts/tshark_runner.py")
        == native.count("python scripts/native.py")
        == 1
    )
    assert native.index("python scripts/tshark_runner.py") < native.index(
        "python scripts/native.py"
    )
    assert "continue-on-error" not in native and "|| true" not in native
    assert (
        installer.URL
        == "https://www.wireshark.org/download/win64/Wireshark-4.6.9-x64.msi"
    )
    assert installer.SIZE == 80_433_152
    assert (
        installer.SHA256
        == "1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217"
    )
    signature = (root / "scripts/check_tshark_signature.ps1").read_text(
        encoding="utf-8"
    )
    assert "Get-AuthenticodeSignature -LiteralPath $Package" in signature
    assert (
        "$taskSignature.Status -ne 'Valid'" in signature
        and "O=Wireshark Foundation" in signature
    )
