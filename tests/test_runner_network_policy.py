"""Actual TShark-job policy mutants for signed disposable-runner acquisition. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 56
# definition: validate_jobs — line 59
# parameter: document — line 59
# variable: found — line 61
# variable: job — line 62
# variable: steps — line 63
# variable: apt — line 64
# variable: i — line 66
# variable: s — line 66
# variable: guards — line 71
# variable: i — line 73
# variable: s — line 73
# variable: s — line 78
# variable: text — line 80
# variable: required — line 81
# variable: i — line 95
# variable: found — line 100
# definition: workflow — line 104
# variable: source — line 106
# variable: body — line 107
# variable: jobs — line 108
# variable: match — line 109
# variable: steps — line 112
# variable: block — line 113
# variable: item — line 114
# variable: key — line 115
# variable: field — line 116
# variable: item — line 125
# definition: test_actual_signed_runner_acquisition_policy — line 134
# definition: test_actual_workflow_admission_mutants — line 142
# parameter: mutation — line 142
# variable: doc — line 144
# variable: job — line 145
# variable: j — line 147
# variable: s — line 150
# variable: steps — line 153
# variable: i — line 154
# variable: i — line 156
# variable: s — line 156
# variable: s — line 165
# variable: target — line 165
# variable: new — line 168
# variable: old — line 168
# definition: test_real_tshark_installation_and_original_golden_oracle_remain_mandatory — line 181
# variable: source — line 183
# END CODE MAP

import re
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def validate_jobs(document):
    """Require admission before the exact TShark APT consumer; other jobs retain their existing independent policy."""
    found = 0
    for job in document["jobs"].values():
        steps = job.get("steps", [])
        apt = [
            i
            for i, s in enumerate(steps)
            if "apt-get" in s.get("run", "") and "tshark" in s.get("run", "")
        ]
        if not apt:
            continue
        guards = [
            i
            for i, s in enumerate(steps)
            if s.get("name")
            == "Bound official mirror access on the disposable Ubuntu runner"
        ]
        assert len(guards) == 1 and guards[0] < min(apt)
        s = steps[guards[0]]
        assert s["if"] == "runner.os == 'Linux'" and s["timeout-minutes"] == "1"
        text = s["run"]
        for required in [
            'test "$GITHUB_ACTIONS" = "true"',
            'test "$RUNNER_OS" = "Linux"',
            'test "$ID" = "ubuntu"',
            'test "$VERSION_ID" = "24.04"',
            "/usr/share/keyrings/ubuntu-archive-keyring",
            "^Signed-By:",
            "https://archive.ubuntu.com/ubuntu/",
            "https://security.ubuntu.com/ubuntu/",
            'Acquire::Retries "0";',
            'Acquire::https::Timeout "15";',
            "apt-config dump",
        ]:
            assert required in text
        for i in apt:
            assert (
                "--allow-unauthenticated" not in steps[i]["run"]
                and "|| true" not in steps[i]["run"]
            )
        found += 1
    assert found >= 1


def workflow():
    """Read the actual authored source, including all original source/sanitizer/native jobs."""
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf8")
    body = source.split("\njobs:\n", 1)[1]
    jobs = {}
    for match in re.finditer(
        r"^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:|\Z)", body, re.M | re.S
    ):
        steps = []
        for block in re.findall(r"^      - .*?(?=^      - |\Z)", match[2], re.M | re.S):
            item = {}
            for key in ("name", "if", "timeout-minutes", "run"):
                field = re.search(r"^ {6,8}(?:- )?" + key + r": (.*)$", block, re.M)
                if field:
                    item[key] = (
                        block[field.end() :]
                        if key == "run" and field[1] == "|"
                        else field[1]
                    )
            steps.append(item)
        if "apt-get" in match[2]:
            assert any("apt-get" in item.get("run", "") for item in steps), (
                "Unsupported APT step layout"
            )
        jobs[match[1]] = {"steps": steps}
    # This is an intentionally narrow authored-step contract. Native actionlint
    # separately parses the complete YAML; this helper is not a YAML parser.
    return {"jobs": jobs}


def test_actual_signed_runner_acquisition_policy():
    """The real TShark job must keep signed source admission before its unchanged package consumer."""
    validate_jobs(workflow())


@pytest.mark.parametrize(
    "mutation", ["missing", "late", "signature", "remotehost", "retry", "ignoreauth"]
)
def test_actual_workflow_admission_mutants(mutation):
    """Real YAML mutations cannot silently remove ordering/keyring/host/no-retry constraints or weaken authentication."""
    doc = deepcopy(workflow())
    job = next(
        j
        for j in doc["jobs"].values()
        if any(
            "apt-get" in s.get("run", "") and "tshark" in s.get("run", "")
            for s in j.get("steps", [])
        )
    )
    steps = job["steps"]
    i = next(
        i
        for i, s in enumerate(steps)
        if s.get("name")
        == "Bound official mirror access on the disposable Ubuntu runner"
    )
    if mutation == "missing":
        steps.pop(i)
    elif mutation == "late":
        steps.append(steps.pop(i))
    elif mutation == "ignoreauth":
        target = next(s for s in steps if "apt-get" in s.get("run", ""))
        target["run"] += " --allow-unauthenticated"
    else:
        old, new = {
            "signature": ("^Signed-By:", "^Unverified:"),
            "remotehost": (
                "https://archive.ubuntu.com/ubuntu/",
                "https://foreign.invalid/ubuntu/",
            ),
            "retry": ('Acquire::Retries "0";', 'Acquire::Retries "3";'),
        }[mutation]
        steps[i]["run"] = steps[i]["run"].replace(old, new)
    with pytest.raises(AssertionError):
        validate_jobs(doc)


def test_real_tshark_installation_and_original_golden_oracle_remain_mandatory():
    """Actual source retains independent TShark vectors; acquisition cannot replace them with synthetic output."""
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert (
        source.count(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y tshark"
        )
        == 1
    )
    assert source.count("      - run: python scripts/native.py") == 1
    assert "continue-on-error" not in source
    assert "tshark" in (ROOT / "scripts/native.py").read_text(encoding="utf-8")
