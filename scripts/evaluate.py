"""Jason Stys: exact independent scenario-oracle evaluation and private local analyst-report export."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 28
# definition: main — line 31
# variable: parser — line 33
# variable: args — line 35
# variable: config — line 37
# variable: results — line 38
# variable: data — line 39
# variable: expected — line 39
# variable: name — line 39
# variable: report — line 40
# variable: folder — line 45
# variable: identity — line 46
# variable: result — line 59
# END CODE MAP

import argparse
import json
import platform
from pathlib import Path

from examples.scenarios import scenarios
from otmon.contracts import policy
from otmon.evidence import export, store
from otmon.monitor import analyze

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Run all manually expected capture cases, fail on missing/extra findings and verify storage idempotency."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "out/evaluation")
    args = parser.parse_args()
    args.out.mkdir(parents=True)
    config = policy((ROOT / "examples/policy.json").read_bytes())
    results = []
    for name, (data, expected) in scenarios().items():
        report = analyze(data, config)
        if report["rule_counts"] != expected:
            raise AssertionError(
                f"scenario oracle mismatch: {name}: {report['rule_counts']} != {expected}"
            )
        folder = args.out / name
        identity = export(folder, report)
        assert store(folder / "evidence.sqlite", report) == identity
        (folder / "synthetic.pcap").write_bytes(data)
        results.append(
            dict(
                case=name,
                expected=expected,
                actual=report["rule_counts"],
                matched=True,
                frames=len(report["frames"]),
                capture_records=report["capture"]["records"],
            )
        )
    result = dict(
        author="Jason Stys",
        scope="independent synthetic OT capture-oracle evaluation",
        python=platform.python_version(),
        cases=len(results),
        matched=len(results),
        policy_sha256=config.digest,
        results=results,
        sqlite_replay_idempotent=True,
    )
    (args.out / "evaluation.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
