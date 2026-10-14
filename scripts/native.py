"""Jason Stys: offline independent TShark golden-vector agreement; no live capture, device access or sockets."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 47
# variable: GOLDEN — line 48
# definition: command — line 59
# parameter: argv — line 59
# definition: rows — line 66
# parameter: text — line 66
# variable: result — line 68
# variable: line — line 69
# variable: columns — line 70
# variable: values — line 75
# variable: value — line 78
# variable: column — line 80
# variable: column — line 82
# variable: function — line 84
# variable: transaction — line 84
# variable: unit — line 84
# definition: main — line 89
# variable: parser — line 91
# variable: args — line 93
# variable: config — line 95
# variable: samples — line 96
# variable: results — line 97
# variable: expected — line 98
# variable: name — line 98
# variable: _ — line 99
# variable: data — line 99
# variable: path — line 100
# variable: decoded — line 102
# variable: model — line 127
# variable: frame — line 129
# variable: report — line 138
# variable: result — line 145
# END CODE MAP

import argparse
import json
import platform
import subprocess
from pathlib import Path

from examples.scenarios import scenarios
from otmon.contracts import policy
from otmon.monitor import analyze

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = {
    "normal-poll": [[1, 1, 3], [1, 1, 3]],
    "segmented-poll": [[1, 1, 3], [1, 1, 3]],
    "coalesced-polls": [[1, 1, 3], [2, 1, 4], [1, 1, 3], [2, 1, 4]],
    "vlan-poll": [[1, 1, 3], [1, 1, 3]],
    "approved-write-6": [[1, 1, 6], [1, 1, 6]],
    "approved-write-16": [[1, 1, 16], [1, 1, 16]],
    "device-exception": [[1, 1, 3], [1, 1, 3]],
}


def command(argv: list[str]) -> str:
    """Run fixed offline dissection/version argv with no shell/live interface and a strict timeout."""
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=60
    ).stdout


def rows(text: str) -> list[list[int]]:
    """Expand coalesced field occurrences into ordered transaction/unit/base-function vectors."""
    result = []
    for line in text.splitlines():
        columns = line.split("|")
        if len(columns) != 3 or not all(columns):
            raise AssertionError(
                "independent dissector returned missing/misaligned fields"
            )
        values = [
            [
                int(value, 16 if value.startswith("0x") else 10)
                for value in column.split(",")
            ]
            for column in columns
        ]
        if len({len(column) for column in values}) != 1:
            raise AssertionError("independent dissector occurrence mismatch")
        for transaction, unit, function in zip(*values, strict=True):
            result.append([transaction, unit, function & 127])
    return result


def main() -> None:
    """Require both the lab and an independent native dissector to match manually written wire-field oracles."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "out/native")
    args = parser.parse_args()
    args.out.mkdir(parents=True)
    config = policy((ROOT / "examples/policy.json").read_bytes())
    samples = scenarios()
    results = []
    for name, expected in GOLDEN.items():
        data, _ = samples[name]
        path = args.out / (name + ".pcap")
        path.write_bytes(data)
        decoded = rows(
            command(
                [
                    "tshark",
                    "-n",
                    "-2",
                    "-r",
                    str(path),
                    "-o",
                    "tcp.desegment_tcp_streams:TRUE",
                    "-Y",
                    "modbus",
                    "-T",
                    "fields",
                    "-E",
                    "separator=|",
                    "-e",
                    "mbtcp.trans_id",
                    "-e",
                    "mbtcp.unit_id",
                    "-e",
                    "modbus.func_code",
                ]
            )
        )
        model = [
            [frame["transaction"], frame["unit"], frame["function"]]
            for frame in analyze(data, config)["frames"]
        ]
        if decoded != expected or model != expected:
            raise AssertionError(
                f"independent wire-field oracle mismatch: {name}: {decoded} vs {model} vs {expected}"
            )
        results.append(
            dict(case=name, expected=expected, tshark=decoded, lab=model, matched=True)
        )
    report = dict(
        author="Jason Stys",
        scope="actual offline native TShark golden-vector dissection",
        python=platform.python_version(),
        tshark_version=command(["tshark", "--version"]).splitlines()[0],
        cases=len(results),
        matched=len(results),
        total_adus=sum(len(result["expected"]) for result in results),
        offline_read_file_only=True,
        results=results,
    )
    (args.out / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
