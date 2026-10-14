"""Jason Stys: offline independent TShark golden-vector agreement; no live capture, device access or sockets."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 55
# variable: GOLDEN — line 56
# definition: command — line 67
# parameter: argv — line 67
# definition: rows — line 74
# parameter: text — line 74
# variable: result — line 76
# variable: line — line 77
# variable: columns — line 78
# variable: values — line 83
# variable: value — line 86
# variable: column — line 88
# variable: column — line 90
# variable: function — line 92
# variable: transaction — line 92
# variable: unit — line 92
# definition: main — line 97
# variable: parser — line 99
# variable: args — line 101
# variable: config — line 103
# variable: samples — line 104
# variable: version — line 105
# variable: results — line 106
# variable: expected — line 107
# variable: name — line 107
# variable: _ — line 108
# variable: data — line 108
# variable: path — line 109
# variable: decoded — line 111
# variable: model — line 136
# variable: frame — line 138
# variable: report — line 147
# variable: result — line 154
# variable: _ — line 159
# variable: split_data — line 159
# variable: split_path — line 160
# variable: split_native — line 162
# variable: split_expected — line 187
# variable: split_lab — line 188
# variable: frame — line 190
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
    "header-intact-segmented-poll": [[1, 1, 3], [1, 1, 3]],
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
    version = command(["tshark", "--version"]).splitlines()[0]
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
        tshark_version=version,
        cases=len(results),
        matched=len(results),
        total_adus=sum(len(result["expected"]) for result in results),
        offline_read_file_only=True,
        results=results,
    )
    # Keep arbitrary-header split application tests; document the older native entry-point limitation separately.
    split_data, _ = samples["segmented-poll"]
    split_path = args.out / "partial-header-probe.pcap"
    split_path.write_bytes(split_data)
    split_native = rows(
        command(
            [
                "tshark",
                "-n",
                "-2",
                "-r",
                str(split_path),
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
    split_expected = [[1, 1, 3], [1, 1, 3]]
    split_lab = [
        [frame["transaction"], frame["unit"], frame["function"]]
        for frame in analyze(split_data, config)["frames"]
    ]
    if split_lab != split_expected:
        raise AssertionError("lab failed arbitrary MBAP-header segmentation")
    report["partial_header_compatibility_probe"] = dict(
        expected=split_expected,
        lab=split_lab,
        tshark=split_native,
        native_complete=split_native == split_expected,
        outside_full_agreement_case_count=True,
        explanation="TShark 4.2.2 checks 8 available bytes before MBAP reassembly; lab tests retain arbitrary header segmentation.",
        upstream_source="https://github.com/wireshark/wireshark/blob/wireshark-4.2.2/epan/dissectors/packet-mbtcp.c",
    )
    (args.out / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
