"""Jason Stys: explicit offline PCAP analysis CLI, private output and no active capture/scanning interfaces."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 21
# parameter: argv — line 21
# variable: parser — line 23
# variable: args — line 34
# variable: report — line 36
# variable: identity — line 39
# END CODE MAP

import argparse
import json
import sqlite3
from pathlib import Path

from otmon.contracts import MAX_CAPTURE, Rejected, policy, read_file
from otmon.evidence import export
from otmon.monitor import analyze


def main(argv: list[str] | None = None) -> int:
    """Analyze one approved local capture and policy; print safe counts/identity or fixed error."""
    parser = argparse.ArgumentParser(
        description="Passive offline OT Security Monitor Lab — created by Jason Stys"
    )
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="New private output directory; never a public source/data folder.",
    )
    args = parser.parse_args(argv)
    try:
        report = analyze(
            read_file(args.pcap, MAX_CAPTURE), policy(read_file(args.policy, 65536))
        )
        identity = export(args.out, report)
        print(
            json.dumps(
                dict(
                    author="Jason Stys",
                    ok=True,
                    analysis_id=identity,
                    records=report["capture"]["records"],
                    decoded_frames=len(report["frames"]),
                    findings=len(report["alerts"]),
                ),
                sort_keys=True,
            )
        )
        return 0
    except (Rejected, OSError, sqlite3.Error) as error:
        print(
            json.dumps(
                dict(
                    author="Jason Stys",
                    ok=False,
                    error=str(error)
                    if isinstance(error, Rejected)
                    else "local filesystem operation failed",
                )
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
