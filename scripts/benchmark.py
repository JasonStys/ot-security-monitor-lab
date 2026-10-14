"""Jason Stys: bounded synthetic passive-monitor benchmark, not an industrial-network throughput guarantee."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 29
# definition: main — line 32
# variable: conversation — line 34
# variable: transaction — line 35
# variable: data — line 38
# variable: config — line 39
# variable: warmup — line 40
# variable: timings — line 42
# variable: _ — line 44
# variable: start — line 45
# variable: report — line 46
# variable: _ — line 48
# variable: peak — line 48
# END CODE MAP

import json
import platform
import statistics
import time
import tracemalloc
from pathlib import Path

from examples.scenarios import Conversation, read_request, read_response
from otmon.contracts import policy
from otmon.monitor import analyze

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Measure 15 complete analyses of 1000 captured read/response pairs with known fidelity."""
    conversation = Conversation()
    for transaction in range(1000):
        conversation.add(read_request(transaction))
        conversation.add(read_response(transaction), response=True)
    data = conversation.bytes()
    config = policy((ROOT / "examples/policy.json").read_bytes())
    warmup = analyze(data, config)
    assert warmup["statistics"]["matched_responses"] == 1000
    timings = []
    tracemalloc.start()
    for _ in range(15):
        start = time.perf_counter_ns()
        report = analyze(data, config)
        timings.append((time.perf_counter_ns() - start) / 1e6)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                scope="synthetic offline 1000 Modbus transaction analysis",
                python=platform.python_version(),
                samples=15,
                capture_bytes=len(data),
                capture_packets=report["capture"]["records"],
                decoded_adus=len(report["frames"]),
                matched_responses=report["statistics"]["matched_responses"],
                median_ms=statistics.median(timings),
                python_peak_bytes=peak,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
