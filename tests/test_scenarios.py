"""Jason Stys: exact manual scenario oracles, including no-finding baselines and subtle visibility failures."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CASES — line 21
# definition: test_manual_oracles — line 25
# parameter: config — line 25
# parameter: name — line 25
# variable: data — line 27
# variable: expected — line 27
# variable: report — line 28
# variable: alert — line 33
# definition: test_fidelity_and_correlation — line 37
# parameter: config — line 37
# END CODE MAP

import pytest

from examples.scenarios import scenarios
from otmon.contracts import Policy
from otmon.monitor import analyze

CASES = scenarios()


@pytest.mark.parametrize("name", list(CASES))
def test_manual_oracles(name: str, config: Policy) -> None:
    """Require exact expected findings, not simply at-least-one alert or derived golden results."""
    data, expected = CASES[name]
    report = analyze(data, config)
    assert report["rule_counts"] == expected
    assert report == analyze(data, config)
    assert all(
        alert["reason"] and alert["basis"] and alert["severity"]
        for alert in report["alerts"]
    )


def test_fidelity_and_correlation(config: Policy) -> None:
    """Verify retransmission deduplication, poisoned-stream visibility and mismatch recovery."""
    assert (
        analyze(CASES["verified-retransmission"][0], config)["statistics"][
            "verified_retransmissions"
        ]
        == 1
    )
    assert (
        analyze(CASES["tcp-gap"][0], config)["statistics"]["blocked_payload_packets"]
        == 1
    )
    assert (
        analyze(CASES["mismatch-then-valid"][0], config)["statistics"][
            "matched_responses"
        ]
        == 1
    )
    assert (
        "observed_timeout"
        not in analyze(CASES["capture-ended-request"][0], config)["rule_counts"]
    )
    assert (
        analyze(CASES["partial-adu-at-eof"][0], config)["statistics"][
            "eof_partial_adus"
        ]
        == 1
    )
