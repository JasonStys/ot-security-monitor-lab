"""Jason Stys: synthetic policy and capture fixtures, no private OT/network data."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: config — line 15
# definition: policy_data — line 23
# END CODE MAP

from pathlib import Path

import pytest

from otmon.contracts import Policy, policy


@pytest.fixture
def config() -> Policy:
    """Load only the committed synthetic RFC5737-address policy."""
    return policy(
        (Path(__file__).resolve().parents[1] / "examples/policy.json").read_bytes()
    )


@pytest.fixture
def policy_data() -> bytes:
    """Supply source JSON for strict-shape mutation tests."""
    return (Path(__file__).resolve().parents[1] / "examples/policy.json").read_bytes()
