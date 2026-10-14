"""Jason Stys: strict policy types, duplicates, intervals, roles and privacy/resource boundary tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: changed — line 65
# parameter: data — line 65
# parameter: field — line 65
# parameter: value — line 65
# variable: record — line 67
# definition: test_root_policy_reject — line 90
# parameter: field — line 90
# parameter: policy_data — line 90
# parameter: value — line 90
# definition: test_policy_syntax — line 109
# parameter: data — line 109
# definition: test_asset_reject — line 128
# parameter: field — line 128
# parameter: policy_data — line 128
# parameter: value — line 128
# variable: record — line 130
# definition: test_policy_relationships — line 136
# parameter: policy_data — line 136
# variable: baseline — line 138
# variable: mutations — line 139
# variable: duplicate — line 140
# variable: endpoint — line 143
# variable: field — line 146
# variable: value — line 146
# variable: data — line 153
# variable: field — line 158
# variable: value — line 158
# variable: data — line 164
# variable: data — line 169
# definition: test_address_reject — line 177
# parameter: value — line 177
# definition: test_helpers — line 183
# parameter: config — line 183
# parameter: policy_data — line 183
# parameter: tmp_path — line 183
# variable: path — line 200
# variable: limit — line 203
# definition: test_policy_fuzz — line 213
# parameter: data — line 213
# END CODE MAP

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from otmon.contracts import (
    Policy,
    Rejected,
    canonical,
    clients,
    integer,
    ipv4,
    policy,
    read_file,
    sha,
)


def changed(data: bytes, field: str, value: object) -> bytes:
    """Mutate one root policy field independently for invalid-input tests."""
    record = json.loads(data)
    record[field] = value
    return canonical(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("site", "Bad"),
        ("site", None),
        ("service_port", 0),
        ("service_port", True),
        ("rate_limit", 1001),
        ("rate_window_ms", -1),
        ("response_timeout_ms", 1.1),
        ("assets", []),
        ("assets", {}),
        ("maintenance", {}),
        ("maintenance", [{}] * 65),
    ],
)
def test_root_policy_reject(field: str, value: object, policy_data: bytes) -> None:
    """Reject wrong types, unsupported schema and excessive cardinality."""
    with pytest.raises(Rejected):
        policy(changed(policy_data, field, value))


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b"{}",
        b"{",
        b"\xff",
        b'{"schema":1,"schema":2}',
        b"x" * 65537,
        b"[" * 2000,
    ],
    ids=["list", "missing", "syntax", "encoding", "duplicate", "size", "depth"],
)
def test_policy_syntax(data: bytes) -> None:
    """Normalize malformed JSON and resource attacks to fixed rejection messages."""
    with pytest.raises(Rejected):
        policy(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "BAD"),
        ("unit", 256),
        ("ip", "host.local"),
        ("readers", [None]),
        ("readers", ["192.0.2.30"] * 2),
        ("writers", []),
        ("registers", []),
        ("registers", [{}]),
    ],
)
def test_asset_reject(field: str, value: object, policy_data: bytes) -> None:
    """Invalid asset roles/names/IPs or maintenance referring to a removed writer fail closed."""
    record = json.loads(policy_data)
    record["assets"][0][field] = value
    with pytest.raises(Rejected):
        policy(canonical(record))


def test_policy_relationships(policy_data: bytes) -> None:
    """Reject duplicated endpoints/names, overlapping registers and incoherent maintenance windows."""
    baseline = json.loads(policy_data)
    mutations = []
    duplicate = json.loads(policy_data)
    duplicate["assets"].append(dict(duplicate["assets"][0]))
    mutations.append(duplicate)
    endpoint = json.loads(policy_data)
    endpoint["assets"].append({**endpoint["assets"][0], "name": "other"})
    mutations.append(endpoint)
    for field, value in [
        ("start", True),
        ("end", 90),
        ("writable", 1),
        ("minimum", 2000),
        ("start", 101),
    ]:
        data = json.loads(policy_data)
        data["assets"][0]["registers"][1 if field == "start" and value == 101 else 0][
            field
        ] = value
        mutations.append(data)
    for field, value in [
        ("asset", "unknown"),
        ("client", "192.0.2.99"),
        ("start_ms", True),
        ("end_ms", 0),
    ]:
        data = json.loads(policy_data)
        data["maintenance"][0][field] = value
        mutations.append(data)
    baseline["extra"] = 1
    mutations.append(baseline)
    for data in mutations:
        with pytest.raises(Rejected):
            policy(canonical(data))


@pytest.mark.parametrize(
    "value", [None, "0.0.0.0", "224.0.0.1", "192.000.2.1", "999.1.1.1", "::1"]
)
def test_address_reject(value: object) -> None:
    """Allow unicast literal labels only; never DNS, multicast or ambiguous normalization."""
    with pytest.raises(Rejected):
        ipv4(value)


def test_helpers(tmp_path: Path, config: Policy, policy_data: bytes) -> None:
    """Exercise canonical identity, exact numeric bounds and bounded/link-free local file reads."""
    assert integer(0, 0, 1) and not integer(True, 0, 1)
    assert clients([]) == ()
    with pytest.raises(Rejected):
        clients({})
    with pytest.raises(Rejected):
        clients(["192.0.2.1"] * 33)
    assert ipv4("192.0.2.1") == "192.0.2.1"
    assert (
        config.digest
        == policy(json.dumps(json.loads(policy_data), indent=4).encode()).digest
    )
    assert (
        sha(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    path = tmp_path / "safe.txt"
    path.write_bytes(b"safe")
    assert read_file(path, 4) == b"safe"
    for limit in (3, -2, True):
        with pytest.raises(Rejected):
            read_file(path, limit)
    with patch.object(Path, "is_junction", return_value=True):
        with pytest.raises(Rejected):
            read_file(path, 4)


@given(st.binary(max_size=2048))
@settings(max_examples=100, deadline=None)
def test_policy_fuzz(data: bytes) -> None:
    """Bounded random JSON bytes always yield an explicit safe policy or a controlled failure."""
    try:
        policy(data)
    except Rejected:
        pass
