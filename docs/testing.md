# Test strategy and acceptance plan

Created by Jason Stys. Threat-driven unit/property/integration layers and independent oracles.

- Contracts: strict JSON schema/types, duplicates, sizes, unicast literal labels, unique asset pairs, role/window scope and nonoverlapping register intervals.
- Protocol: manually encoded hex vectors, quantity 125/123 boundaries, MBAP/PDU sizes, register address overflow, exact response byte counts and exceptions.
- Capture: four PCAP formats, timestamp order, length/snaplen limits, VLAN, malformed/unsupported layers, record truncation and explicit visibility counters.
- Transport: observed SYN/SYN-ACK, split/coalesced ADUs, verified duplicate/partial overlaps, conflicts, gap poisoning, sequence wrap, FIN/RST/restarts and flow/buffer caps.
- Monitor: exact independently written scenario findings, no-alert baselines, maintenance cannot hide unsafe/unauthorized writes, rate-window rearm, pending/frame/alert caps, response mismatch recovery and two-connection reset isolation.
- Evidence/CLI: real file/JSON/HTML/SQLite lifecycle, idempotent indexed lookup, conflict rollback, safe escaping/CSP, overwrite refusal, normalized IO/database errors and module execution.
- Properties: 100 random policy/capture cases, 150 random ADU/direction cases, 100 structured read-quantity/address cases; controlled rejection and no code/network execution.
- Independent native: seven manually stated wire-field vector cases, 16 ADUs, compare both TShark offline dissection and lab against expected transaction/unit/base-function values. Header-intact segmented messages are included. Original arbitrary-header splitting remains a strict application scenario and is separately recorded as a compatibility probe: Ubuntu TShark 4.2.2's entry point checks eight bytes before invoking MBAP reassembly.
- CI: Linux 3.12/3.14, Windows 3.14, macOS Intel 3.14; ruff, mypy, >=95% combined statement/branch coverage over every runtime module, exact header/file maps, privacy/passive guards, full-graph pip audit, Gitleaks, actionlint and security-extended CodeQL.

100% measured coverage, if reported, is not exhaustive branch-expression combinations, arbitrary TCP/plant behavior or security proof. TShark comparison covers selected wire fields, not a full conformance certification or all detection rules.

```text
python -m pytest --cov=otmon --cov-report=term-missing:skip-covered
python -m ruff check .
python -m ruff format --check .
python -m mypy
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
python -m pip_audit -r requirements-dev.lock --disable-pip --no-deps
```

Native TShark is installed only on a disposable GitHub Ubuntu runner through signed distro packages and used with explicit -r. Its actual version is recorded; no local Wireshark/capture-driver installation is required. No CI artifact upload/cache steps.
