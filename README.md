# OT Security Monitor Lab

[![Validate](https://github.com/JasonStys/ot-security-monitor-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/ot-security-monitor-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/JasonStys/ot-security-monitor-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/ot-security-monitor-lab/actions/workflows/codeql.yml)

Created by **Jason Stys** — [GitHub/contact](https://github.com/JasonStys) · [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/).

A passive, offline Python/SQL portfolio lab for operational-technology security: bounded Modbus/TCP parsing, asset/register baselines, scoped maintenance, request/response correlation, explainable detections, and private SQLite/JSON/HTML evidence. It reads captured bytes; **it never connects to, scans, blocks or writes to an OT device**.

This is a documented learning/assurance lab, not a production IDS, universal industrial protocol parser, physical safety controller, authenticated asset inventory or compliance certification. Incomplete/unsupported captures are visible. A missing response, unusual source IP or exception is not automatically proof of attack.

## Features

| Feature | Behavior |
| --- | --- |
| Strict protocol profile | Exact MBAP, FC03/04 reads, FC06/16 writes and exception bounds; other functions are explicitly unsupported. |
| Passive capture import | Bounded classic PCAP, four endianness/resolution variants, Ethernet/one VLAN/IPv4/TCP; unsupported/truncated layers counted. |
| Conservative TCP fidelity | Observed SYN, split/coalesced ADUs, verified retransmissions/overlaps and sequence wrap; block ambiguous/gapped directions, report EOF partials. |
| Asset-aware detections | Unknown server/unit, unexpected peer, unauthorized/read-only writes, outside-baseline registers, raw value envelope and rolling poll bursts. |
| Scoped maintenance | Exact asset + writer + half-open time window. Never suppress unauthorized peer, read-only register or unsafe-value detections. |
| Correlation | Exact connection/transaction/unit/function, write echoes and read quantities; mismatches cannot consume valid pending requests. EOF vs elapsed-time timeout distinguished. |
| Explainable local evidence | Fixed reason/severity/basis, packet/time/flow/hash references; idempotent parameterized SQLite, JSON and inert escaped HTML. |
| Independent assurance | Hand-authored scenario oracles, property tests, cross-platform coverage/types/scans and separate native TShark wire-field checks. |

## Quick start

Python 3.12+; runtime uses only the standard library (SQLite 3.37+). Clone or download this repo; no Docker/admin/network-capture permission is needed.

From the repository root, set PYTHONPATH=. for scripts: PowerShell uses `$env:PYTHONPATH='.'`; Bash uses `export PYTHONPATH=.`.

```text
python -m otmon.cli --help
python scripts/evaluate.py --out out/demo-first
python -m otmon.cli --pcap out/demo-first/unknown-writer/synthetic.pcap --policy examples/policy.json --out out/analyst-first
```

For scripts, run from the repository root with `PYTHONPATH=.` (PowerShell: `$env:PYTHONPATH='.'`; Bash: `export PYTHONPATH=.`). Open `out/analyst-first/report.html` in your browser. That report has usage guidance, capture visibility and Jason Stys attribution/contact. Outputs refuse directory overwrites and remain under ignored `out/`.

For development:

```text
python -m venv .venv
# Activate .venv using your OS shell, then:
python -m pip install --require-hashes -r requirements-dev.lock
python -m pytest --cov=otmon --cov-report=term-missing:skip-covered
python -m mypy
python scripts/benchmark.py
```

All example captures are generated **in memory** from public documentation-range IPs; no real plant/customer data or executable traffic payloads are committed. The CLI also accepts an explicitly authorized local capture in the documented profile. Keep real captures/policies/results private and review [security](docs/security.md) before use.

## Documentation

[Architecture/ADR](docs/architecture.md) · [Contracts](docs/contracts.md) · [Detection catalog](docs/detections.md) · [Usage](docs/usage.md) · [Runbook](docs/runbook.md) · [Security](docs/security.md) · [Testing](docs/testing.md) · [Actual validation](docs/validation.md) · [Performance](docs/performance.md) · [Coding](docs/coding.md) · [Research](docs/research.md).

Every authored source has purpose/function/class descriptions and CI-checked exact physical definition/parameter/variable maps (Python AST; SQL/workflow lexical indexes). The complete file guide below covers the exact tracked set, including each code, test, workflow, documentation and report file.

## Complete file guide

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform passive monitoring, independent offline TShark and audited tools; zero artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude captured traffic, local databases, reports, credentials and tool caches. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | OT Security Monitor Lab. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR 001 — passive OT assurance. |
| [docs/coding.md](docs/coding.md) | Coding and documentation conventions. |
| [docs/contracts.md](docs/contracts.md) | Input, state and evidence contracts. |
| [docs/detections.md](docs/detections.md) | Detection catalog and interpretation. |
| [docs/performance.md](docs/performance.md) | Complexity and benchmark methodology. |
| [docs/research.md](docs/research.md) | Primary-source research. |
| [docs/runbook.md](docs/runbook.md) | Operational review and release runbook. |
| [docs/security.md](docs/security.md) | Security, safety and privacy boundaries. |
| [docs/testing.md](docs/testing.md) | Test strategy and acceptance plan. |
| [docs/usage.md](docs/usage.md) | Usage and analyst workflow. |
| [docs/validation.md](docs/validation.md) | Actual validation results. |
| [examples/\_\_init\_\_.py](examples/__init__.py) | Jason Stys: independent synthetic capture constructors, never active device traffic. |
| [examples/policy.json](examples/policy.json) | Synthetic water-treatment asset roles, register ranges and scoped maintenance. |
| [examples/scenarios.py](examples/scenarios.py) | Jason Stys: synthetic water-treatment PCAP scenarios with independent explicit expected rule counts. |
| [otmon/\_\_init\_\_.py](otmon/__init__.py) | OT Security Monitor Lab: passive bounded offline assurance, created by Jason Stys. |
| [otmon/capture.py](otmon/capture.py) | Jason Stys: bounded classic PCAP Ethernet/one-VLAN IPv4/TCP import; unsupported layers stay visible. |
| [otmon/cli.py](otmon/cli.py) | Jason Stys: explicit offline PCAP analysis CLI, private output and no active capture/scanning interfaces. |
| [otmon/contracts.py](otmon/contracts.py) | Jason Stys: strict bounded asset/register/maintenance policy and fixed-message input validation. |
| [otmon/evidence.py](otmon/evidence.py) | Jason Stys: parameterized idempotent SQLite evidence and script-free escaped HTML report exports. |
| [otmon/monitor.py](otmon/monitor.py) | Jason Stys: passive explainable OT detections, bounded correlation and explicit capture visibility limits. |
| [otmon/protocol.py](otmon/protocol.py) | Jason Stys: bounded Modbus/TCP ADU decoder for FC03/04/06/16 and explicit unsupported-code visibility. |
| [otmon/transport.py](otmon/transport.py) | Jason Stys: conservative bounded TCP sequence tracking and Modbus boundary extraction, no active sockets. |
| [pyproject.toml](pyproject.toml) | Jason Stys: zero-dependency passive runtime, strict types and combined statement/branch coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: hash-locked tests, properties, typing, formatting and independent dependency/security tooling. |
| [requirements-dev.lock](requirements-dev.lock) | Universal complete hash-locked test and security-tool graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: bounded synthetic passive-monitor benchmark, not an industrial-network throughput guarantee. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/evaluate.py](scripts/evaluate.py) | Jason Stys: exact independent scenario-oracle evaluation and private local analyst-report export. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native.py](scripts/native.py) | Jason Stys: offline independent TShark golden-vector agreement; no live capture, device access or sockets. |
| [scripts/preview.py](scripts/preview.py) | Jason Stys: temporary loopback-only inert synthetic HTML preview for visual QA, not a hosted OT service. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-file privacy, passive-runtime imports and zero-artifact/cache workflow guards. |
| [sql/evidence.sql](sql/evidence.sql) | Jason Stys: atomic offline analysis evidence, keyed idempotency and indexed analyst rule lookup. |
| [tests/conftest.py](tests/conftest.py) | Jason Stys: synthetic policy and capture fixtures, no private OT/network data. |
| [tests/test\_capture.py](tests/test_capture.py) | Jason Stys: classic PCAP endianness/resolution, truncation, layer visibility and adversarial length fuzzing. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict policy types, duplicates, intervals, roles and privacy/resource boundary tests. |
| [tests/test\_evidence\_cli.py](tests/test_evidence_cli.py) | Jason Stys: real CLI/export/SQLite lifecycle, idempotency/conflict rollback and inert report escaping. |
| [tests/test\_monitor.py](tests/test_monitor.py) | Jason Stys: bounded analyst-state, exact connection correlation, reset/maintenance and rate-boundary tests. |
| [tests/test\_protocol.py](tests/test_protocol.py) | Jason Stys: independent hex/field protocol vectors, extreme quantities and structured/random fuzzing. |
| [tests/test\_scenarios.py](tests/test_scenarios.py) | Jason Stys: exact manual scenario oracles, including no-finding baselines and subtle visibility failures. |
| [tests/test\_transport.py](tests/test_transport.py) | Jason Stys: conservative TCP overlap/gap/SYN/FIN/reset/sequence-wrap and state-cap regressions. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->
