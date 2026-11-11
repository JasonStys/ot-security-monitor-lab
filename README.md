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

## Native Windows workbench

**OT Security Monitor Workbench 1.1.0** turns the existing offline engine into a complete one-file graphical application: real supported file/policy settings, meaningful evidence views, literal search/full details, bounded durable history, exact export, explicit retention controls and normal retained-worker close. Analyze authorized classic-PCAP files and chosen asset/register/maintenance policies through the original conservative TCP/Modbus engine. Inspect original detections, request/response frames, exact matched reads, separate FC03/FC04 intervals and unfiltered capture caveats.

Nine prepared/acceptance workflows run inside this same application. They are optional inputs, not a separate demo or substitute for authorized files. The portable includes patched Python/Tk and fixed resources; no separate development tools or Docker are needed to use it. The existing CLI and real native assurance lanes remain available. [Application guide](docs/native-workbench.md) · [Actual dated validation](docs/reports/native-workbench-2026-11-11.md). Source/build, hosted validation, release publication and PC installation are distinct operations; this source change does not claim an unrun later release.

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

## Review passive asset/register observation coverage

Every new CLI/SQLite/JSON/HTML report includes `read_coverage`: all configured server/unit assets, separate FC03 holding-register and FC04 input-register spaces, observed and unobserved baseline intervals, excluded unexpected-peer reads, and exact successful request/response packet/time/hash references. The UI has a dedicated coverage panel. No extra polling or device connection is performed.

Only a successful exact correlated read from an expected IP peer contributes. Exception, mismatched, orphaned, unresolved or write traffic cannot fill read-observation gaps. Overlaps/retransmissions do not double-count addresses; out-of-baseline requests retain their original alert and only their overlap counts. Absent assets remain explicit. Original capture and correlation caveats stay visible alongside coverage.

An unobserved range is **not** a failed device, mandatory polling requirement, security pass or physical-process safety verdict. Existing generic baseline intervals are shown independently in each register space; the tool does not assume every space/range must be polled. Review the actual engineering register map/capture vantage with an authorized control engineer. IP peer labels are observations, not authentication.

## Documentation

[Architecture/ADR](docs/architecture.md) · [Contracts](docs/contracts.md) · [Detection catalog](docs/detections.md) · [Usage](docs/usage.md) · [Runbook](docs/runbook.md) · [Security](docs/security.md) · [Testing](docs/testing.md) · [Actual validation](docs/validation.md) · [Performance](docs/performance.md) · [Coding](docs/coding.md) · [Research](docs/research.md).

Every authored source has purpose/function/class descriptions and CI-checked exact physical definition/parameter/variable maps (Python AST; SQL/workflow lexical indexes). The complete file guide below covers the exact tracked set, including each code, test, workflow, documentation and report file.

Earlier baseline evidence: 130 tests on every OS, 100% runtime coverage, 27 exact synthetic scenario outcomes and 16 independently dissected wire-vector ADUs. [Actual results](docs/validation.md) disclose the separate older TShark partial-header limitation. [Download/inspect the inert synthetic HTML report](docs/reports/example.html); no hosted site or real plant data is included.

## Complete file guide

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform passive monitoring, independent offline TShark and audited tools; zero artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude captured traffic, local databases, reports, credentials and tool caches. |
| [CHANGELOG.md](CHANGELOG.md) | Changelog. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | OT Security Monitor Lab. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR 001 — passive OT assurance. |
| [docs/coding.md](docs/coding.md) | Coding and documentation conventions. |
| [docs/contracts.md](docs/contracts.md) | Input, state and evidence contracts. |
| [docs/detections.md](docs/detections.md) | Detection catalog and interpretation. |
| [docs/handbook.md](docs/handbook.md) | OT Security Monitor Lab handbook. |
| [docs/native-workbench.md](docs/native-workbench.md) | OT Security Monitor Workbench: Windows application. |
| [docs/performance.md](docs/performance.md) | Complexity and benchmark methodology. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded capture analysis and Python allocation peak. |
| [docs/reports/ci.json](docs/reports/ci.json) | Actual immutable accepted-source CI snapshot. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Actual independent synthetic scenario detection/capture-integrity outcomes. |
| [docs/reports/example.html](docs/reports/example.html) | Generated inert public synthetic analyst report; no real capture data. |
| [docs/reports/installed-windows-1.1.0-2026-11-11.md](docs/reports/installed-windows-1.1.0-2026-11-11.md) | Installed Windows 1.1.0 validation — 11 November 2026. |
| [docs/reports/native-workbench-2026-11-11.md](docs/reports/native-workbench-2026-11-11.md) | Native offline workbench validation — 2026-11-11. |
| [docs/reports/native.json](docs/reports/native.json) | Actual independent TShark dissection of synthetic segmented Modbus traffic. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed source-bound Word guide with dated validation observations and practical limits. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact publication hashes, reviewed page identities and source/evidence baselines. |
| [docs/reports/read-coverage-2026-11-09.md](docs/reports/read-coverage-2026-11-09.md) | Passive read observation coverage validation — November 9, 2026. |
| [docs/reports/tshark-runner-acquisition-2026-11-11.md](docs/reports/tshark-runner-acquisition-2026-11-11.md) | Independent TShark acquisition — 11 November 2026. |
| [docs/reports/windows-application-guide-1.1.0.docx](docs/reports/windows-application-guide-1.1.0.docx) | Current illustrated installed workbench guide with actual screenshots, exact source and measured limits. |
| [docs/reports/windows-application-guide-1.1.0.json](docs/reports/windows-application-guide-1.1.0.json) | Current Word, screenshot, immutable source and reviewed-page digests. |
| [docs/research.md](docs/research.md) | Primary-source research. |
| [docs/review.md](docs/review.md) | Implementation review and debugging record. |
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
| [otmon/coverage.py](otmon/coverage.py) | Jason Stys: passive matched-read observation coverage, preserving asset/unit and register-space boundaries. |
| [otmon/desktop.py](otmon/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [otmon/desktop\_io.py](otmon/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [otmon/desktop\_project.py](otmon/desktop_project.py) | Actual passive PCAP, policy and register-observation workflows for the native workbench. Jason Stys. |
| [otmon/desktop\_state.py](otmon/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [otmon/evidence.py](otmon/evidence.py) | Jason Stys: parameterized idempotent SQLite evidence and script-free escaped HTML report exports. |
| [otmon/inputs.py](otmon/inputs.py) | Bounded stable ordinary-file reads and streaming tool hashes for offline identity inputs. Jason Stys. |
| [otmon/monitor.py](otmon/monitor.py) | Jason Stys: passive explainable OT detections, bounded correlation and explicit capture visibility limits. |
| [otmon/protocol.py](otmon/protocol.py) | Jason Stys: bounded Modbus/TCP ADU decoder for FC03/04/06/16 and explicit unsupported-code visibility. |
| [otmon/transport.py](otmon/transport.py) | Jason Stys: conservative bounded TCP sequence tracking and Modbus boundary extraction, no active sockets. |
| [pyproject.toml](pyproject.toml) | Jason Stys: zero-dependency passive runtime, strict types and combined statement/branch coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: hash-locked tests, properties, typing, formatting and independent dependency/security tooling. |
| [requirements-dev.lock](requirements-dev.lock) | Universal complete hash-locked test and security-tool graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked portable freezing tools, separate from zero-dependency runtime. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: bounded synthetic passive-monitor benchmark, not an industrial-network throughput guarantee. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/evaluate.py](scripts/evaluate.py) | Jason Stys: exact independent scenario-oracle evaluation and private local analyst-report export. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native.py](scripts/native.py) | Jason Stys: offline independent TShark golden-vector agreement; no live capture, device access or sockets. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Actual final portable widgets/core/native-window acceptance with independent oracles. Jason Stys. |
| [scripts/native\_common.py](scripts/native_common.py) | Actual patched Python/Tcl/Tk/PyInstaller runtime notices and authored portable icon. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/preview.py](scripts/preview.py) | Jason Stys: temporary loopback-only inert synthetic HTML preview for visual QA, not a hosted OT service. |
| [scripts/publication\_text.py](scripts/publication_text.py) | Jason Stys: inspect only named reviewed Office editions without hiding their XML. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-file privacy, passive-runtime imports and zero-artifact/cache workflow guards. |
| [sql/evidence.sql](sql/evidence.sql) | Jason Stys: atomic offline analysis evidence, keyed idempotency and indexed analyst rule lookup. |
| [tests/conftest.py](tests/conftest.py) | Jason Stys: synthetic policy and capture fixtures, no private OT/network data. |
| [tests/test\_capture.py](tests/test_capture.py) | Jason Stys: classic PCAP endianness/resolution, truncation, layer visibility and adversarial length fuzzing. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict policy types, duplicates, intervals, roles and privacy/resource boundary tests. |
| [tests/test\_coverage.py](tests/test_coverage.py) | Jason Stys: independent successful-read coverage and incomplete-observation regression oracles. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_io.py](tests/test_desktop_io.py) | Private state JSON and bounded descriptor-read boundary cases with actual file bytes. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Independent passive-capture GUI adapter oracles, threshold provenance and exact retained evidence. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_evidence\_cli.py](tests/test_evidence_cli.py) | Jason Stys: real CLI/export/SQLite lifecycle, idempotency/conflict rollback and inert report escaping. |
| [tests/test\_monitor.py](tests/test_monitor.py) | Jason Stys: bounded analyst-state, exact connection correlation, reset/maintenance and rate-boundary tests. |
| [tests/test\_native\_inputs.py](tests/test_native_inputs.py) | Actual same-descriptor input bounds and ownership-change cases for selected offline reports. Jason Stys. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_protocol.py](tests/test_protocol.py) | Jason Stys: independent hex/field protocol vectors, extreme quantities and structured/random fuzzing. |
| [tests/test\_publication\_text.py](tests/test_publication_text.py) | Jason Stys: actual Office ZIP fixtures retain text scanning and reject unknown content. |
| [tests/test\_runner\_network\_policy.py](tests/test_runner_network_policy.py) | Actual TShark-job policy mutants for signed disposable-runner acquisition. Jason Stys. |
| [tests/test\_scenarios.py](tests/test_scenarios.py) | Jason Stys: exact manual scenario oracles, including no-finding baselines and subtle visibility failures. |
| [tests/test\_transport.py](tests/test_transport.py) | Jason Stys: conservative TCP overlap/gap/SYN/FIN/reset/sequence-wrap and state-cap regressions. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.


## Current Windows application guide

The published **1.1.0** app has a [four-page illustrated guide](docs/reports/windows-application-guide-1.1.0.docx) with actual installed screenshots, a worked user journey, source excerpts and operating limits. Read the [installed validation report](docs/reports/installed-windows-1.1.0-2026-11-11.md) and [review manifest](docs/reports/windows-application-guide-1.1.0.json) for exact scope. Historical editions remain unchanged.

## Hosted TShark setup evidence

The [dated acquisition report](docs/reports/tshark-runner-acquisition-2026-11-11.md) distinguishes a failed signed-package download from an actual protocol/golden-vector failure. The original independent TShark gate remains mandatory.
