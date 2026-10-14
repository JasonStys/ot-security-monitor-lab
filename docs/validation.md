# Actual validation results

Created by Jason Stys, 2026-10-14.

Accepted implementation revision: **3169805dcf239b1f623fa53c039a5c1d588257d9**. [Validate run](https://github.com/JasonStys/ot-security-monitor-lab/actions/runs/38615665278): all six jobs passed. [CodeQL run](https://github.com/JasonStys/ot-security-monitor-lab/actions/runs/38615665327): Python security-extended analysis passed; zero open alerts.

| Actual check | Accepted result |
| --- | --- |
| Linux Python 3.12/3.14, Windows 3.14, macOS Intel 3.14 | 130 tests passed on each, no skipped tests. |
| All eight runtime modules | 100% combined coverage; 164 branches; 553 statement lines on 3.14, 556 on 3.12 (interpreter-dependent accounting), no exclusions. |
| Independent scenario evaluation | 27 exact manually expected cases matched, including no-finding baselines and original arbitrary header splitting. |
| Native TShark 4.2.2 | Seven strict wire-vector agreement cases, 16 ADUs; normal, header-intact segmentation, coalescing, VLAN, FC06/16 and exceptions. |
| Explicit native compatibility probe | Original partial-header fixture: lab two expected messages, TShark one; native_complete=false is recorded outside full-agreement counts. |
| Evidence/CLI | Real SQLite/JSON/HTML export, idempotent indexed lookup, conflict rejection, fixed errors, escaping/CSP and overwrite refusal tested. |
| Browser report QA | Three synthetic findings and guidance visible, Jason Stys attribution/contact, no scripts/external media, no-referrer. Temporary loopback preview stopped. |
| Quality/security | ruff, strict mypy, maps/file inventory, privacy/passive guards, full hash-locked pip audit, Gitleaks, actionlint and CodeQL passed. No known vulnerabilities in the locked Python graph. |
| Repo Actions storage | Zero artifacts/caches at acceptance; no upload/cache/CodeQL database-upload steps. |

Actual public synthetic evidence: [CI snapshot](reports/ci.json), [scenario evaluation](reports/evaluation.json), [native dissection/limitation](reports/native.json), [benchmark](reports/benchmark.json), [inert report example](reports/example.html). Reports reference immutable accepted source/run/job IDs, not a fabricated final-document self-hash. Latest-main jobs are checked again after this documentation commit.

Local Windows Python 3.14.6 also passed all 130 tests, 100% runtime coverage, strict quality/audit checks and all 27 scenario expectations. No devices, host network rules, Docker settings or live capture drivers were changed.

Initial [Validate run 38614854211](https://github.com/JasonStys/ot-security-monitor-lab/actions/runs/38614854211) failed only the independent native job on an arbitrary MBAP-header split. The official versioned TShark source revealed its eight-byte pre-reassembly admission check. All original strict application tests remain; an additional header-intact native fixture passes the original complete-message oracle, and the partial-header limitation is publicly recorded. This is a selected oracle coverage limit, not a full segmentation agreement claim. Failed history remains visible.

No test coverage result is exhaustive proof, physical process safety assurance, authenticated asset identity or compliance certification. Read [security](security.md), [testing scope](testing.md) and [review](review.md).
