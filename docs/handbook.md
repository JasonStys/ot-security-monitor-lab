# OT Security Monitor Lab handbook

By Jason Stys.

Report expected-peer successful-read address coverage with separate function codes, interval unions, absent assets and capture gaps.

Report expected-peer successful-read address coverage with separate function codes, interval unions, absent assets and capture gaps.

Makes passive monitoring coverage auditable without contacting devices or treating unobserved activity as safe.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [review](review.md)
- [runbook](runbook.md)
- [usage](usage.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`88a34d59e7433aeba3e47066840274666fa7f8c3`](https://github.com/JasonStys/ot-security-monitor-lab/tree/88a34d59e7433aeba3e47066840274666fa7f8c3). The observed functional workflow baseline is `88a34d59e7433aeba3e47066840274666fa7f8c3`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/read-coverage-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/ot-security-monitor-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Passive capture review only; no new wire-function support, active polling or device access is supplied.
- Generic existing baselines are shown independently per address space; no polling expectation is invented.
- Unobserved addresses are capture gaps, not failed devices, security passes or safety proof. IP labels do not establish device identity.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
