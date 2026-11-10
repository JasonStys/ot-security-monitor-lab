# Documentation refresh — 2026-11-09

By Jason Stys.

This documentation-only edition describes source `88a34d59e7433aeba3e47066840274666fa7f8c3`. It does not change application behavior, accounts, private data, installers or published releases.

## Published editions and completed review

| File | Bytes | SHA-256 | Reviewed scope |
| --- | ---: | --- | --- |
| [project-guide.docx](project-guide.docx) | 43843 | `9ceb3bd067625db4895ef49012bb766899ec0dbe2943ffba81e74ba7f6324b3b` | 4 pages, each viewed individually |

Word review checked plain black titles, readable pagination, whole table rows, source references, practical limits and absence of clipping or overflow. Render receipts were matched to the current DOCX digest before approval.

## Evidence and change boundary

- Functional baseline: `88a34d59e7433aeba3e47066840274666fa7f8c3`.
- Workflow observation: `2026-11-10T05:25:40.628667+00:00`; exact run URLs and source identities remain in [publications.json](publications.json).
- Local document-package validation verifies exact copied bytes, Office ZIP integrity, approved page/tab identities and internal documentation links. Repository-specific documentation and source-policy commands are run separately and recorded in the integration handoff.
- Source/index metadata is regenerated using the repository’s existing tools. Existing privacy, security, coverage and workflow gates are retained.
- PR and later main workflows must pass independently. This record does not claim future or unrun integration CI success.

## Interpretation

The Word files document the cited source; dated source reports retain their original execution scope. A passing workflow is distinct from completed analysis with zero findings, and neither establishes production suitability. Checksums identify exact bytes, not a signature or publisher attestation.

Use the [handbook](../handbook.md) to choose usage, design, security and test documentation. Keep editable Markdown and reviewed editions together; do not replace historical measurements with undated claims.

## Documentation input handling and local checks

The existing tracked-source privacy scan now reads bounded XML and relationships from the exact reviewed Office edition paths; unknown binary names still fail strict UTF-8 handling. The reader opens each package once, checks its descriptor byte size, member identities and expansion budgets, and rejects encrypted, active or embedded payloads. Eight independent real-ZIP tests verify named editions, unknown files, malformed packages, invalid UTF-8 and bounded expansion. No Office content is executed.

The documentation integration passed 143 Python tests with 100% combined runtime statement/branch coverage (existing 95% floor), Ruff/format, strict mypy, exact source maps, full staged-file inventory and the original privacy/workflow contracts. These integration results are separate from the older functional measurements reproduced in the Word guide; exact-source hosted PR/main checks remain required.
