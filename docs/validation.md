# Actual validation results

Created by Jason Stys, 2026-10-14.

Local Windows Python 3.14.6 initially: 129 tests passed, 100% measured combined runtime coverage (553 statements, 164 branches), ruff and strict mypy pass. All 26 initial manually stated synthetic scenario oracles matched. One additional header-intact segmentation scenario was added during independent-oracle debugging; original arbitrary-header splitting remains required. SQLite replay/conflict/escaping/CLI integration is exercised. No live device was contacted.

Remote acceptance is pending actual cross-platform/native/security/CodeQL runs. This document will be updated with real immutable source/run/job references and public synthetic reports. No fabricated independent TShark or remote pass is claimed.
