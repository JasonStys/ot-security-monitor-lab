# Coding and documentation conventions

Created by Jason Stys. Self-documentation starts with domain names, typed contracts and fixed explicit limits; comments explain trust boundaries and surprising protocol/failure semantics.

Use Python for bounded parsing/correlation and SQL for transactional evidence. Runtime is standard-library only, separated into strict contracts, protocol, capture, transport, monitor, evidence and CLI. HTML is generated inert/escaped, not a JavaScript-heavy UI. No unused language layering, generic submitted-code execution, shell strings or magic silent repairs.

Every authored Python module has a purpose header; functions/classes have descriptions and meaningful typed parameters. scripts/code_map.py generates exact physical definition/parameter/store-variable/attribute locations with Python AST, never executing source. SQL/workflow indexes are lexical, not AST guarantees. Format first, regenerate maps, stage reviewed files, generate complete README file guide, run checks and git diff --check. Generated locks/data have explicit purposes in the file guide rather than invalid JSON comments.

No plaintext secrets, real capture/policy data or local database/report outputs in source. Privacy checks and Gitleaks complement human review. Deterministic analysis IDs include engine semantics/version; do not update logic against an existing evidence store without versioning. Fixed errors avoid printing private paths/data on rejection. Tests assert exact independent outcomes, not merely one positive hit.

Use primary official protocol/security/tool docs, specify interpretation/coverage gaps, measure real performance and never present alerts as automatic physical-safety or compliance proof.
