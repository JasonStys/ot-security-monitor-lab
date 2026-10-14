# Architecture and ADR 001 — passive OT assurance

Created by Jason Stys. Accepted for an authorized offline portfolio lab, 2026-10-14.

## Context and decision

OT availability/process safety constraints make active device testing inappropriate for this lab. Choose offline packet parsing and bounded explainable rules, not network polling, opaque attack classification or automatic enforcement.

```text
Approved local PCAP -> bounded Ethernet/IPv4/TCP import -> conservative TCP streams -> validated Modbus ADUs
Reviewed policy -> asset/register/window/rate baselines -> exact request/response correlation -> analyst findings
Findings + fidelity statistics + input/policy hashes -> atomic idempotent SQLite -> JSON/inert HTML
Independent synthetic expectations + native TShark -> actual CI evidence (not self-derived assertions)
```

## Options/trade-offs

| Decision | Why / consequence |
| --- | --- |
| Standard-library Python | Typed bounded parsing/state is readable and portable with no third-party runtime graph; not a line-rate sensor. |
| SQL/SQLite | Transactional idempotency and indexed analyst lookup without a server; local owner ACLs/encryption remain external. |
| Escaped script-free HTML | Portable browser report with no remote dependencies/scripts/ads/telemetry; not an interactive hosted dashboard or authenticated service. |
| Small exact protocol/capture profile | Clear correctness/fidelity boundaries; intentionally no IPv6, pcapng, double VLAN, IP-fragment/out-of-order reassembly, TLS or other OT protocols. |
| Conservative sequence state | Verify retransmitted overlap bytes; stop guessing after loss/conflict. Requires observed SYN and bounded history; visibility gaps reduce detection coverage. |
| Explicit baseline rules | Fixed reasons and independent manual oracles; no AI confidence claims, authenticated-IP assumption or inferred device safety. |
| TShark as independent oracle | Compare manually written wire-field vectors with a mature native dissector, always offline -r; not merely round-trip tests of our own encoder. |

## Boundaries and failure behavior

External analysis entry point is analyze(capture_bytes, validated_policy). CLI reads bounded ordinary files, creates a new private output folder and refuses overwrites. Lower-level dataclasses/state helpers are typed internal interfaces, not arbitrary unvalidated network services.

Capture format errors/order/caps fail the analysis rather than publish a partial successful result. Unsupported packet layers produce explicit counters. Stream gaps/conflicts poison that direction until a new SYN. FIN closes directional state, RST/new client SYN invalidates only that connection's pending requests. Bounded state is never silently evicted.

Response correlation is scoped to full client/server addresses/ports + transaction, then unit/function/quantity/echo. Mismatches leave the real request pending. A matched read response uses the captured request address; orphan values are not guessed. EOF unresolved requests are visibility notes, not invented future timeouts.
