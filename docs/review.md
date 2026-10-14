# Implementation review and debugging record

Created by Jason Stys with AI-assisted implementation/review, 2026-10-14. Not an independent security audit or production OT deployment approval.

| Review finding | Resolution / evidence |
| --- | --- |
| Missing/unsupported capture data must not imply healthy devices | Explicit packet-layer counts, gap poisoning, EOF partial/unresolved statistics and visible analyst cautions; strict scenario oracles. |
| FIN without payload must close partial directional state | Handled control-only FIN and tested both complete/partial payload/control closure. |
| Reset must not clear another connection's pending requests | Exact flow/transaction scope; two-connection reset isolation regression. |
| Maintenance must not blanket-suppress unsafe activity | Exact asset/writer/time approval; unauthorized/read-only/envelope tests remain independent. |
| Orphan/mismatched response values have no proven register address | Correlate captured request first; mismatch does not consume it; no guessed orphan value interpretation. |
| Missing internal request metadata could hide baseline checks | Explicit complete supported-request guard before updating state; typed internal rejection test. |
| Database/IO failure can expose private paths in tracebacks | Normalize CLI errors; parameterized SQL/idempotency and conflicting-report rollback tests. |
| Generated physical SQL map must identify real objects | Recognize IF NOT EXISTS before table/index names; CI drift guard. |
| HTML report can disclose visibility gaps poorly | Show both unsupported-layer and stream/correlation counters; inert escaped CSP/no-referrer report, browser QA. |
| Independent native oracle was overclaimed for partial MBAP headers | Reproduced TShark 4.2.2 mismatch, read versioned official source (eight-byte entry check), preserved original app test, added strict header-intact native case and explicit separate compatibility evidence. |

Accepted for the documented passive offline lab after actual seven-job CI, all OS tests, independent vectors and scans. Residual boundaries are explicit: decoder/capture scope, older native-dissector limits, source-IP spoofing, hostile owner/host manipulation, packet checksum/capture authenticity, unreviewed baselines and raw-value vs physical-process interpretation. Human/operator review remains necessary; no automatic live action occurs.
