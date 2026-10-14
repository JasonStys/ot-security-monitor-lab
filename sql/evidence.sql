-- Jason Stys: atomic offline analysis evidence, keyed idempotency and indexed analyst rule lookup.
-- Tables analyses and alerts store reviewed results, never execute submitted payloads or SQL.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- SQL object: analyses — line 20
-- column: analysis_id — line 21
-- column: source_sha256 — line 22
-- column: policy_sha256 — line 23
-- column: report_sha256 — line 24
-- column: report_json — line 25
-- SQL object: alerts — line 27
-- column: analysis_id — line 28
-- column: ordinal — line 29
-- column: rule — line 30
-- column: severity — line 31
-- column: basis — line 32
-- column: packet — line 33
-- column: time_ms — line 34
-- SQL object: alerts_by_rule — line 37
-- END CODE MAP
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id TEXT PRIMARY KEY CHECK(length(analysis_id)=64),
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),
    policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
    report_sha256 TEXT NOT NULL CHECK(length(report_sha256)=64),
    report_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS alerts (
    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    rule TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')),
    basis TEXT NOT NULL,
    packet INTEGER,
    time_ms INTEGER,
    PRIMARY KEY (analysis_id,ordinal)
) STRICT;
CREATE INDEX IF NOT EXISTS alerts_by_rule ON alerts(rule,severity,analysis_id);
