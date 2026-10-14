# Usage and analyst workflow

Created by Jason Stys. Runtime: Python 3.12+, SQLite 3.37+ and approved local files; no administrator/capture privileges or Docker needed.

## Synthetic demo

From repo root, set PYTHONPATH=. for development scripts. PowerShell: `$env:PYTHONPATH='.'`; Bash: `export PYTHONPATH=.`. Then:

```text
python scripts/evaluate.py --out out/demo-first
python -m otmon.cli --pcap out/demo-first/unknown-writer/synthetic.pcap --policy examples/policy.json --out out/analyst-first
```

Open out/analyst-first/report.html in a browser. report.json contains full structured evidence and capture/statistics; evidence.sqlite supports repeatable analyst queries. Output must be a **new** folder; do not select your repo root or a public shared source directory. Generated examples are synthetic offline files, not transmitted packets.

## Explicit authorized capture

1. Obtain owner approval and capture privacy/classification requirements outside this lab.
2. Export an existing approved capture into the documented uncompressed classic PCAP Ethernet/IPv4/TCP profile. This repo does not perform live capture or change device/switch configuration.
3. Create a reviewed policy using the exact schema, zero-based register mapping and raw uint16 bounds. Review gateway unit IDs, real operator peers, [start,end) window boundaries and capture-time units.
4. Run the same CLI with explicit paths, keeping inputs/results in a protected ignored location.
5. Inspect capture gaps/unsupported counters, EOF pending/partials and blocked payloads before interpreting findings. Verify role/register/window assumptions.
6. Correlate packet/time/hash references with the original approved capture and process/operator logs. Human review—not automatic enforcement—determines next steps.

## SQLite query example

Use read-only access with Python/sqlite tooling on your own private evidence database:

```sql
SELECT rule, severity, COUNT(*) AS findings
FROM alerts
GROUP BY rule, severity
ORDER BY findings DESC, rule;
```

No submitted strings become SQL commands. Capture/policy hashes and engine version define replay identity; exact report repeats insert no duplicates. Keep authorized evidence backed up privately; this application does not delete old reports or captures.
