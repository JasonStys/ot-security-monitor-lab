# Security, safety and privacy boundaries

Created by Jason Stys. Analyze only captures/policies you are authorized to possess.

The runtime has no network sockets, device client, active capture interface, subprocess execution, submitted-code loader, pickle/YAML object deserialization or automatic blocking/writing. An AST import guard complements code review; it is not a general Python sandbox. Capture data is inert parsed bytes. The independent CI tool always uses offline TShark -r on authored synthetic captures, never -i/live defaults.

Limits, fixed errors, strict shape/type validation, poisoned-stream handling, parameterized SQL, exact replay/conflict checks, escaped HTML and restrictive report CSP reduce common parser/resource/injection risks. HTML has no executable scripts/embedded external assets/telemetry; links are voluntary professional contact. Malicious content is not inserted into script/style contexts.

## Privacy

Real captures may contain device addressing, operations or proprietary process information. Never commit them, their policies or reports. Git ignores out/, *.pcap/*.pcapng/*.sqlite/*.db and credentials; validation rejects such tracked files. Reports intentionally retain evidence metadata, so they are **not anonymized**. POSIX new output mode is 0700; Windows depends on inherited user ACLs. Local SQLite/report files are not encrypted by this application: use approved disk encryption, ACLs and retention policies. No public host/account/login/storage service exists in this lab.

Synthetic committed fixtures/public CI evidence use documentation-only 192.0.2.0/24 addresses. Account billing data stays private/local and is never published as a report.

## Honest limits

Not a production IDS/IPS, government authorization/certification, packet authenticator or physical safety controller. No IPv6/pcapng/fragment/out-of-order reassembly, encrypted Modbus Security/TLS, serial Modbus, vendor-defined PDU parsing, other OT protocol suite, trusted identity/clock distribution, signature-based malicious-PCAP classification, tamper-proof logs, live sensor deployment, automatic incident response or universal register decoding.

A zero-finding capture can still be incomplete/unsupported. Byte integrity hashes do not prove who sent a packet. Source IP is a label, not authentication. Baseline/envelope/timeout quality determines false-positive/false-negative behavior. Control engineers and operators must interpret findings alongside process history and change logs. Do not disrupt OT systems based solely on these outputs.

Report vulnerabilities privately via [Jason Stys GitHub/contact](https://github.com/JasonStys) or [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). Do not post private captured data, credentials or production details publicly.
