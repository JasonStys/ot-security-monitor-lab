# Detection catalog and interpretation

Created by Jason Stys. Findings are analyst-review suggestions, not confirmed attacker identity, malware verdict or process-safety decisions.

| Rule | Basis / interpretation |
| --- | --- |
| unknown_asset | Server/unit absent from reviewed inventory; could be an outdated inventory or gateway unit mapping. |
| unexpected_peer | Source IP not an expected reader/writer; IP can be spoofed, NAT/shared or misconfigured. |
| unauthorized_write | Write observed from a source outside expected writers; review access/operator logs. |
| outside_maintenance | No exact asset/writer/[start,end) approval; update reviewed approvals, not blanket suppressions. |
| readonly_write | Write touches a configured read-only interval; check register map correctness/change authorization. |
| register_outside_baseline | Any requested address is unknown; no implicit inferred register meaning. |
| process_envelope | Raw uint16 outside explicit bounds; no signed/float/endian/measurement-unit inference or physical danger claim. |
| rate_burst | Configured rolling request threshold crossed once per sustained burst; normal startup/batch polling can trigger it. |
| transaction_reuse | Same connection transaction reused while pending; could be client retry/implementation behavior. |
| unexpected_response | No pending captured transaction; capture loss, late replies or asymmetric observation are possible. |
| response_mismatch | Unit/function/quantity/write echo differs; keep valid request pending for later resolution. |
| device_exception | Valid protocol exception; availability/configuration/device errors can be benign. |
| unsupported_function | Explicit decoder coverage gap, not automatic malicious-function classification. |
| malformed_adu | Invalid framed PDU within supported contract; capture corruption and client bugs are alternatives to attack. |
| capture_gap | Missing SYN, sequence gap/conflict, unsupported SYN-data/direction/MBAP or partial EOF/FIN ADU. |
| observed_timeout | Later observed timestamp exceeded threshold; missing visibility/network latency are alternatives to failed device. |
| eof_unresolved | Capture ended before a response; never manufacture a future timeout. |
| session_reset | Only that connection's pending transactions ended on RST/new SYN; do not clear another connection. |

Maintenance changes only outside_maintenance. It cannot suppress unauthorized_write, readonly_write, process_envelope or other rules. Report basis distinguishes policy, process, protocol, correlation, behavior and visibility. Multiple findings may refer to one observed message; do not treat their count as independent attacks or statistical confidence.

Synthetic examples model a water-treatment pump skid: historian reads registers 100..103, engineering workstation writes 200..203 during a reviewed maintenance window, unknown-source writes, polling bursts, sensor raw-value envelopes and capture/protocol faults. All addresses/data are fabricated, not a real device's register map.
