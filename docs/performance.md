# Complexity and benchmark methodology

Created by Jason Stys. B=bounded capture bytes; P=packets; A=decoded ADUs; T=pending transactions; R=register intervals; Q=requested registers; W=maintenance windows.

Capture import O(B+P), with packet/time bounds and one copy of supported payloads; decoding O(A*Q), Q<=125. Stream buffers/history <=4096 per direction and <=128 connection keys; SYN connection-cap check O(number of bounded directions). Complete ADU extraction is bounded by stream size.

Pending expiration scans at most T<=256 per segment: O(P*T), not falsely claimed O(P). Asset lookup <=16, register checks O(A*Q*R), R<=32, window checks O(A*W), W<=64. Rolling rate queues have at most limit+1 entries per client/server pair; old sample eviction is amortized bounded per captured request, one finding per sustained crossing.

Evidence memory O(B+A+findings+bounded stream/pending/rate state); <=10000 decoded frames/findings; JSON <=16 MiB. SQLite inserts/findings are transactional and indexed by rule/severity; identity replay does not create duplicates. File read/record/state caps bound work but do not promise fixed RSS or resistance against every OS-level resource exhaustion.

scripts/benchmark.py warms up then runs 15 analyses of 1000 synthetic read/response pairs (2003 packets, 2000 ADUs). Median time and Python tracemalloc peak are recorded after actual CI. Native allocations/SQLite/disk export are not included; this is not a line-rate live sensor throughput claim or arbitrary latency gate.

Accepted Ubuntu/Python 3.14.8 result: median 188.053 ms, Python peak 4,116,969 bytes, 165,234-byte capture, all 1000 responses correlated. These are that runner/sample measurements only; see the immutable [report](reports/benchmark.json).
