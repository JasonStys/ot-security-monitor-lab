# Input, state and evidence contracts

Created by Jason Stys. No implicit coercion, DNS lookup, active capture or silently ignored policy fields.

## Policy schema 1

Exact root: schema, site, service_port, response_timeout_ms, rate_window_ms, rate_limit, assets, maintenance. Site/asset names: lowercase ASCII 1–48 characters. Numeric values: exact integers, excluding bool/float. Service port 1..65535; timeout/window 1..60000 ms; rate limit 1..1000.

Up to 16 exact unique server IPv4/unit pairs; unit IDs 0..255, not IP-derived. Peers: distinct literal unicast IPv4 lists, max 32 each, no hostname resolution/authentication claim. Each asset has 1..32 sorted nonoverlapping inclusive zero-based register intervals, raw uint16 min/max, and boolean writable. Up to 64 maintenance windows: known asset, expected writer, start_ms < end_ms; approval is [start,end). Policies are 64 KiB maximum; duplicate JSON keys, bad shape/types, NaN-like numeric fields and excessive recursion fail.

Fingerprint is canonical parsed policy JSON, so whitespace changes do not change semantic identity. It is an audit label, not a signature or approved-change authorization.

## Capture and TCP profile

8 MiB file, <=10000 records; classic PCAP 2.4 only, micro/nano and little/big endian. Ethernet link type=1, snaplen 54..65535, no nonzero reserved/timezone fields, original/included lengths bounded and monotonically ordered integer-ms timestamps (ties allowed). Truncated record bytes are fatal; snaplen-truncated packets/layers not supported are counted, never decoded as complete.

Ethernet/one 802.1Q VLAN/IPv4/TCP only. IPv4 options and TCP options are skipped by valid header lengths. IP fragments, IPv6, other transports and malformed layer headers remain classified. Packet checksums are not validated (capture offloading can alter them); this is not a forensic proof of traffic authenticity.

At most 128 active observed connection keys, 256 directions, 4096 bytes each of pending buffer and recent overlap history. Observed SYN establishes sequence; modular wrap supported. Unverifiable older overlaps/out-of-order gaps stop that direction until new SYN. TCP SYN payload/ambiguous service direction unsupported and visible. FIN/RST/SYN-reset semantics are tested. A file timestamp for a decoded ADU is its final captured segment's timestamp.

## Modbus profile

ADU 8..260 bytes, protocol ID=0, exact MBAP following-byte count including unit, bounded 2..254. Big endian. FC03/04 request quantity 1..125; response even byte count equals captured values (1..125). FC06 exact single-register echo. FC16 request quantity 1..123 with exact value/byte count; response echoes address/quantity. Address+quantity <=65536. Valid exception code profile: 1,2,3,4,5,6,8,10,11; no request exceptions. Other nonzero functions/exception bases are explicitly unsupported rather than clean.

## Bounded monitor/output

<=256 pending transactions, 128 client/server-IP rate keys, 10000 decoded ADUs and 10000 findings; cap exhaustion fails loudly. Rolling request interval is (t-window,t], grouped by observed client/server IP across connections/units, one finding per sustained crossing; no learn-from-untrusted-input auto-baseline. Timeout when later capture time reaches request_time+timeout; no EOF clock advance.

Evidence records fixed rule/severity/basis/reason, packet/time/flow/transaction/unit/function and ADU SHA256, not raw payload bytes. JSON report <=16 MiB on database storage. Analysis identity hashes input SHA256 + canonical policy SHA256 + engine version; conflicting same-identity evidence fails. Exact replay is idempotent. Engine semantic changes require a version bump before reuse of old evidence stores.
