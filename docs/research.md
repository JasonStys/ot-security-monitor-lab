# Primary-source research

Reviewed 2026-10-14 by Jason Stys. No vendor-employer claims or compliance certification.

- [Modbus Application Protocol V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf), sections 6.3/6.4/6.6/6.12/7: implemented read/write quantities, big-endian register/address fields and exception profile.
- [Modbus Messaging on TCP/IP V1.0b](https://www.modbus.org/file/secure/messagingimplementationguide.pdf), section 3.1.3: MBAP following-byte length/unit/transaction fields and request/response pairing motivate exact framing/correlation.
- [Modbus specifications](https://www.modbus.org/modbus-specifications): plain Modbus/TCP is the supported profile; Modbus Security/TLS is outside passive payload decoding here.
- [NIST SP 800-82 Rev.3 final](https://csrc.nist.gov/pubs/sp/800/82/r3/final), monitoring guidance and appendix E.2: passive observation and offline testing support the lab's nonintrusive boundary. Rev.4 is a draft as of research; no conformance claim to either.
- [TShark official manual](https://www.wireshark.org/docs/man-pages/tshark.html), [Modbus/TCP fields](https://www.wireshark.org/docs/dfref/m/mbtcp.html), [Modbus fields](https://www.wireshark.org/docs/dfref/m/modbus.html): explicit offline -r/-2/-T fields and documented transaction/unit/function identifiers for independent golden-vector checks.
- [Python sqlite3](https://docs.python.org/3.14/library/sqlite3.html): parameter substitution and explicit transaction/connection close for bounded local evidence, not a server authentication/encryption service.

Developer tools are fully pinned/hash-locked via uv 0.13.1; no third-party runtime dependency. Scanner URLs/hashes are in tools.lock.json, remote Actions are immutable commit pins. Ubuntu TShark comes from signed distro packages; exact actual version is recorded rather than advertised as a timeless hermetic pin.

Debugging found a selected-oracle boundary in [Wireshark 4.2.2 Modbus source](https://github.com/wireshark/wireshark/blob/wireshark-4.2.2/epan/dissectors/packet-mbtcp.c): dissect_mbtcp_common checks eight captured bytes before its tcp_dissect_pdus call. Full native agreement uses header-intact segmentation; arbitrary-header segmentation is still required of the lab and separately disclosed in native compatibility evidence, not falsely labeled complete native coverage.
