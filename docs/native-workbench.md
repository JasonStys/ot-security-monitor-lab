# OT Security Monitor Workbench: Windows application

Created by Jason Stys · [GitHub](https://github.com/JasonStys) · [Professional contact](https://www.linkedin.com/in/jason-stys-31b30b351/).

## Purpose and normal use

Analyze authorized classic-PCAP files and chosen asset/register/maintenance policies through the original conservative TCP/Modbus engine. Inspect original detections, request/response frames, exact matched reads, separate FC03/FC04 intervals and unfiltered capture caveats.

Launch `OtSecurityMonitorLab.exe`. The Windows x64 one-file portable includes patched CPython 3.14.10, Tcl/Tk 9.0.4, its actual notices and all fixed authored data resources; users need no Python, terminal setup, administrator rights or Docker. Source builds do not themselves publish/install a package. Obtain only the owner-published matching release, verify its checksum and keep its source metadata/notices.

Choose a built-in inert capture or select your authorized PCAP, choose a supported policy and optionally enter bounded response-timeout/rate overrides. Blank overrides preserve exact policy bytes; changed assumptions retain both original and effective policy snapshots and hashes. Capture timestamps determine maintenance/correlation, not the PC clock. Prepared cases cover unauthorized/read-only/out-of-window writes, raw-value envelopes, bursts, gaps and separate register spaces.

Prepared scenarios populate the same editable controls and run the same engine; there is no separate demo application or automatic success result. Select your own supported files and settings when authorized. The permission checkbox is an operator acknowledgement, not authentication. Help describes purpose, inputs and limits; Licenses opens actual bundled text locally. Creator/contact attribution is visible in the window.

## Inspect and retain

Choose an evidence view, search literal records, select a row and inspect its full structured detail. Display filtering never changes whole-result counts, scope or exported evidence. At most 5,000 matching rows render; full bounded results remain exportable. Saved analyses reopens exact bundle bytes and original settings, never silently re-runs inputs. Export creates a NEW private directory and refuses overwrite.

Profiles default to the OS-local application-data directory under `JasonStys/OtSecurityMonitorLab` outside the EXE and repository. They are plaintext owner-local data, protected by OS permissions rather than encryption/multiuser accounts. Developer `--profile` selects a separate authorized path. History is limited to 20 runs / 128 MiB of retained payloads (SQLite metadata adds overhead), 64 MiB per bundle and 32 MiB per file. Export wanted data and explicitly delete selected local copies to manage retention; no silent eviction occurs. Back up the whole profile only after normal exit.

Existing linked/nonregular/multiply linked fixed marker, lock, database and recovery-sidecar paths are rejected BEFORE initialization and before later SQLite connections; regular genuine WAL/hot rollback recovery remains supported. This prevents accidental aliases, not every race by a malicious same-OS administrator. No saved evidence is reset on refusal. A retained owner lock prevents a second instance. Exit waits for active analysis and its committed result; repeated Exit does not abandon a write or force-kill another process.

## Scope and privacy

No socket, capture driver, packet transmission, scan, process launch, device query, PLC write or enforcement path exists in the GUI runtime. IP peer labels are not authentication. Unsupported/incomplete captures remain explicit, and unobserved intervals do not prove device failure, mandatory polling or physical-process safety. Only the original documented classic-PCAP/Modbus profile is implemented.

Raw PCAP bytes stay in your original input; saved private results include packet metadata and both policy snapshots. Keep originals separately for reproduction.

Neither app/runtime nor exports include ads, analytics, provider keys or remote content. SHA256 identifies bytes, not an application Authenticode signature or malware/compliance guarantee. This native proof covers Windows x64; it is not an all-OS installer claim.

## Developer build and actual consumer

```text
python -m pip install --require-hashes -r requirements-dev.lock -r requirements-native.lock
python scripts/build_native.py
python scripts/test_native_app.py
```

Use an isolated full Windows CPython 3.14.10 with Tk. The builder checks version coherence, hashes exact resources including the actual interpreter DLL, collects actual Python/Tcl/Tk/PyInstaller notices and freezes a windowed portable. It changes no global SDK, registry, profile or Docker configuration. Source GUI: `python -m otmon.desktop`. Existing CLI commands remain unchanged.

The actual final-EXE consumer drives the SAME Tk widgets/handlers/mainloop, original core, supported external-file chooser, minimum 980 × 700 layout, literal details, actual notices window, exact export, invalid-input history preservation and a second process reopening all 9 unchanged bundles. Both application/bootloader PIDs must exit normally. Only OS file-picker selection is supplied by the harness; no analysis result is mocked. Working receipts/screenshots remain private ignored outputs. CI requires a clean source checkout, records `source_dirty: false` and retains all original source/native/security gates.
