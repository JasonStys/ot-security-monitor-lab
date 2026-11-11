# Independent TShark acquisition — 11 November 2026

By Jason Stys. This change hardens a disposable hosted-runner setup step;
it does not change application analysis, the published1.1.0 binary, current
illustrated guide or any golden-vector expectation.

The guide-only main at68725659d37e704215d39b5d5bef5a03c1a151dc failed only
the independent TShark job130573405115 in run43035584501. Its actual log
reported temporary DNS-resolution failures while installing signed Ubuntu
packages, then APT exit100, before `python scripts/native.py` ran. Other jobs
passed. No parser or golden-vector assertion failed. Requests to the official
fallback archive/security mirrors also failed; this evidence does not identify
the resolver root cause or prove a mirror-list change repairs DNS.

Before the unchanged TShark installation, require an actual hosted Linux/x86_64
Ubuntu24.04 runner and the existing signed mirror-file/keyring contract. Select
only official HTTPS archive/security mirrors while retaining source suites,
components and Ubuntu signature verification. Effective APT acquisition uses
zero retries and15-second transport timeouts. The one-minute setup deadline
is separate from the unchanged original job and golden-vector test deadlines.
No unsigned fallback, test skip, local PC DNS/source edit, Docker change or live
packet capture is introduced. Persistent network failures still fail the job.

Eight actual-workflow cases cover admission/order/signature/host/retry/unsigned
mutations and preservation of the original TShark command and golden oracle.
The helper deliberately checks this authored step layout; the original native
actionlint gate still parses the complete workflow. Fresh hosted package setup
and actual golden vectors must pass before merge. Local policy results alone
are not a claim of successful network or TShark execution.

Observed failure: [independent TShark job](https://github.com/JasonStys/ot-security-monitor-lab/actions/runs/43035584501/job/130573405115).

## Follow-up: original independent oracle on a verified Windows dependency

The bounded signed-mirror setup also failed at `f6f0ea1`, job130592957438,
with explicit temporary DNS failures for archive.ubuntu.com while acquiring
the additional TShark packages. Its admission/configuration checks passed;
`python scripts/native.py` still had not run. This does not establish a parser
regression or a successful network repair. The earlier setup and failure remain
historical evidence, not a passing current result.

The independent-dissection job now runs on a disposable Windows worker with
the original15-minute job limit and unchanged `scripts/native.py`, its seven
manually specified golden-vector oracles and60-second dissection timeouts.
Linux3.12/3.14, macOS and Windows source gates remain separate and unchanged.
The independent job explicitly changes platform/version; it no longer claims
to run Ubuntu's4.2.2 package. The actual dissector version is recorded in its
existing result report, including the separate partial-header compatibility
observation outside the seven-case agreement count.

The dependency is the official stable Wireshark4.6.9 x64 MSI:80,433,152bytes,
SHA-256 `1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217`.
The URL, size and digest were read from the provider's
[published signatures](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt).
Before any MSI execution the download is bounded and must match those exact
bytes and the original valid Wireshark Foundation Authenticode signature.
Administrative extraction (`msiexec /a`) creates a disposable runner image;
no product/driver installation, live capture or local-PC Wireshark change is
performed. Only the extracted CLI's version and original offline read-file
commands run. No Npcap installation is needed for offline saved captures,
as described in the [official Windows guide](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).

Ten new real-file, host-admission and actual-workflow checks replace the eight
now-obsolete authored mirror-policy checks; no original product test is removed.
They retain incorrect/oversize/truncated/existing-file refusal and prohibit
network/process execution on an ordinary PC. All current hosted checks and the
actual independent golden comparison remain required before merge.
