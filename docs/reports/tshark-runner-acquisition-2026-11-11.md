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
