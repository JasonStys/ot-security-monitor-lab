# Operational review and release runbook

Created by Jason Stys. This is an offline lab, not a change to a live control network.

## Before analysis

Verify capture owner authorization, privacy/classification, approved source chain and completeness. Check documented protocol/link/time profile, actual observation point/asymmetry and change/register baseline. Never use credentials/private captured data in public CI. Test policy changes against independent approved synthetic/captured baselines before interpreting results.

## Findings

Start with visibility: unsupported/truncated layers, missing SYN, stream gaps, partial ADUs, EOF pending and blocked packets. They limit coverage. Confirm exact server/unit mapping and observed peer roles; distinguish source labels from authenticated users. Review maintenance boundaries, raw unsigned register interpretation, poll thresholds and actual plant process context.

Escalate a suspected unauthorized write using established human/operator safety procedures. Do not run this lab against live devices, switch a PLC state, introduce active scans or block traffic from a report alone. Exceptions/timeouts may reflect device/network/capture behavior. Preserve approved evidence privately.

## Failure/recovery

Format/order/resource-cap error produces no successful completed report. Failed export may leave a new output folder for inspection; do not overwrite/delete it automatically. Use a fresh output path after correcting approved inputs. Idempotent SQLite replays prevent duplicate findings; conflicting identity requires investigation/engine version change, not silent overwrite.

## Publication checklist

Require all latest-main quality/native/security/CodeQL jobs green; inspect actual counts/coverage and independent fields, no fake pass reports. Review privacy and absence of live-network/process imports in runtime. Confirm complete README/source maps, explicit scope/limits and repository artifact/cache counters. Account Actions storage must be checked before triggering workflows; cleanup needs a fresh approval, not reused historical consent.

No production deploy/rollback, host network rules, capture driver or Docker configuration changes are included.
