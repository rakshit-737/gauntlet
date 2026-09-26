# ADR 0001 - Replay recorded attack telemetry instead of simulating it

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

The MVP generated synthetic events from hand-written templates, then ran
hand-written rules written against the same templates. Coverage numbers from
that loop are circular: the detections and the telemetry were designed together,
so "coverage" measures the author's consistency, not detection quality.

Executing real techniques (Atomic Red Team / Caldera) in a lab would give real
telemetry, but needs Windows VMs, Sysmon, and a strictly isolated range. It is
not reproducible by a reader with a laptop, and it is the part of the spec with
the highest safety burden.

## Decision

The default OBSERVE stage **replays public recordings of real technique
executions**: the OTRF Security-Datasets (Mordor) Windows *atomic* host
datasets, each captured in the OTRF "shire" lab with Sysmon, Security,
PowerShell and other channels enabled, and each mapped to ATT&CK technique(s)
in its metadata. The metadata mapping is the ground truth.

Live emulation remains possible but out of band: `gauntlet manifest` emits a
dry-run Atomic Red Team manifest (test GUIDs in CTI priority order) for an
operator to execute inside an isolated range; its logs can be replayed through
the same pipeline because the loader accepts JSON-lines Windows events.

The original simulated loop is kept (`gauntlet sim` / `run`) because it runs in
milliseconds with zero downloads and exercises the regression-suite mechanics.

## Consequences

- Coverage is measured against telemetry nobody in this project wrote.
- Technique universe is limited to what OTRF recorded (~100 Windows recordings,
  heavy on credential access / lateral movement / Empire-era tradecraft).
- Recordings include lab background noise and adjacent attack steps, so
  "off-target alerts" are an upper bound on false positives, not a true FP rate.
- Some recordings contain attack-tool strings that local anti-virus may
  quarantine; the loader skips unreadable files and reports them.
