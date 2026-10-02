# ADR 0002 - Evaluate Sigma rules directly in Python

- Status: accepted (v0.2.0)
- Date: 2026-09-26

## Context

Scoring detections needs *evaluation* of rules over events, not translation to
a SIEM query language. Options considered:

| Option | Pros | Cons |
|---|---|---|
| pySigma + a SIEM (Elastic/Splunk) in Docker | reference semantics | heavyweight, slow CI, non-trivial to reproduce |
| pySigma "evaluation" backends | reuse parser | no maintained in-memory matcher; Python 3.14 wheels uncertain |
| Chainsaw / Hayabusa over EVTX | fast, mature | recordings are JSON not EVTX; external binaries; field mapping differs |
| **Own evaluator on PyYAML** | zero heavy deps, fast enough, testable | must re-implement semantics carefully |

## Decision

Implement a focused Sigma evaluator (`gauntlet/sigma.py`): full condition
grammar except aggregations; the value modifiers used by SigmaHQ Windows rules
(contains/startswith/endswith/all/windash/re+flags/base64/base64offset/utf16*/
cased/cidr/exists/gt*/lt*/fieldref); wildcard semantics; `null` values; keyword
searches; Sysmon category -> EventID mapping and Security 4688 field mapping.

Anything else raises `UnsupportedRule` and is **reported, never silently
treated as non-matching**. On the pinned SigmaHQ release fewer than 2% of Windows
rules are unsupported (mostly logsources with no equivalent in the recordings).

## Consequences

- Semantics are pinned by unit tests per modifier and condition form.
- Rules are indexed by (channel, EventID) so a replay of ~100 recordings
  against the ~2,500 Windows rules evaluated (~2,200 when this ADR was written) runs in minutes on a laptop with a process pool.
- Divergence from a production backend is possible in edge cases (regex
  dialect, field-name case folding: we match field names case-insensitively).
