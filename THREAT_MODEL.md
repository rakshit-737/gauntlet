# Threat Model — GAUNTLET

## Scope
Current MVP: a local Python CLI that generates synthetic telemetry, evaluates JSON detection rules, and writes JSON reports. It does no execution and no network I/O.

## Assets
- Integrity of coverage results. A falsely green report creates false confidence.
- Detection rule set and baselines, which are the regression-gate inputs.
- In future: the isolated range and any host that runs it.

## Trust boundaries
1. **Rule files** (`rules/*.json`, `--rules`) are semi-trusted input.
2. **Baseline JSON** (`--baseline`) is semi-trusted input.
3. **Future:** emulation backend to range hosts. This is the critical boundary.

## Threats and mitigations

| # | Threat | Mitigation (MVP) | Residual / TODO |
| --- | --- | --- | --- |
| T1 | Project misused as attack tooling | Simulation only. Steps are inert templates with `<SIMULATED>` placeholders, `.invalid` domains and lab IPs, enforced by a test | Any future executor must be range-bound. Code review required |
| T2 | Emulation escapes the lab (future) | N/A, nothing executes | Internal-only network, no egress, cap_drop ALL, read-only containers, a kill-switch, and egress verification tests (Grade D) |
| T3 | Malicious rule file causes ReDoS through `|re` | Rules are local, operator-authored files | TODO: regex timeout or a safe regex engine, and rule linting in CI |
| T4 | Tampered baseline hides a regression | Baselines are version-controlled and diffs are reviewed in PRs | TODO: sign or hash baselines |
| T5 | Over-trust in coverage numbers: synthetic telemetry does not equal real telemetry | README and CLI output label results SIMULATED | Validate against real range telemetry (roadmap) |
| T6 | Rule that fires on everything inflates coverage | False positives on benign noise are counted and reported | TODO: fail CI above an FP threshold |
| T7 | Unknown rule syntax silently ignored | Unsupported conditions and modifiers raise errors | Extend to full Sigma through pySigma |
| T8 | Supply chain | Zero runtime dependencies. CI uses pinned major versions of the official actions | TODO: pin by SHA, add Dependabot |
