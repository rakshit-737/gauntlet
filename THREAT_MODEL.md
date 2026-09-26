# Threat Model — GAUNTLET

## Scope
v0.2: a local Python CLI that (a) downloads pinned public datasets (ATT&CK STIX, SigmaHQ rules, OTRF recorded Windows logs, Atomic Red Team index) with SHA-256 verification, (b) replays recorded logs through Sigma rules and scores coverage, and (c) keeps the offline synthetic-telemetry mode. It never executes techniques; the only network I/O is `scripts/download_data.py`.

## Assets
- Integrity of coverage results. A falsely green report creates false confidence.
- Detection rule set and baselines, which are the regression-gate inputs.
- In future: the isolated range and any host that runs it.

## Trust boundaries
1. **Rule files** (`rules/*.json`, `--rules`, SigmaHQ YAML) are semi-trusted input. YAML is parsed with `yaml.safe_load` only.
2. **Downloaded datasets** are third-party input: pinned refs + SHA-256 manifest (`scripts/checksums.sha256`).
3. **Baseline JSON** (`--baseline`) is semi-trusted input.
4. **Operator-run emulation** (outside GAUNTLET): `gauntlet manifest` output executed in an isolated range. This is the critical boundary.

## Threats and mitigations

| # | Threat | Mitigation (MVP) | Residual / TODO |
| --- | --- | --- | --- |
| T1 | Project misused as attack tooling | Simulation only. Steps are inert templates with `<SIMULATED>` placeholders, `.invalid` domains and lab IPs, enforced by a test | Any future executor must be range-bound. Code review required |
| T2 | Emulation escapes the lab (future) | N/A, nothing executes | Internal-only network, no egress, cap_drop ALL, read-only containers, a kill-switch, and egress verification tests (Grade D) |
| T3 | Malicious rule file causes ReDoS through `|re` | Rules are local, operator-authored files | TODO: regex timeout or a safe regex engine, and rule linting in CI |
| T4 | Tampered baseline hides a regression | Baselines are version-controlled and diffs are reviewed in PRs | TODO: sign or hash baselines |
| T5 | Over-trust in coverage numbers | v0.2 measures coverage on real recorded attack telemetry (OTRF), reports family *and* exact-ID coverage, off-target alert burden, and limitations; simulation output stays labelled SIMULATED | Recordings are one lab, mostly 2019-2020 tradecraft; not a production FP rate |
| T9 | Poisoned / swapped dataset or rule release | Immutable refs (commit SHA / release tag / versioned file) and SHA-256 verification on every run | Checksums are TOFU (written on first download) |
| T10 | Recorded attack logs mistaken for malware by AV | Logs are JSON text, not binaries; unreadable (quarantined) files are skipped and reported | Users may need an AV exclusion for the data dir |
| T6 | Rule that fires on everything inflates coverage | False positives on benign noise are counted and reported | TODO: fail CI above an FP threshold |
| T7 | Unknown rule syntax silently ignored | Unsupported conditions, modifiers and logsources raise `UnsupportedRule` and are counted in the report | Aggregation/correlation rules not evaluated |
| T8 | Supply chain | One runtime dependency (PyYAML, safe loader); matplotlib optional. CI uses pinned major versions of the official actions and a pinned ruff | TODO: pin actions by SHA, add Dependabot |
