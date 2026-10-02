# Threat Model — GAUNTLET

## Scope
1.x: a local Python CLI that (a) downloads pinned public datasets (ATT&CK STIX, SigmaHQ rules, OTRF recorded Windows logs, Splunk attack_data Windows/Linux logs, Atomic Red Team index) with SHA-256 verification, (b) parses JSON, XML-event and raw auditd logs and replays them through Sigma rules, and (c) keeps the offline synthetic-telemetry mode. The package never executes techniques; the only network I/O is `scripts/download_data.py`. Separately, the `live-telemetry` CI workflow runs an allowlist of benign discovery commands on an ephemeral GitHub runner (ADR 0005).

## Assets
- Integrity of coverage results. A falsely green report creates false confidence.
- Detection rule set and baselines, which are the regression-gate inputs.
- In future: the isolated range and any host that runs it.

## Trust boundaries
1. **Rule files** (`gauntlet/data/rules/*.json`, `--rules`, SigmaHQ YAML) are semi-trusted input. YAML is parsed with `yaml.safe_load` only.
2. **Downloaded datasets** are third-party input: pinned refs + SHA-256 manifest (`scripts/checksums.sha256`).
3. **Baseline JSON** (`--baseline`) is semi-trusted input.
4. **Live CI emulation**: `scripts/live_emulate.py` on an ephemeral GitHub-hosted runner, allowlist only.
5. **Parsed telemetry** (Splunk XML/auditd, live audit logs): untrusted text, parsed with bounded regexes and a 1 MiB line cap.
6. **Operator-run emulation** (outside GAUNTLET): `gauntlet manifest` output executed in an isolated range. This is the critical boundary.

## Threats and mitigations

| # | Threat | Mitigation | Residual / TODO |
| --- | --- | --- | --- |
| T1 | Project misused as attack tooling | The package only replays recorded logs or simulates. Steps are inert templates with `<SIMULATED>` placeholders, `.invalid` domains and lab IPs, enforced by a test | Any future executor must be range-bound. Code review required |
| T2 | Emulation escapes the lab (future) | N/A, nothing executes | Internal-only network, no egress, cap_drop ALL, read-only containers, a kill-switch, and egress verification tests (Grade D) |
| T3 | ReDoS: malicious rule `|re`, or hostile log lines | Rules come from a pinned SigmaHQ release; log parsers use bounded, non-backtracking patterns, a 1 MiB line cap and an argc cap, with a timing regression test | Rule regexes run on Python `re` without a timeout |
| T4 | Tampered baseline hides a regression | Baselines are version-controlled and diffs are reviewed in PRs | TODO: sign or hash baselines |
| T5 | Over-trust in coverage numbers | v0.2 measures coverage on real recorded attack telemetry (OTRF), reports family *and* exact-ID coverage, off-target alert burden, and limitations; simulation output stays labelled SIMULATED | Recordings are one lab, mostly 2019-2020 tradecraft; not a production FP rate |
| T6 | Rule that fires on everything inflates coverage | False positives on benign noise are counted and reported | TODO: fail CI above an FP threshold |
| T7 | Unknown rule syntax silently ignored | Unsupported conditions, modifiers and logsources raise `UnsupportedRule` and are counted in the report | Aggregation/correlation rules not evaluated |
| T8 | Supply chain | One runtime dependency (PyYAML, safe loader); matplotlib optional. Actions pinned by commit SHA, Dependabot (actions, pip, docker), base images pinned by digest, pip-audit and gitleaks in CI, release provenance attestation | Python dependencies are not hash-locked |
| T9 | Poisoned / swapped dataset or rule release | Immutable refs (commit SHA / release tag / pinned ATT&CK commit); downloads are hashed before install and discarded on mismatch, existing files with a wrong digest are re-fetched, paths outside the data dir are refused, Splunk files are checked against git-LFS oids | Checksums are TOFU for OTRF/ATT&CK; `bench` does not re-verify files at run time |
| T10 | Recorded attack logs mistaken for malware by AV | Logs are JSON text, not binaries; unreadable (quarantined) files are skipped and reported | Users may need an AV exclusion for the data dir |
| T11 | Allowlist tampering turns the live CI job into real attack execution | Allowlist is a fixed tuple in `scripts/live_emulate.py`, a unit test pins it to approved read-only binaries and rejects forbidden ones, CODEOWNERS review, job runs unprivileged on an ephemeral runner with `contents: read` and no secrets | A maintainer could still change both test and list |
