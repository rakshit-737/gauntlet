# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

## [1.1.0] - 2026-10-02

### Added
- `gauntlet/formats.py`: XML event (Splunk, Sysmon for Linux) and raw auditd parsing, with a
  synthetic process-creation view from SYSCALL+EXECVE+CWD; Linux Sigma logsources (`sigma-linux`).
- Data: OTRF compound LSASS campaigns and Splunk attack_data (committed manifest, LFS-oid verified).
- `gauntlet extended`: cross-dataset benchmark and claimed-vs-measured coverage with gap classes
  and exact McNemar tests; held-out rule selection (pick on OTRF, test on Splunk).
- `gauntlet live` + `live-telemetry` workflow: allowlisted benign discovery commands under auditd on
  an ephemeral runner, event-level labels, compared with replayed Splunk recordings (ADR 0005).
- `gauntlet compare`: CTID `has_sigma` and RedGap published outcomes vs measured coverage.
- `benchmark` workflow: cold, clean-Linux run that produces the committed `results/`.
- CLI `--version`, help text with defaults, `bench --no-cache`.
- Repo: dependabot, CODEOWNERS, issue/PR templates, CITATION.cff, pip-audit and gitleaks in CI,
  wheel/sdist/container smoke tests, Python 3.10-3.14 matrix.

### Fixed
- Packaging: legacy rules ship as package data, data/results default to the working directory (the v1.0.0 wheel and image reported 0% in `sim`); distribution renamed to `gauntlet-coverage`, Python 3.11+.
- CLI creates parent directories for `--out`/`--json`/`--navigator`.
- Docs: hero wording (two providers), exact p-value, corrected Wilson bounds; install pinned to v1.1.0.

### Changed
- Published results now come from a clean Linux runner: 98 OTRF recordings / 55 techniques (was
  96 / 54 with 2 recordings quarantined by local AV). **Numbers got slightly worse**: sigma-core
  66.7% to 65.5%, sigma-all 81.5% to 80.0%; sprint 35.2% to 34.5%.
- Leakage filter broadened (OTRF co-founder blog/handles): sigma-core leakage-controlled coverage
  58.2% (was 61.1% with the narrow filter on 96 recordings).
- Cloud-profile comparisons (n = 4 groups) report per-group differences and an exact sign test
  instead of bootstrap CIs; they are not statistically distinguishable (p = 0.125).
- Recall curves cover the full 266-technique universe; the figure marks the 80% crossing.
- Replay cache keyed by a fingerprint of rules and evaluator code.

### Fixed
- Installed wheel and container loaded 0 legacy rules and reported 0% (rules now package data;
  data/results default to the working directory; empty rule dirs raise).
- Release notes are taken from this file (the awk pattern never matched).
- Downloader: verify before install, discard mismatches, refuse paths outside the data dir,
  remember AV-quarantined files, pin ATT&CK to a commit, no token on redirects.
- Parser ReDoS / argc-driven allocation on malformed input.

## [1.0.0] - 2026-09-26

### Added
- `gauntlet/stats.py`: Wilson intervals, bootstrap and paired-bootstrap CIs (fixed seeds).
- Benchmark reports 95% CIs for coverage and recall, paired CTI-vs-baseline deltas over
  held-out groups, and next-technique recall across 5 hide-split seeds (`predict.evaluate_seeds`).
- MkDocs Material docs site on GitHub Pages with mkdocstrings API reference and a static
  coverage explorer (`/demo/`) built from the committed `results/` JSON.
- `Dockerfile` (slim, non-root) and a release workflow that pushes `ghcr.io/rakshit-737/gauntlet`
  and publishes wheel/sdist to a GitHub Release.

### Changed
- README: CIs on headline numbers; the ransomware CTI-vs-prevalence gap (8.0 steps, CI 3.9-12.2)
  is now shown to be real, espionage/financial ties confirmed. (The v1.0.0 note "cloud favours
  prevalence" was withdrawn in the next release: with 4 groups it is not significant.)
- Mermaid labels quoted so the diagram renders on GitHub and the docs site.

## [0.2.0] - 2026-09-26

### Added
- **Real data pipeline**: `scripts/download_data.py` fetches pinned MITRE ATT&CK
  Enterprise v19.2 (STIX), SigmaHQ release r2026-07-01, OTRF Security-Datasets
  Windows atomic recordings and the Atomic Red Team Windows index, with SHA-256
  verification.
- `gauntlet/sigma.py`: in-process SigmaHQ rule evaluator (conditions, modifiers,
  Sysmon/Security/PowerShell logsource + field mapping).
- `gauntlet/replay.py`: parallel replay of recorded attack telemetry through a rule set.
- `gauntlet/coverage.py`: real-data technique coverage, off-target alert burden,
  threat-weighted coverage, greedy "cheapest wins", telemetry-channel ablation,
  ATT&CK Navigator layer export.
- `gauntlet/attack.py` + `gauntlet/prioritize.py`: threat profiles built from real
  ATT&CK groups; five prioritization strategies with leave-one-group-out evaluation.
- `gauntlet/predict.py`: technique co-occurrence model for next-technique prediction.
- `gauntlet/atomics.py`: Atomic Red Team index and dry-run emulation manifest.
- CLI: `profiles`, `plan`, `manifest`, `predict`, `replay`, `bench`, `kb`; `sim` alias for
  the offline simulation.
- `results/`: benchmark tables, JSON, Navigator layers and figures from real runs.
- Revoked ATT&CK ids (e.g. T1086, T1562.x in ATT&CK v19) are mapped to their replacements
  before scoring; leakage-controlled coverage excludes Sigma rules that cite OTRF data.
- LICENSE (MIT), CONTRIBUTING, ADRs under `docs/adr/`, dataset card `docs/DATASETS.md`.

### Changed
- `plan` and `profiles` now use real ATT&CK data instead of hand-typed weights.
- Package version 0.2.0; PyYAML is now a runtime dependency.

## [0.1.0] - 2026-09-26

### Added
- Simulation MVP: hand-weighted CTI prioritizer, simulated emulation plans and
  synthetic telemetry, JSON rule engine, coverage scorer, gap recommendations,
  regression diff, CLI, tests and CI.
