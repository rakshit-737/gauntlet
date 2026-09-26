# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

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
  is now shown to be real, espionage/financial ties confirmed, cloud favours prevalence.
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
