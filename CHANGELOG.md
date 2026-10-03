# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [Unreleased]

### Added
- `gauntlet selftest`: evaluator fidelity control. Every SigmaHQ positive regression sample is
  replayed through the rule it was recorded for: 197 of 197 fire (95% Wilson [98.1, 100.0]).
- Splunk replay completeness in `live.json` / `LIVE.md`: per recording sourcetype, EXECVE/SYSCALL
  records, Sysmon EventID 1 events and the rules that fired. 8 of the 12 Splunk Linux recordings
  of the live techniques are auditd extracts without EXECVE; the 4 Sysmon for Linux recordings
  have process-creation events, but the rules that fire are tagged T1087.001 / T1007.
- Exact-ID claimed-vs-measured variant, unparsed-channel counts, an interval for every reported
  statistic (Wilson, percentile bootstrap for weighted coverage, paired bootstrap for
  breadth-vs-random and MRR), and the GitHub run id and commit in every generated result file.
- `scripts/verify_results.py` (field-by-field check of a reproduction), `scripts/live_history.py`
  and `results/live-history.json` (identical per-command outcomes on 4 live runs).
- CI: replay tests against the installed wheel; docs-sync tests for the architecture diagrams.

### Changed
- Nested comparisons (claimed vs measured, core vs all, channel ablation, leakage control) are
  reported as points with a Wilson interval instead of an exact McNemar p, which only restated
  the discordant count. McNemar is kept for non-nested comparisons (CTID, OTRF vs Splunk).
- Gap classes check a tagged rule's (channel, EventID) target, not only its channel.
- Splunk files are routed by sourcetype; mixed recordings are scored with both platforms' rules.
  **Splunk Windows numbers got slightly worse**: 398 to 414 recordings, 188 to 195 techniques,
  measured coverage 36.2% to 35.9%, overstatement 58.5 to 59.0 points (sigma-full 38.8% to
  37.9%). OTRF, compound and Splunk Linux coverage is unchanged; with the stricter (channel,
  EventID) check, Splunk Linux gap classes moved from 6 telemetry / 27 rule-logic to 10 / 23
  (sigma-all).
- `benchmark` workflow: pipefail, fresh output directory, selftest, compare and the README replay
  example, an assertion that every file was written by the run; artefacts kept 90 days (live
  too). Results regenerated from benchmark run 37094883465 and live-telemetry run 37092465944.
- Architecture diagram split into Plan and Measure diagrams with module-name labels.
- `sim --disable-source` and `predict --observed` reject unknown values.

### Fixed
- `stats.wilson` rounded bounds to 4 decimals before the writers rounded them to 0.1 point; three
  published lower bounds were 0.1 too high (3/98: 1.0 not 1.1; 42/55: 63.7 not 63.6; 73/188: 32.2
  not 32.1) and the explorer showed 14.8 / 52.2 where the README said 14.9 / 52.3. Intervals are
  now computed from raw counts and rounded once.
- Downloader: a file blocked by AV while still a `.part` crashed the download instead of being
  recorded in `.av-skipped.json`; the data-dir check could fail under concurrent downloads on
  Windows.
- Sigma evaluator: event fields with spaces (Defender's "Threat Name") now match rule fields
  (ThreatName).

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
  wheel/sdist/container smoke tests, Python 3.11-3.14 test matrix.

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
- Packaging: legacy rules ship as package data and data/results default to the working directory
  (the v1.0.0 wheel and image loaded 0 legacy rules and reported 0% in `sim`); empty rule dirs
  raise; distribution renamed to `gauntlet-coverage`, Python 3.11+.
- CLI creates parent directories for `--out`/`--json`/`--navigator`.
- Release notes are taken from this file (the awk pattern never matched).
- Downloader: verify before install, discard mismatches, refuse paths outside the data dir,
  record files local AV makes unreadable after download (a file blocked while still a `.part`
  was not handled until the next release), pin ATT&CK to a commit, no token on redirects.
- Parser ReDoS / argc-driven allocation on malformed input.
- Docs: hero wording (two providers), exact p-value, install pinned to v1.1.0. Three Wilson
  bounds were corrected by hand in the README; the generator still rounded twice and three other
  bounds stayed 0.1 point off (fixed in the next release).

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
