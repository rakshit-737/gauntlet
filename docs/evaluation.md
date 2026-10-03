# Evaluation

All numbers on this page come from committed files in [`results/`](https://github.com/rakshit-737/gauntlet-detection-coverage/tree/main/results), included here verbatim. They were produced by `benchmark` run [37094883465](https://github.com/rakshit-737/gauntlet-detection-coverage/actions/runs/37094883465) (a cold run on a clean ubuntu-24.04 runner) and `live-telemetry` run [37092465944](https://github.com/rakshit-737/gauntlet-detection-coverage/actions/runs/37092465944); every generated file names its run and commit in its first lines.

## Methodology

**Ground truth.** OTRF and Splunk recordings carry ATT&CK labels per recording. A rule *fires on-target* on a recording when one of its ATT&CK tags is in the same technique family as one of the recording's labels (T1059 / T1059.001 / T1059.003 are one family). *Exact-ID* coverage requires the same ID. Revoked IDs (for example T1086) are first mapped to their current replacement. The live job labels **individual events**: every audit record whose `SYSCALL` PID belongs to an allowlisted command.

**Outcomes.** For each technique: *detected* = every recording of it has an on-target alert; *partial* = some do; *missed* = none do. **Technique coverage counts partial as covered.** The stricter *fully detected* coverage is reported next to it.

**Claimed vs measured.** *Claimed* = at least one rule in the set is tagged with the technique's family. This is what a tag-generated ATT&CK Navigator layer reports. *Measured* = such a rule fired on-target. Claimed-but-missed techniques are split into *telemetry gaps* (no tagged rule's target (channel, EventID) occurs in any recording of the technique) and *rule-logic gaps* (events of a tagged rule's target log source and event type are in a recording, but no tagged rule matched). Measured coverage is nested in claimed coverage by construction, so every discordant technique points the same way: an exact McNemar test (for OTRF sigma-all, p = 0.001, exactly 0.00098, from 11 discordant techniques) would only restate their count. The overstatement is therefore reported as claimed-but-not-measured techniques / techniques, in points, with a Wilson interval. The same holds for sigma-core vs sigma-all, channel ablation and leakage control, which can only lose (or only gain) detections. Exact McNemar tests are kept for non-nested comparisons: CTID `has_sigma` vs measured, and OTRF vs Splunk outcomes.

**Off-target alerts.** Rules that fire but are not on-target. The recordings contain lab background activity and adjacent attack steps, so this is an upper bound on alert burden, not a false-positive rate.

**Threat weighting.** Each technique is weighted by its *relevance* to a profile: the share of the profile's ATT&CK groups that use it.

**Rule sets.**

- `legacy`: the 6 replayable v0.1 hand-written rules.
- `sigma-core`: SigmaHQ release package rules with status stable/test and level high/critical.
- `sigma-all`: every Windows rule in the SigmaHQ `sigma_all_rules` release package. That package contains **medium, high and critical** rules only, and no threat-hunting rules.
- `sigma-full`: a checkout of the same tag that adds low and informational rules and `rules-threat-hunting/`. It is used in the cross-dataset and live runs.

**Uncertainty.** Every bracket says what it is where it appears:

- *95% Wilson* for proportions (coverage, recall, overstatement, agreement), computed from the raw counts and rounded once. Wilson treats recordings and techniques as independent; a cluster bootstrap by technique family would be wider.
- *95% percentile bootstrap* for threat-weighted coverage (2,000 resamples of techniques, seed 0) and for strategy means over held-out groups.
- *95% paired percentile bootstrap* plus an exact sign test for prioritization and prediction differences on the same held-out groups. With fewer than 10 held-out groups (the cloud profile has 4), no CI is printed and the per-group differences are shown instead. Prediction uses leave-one-group-out with 5 hide-split seeds.
- *2.5-97.5 percentile of 200 random draws* for the random-rule baseline of the held-out selection.

Descriptive figures (off-target alert burden, the in-sample greedy path) say so and carry no interval.

**Leakage control.** Rules whose references or description cite OTRF, Security-Datasets, the Threat Hunter Playbook, or the OTRF co-founder's blog and handles are removed. Coverage is then recomputed.

## Headline: claimed vs measured coverage

![Claimed vs measured](assets/results/claimed_vs_measured.png)

--8<-- "results/EXTENDED.md"

## Control: is the gap the rules or the evaluator? {#selftest}

The claimed-vs-measured gap could partly be an artefact of GAUNTLET's in-house Sigma evaluator. SigmaHQ ships positive regression samples for some rules; replaying each sample through the rule it was recorded for isolates evaluator fidelity from rule logic.

--8<-- "results/SELFTEST.md"

## Live auditd telemetry vs replayed recordings {#live}

The `live-telemetry` workflow runs on an ephemeral ubuntu-24.04 runner. It runs allowlisted, read-only discovery commands under auditd ([ADR 0005](adr/0005-benign-live-emulation.md)), then scores the Linux SigmaHQ rules on that telemetry, event by event.

Four runner executions (runs 36995051317, 36998137511, 37016216096 and 37092465944) gave identical per-command outcomes (`results/live-history.json`). Three findings stand out:

- The release package's Linux rules detect none of the commands. The rules that would match (user, system and process discovery) are *low* or *informational* level, or threat-hunting rules, and the package does not ship those.
- None of the 12 Splunk Linux recordings of the same techniques is detected. 8 are auditd extracts with no `EXECVE` record, so no command line exists for a process-creation rule to match. The other 4 are Sysmon for Linux recordings that do contain process-creation events (`id`, `crontab -l`); the rules that fire on them are tagged with other techniques (T1087.001, T1007). The live-vs-replay difference is therefore partly missing telemetry and partly label/tag disagreement, not evidence that replay generally underestimates live coverage.
- `crontab -l` is tagged T1007 (System Service Discovery) upstream, while the live job and Splunk label it T1053.003 (Scheduled Task/Job: Cron), so it counts as off-target: a taxonomy disagreement, not a detection miss.

--8<-- "results/LIVE.md"

## Comparison with published numbers

--8<-- "results/PUBLISHED.md"

## Full benchmark tables (OTRF atomic) {#prioritization}

![Per-tactic coverage](assets/results/tactic_coverage.png)

--8<-- "results/RESULTS.md"
