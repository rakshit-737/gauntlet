# Evaluation

All numbers on this page come from committed files in [`results/`](https://github.com/rakshit-737/gauntlet/tree/main/results). They were produced by the `benchmark` workflow (a cold run on a clean ubuntu-24.04 runner) and the `live-telemetry` workflow, and are included here verbatim.

## Methodology

**Ground truth.** OTRF and Splunk recordings carry ATT&CK labels per recording. A rule *fires on-target* on a recording when one of its ATT&CK tags is in the same technique family as one of the recording's labels (T1059 / T1059.001 / T1059.003 are one family). *Exact-ID* coverage requires the same ID. Revoked IDs (for example T1086) are first mapped to their current replacement. The live job labels **individual events**: every audit record whose `SYSCALL` PID belongs to an allowlisted command.

**Outcomes.** For each technique: *detected* = every recording of it has an on-target alert; *partial* = some do; *missed* = none do. **Technique coverage counts partial as covered.** The stricter *fully detected* coverage is reported next to it.

**Claimed vs measured.** *Claimed* = at least one rule in the set is tagged with the technique's family. This is what a tag-generated ATT&CK Navigator layer reports. *Measured* = such a rule fired on-target. Claimed-but-missed techniques are split into *telemetry gaps* (no tagged rule's target channel occurs in any recording of the technique) and *rule-logic gaps* (the telemetry is there but no tagged rule matched). The paired difference is tested with an exact McNemar test.

**Off-target alerts.** Rules that fire but are not on-target. The recordings contain lab background activity and adjacent attack steps, so this is an upper bound on alert burden, not a false-positive rate.

**Threat weighting.** Each technique is weighted by its *relevance* to a profile: the share of the profile's ATT&CK groups that use it.

**Rule sets.**

- `legacy`: the 6 replayable v0.1 hand-written rules.
- `sigma-core`: SigmaHQ release package rules with status stable/test and level high/critical.
- `sigma-all`: every Windows rule in the SigmaHQ `sigma_all_rules` release package. That package contains **medium, high and critical** rules only, and no threat-hunting rules.
- `sigma-full`: a checkout of the same tag that adds low and informational rules and `rules-threat-hunting/`. It is used in the cross-dataset and live runs.

**Uncertainty.** Proportions get 95% Wilson intervals, which treat recordings and techniques as independent; a cluster bootstrap by technique family would be wider. Prioritization compares strategies on the same held-out groups with a paired percentile bootstrap (2,000 resamples, seed 0) and an exact sign test. With fewer than 10 held-out groups (the cloud profile has 4), no CI is printed and the per-group differences are shown instead. Prediction uses leave-one-group-out with 5 hide-split seeds.

**Leakage control.** Rules whose references or description cite OTRF, Security-Datasets, the Threat Hunter Playbook, or the OTRF co-founder's blog and handles are removed. Coverage is then recomputed.

## Headline: claimed vs measured coverage

![Claimed vs measured](assets/results/claimed_vs_measured.png)

--8<-- "results/EXTENDED.md"

## Live auditd telemetry vs replayed recordings {#live}

The `live-telemetry` workflow runs on an ephemeral ubuntu-24.04 runner. It runs allowlisted, read-only discovery commands under auditd ([ADR 0005](adr/0005-benign-live-emulation.md)), then scores the Linux SigmaHQ rules on that telemetry, event by event.

Three findings stand out:

- The release package's Linux rules detect none of the commands. The rules that would match (user, system and process discovery) are *low* or *informational* level, or threat-hunting rules, and the package does not ship those.
- Splunk's replayed auditd recordings of the same techniques contain no `EXECVE` records, so the same rules cannot fire on them. Replay underestimates live coverage here.
- `crontab -l` is tagged T1007 upstream, not T1053.003, so it counts as off-target.

--8<-- "results/LIVE.md"

## Comparison with published numbers

--8<-- "results/PUBLISHED.md"

## Full benchmark tables (OTRF atomic) {#prioritization}

![Per-tactic coverage](assets/results/tactic_coverage.png)

--8<-- "results/RESULTS.md"
