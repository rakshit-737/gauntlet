# Limitations and roadmap

## Limitations

- **Small technique universes.** OTRF covers 55 techniques, skewed to 2019-2020 Empire/Mimikatz-era credential access and lateral movement; 80% there is not 80% of ATT&CK. Splunk attack_data broadens this to 195 Windows and 55 Linux techniques, but only recordings with files of at most 2 MB are used.
- **Recording-level labels.** OTRF and Splunk label whole recordings; only the live auditd job has event-level labels, and it covers 4 benign discovery techniques (n = 4: per-command outcomes, not a rate).
- **"Claimed" is a lower bar by design.** It counts any rule tagged with the technique family, whatever its logsource. Claimed-but-missed techniques whose tagged rules target a (channel, EventID) that never occurs in the recordings are reported separately as telemetry gaps.
- **Labels and tags disagree.** Splunk labels `crontab -l` as T1053.003 (Scheduled Task/Job: Cron) while SigmaHQ tags its rule T1007, and `/usr/bin/id` is matched by a rule tagged T1087.001 rather than T1033. Such misses are taxonomy disagreements, not missing telemetry ([live results](evaluation.md#live)).
- **Possible rule/data leakage.** Some SigmaHQ rules were written against these public recordings. Rules citing OTRF, Security-Datasets, the Threat Hunter Playbook or the OTRF co-founder's blog/handles are removed in the leakage-controlled column (sigma-core 65.5% to 58.2%: 4 of 55 techniques, -7.3 points, 95% Wilson [2.9, 17.3]). Uncited influence cannot be excluded.
- **"Off-target" is not a false-positive rate.** Recordings contain lab background activity and adjacent attack steps; the off-target columns are descriptive.
- **Independence assumptions.** Wilson intervals treat techniques/recordings as independent; a cluster bootstrap by technique family would be wider. The sprint and the cheapest-wins path are in-sample, so their intervals do not account for selecting the rules on the same data.
- **CTI bias.** ATT&CK procedure examples measure *reporting* frequency. Profiles are regex-selected: 18 ransomware, 57 espionage, 24 financial and only 4 cloud groups; cloud comparisons are not statistically distinguishable (sign test p = 0.125 at n = 4).
- **In-sample cheapest wins.** The sprint (5.5% to 34.5%) selects and scores rules on the same recordings; the held-out OTRF-to-Splunk selection in [Evaluation](evaluation.md) is the out-of-sample check, and it shows no transfer.
- **Evaluator divergence.** The in-house Sigma evaluator fires on all 197 SigmaHQ regression samples it can run (95% Wilson [98.1, 100.0], `results/SELFTEST.md`), but those samples cover mostly Windows process-creation, registry and file rules; production backends may still differ in edge cases. 35 Windows rules in the release package are unsupported (mostly log sources absent from the recordings, `results/RESULTS.md`), and aggregation/correlation rules are not evaluated. auditd has no parent image, so `ParentImage` rules cannot fire on the auditd process view.
- **Unparsed Splunk events.** 39 events in 7 Splunk Windows recordings and 4 in 1 Linux recording have no parseable channel (Splunk JSON exports without a `Channel` field), so no rule can match them (`results/EXTENDED.md`).
- **Local AV.** Windows Defender may quarantine OTRF and Splunk recordings; the downloader records them in `.av-skipped.json` and skips them. Published numbers therefore come from a Linux CI runner.
- **Results artefacts expire.** The `benchmark` and `live-telemetry` artefacts are kept for 90 days; the committed `results/` files are the permanent record and name the run that produced them.

## Roadmap

- [x] Real CTI prevalence and profiles (ATT&CK v19.2)
- [x] Sigma detection scoring on real recorded telemetry
- [x] ATT&CK Navigator export, cheapest wins, telemetry ablation
- [x] Research question: CTI vs breadth-first (leave-one-group-out)
- [x] Technique co-occurrence prediction
- [x] 95% CIs for every reported statistic: Wilson for proportions, bootstrap for weighted coverage and paired strategy differences, exact sign and McNemar tests where comparisons are not nested
- [x] Evaluator self-test on SigmaHQ regression samples
- [x] Docs site, static coverage explorer, container image and tagged releases (v1.0.0, v1.1.0, v1.1.1, v1.1.2)
- [ ] Run the ART manifest in the isolated Docker/VM range and replay its Sysmon logs (the loader already accepts JSON-lines events). Needs a Windows lab VM with Sysmon; executing atomics on this workstation is out of scope by design (ADR 0004)
- [x] OTRF compound campaigns and Splunk attack_data as additional sources; claimed-vs-measured analysis; held-out rule selection
- [x] Live auditd telemetry with event-level labels in CI (benign allowlist, ADR 0005)
- [x] Comparison with published numbers (CTID `has_sigma`, RedGap)
- [ ] Event-level labels for recorded Windows data. The public recordings are labelled per recording; per-event labelling of attacker vs background activity needs human annotation
- [ ] Regression-catch rate across consecutive SigmaHQ releases (replay OTRF through r2026-0x tags) and rule-mutation testing
- [ ] ML detector (FEINT) as a fourth rule set next to Sigma. Depends on a separate project and a trained model; not in this repo
- [ ] Red Canary Threat Detection Report weights as an alternative prevalence source. The report publishes no machine-readable, redistributable table; transcribing it by hand needs licence review
- [ ] Sigma correlation/aggregation rules. The pinned SigmaHQ release ships no Windows correlation rules, so there is nothing to benchmark yet
