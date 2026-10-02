# Limitations and roadmap

## Limitations

- **Small technique universes.** OTRF covers 55 techniques, skewed to 2019-2020 Empire/Mimikatz-era credential access and lateral movement; 80% there is not 80% of ATT&CK. Splunk attack_data broadens this to 188 Windows and 55 Linux techniques, but only recordings with files of at most 2 MB are used.
- **Recording-level labels.** OTRF and Splunk label whole recordings; only the live auditd job has event-level labels, and it covers 4 benign discovery techniques.
- **"Claimed" is a lower bar by design.** It counts any rule tagged with the technique family, whatever its logsource; some claimed-but-missed techniques could never fire on the recorded log types (reported as telemetry gaps).
- **Possible rule/data leakage.** Some SigmaHQ rules were written against these public recordings. Rules citing OTRF, Security-Datasets, the Threat Hunter Playbook or the OTRF co-founder's blog/handles are removed in the leakage-controlled column (sigma-core 65.5% to 58.2%). Uncited influence cannot be excluded.
- **"Off-target" is not a false-positive rate.** Recordings contain lab background activity and adjacent attack steps.
- **Independence assumptions.** Wilson intervals treat techniques/recordings as independent; a cluster bootstrap by technique family would be wider.
- **CTI bias.** ATT&CK procedure examples measure *reporting* frequency. Profiles are regex-selected: 18 ransomware, 57 espionage, 24 financial and only 4 cloud groups; cloud comparisons are not statistically distinguishable (sign test p = 0.125 at n = 4).
- **In-sample cheapest wins.** The sprint (5.5% to 34.5%) selects and scores rules on the same recordings; the held-out OTRF-to-Splunk selection in [Evaluation](evaluation.md) is the out-of-sample check.
- **Evaluator divergence.** The in-house Sigma evaluator may differ from production backends in edge cases; 40 Windows rules are unsupported (mostly log sources absent from the recordings); aggregation/correlation rules are not evaluated. auditd has no parent image, so `ParentImage` rules cannot fire on the auditd process view.
- **Local AV.** Windows Defender may quarantine OTRF recordings; published numbers therefore come from a Linux CI runner.
- **Known gaps in v1.1.0.** Wilson bounds are rounded to 4 decimals in `stats.wilson` before display, so a few generated upper bounds can be 0.1 point low (hand-corrected in the README headline tables). `results/LIVE.md` comes from live-telemetry run 36995051317, not the latest green run 37016216096, and does not yet note Splunk EXECVE completeness. The architecture diagram's labels are small at content width. The Quickstart's data-dependent steps are exercised by the benchmark and live workflows, not by a wheel-plus-replay smoke test in `ci.yml`.

## Roadmap

- [x] Real CTI prevalence and profiles (ATT&CK v19.2)
- [x] Sigma detection scoring on real recorded telemetry
- [x] ATT&CK Navigator export, cheapest wins, telemetry ablation
- [x] Research question: CTI vs breadth-first (leave-one-group-out)
- [x] Technique co-occurrence prediction
- [x] 95% CIs for coverage and recall, paired bootstrap and sign tests for prioritization, McNemar tests for rule-set and telemetry differences
- [x] Docs site, static coverage explorer, container image and tagged releases (v1.0.0, v1.1.0)
- [ ] Run the ART manifest in the isolated Docker/VM range and replay its Sysmon logs (the loader already accepts JSON-lines events). Needs a Windows lab VM with Sysmon; executing atomics on this workstation is out of scope by design (ADR 0004)
- [x] OTRF compound campaigns and Splunk attack_data as additional sources; claimed-vs-measured analysis; held-out rule selection
- [x] Live auditd telemetry with event-level labels in CI (benign allowlist, ADR 0005)
- [x] Comparison with published numbers (CTID `has_sigma`, RedGap)
- [ ] Event-level labels for recorded Windows data. The public recordings are labelled per recording; per-event labelling of attacker vs background activity needs human annotation
- [ ] Regression-catch rate across consecutive SigmaHQ releases (replay OTRF through r2026-0x tags) and rule-mutation testing
- [ ] ML detector (FEINT) as a fourth rule set next to Sigma. Depends on a separate project and a trained model; not in this repo
- [ ] Red Canary Threat Detection Report weights as an alternative prevalence source. The report publishes no machine-readable, redistributable table; transcribing it by hand needs licence review
- [ ] Sigma correlation/aggregation rules. The pinned SigmaHQ release ships no Windows correlation rules, so there is nothing to benchmark yet
