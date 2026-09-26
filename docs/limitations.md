# Limitations and roadmap

## Limitations

- **Small technique universe.** The OTRF recordings cover 54 techniques, skewed toward 2019-2020 Empire/Mimikatz-era credential access and lateral movement. Coverage of 81.5% here does not mean 81.5% of ATT&CK.
- **Possible rule/data leakage.** Some SigmaHQ rules were written or tuned against these public recordings. The *w/o rules citing OTRF data* column removes rules whose references or description cite OTRF, Security-Datasets or the Threat Hunter Playbook. Coverage drops by 4-6 points. Uncited influence cannot be excluded.
- **"Off-target" is not a false-positive rate.** The recordings contain lab background activity and adjacent attack steps. The off-target figures are an upper bound on alert burden in one small lab, not a production FP rate.
- **Ground truth is coarse.** Each recording is labelled with its technique(s) and GAUNTLET scores at recording level, not event level. Family matching (for example T1059 vs T1059.001) is the headline number, with exact-ID coverage shown alongside.
- **CTI bias.** ATT&CK procedure examples measure *reporting* frequency. That favours well-studied actors and older tradecraft. Profiles are regex-selected from group descriptions: 18 ransomware, 57 espionage, 24 financial and only 4 cloud groups.
- **Evaluator divergence.** The in-house Sigma evaluator may differ from production backends in edge cases (regex dialect, case-insensitive field names). 35 of 2,554 Windows rules are unsupported (mostly log sources absent from the recordings), and aggregation/correlation rules are not evaluated.
- **Local AV.** Windows Defender may quarantine 2 recordings that contain attack-tool strings. They are skipped and counted.

## Roadmap

- [x] Real CTI prevalence and profiles (ATT&CK v19.2)
- [x] Sigma detection scoring on real recorded telemetry
- [x] ATT&CK Navigator export, cheapest wins, telemetry ablation
- [x] Research question: CTI vs breadth-first (leave-one-group-out)
- [x] Technique co-occurrence prediction
- [x] 95% confidence intervals and paired like-for-like comparisons for every headline number (v1.0.0)
- [x] Docs site, static coverage explorer, container image and tagged releases (v1.0.0)
- [ ] Run the ART manifest in the isolated Docker/VM range and replay its Sysmon logs (the loader already accepts JSON-lines events). Needs a Windows lab VM with Sysmon; executing atomics on this workstation is out of scope by design (ADR 0004)
- [ ] Event-level ground truth (OTRF compound datasets with timelines). Needs per-event human labelling of attacker vs background activity; the public recordings are labelled at recording level only
- [ ] ML detector (FEINT) as a fourth rule set next to Sigma. Depends on a separate project and a trained model; not in this repo
- [ ] Red Canary Threat Detection Report weights as an alternative prevalence source. The report publishes no machine-readable, redistributable table; transcribing it by hand needs licence review
- [ ] Sigma correlation/aggregation rules. The pinned SigmaHQ release ships no Windows correlation rules, so there is nothing to benchmark yet
