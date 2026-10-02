# Getting started

```bash
pip install -e .

# Works offline (ATT&CK KB + ART index ship with the package)
gauntlet profiles                                  # real ATT&CK groups per profile
gauntlet plan --profile ransomware --top 15        # CTI-prioritized emulation plan
gauntlet plan --profile APT29,G0007 --top 10       # custom profile from groups
gauntlet predict --observed T1566.001,T1059.001    # likely next techniques
gauntlet manifest --profile ransomware --top 10 --out out/plan.json   # DRY-RUN ART manifest

# Real data (~117 MB, pinned + SHA-256 verified; add --only ...,mordor-compound,splunk,published for ~65 MB more)
export GAUNTLET_DATA_DIR=/path/outside/repo        # default ./data (git-ignored)
python scripts/download_data.py
gauntlet replay --profile ransomware --top 15 --ruleset sigma-core \
       --navigator out/layer.json --json out/baseline.json   # coverage on real recordings
gauntlet replay --profile ransomware --top 15 --ruleset sigma-core \
       --baseline out/baseline.json                          # exit 2 on a coverage regression
gauntlet bench --out out                                     # OTRF benchmark
```

Exact commands, expected outputs and runtimes for every published number are in [Reproduce](reproduce.md).

Example: `replay --profile ransomware --top 15 --ruleset sigma-core` (abridged, from v1.0.0):

```text
Replaying 33 recordings for 15 prioritized techniques (profile 'ransomware', 18 groups) through sigma-core ...

    technique    prio  tactic                result   detections
[~] T1059       0.944  execution             partial  PCRE.NET Package Image Load; PCRE.NET Package Temp Files
[-] T1059.001   0.556  execution             missed   -
[+] T1003       0.549  credential-access     detected DPAPI Domain Backup Key Extraction
[+] T1021       0.535  lateral-movement      detected CobaltStrike Service Installations - Security; ...
[-] T1547.001   0.494  persistence           missed   -
[+] T1543.003   0.473  persistence           detected Suspicious Service Path Modification
[~] T1003.001   0.418  credential-access     partial  HackTool - Dumpert Process Dumper Default File; ...
[-] T1135       0.403  discovery             missed   -
...
Technique coverage: 56%  threat-weighted: 61%  off-target rules/recording: 1.5
```

The 56% is over the 18 techniques labelled on the 33 chosen recordings, which include 3 co-labelled techniques beyond the 15 prioritized ones; over the 15 prioritized techniques alone it is 9/15 = 60%. For T1547.001 the full SigmaHQ package *does* detect both recordings, but only with medium-level rules that the *core* filter drops.

Load `out/layer.json` or `results/navigator-*.json` in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to view coverage as a heatmap: green = detected, amber = partial, red = missed.

## Docker

The container image `ghcr.io/rakshit-737/gauntlet:1.1.0` is built from the v1.1.0 tag. Avoid the older `1.0.0` image: it resolves rules inside site-packages (`sim` reports 0%).

See [Reproduce](reproduce.md) for runtimes and expected outputs, and [Evaluation](evaluation.md) for what the numbers mean.
