# Getting started

```bash
pip install -r requirements.txt

# Works offline (ATT&CK KB + ART index ship with the package)
python -m gauntlet profiles                                  # real ATT&CK groups per profile
python -m gauntlet plan --profile ransomware --top 15        # CTI-prioritized emulation plan
python -m gauntlet plan --profile APT29,G0007 --top 10       # custom profile from groups
python -m gauntlet predict --observed T1566.001,T1059.001    # likely next techniques
python -m gauntlet manifest --profile ransomware --top 10 --out plan.json   # DRY-RUN ART manifest

# Real data (~117 MB, pinned + SHA-256 verified)
export GAUNTLET_DATA_DIR=/path/outside/repo                   # default ./data (git-ignored)
python scripts/download_data.py
python -m gauntlet replay --profile ransomware --top 15 --ruleset sigma-core \
       --navigator layer.json --json baseline.json            # coverage on real recordings
python -m gauntlet replay --profile ransomware --top 15 --ruleset sigma-core \
       --baseline baseline.json                               # exit 2 on a coverage regression
python -m gauntlet bench                                      # full benchmark -> results/
```

`make` targets exist (`make data`, `make bench`, `make demo`, `make test`) for systems that have make.

Example: `replay --profile ransomware --top 15 --ruleset sigma-core` (abridged):

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

The top-priority gaps are PowerShell (T1059.001), Run keys (T1547.001) and discovery. For T1547.001 the full SigmaHQ set *does* detect both recordings, but only with medium-level rules that the *core* filter drops. That is exactly the kind of trade-off the coverage matrix is meant to surface.

Load `layer.json` or `results/navigator-*.json` in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to view coverage as a heatmap: green = detected, amber = partial, red = missed.

## Docker

```bash
docker run --rm ghcr.io/rakshit-737/gauntlet:latest plan --profile ransomware --top 10
# real data: mount a data dir
docker run --rm -v $PWD/data:/data -e GAUNTLET_DATA_DIR=/data ghcr.io/rakshit-737/gauntlet:latest bench
```

## Reproducibility

- Every source is pinned (git commit for OTRF and Atomic Red Team, release tag for SigmaHQ, versioned file name for ATT&CK) and verified against [`scripts/checksums.sha256`](https://github.com/rakshit-737/gauntlet/blob/main/scripts/checksums.sha256).
- `python -m gauntlet bench` is deterministic. Random baselines use fixed seeds, 30 per held-out group. Replay results are cached under `$GAUNTLET_DATA_DIR/cache`. A cold run takes about 25 minutes on a 16-core laptop; a cached re-run takes about a minute.
- CI (`.github/workflows/ci.yml`) runs ruff and the 78 offline tests on Python 3.10/3.12/3.13 without downloads; the 2 `@pytest.mark.realdata` tests are skipped there and pass locally once the data is present.
