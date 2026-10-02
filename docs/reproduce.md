# Reproduce

Every published number can be regenerated from pinned public data.

| Step | Command | Where | Runtime (measured) |
|---|---|---|---|
| Install | `pip install -e ".[figures]"` | anywhere | about 15 s |
| Offline commands | `gauntlet plan ...`, `predict`, `sim` | anywhere, no download | about 2 s each |
| Default data (ATT&CK, SigmaHQ, OTRF atomic, ART) | `python scripts/download_data.py` | ~117 MB | 1-3 min |
| Extra data (OTRF compound, Splunk, published comparators) | `python scripts/download_data.py --only mordor-compound,splunk,published` | ~65 MB | 1-2 min |
| Full SigmaHQ tag (low-level and hunting rules) | `git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$GAUNTLET_DATA_DIR/sigma-full"` | ~30 MB | under 1 min |
| OTRF benchmark | `gauntlet bench --no-cache` | 4-core CI runner | about 3 min (cold) |
| Cross-dataset benchmark | `gauntlet extended --no-cache --full-rules "$GAUNTLET_DATA_DIR/sigma-full"` | 4-core CI runner | about 4-5 min (cold) |
| Published comparison | `gauntlet compare` | anywhere | seconds |
| Live telemetry | `live-telemetry` workflow (GitHub Actions only) | ephemeral runner | about 1.5 min |

The published `results/` come from the [`benchmark`](https://github.com/rakshit-737/gauntlet/actions/workflows/benchmark.yml) workflow (workflow_dispatch, ubuntu-24.04). It downloads everything, verifies checksums, runs `bench` and `extended` without cache, and uploads `results/` as an artefact.

=== "bash"

    ```bash
    export GAUNTLET_DATA_DIR=$HOME/gauntlet-data
    python scripts/download_data.py --only attack,sigma,art,mordor,mordor-compound,splunk,published
    git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$GAUNTLET_DATA_DIR/sigma-full"
    gauntlet bench --no-cache --out out
    gauntlet extended --no-cache --full-rules "$GAUNTLET_DATA_DIR/sigma-full" --out out
    cp results/live.json results/LIVE.md out/ && gauntlet compare --results out
    diff <(python -c "import json;print(json.load(open('results/results.json'))['detection']['sigma-all']['technique_coverage'])") \
         <(python -c "import json;print(json.load(open('out/results.json'))['detection']['sigma-all']['technique_coverage'])")
    ```

=== "PowerShell"

    ```powershell
    $env:GAUNTLET_DATA_DIR = "$HOME\gauntlet-data"
    python scripts/download_data.py --only attack,sigma,art,mordor,mordor-compound,splunk,published
    git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$env:GAUNTLET_DATA_DIR\sigma-full"
    gauntlet bench --no-cache --out out
    gauntlet extended --no-cache --full-rules "$env:GAUNTLET_DATA_DIR\sigma-full" --out out
    ```

## Expected key outputs

| Metric | File / key | Value |
|---|---|---|
| OTRF recordings / techniques | `results.json` `recordings`, `recorded_techniques` | 98 / 55 |
| sigma-core technique coverage | `detection.sigma-core.technique_coverage` | 0.6545 |
| sigma-all technique coverage | `detection.sigma-all.technique_coverage` | 0.80 |
| Claimed vs measured, OTRF sigma-all | `extended.json` `sources.otrf.rulesets.sigma-all.claimed_vs_measured` | 1.00 vs 0.80, p = 0.00098 |
| Ransomware steps to 80% (CTI / breadth) | `prioritization.ransomware.strategies` | 118.9 / 194.4 |
| Live coverage, sigma-full | `live.json` `rulesets.sigma-full.technique_coverage` | 0.75 |

## Notes

- **Windows and antivirus.** Microsoft Defender may quarantine OTRF recordings that contain attack-tool strings. The downloader records them in `.av-skipped.json` and does not fetch them again, and `bench` lists them as `skipped_recordings`. That is why the published numbers come from a Linux runner.
- **Determinism.** Random baselines use fixed seeds. The replay cache is keyed by a fingerprint of the rule files and the evaluator code, and `--no-cache` forces a fresh replay.
- **Docs.** `pip install -r requirements-docs.txt -e .` and then `mkdocs serve`. An MkDocs hook copies `results/` into the site.
