# Reproduce

Every published number can be regenerated from pinned public data.

**Source runs of the committed results.** `results/RESULTS.md`, `EXTENDED.md`, `SELFTEST.md`, `PUBLISHED.md`, their JSON files, the figures and the Navigator layers come from `benchmark` run [37094883465](https://github.com/rakshit-737/gauntlet-detection-coverage/actions/runs/37094883465) at commit `d501d40`. `results/LIVE.md` and `live.json` come from `live-telemetry` run [37092465944](https://github.com/rakshit-737/gauntlet-detection-coverage/actions/runs/37092465944) at commit `82694b3`. Both were committed unedited from the runs' artefacts; each file names its run and commit.

| Step | Command | Where | Runtime (measured) |
|---|---|---|---|
| Install | `pip install -e ".[figures]"` | anywhere | about 15 s |
| Offline commands | `gauntlet plan ...`, `predict`, `sim` | anywhere, no download | about 2 s each |
| Default data (ATT&CK, SigmaHQ, OTRF atomic, ART) | `python scripts/download_data.py` | ~117 MB | 1-3 min |
| Extra data (OTRF compound, Splunk, published comparators) | `python scripts/download_data.py --only mordor-compound,splunk,published` | ~65 MB | 1-2 min |
| Full SigmaHQ tag (low-level and hunting rules, regression samples) | `git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$GAUNTLET_DATA_DIR/sigma-full"` | ~30 MB | under 1 min |
| OTRF benchmark | `gauntlet bench --no-cache` | 4-core CI runner | about 3 min (cold) |
| Cross-dataset benchmark | `gauntlet extended --no-cache --full-rules "$GAUNTLET_DATA_DIR/sigma-full"` | 4-core CI runner | about 4-5 min (cold) |
| Evaluator self-test | `gauntlet selftest --sigma-checkout "$GAUNTLET_DATA_DIR/sigma-full"` | anywhere | about 20 s |
| Published comparison | `gauntlet compare --live results/live.json` | anywhere | seconds |
| Check against the committed results | `python scripts/verify_results.py results out` | anywhere | seconds |
| Live telemetry | `live-telemetry` workflow (GitHub Actions only) | ephemeral runner | about 1 min |

The [`benchmark`](https://github.com/rakshit-737/gauntlet-detection-coverage/actions/workflows/benchmark.yml) workflow (workflow_dispatch, ubuntu-24.04) runs exactly these steps into a fresh directory with `pipefail`, asserts that every expected file was written by that run, compares the fresh JSON with the committed JSON (`verify_results.py`, in the step summary) and uploads the directory as an artefact kept for 90 days.

=== "bash"

    ```bash
    export GAUNTLET_DATA_DIR=$HOME/gauntlet-data
    python scripts/download_data.py --only attack,sigma,art,mordor,mordor-compound,splunk,published
    git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$GAUNTLET_DATA_DIR/sigma-full"
    gauntlet bench --no-cache --out out
    gauntlet extended --no-cache --full-rules "$GAUNTLET_DATA_DIR/sigma-full" --out out
    gauntlet selftest --sigma-checkout "$GAUNTLET_DATA_DIR/sigma-full" --out out
    gauntlet compare --results out --live results/live.json
    python scripts/verify_results.py results out   # exit 1 and a list of fields if anything differs
    ```

=== "PowerShell"

    ```powershell
    $env:GAUNTLET_DATA_DIR = "$HOME\gauntlet-data"
    python scripts/download_data.py --only attack,sigma,art,mordor,mordor-compound,splunk,published
    git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma "$env:GAUNTLET_DATA_DIR\sigma-full"
    gauntlet bench --no-cache --out out
    gauntlet extended --no-cache --full-rules "$env:GAUNTLET_DATA_DIR\sigma-full" --out out
    gauntlet selftest --sigma-checkout "$env:GAUNTLET_DATA_DIR\sigma-full" --out out
    gauntlet compare --results out --live results\live.json
    python scripts/verify_results.py results out
    ```

    On Windows, Defender may quarantine some recordings (see the notes below), so `verify_results.py` will report differences for the affected sources; the published numbers come from Linux.

`verify_results.py` compares every field of every JSON file present in both directories, ignoring only timing and provenance (`run_id`, `commit`, runtimes). Run it on a subset of outputs and it compares just those files.

## Expected key outputs

| Metric | File / key | Value |
|---|---|---|
| OTRF recordings / techniques | `results.json` `recordings`, `recorded_techniques` | 98 / 55 |
| sigma-core technique coverage | `detection.sigma-core.technique_coverage` | 0.6545 (36/55) |
| sigma-all technique coverage | `detection.sigma-all.technique_coverage` | 0.80 (44/55) |
| Claimed vs measured, OTRF sigma-all | `extended.json` `sources.otrf.rulesets.sigma-all.claimed_vs_measured` | 1.00 vs 0.80; overstatement 20.0 points, 95% Wilson [11.6, 32.4] |
| Evaluator self-test | `selftest.json` `fired` / `tested` | 197 / 197 |
| Ransomware steps to 80% (CTI / breadth) | `prioritization.ransomware.strategies` | 118.9 / 194.4 |
| Live, sigma-full | `live.json` `rulesets.sigma-full.techniques_measured` | 3 of 4 techniques |

## Notes

- **Windows and antivirus.** Microsoft Defender may quarantine OTRF and Splunk recordings that contain attack-tool strings, sometimes while they are still being downloaded. The downloader records every such file in `.av-skipped.json`, keeps going with the other files and does not fetch them again (use `--force` to retry); `bench` lists the affected recordings as `skipped_recordings`. That is why the published numbers come from a Linux runner.
- **Determinism.** Random baselines and bootstraps use fixed seeds. The replay cache is keyed by a fingerprint of the rule files and the evaluator code, and `--no-cache` forces a fresh replay.
- **Live telemetry.** The live job runs only on GitHub-hosted runners (ADR 0005). Its artefact holds `audit.log`, `labels.json` (committed as `results/live-labels.json`), `live.json` and `LIVE.md`. `scripts/live_history.py` compares several runs' `live.json`; `results/live-history.json` shows identical per-command outcomes on four runs.
- **Docs.** `pip install -r requirements-docs.txt -e .` and then `mkdocs serve`. An MkDocs hook copies `results/` into the site.
