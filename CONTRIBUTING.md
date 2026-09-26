# Contributing to GAUNTLET

Thanks for helping make threat-informed defense measurable.

## Ground rules

- **Safety first.** GAUNTLET never executes attack techniques. PRs that add code
  paths that run payloads, download binaries/malware, or reach anything other
  than localhost / your own isolated range will be closed. See
  [ADR 0004](docs/adr/0004-safety-boundary.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- **No datasets in git.** Add a fetcher to `scripts/download_data.py` (pinned ref +
  SHA-256 in `scripts/checksums.sha256`) and commit only small derived artefacts
  (< 1 MB) or tiny test fixtures.
- **Honest numbers.** Benchmark changes must regenerate `results/` with
  `python -m gauntlet bench` and explain any movement in the PR description.

## Dev setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q          # offline; real-data tests auto-skip without downloads
python -m ruff check .
```

Optional real data (~115 MB):

```bash
export GAUNTLET_DATA_DIR=/path/outside/repo      # default: ./data (git-ignored)
python scripts/download_data.py
python -m pytest -q -m realdata
python -m gauntlet bench
```

## Where things live

| Area | Module |
|---|---|
| ATT&CK STIX loader / KB | `gauntlet/attack.py` |
| Profiles + prioritization strategies | `gauntlet/prioritize.py` |
| Sigma evaluator | `gauntlet/sigma.py` |
| Recording loader / replay engine | `gauntlet/mordor.py`, `gauntlet/replay.py` |
| Coverage, cheapest wins, Navigator | `gauntlet/coverage.py` |
| Benchmark + figures | `gauntlet/bench.py`, `gauntlet/figures.py` |
| Offline simulation (regression demo) | `gauntlet/cti.py`, `plans.py`, `range_sim.py`, `score.py` |

## Adding Sigma support

If a SigmaHQ rule is reported as unsupported, add the modifier / logsource to
`gauntlet/sigma.py` **with a unit test in `tests/test_sigma.py`** that pins the
semantics (case sensitivity, wildcard handling, list/all behaviour).

## Commits and PRs

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`,
`refactor:`, `ci:`), small and logical. CI (pytest on 3.10-3.13 + ruff) must be green.
