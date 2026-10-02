# Contributing to GAUNTLET

Thanks for helping make threat-informed defense measurable.

## Ground rules

- **Safety first.** The `gauntlet` package never executes attack techniques; the only
  execution is the allowlisted benign live job in CI ([ADR 0005](docs/adr/0005-benign-live-emulation.md)),
  and changes to its allowlist need maintainer review. PRs that add code
  paths that run payloads, download binaries/malware, or reach anything other
  than localhost / your own isolated range will be closed. See
  [ADR 0004](docs/adr/0004-safety-boundary.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- **No datasets in git.** Add a fetcher to `scripts/download_data.py` (pinned ref +
  SHA-256 in `scripts/checksums.sha256`) and commit only small derived artefacts
  (< 1 MB) or tiny test fixtures.
- **Honest numbers.** Benchmark changes must regenerate `results/` with
  the `benchmark` workflow (or `python -m gauntlet bench`) and explain any movement in the PR
  description, including numbers that got worse.

## Dev setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q          # offline; real-data tests auto-skip without downloads
python -m ruff check .
```

Optional real data (~117 MB default, ~182 MB with all sources):

```bash
export GAUNTLET_DATA_DIR=/path/outside/repo      # default: ./data (git-ignored)
python scripts/download_data.py
python -m pytest -q -m realdata
python -m gauntlet bench
```

## Docs

```bash
pip install -r requirements-docs.txt -e .
mkdocs serve        # an MkDocs hook copies results/ into the site; no separate prepare step
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
`refactor:`, `ci:`), small and logical. CI (pytest on 3.11-3.14, ruff, wheel/sdist/container smoke tests, pip-audit, gitleaks) must be green.
