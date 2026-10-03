# CLI and API reference

## CLI

```text
python -m gauntlet profiles                         # ATT&CK groups per threat profile
python -m gauntlet plan --profile ransomware --top 15
python -m gauntlet manifest --profile ransomware --top 10 --out plan.json   # DRY RUN
python -m gauntlet predict --observed T1566.001,T1059.001 -k 10
python -m gauntlet replay --profile ransomware --top 15 --ruleset sigma-core --navigator layer.json --json report.json [--baseline old.json]   # exit 2 on regression
python -m gauntlet bench [--no-cache]               # OTRF benchmark -> results/
python -m gauntlet extended --full-rules DIR        # cross-dataset, claimed vs measured -> results/extended.json
python -m gauntlet live --audit audit.log --labels labels.json   # score live auditd telemetry (CI job)
python -m gauntlet compare [--live live.json]       # published-number comparison -> results/PUBLISHED.md
python -m gauntlet selftest --sigma-checkout DIR    # evaluator recall on SigmaHQ regression samples -> results/SELFTEST.md
python -m gauntlet kb                               # rebuild the shipped ATT&CK KB
python -m gauntlet sim --profile ransomware         # offline simulation demo
```

Run `python -m gauntlet <command> --help` for all options.

## Python API

::: gauntlet.prioritize

::: gauntlet.coverage

::: gauntlet.sigma
    options:
      members: [SigmaRule, load_rules]

::: gauntlet.replay

::: gauntlet.predict

::: gauntlet.stats
