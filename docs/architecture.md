# Architecture

```mermaid
flowchart LR
  subgraph CTI["CTI - MITRE ATT&CK v19.2"]
    KB["attack.py<br/>STIX to KB, revoked-id map"]
  end
  TP["Threat profile<br/>real ATT&CK groups"] --> PR
  KB --> PR["prioritize.py<br/>relevance x prevalence<br/>5 strategies + LOGO eval"]
  KB --> PRED["predict.py<br/>co-occurrence next-technique"]
  PR --> PLAN["atomics.py<br/>dry-run ART manifest"]
  PR --> SEL["recordings for<br/>prioritized techniques"]
  OTRF[("OTRF Security-Datasets<br/>recorded Windows telemetry")] --> SEL
  SEL --> RP["replay.py<br/>channel/EventID-indexed replay<br/>process pool + cache"]
  SIG[("SigmaHQ rules")] --> SE["sigma.py<br/>Sigma evaluator"]
  SE --> RP
  RP --> COV["coverage.py<br/>coverage, off-target burden,<br/>cheapest wins, ablation"]
  COV --> NAV["ATT&CK Navigator layer"]
  COV --> REP["results/ + figures"]
  COV --> REG["regression gate<br/>--baseline, exit 2"]
  SIM["offline simulation<br/>cti/plans/range_sim"] -.-> REG
```

| Module | Purpose |
|---|---|
| `attack.py` | Parses ATT&CK STIX 2.1 into techniques, tactics, groups (software-inherited techniques included), prevalence and the revoked-id map (for example T1086 → T1059.001). A 426 KB derivative ships in the package |
| `prioritize.py` | Builds profiles from real groups (regex over group descriptions or explicit IDs) and ranks with the `cti`, `relevance`, `prevalence`, `breadth` and `random` strategies. Includes the leave-one-group-out evaluation |
| `sigma.py` | Evaluates SigmaHQ YAML directly. Supports the full condition grammar (except aggregations), 20+ modifiers, Sysmon/Security-4688/PowerShell logsource and field mapping. Anything unsupported is reported, never silently ignored |
| `mordor.py`, `replay.py` | Load OTRF recordings (zip or tar.gz, JSON lines) and replay them through a rule set indexed by `(channel, EventID)`, in parallel and cached |
| `coverage.py` | Scores family and exact-ID matches, off-target alert burden, threat-weighted coverage, greedy cheapest-win rules and channel ablation, and exports ATT&CK Navigator 4.5 layers |
| `predict.py` | Item-item cosine co-occurrence model with leave-one-group-out evaluation against a popularity baseline |
| `atomics.py` | Atomic Red Team Windows index and a DRY-RUN manifest in priority order |
| `bench.py`, `figures.py` | The whole benchmark, which writes `results/` |
| `cti.py`, `plans.py`, `range_sim.py`, `detect.py`, `score.py` | The v0.1 offline simulation, kept as a zero-download demo of the regression gate |

Design decisions are recorded in [ADRs](adr/index.md).
