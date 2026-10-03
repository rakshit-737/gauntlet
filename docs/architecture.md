# Architecture

GAUNTLET has two halves. **Plan** turns CTI into a ranked list of techniques, a dry-run emulation plan and the recordings to replay. **Measure** replays recorded and live telemetry through Sigma rules and scores coverage. The diagrams name modules only; the table below says what each one does.

**Plan: from CTI to what to emulate**

```mermaid
--8<-- "docs/assets/diagrams/plan.mmd"
```

**Measure: from telemetry to coverage**

```mermaid
--8<-- "docs/assets/diagrams/measure.mmd"
```

*Recordings* are OTRF atomic and compound and Splunk attack_data; *live auditd* is the event-labelled CI job; *reports* are `results/` from `bench`, `extended`, `live`, `compare` and `selftest`. The offline simulation (`cti.py`, `plans.py`, `range_sim.py`) feeds the same regression gate without any download.

| Module | Purpose |
|---|---|
| `attack.py` | Parses ATT&CK STIX 2.1 into techniques, tactics, groups (software-inherited techniques included), prevalence and the revoked-id map (for example T1086 → T1059.001). A 426 KB derivative ships in the package |
| `prioritize.py` | Builds profiles from real groups (regex over group descriptions or explicit IDs) and ranks with the `cti`, `relevance`, `prevalence`, `breadth` and `random` strategies. Includes the leave-one-group-out evaluation |
| `sigma.py` | Evaluates SigmaHQ YAML directly: the full condition grammar except aggregations, more than 20 modifiers, and Windows (Sysmon, Security 4688, PowerShell) and Linux (Sysmon for Linux, auditd) logsources. Anything unsupported is reported, never silently ignored |
| `formats.py`, `mordor.py`, `replay.py` | Parse JSON-lines, XML-event and raw auditd recordings (OTRF atomic and compound, Splunk), and replay them through a rule set indexed by `(channel, EventID)`, in parallel and cached |
| `coverage.py` | Scores family and exact-ID matches, off-target alert burden, threat-weighted coverage, greedy cheapest-win rules and channel ablation, and exports ATT&CK Navigator 4.5 layers |
| `extended.py`, `live.py`, `published.py` | Cross-dataset claimed-vs-measured analysis and held-out rule selection; live auditd scoring with event-level labels and the Splunk replay completeness profile; comparison with CTID and RedGap |
| `selftest.py` | Evaluator fidelity control: SigmaHQ's own regression samples replayed through the rules they were recorded for |
| `predict.py` | Item-item cosine co-occurrence model with leave-one-group-out evaluation against a popularity baseline |
| `atomics.py` | Atomic Red Team Windows index and a DRY-RUN manifest in priority order |
| `bench.py`, `figures.py` | The OTRF benchmark, which writes `results/` |
| `stats.py`, `paths.py` | Wilson, bootstrap and exact tests (unrounded; display rounds once); data locations and run provenance |
| `cti.py`, `plans.py`, `range_sim.py`, `detect.py`, `score.py` | The v0.1 offline simulation, kept as a zero-download demo of the regression gate |

Design decisions are recorded in [ADRs](adr/index.md).
