"""Coverage scoring, gap ranking, and regression diffing."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import (Alert, CoverageReport, EmulationStep, Event, Outcome, Range,
                     RankedTechnique, TechniqueResult)


def score(profile: str, ranked: list[RankedTechnique], plan: list[EmulationStep],
          events: list[Event], alerts: list[Alert], rng: Range) -> CoverageReport:
    steps = {s.technique_id: s for s in plan}
    available = set().union(*(h.log_sources for h in rng.hosts))
    emitted: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.technique_id:
            emitted[e.technique_id].append(e)
    hit_ids: dict[str, set[int]] = defaultdict(set)
    fired: dict[str, set[str]] = defaultdict(set)
    fp = set()
    for a in alerts:
        tid = a.event.technique_id
        if tid is None:
            fp.add(id(a.event))
        else:
            hit_ids[tid].add(id(a.event))
            fired[tid].add(a.rule_id)

    results = []
    for r in ranked:
        tid = r.technique.id
        n, d = len(emitted[tid]), len(hit_ids[tid])
        if n and d == n:
            outcome = Outcome.DETECTED
        elif d:
            outcome = Outcome.PARTIAL
        else:
            outcome = Outcome.MISSED
        step = steps.get(tid)
        needed = {step.requires_source} if step else set(r.technique.data_sources)
        results.append(TechniqueResult(tid, r.technique.tactic, outcome, sorted(fired[tid]),
                                       n, d, sorted(needed - available)))
    return CoverageReport(profile, results, len(fp))


def gap_recommendations(report: CoverageReport, ranked: list[RankedTechnique]) -> list[dict[str, Any]]:
    """Rank fixes by priority-weighted techniques unlocked.

    Missing telemetry sources are grouped (one config change can fix many
    techniques); techniques with telemetry but no rule each need a new rule.
    """
    weight = {r.technique.id: r.score for r in ranked}
    by_source: dict[str, list[str]] = defaultdict(list)
    recs = []
    for res in report.results:
        if res.outcome == Outcome.DETECTED:
            continue
        if res.missing_sources:
            for s in res.missing_sources:
                by_source[s].append(res.technique_id)
        else:
            recs.append({"action": f"write/fix detection rule for {res.technique_id}",
                         "kind": "rule", "techniques": [res.technique_id],
                         "value": round(weight.get(res.technique_id, 0), 4)})
    for s, tids in by_source.items():
        recs.append({"action": f"enable '{s}' telemetry in the range", "kind": "telemetry",
                     "techniques": sorted(tids), "value": round(sum(weight.get(t, 0) for t in tids), 4)})
    recs.sort(key=lambda x: (-x["value"], x["action"]))
    return recs


def diff(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Return regressions: techniques whose outcome got worse vs. baseline."""
    rank = {"missed": 0, "partial": 1, "detected": 2}
    base = {r["technique"]: r["outcome"] for r in baseline["results"]}
    regressions = []
    for r in current["results"]:
        b = base.get(r["technique"])
        if b is not None and rank[r["outcome"]] < rank[b]:
            regressions.append(f"{r['technique']}: {b} -> {r['outcome']}")
    return regressions
