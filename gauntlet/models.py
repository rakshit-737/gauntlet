"""Typed data models for GAUNTLET."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    DETECTED = "detected"
    PARTIAL = "partial"
    MISSED = "missed"


@dataclass(frozen=True)
class Technique:
    id: str                 # ATT&CK ID, e.g. T1003.001
    name: str
    tactic: str
    prevalence: float       # 0..1 public prevalence weight
    data_sources: tuple[str, ...] = ()  # telemetry sources needed to observe it


@dataclass(frozen=True)
class ThreatProfile:
    name: str
    description: str
    # technique id -> relevance weight (0..1) for this actor/sector
    relevance: dict[str, float]


@dataclass(frozen=True)
class RankedTechnique:
    technique: Technique
    score: float


@dataclass(frozen=True)
class EmulationStep:
    """A SIMULATED step: describes benign telemetry to emit, never executes anything."""
    technique_id: str
    description: str
    events: tuple[dict[str, Any], ...]  # event templates (fields merged onto host context)
    # events that only appear when the named log source is enabled on the host
    requires_source: str = "sysmon"


@dataclass(frozen=True)
class Host:
    name: str
    os: str
    role: str
    log_sources: frozenset[str]


@dataclass(frozen=True)
class Range:
    name: str
    hosts: tuple[Host, ...]


@dataclass
class Event:
    host: str
    source: str
    fields: dict[str, Any]
    technique_id: str | None = None  # ground-truth label (None = background noise)
    ts: float = 0.0


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    techniques: tuple[str, ...]
    source: str
    selection: dict[str, Any]
    condition: str = "selection"
    filter: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    rule_id: str
    event: Event


@dataclass
class TechniqueResult:
    technique_id: str
    tactic: str
    outcome: Outcome
    rules_fired: list[str]
    emulated_events: int
    detected_events: int
    missing_sources: list[str]


@dataclass
class CoverageReport:
    profile: str
    results: list[TechniqueResult]
    false_positives: int

    @property
    def coverage(self) -> float:
        if not self.results:
            return 0.0
        pts = sum(1.0 if r.outcome == Outcome.DETECTED else 0.5 if r.outcome == Outcome.PARTIAL else 0.0
                  for r in self.results)
        return pts / len(self.results)

    def by_tactic(self) -> dict[str, float]:
        out: dict[str, list[float]] = {}
        for r in self.results:
            v = 1.0 if r.outcome == Outcome.DETECTED else 0.5 if r.outcome == Outcome.PARTIAL else 0.0
            out.setdefault(r.tactic, []).append(v)
        return {k: sum(v) / len(v) for k, v in sorted(out.items())}

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "coverage": round(self.coverage, 4),
            "false_positives": self.false_positives,
            "by_tactic": {k: round(v, 4) for k, v in self.by_tactic().items()},
            "results": [
                {"technique": r.technique_id, "tactic": r.tactic, "outcome": r.outcome.value,
                 "rules_fired": r.rules_fired, "emulated_events": r.emulated_events,
                 "detected_events": r.detected_events, "missing_sources": r.missing_sources}
                for r in self.results
            ],
        }
