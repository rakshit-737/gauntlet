"""Coverage scoring on replayed real telemetry, gap ranking and ATT&CK Navigator export.

Ground truth is the dataset's ATT&CK mapping. A rule firing on a recording is
*on-target* when one of its ATT&CK tags is in the same technique family as one
of the recording's techniques (``T1059`` / ``T1059.001`` / ``T1059.003`` are one
family); a stricter exact-id mode is also available. Rules that fire but are
not on-target are counted as *off-target* alerts: the recordings contain lab
background activity and other attack steps, so this is an upper bound on the
false-positive burden, not an exact FP rate.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .attack import KnowledgeBase, parent
from .replay import ReplayResult
from .sigma import SigmaRule


def on_target(rule_techs: Iterable[str], ds_techs: Iterable[str], exact: bool = False) -> bool:
    rt, dt = set(rule_techs), set(ds_techs)
    if exact:
        return bool(rt & dt)
    return bool({parent(t) for t in rt} & {parent(t) for t in dt})


@dataclass
class TechniqueCoverage:
    technique: str
    name: str
    tactic: str
    datasets: int
    detected: int
    rules: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        if self.detected == 0:
            return "missed"
        return "detected" if self.detected == self.datasets else "partial"

    @property
    def value(self) -> float:
        return {"detected": 1.0, "partial": 0.5, "missed": 0.0}[self.outcome]


@dataclass
class CoverageSummary:
    ruleset: str
    n_rules: int
    datasets: int
    datasets_detected: int
    datasets_any_alert: int
    events: int
    off_target_rules_per_dataset: float
    off_target_alerts_per_10k: float
    techniques: list[TechniqueCoverage]

    @property
    def technique_coverage(self) -> float:
        """Share of techniques with >=1 on-target detection (partial counts as covered)."""
        return sum(t.detected > 0 for t in self.techniques) / max(len(self.techniques), 1)

    @property
    def dataset_recall(self) -> float:
        return self.datasets_detected / max(self.datasets, 1)

    def by_tactic(self) -> dict[str, tuple[int, int]]:
        out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for t in self.techniques:
            out[t.tactic][0] += t.detected > 0
            out[t.tactic][1] += 1
        return {k: (v[0], v[1]) for k, v in sorted(out.items())}

    def weighted(self, weights: dict[str, float]) -> float:
        num = den = 0.0
        for t in self.techniques:
            w = weights.get(t.technique, weights.get(parent(t.technique), 0.0))
            num += w * (t.detected > 0)
            den += w
        return num / den if den else 0.0

    def weighted_ci(self, weights: dict[str, float]) -> tuple[float, float]:
        """95% percentile bootstrap CI of :meth:`weighted`, resampling techniques (fixed seed)."""
        from .stats import weighted_bootstrap_ci

        w = [weights.get(t.technique, weights.get(parent(t.technique), 0.0)) for t in self.techniques]
        return weighted_bootstrap_ci([float(t.detected > 0) for t in self.techniques], w)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleset": self.ruleset, "rules": self.n_rules, "datasets": self.datasets,
            "dataset_recall": self.dataset_recall,
            "datasets_any_alert": self.datasets_any_alert,
            "technique_coverage": self.technique_coverage,
            "techniques": len(self.techniques), "events": self.events,
            "off_target_rules_per_dataset": round(self.off_target_rules_per_dataset, 2),
            "off_target_alerts_per_10k_events": round(self.off_target_alerts_per_10k, 2),
            "by_tactic": {k: {"covered": a, "total": b} for k, (a, b) in self.by_tactic().items()},
            "results": [{"technique": t.technique, "name": t.name, "tactic": t.tactic,
                         "outcome": t.outcome, "datasets": t.datasets, "detected": t.detected,
                         "rules": t.rules[:10]} for t in self.techniques],
        }


def _canon(kb: KnowledgeBase | None):
    if kb is None:
        return lambda ids: tuple(ids)
    return lambda ids: tuple(sorted({kb.canonical(t) for t in ids}))


def score(ruleset: str, results: Sequence[ReplayResult], rules: dict[str, SigmaRule],
          kb: KnowledgeBase | None = None, drop_channels: Iterable[str] = (),
          exact: bool = False) -> CoverageSummary:
    """Score replay results. With ``kb``, revoked ATT&CK ids in dataset labels and rule
    tags (e.g. T1086 -> T1059.001) are mapped to their current replacement first."""
    drop = list(drop_channels)
    canon = _canon(kb)
    rtech = {r: canon(rule.techniques) for r, rule in rules.items()}
    per_t: dict[str, TechniqueCoverage] = {}
    det = anyalert = 0
    off_rules = 0
    off_alerts = 0
    events = 0
    for res in results:
        events += res.n_events
        dtech = canon(res.techniques)
        fired = {r for r in res.fired(drop) if r in rules}
        on = {r for r in fired if on_target(rtech[r], dtech, exact)}
        off = fired - on
        off_rules += len(off)
        off_alerts += sum(n for r in off for c, n in res.hits[r].items() if c not in drop)
        det += bool(on)
        anyalert += bool(fired)
        for t in dtech:
            tc = per_t.get(t)
            if tc is None:
                tc = per_t[t] = TechniqueCoverage(
                    t, kb.name_of(t) if kb else t, kb.tactic_of(t) if kb else "unknown", 0, 0)
            tc.datasets += 1
            hit = {r for r in on if on_target(rtech[r], [t], exact)}
            tc.detected += bool(hit)
            tc.rules = sorted(set(tc.rules) | {rules[r].title or r for r in hit})
    n = max(len(results), 1)
    return CoverageSummary(ruleset, len(rules), len(results), det, anyalert, events,
                           off_rules / n, 1e4 * off_alerts / max(events, 1),
                           sorted(per_t.values(), key=lambda x: x.technique))


def greedy_rule_selection(results: Sequence[ReplayResult], rules: dict[str, SigmaRule],
                          weights: dict[str, float] | None = None, top: int = 10,
                          kb: KnowledgeBase | None = None) -> list[dict[str, Any]]:
    """'Cheapest wins': the few rules that buy the most (weighted) technique coverage."""
    canon = _canon(kb)
    rtech = {r: canon(rule.techniques) for r, rule in rules.items()}
    covers: dict[str, set[str]] = defaultdict(set)
    for res in results:
        dtech = canon(res.techniques)
        for r in res.fired():
            if r in rules:
                for t in dtech:
                    if on_target(rtech[r], [t]):
                        covers[r].add(t)

    def w(t: str) -> float:
        if weights is None:
            return 1.0
        return weights.get(t, weights.get(parent(t), 0.0)) or 1e-6

    total = sum(w(t) for t in {t for r in results for t in canon(r.techniques)})
    got: set[str] = set()
    out = []
    for _ in range(top):
        best = max(covers, key=lambda r: (sum(w(t) for t in covers[r] - got), r), default=None)
        if best is None:
            break
        gain = covers[best] - got
        if not gain:
            break
        got |= gain
        out.append({"rule": rules[best].title or best, "id": best, "path": rules[best].path,
                    "new_techniques": sorted(gain),
                    "cumulative_weighted_coverage": sum(w(t) for t in got) / total})
    return out


def channel_ablation(results: Sequence[ReplayResult], rules: dict[str, SigmaRule],
                     channels: Iterable[str], kb: KnowledgeBase | None = None) -> list[dict[str, Any]]:
    """Techniques lost if a telemetry channel were not collected (value of each log source)."""
    base = score("base", results, rules, kb)
    base_cov = {t.technique for t in base.techniques if t.detected}
    out = []
    for ch in channels:
        s = score(f"-{ch}", results, rules, kb, drop_channels=[ch])
        lost = base_cov - {t.technique for t in s.techniques if t.detected}
        out.append({"channel": ch, "techniques_lost": len(lost), "lost": sorted(lost),
                    "coverage_without": s.technique_coverage})
    out.sort(key=lambda x: -x["techniques_lost"])
    return out


_COLORS = {"detected": "#0ca30c", "partial": "#fab219", "missed": "#d03b3b"}


def navigator_layer(summary: CoverageSummary, attack_version: str = "19",
                    name: str | None = None, weights: dict[str, float] | None = None) -> dict[str, Any]:
    """ATT&CK Navigator layer (format 4.5): green detected / orange partial / red missed."""
    techs = []
    for t in summary.techniques:
        c = f"{t.outcome}: {t.detected}/{t.datasets} recordings detected"
        if t.rules:
            c += "; rules: " + "; ".join(t.rules[:5])
        entry = {"techniqueID": t.technique, "score": t.value * 100, "color": _COLORS[t.outcome],
                 "comment": c, "enabled": True}
        if weights:
            entry["metadata"] = [{"name": "priority", "value": str(round(weights.get(t.technique, 0.0), 3))}]
        techs.append(entry)
    return {
        "name": name or f"GAUNTLET coverage - {summary.ruleset}",
        "versions": {"attack": str(attack_version).split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Detection coverage of {summary.ruleset} on {summary.datasets} OTRF "
                        f"Security-Datasets recordings ({summary.technique_coverage:.0%} of "
                        f"{len(summary.techniques)} techniques). Generated by GAUNTLET."),
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techs,
        "gradient": {"colors": ["#d03b3b", "#fab219", "#0ca30c"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": k, "color": v} for k, v in _COLORS.items()],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }
