"""CTI prioritizer on real ATT&CK data.

Threat profiles are *sets of real ATT&CK groups*. By default a profile is
selected reproducibly from group descriptions (e.g. every group whose ATT&CK
description mentions ransomware), or explicitly by group ids/names.

    relevance(T)  = share of profile groups with a documented procedure for T
    prevalence(T) = share of *all* ATT&CK groups with a documented procedure for T
    score(T)      = relevance(T) * prevalence(T) / max(prevalence)     ("cti")

Alternative strategies (for the research question "does CTI-prioritized
emulation reach relevant coverage faster than breadth-first?"):
``breadth`` (ATT&CK id order), ``random``, ``prevalence`` (global only),
``relevance`` (profile only), ``cti`` (product, default).
"""
from __future__ import annotations

import random
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from . import stats
from .attack import AttackGroup, KnowledgeBase, parent

PROFILE_PATTERNS: dict[str, tuple[str, str]] = {
    "ransomware": (r"ransomware", "Groups whose ATT&CK description mentions ransomware"),
    "espionage": (r"espionage|intelligence[- ]gathering|intelligence collection",
                  "Cyber-espionage groups (description mentions espionage / intelligence collection)"),
    "financial": (r"financially[- ]motivated|financial gain|financial crime",
                  "Financially-motivated crime groups"),
    "cloud": (r"\bcloud\b|\bSaaS\b|Microsoft 365|Office 365|Azure|\bAWS\b",
              "Groups documented operating against cloud / SaaS environments"),
}

STRATEGIES = ("cti", "relevance", "prevalence", "breadth", "random")


@dataclass(frozen=True)
class Ranked:
    technique: str
    score: float
    relevance: float
    prevalence: float


def profile_groups(kb: KnowledgeBase, profile: str) -> list[AttackGroup]:
    """Resolve a named profile or a comma list of group ids / names / aliases."""
    if profile in PROFILE_PATTERNS:
        return [g for g in kb.groups_matching(PROFILE_PATTERNS[profile][0]) if g.techniques]
    out = []
    for key in profile.split(","):
        g = kb.find_group(key)
        if g is None:
            raise KeyError(f"unknown ATT&CK group {key!r}")
        out.append(g)
    return out


def _uses(groups: Iterable[AttackGroup]) -> list[set[str]]:
    return [g.techniques | {parent(t) for t in g.techniques} for g in groups]


def relevance(groups: Sequence[AttackGroup]) -> dict[str, float]:
    sets = _uses(groups)
    n = max(len(sets), 1)
    out: dict[str, float] = {}
    for s in sets:
        for t in s:
            out[t] = out.get(t, 0) + 1 / n
    return out


def prevalence(groups: Sequence[AttackGroup]) -> dict[str, float]:
    return relevance(groups)


def rank(candidates: Iterable[str], rel: dict[str, float], prev: dict[str, float],
         strategy: str = "cti", seed: int = 0) -> list[Ranked]:
    """Order candidate technique ids by a strategy (ties broken by id, deterministic)."""
    cands = sorted(set(candidates))
    pmax = max(prev.values(), default=1.0) or 1.0

    def r(t: str) -> float:
        return rel.get(t, rel.get(parent(t), 0.0) * 0.5)  # sub-tech inherits half of parent use

    def p(t: str) -> float:
        return prev.get(t, prev.get(parent(t), 0.0) * 0.5) / pmax

    if strategy == "breadth":
        return [Ranked(t, 0.0, r(t), p(t)) for t in cands]
    if strategy == "random":
        rnd = random.Random(seed)
        cands = cands[:]
        rnd.shuffle(cands)
        return [Ranked(t, 0.0, r(t), p(t)) for t in cands]
    key = {"cti": lambda t: r(t) * p(t), "relevance": r, "prevalence": p}[strategy]
    out = [Ranked(t, round(key(t), 6), round(r(t), 4), round(p(t), 4)) for t in cands]
    out.sort(key=lambda x: (-x.score, -x.relevance, x.technique))
    return out


# ------------------------------------------------------------------ evaluation
def recall_curve(order: Sequence[str], target: set[str]) -> list[float]:
    got, out = 0, []
    for t in order:
        got += t in target
        out.append(got / len(target) if target else 0.0)
    return out


def steps_to(curve: Sequence[float], level: float) -> int:
    for i, v in enumerate(curve, 1):
        if v >= level - 1e-12:
            return i
    return len(curve) + 1


def evaluate_logo(kb: KnowledgeBase, profile: str, universe: set[str], ks=(10, 25, 50),
                  random_seeds: int = 30, min_target: int = 5, curve_len: int = 100) -> dict:
    """Leave-one-group-out evaluation of prioritization strategies.

    For each group g in the profile: relevance is computed from the *other*
    profile groups, prevalence from all groups except g, the candidate list is
    ``universe`` (techniques GAUNTLET can emulate), and we measure how quickly
    each ordering covers g's techniques inside the universe.
    """
    groups = profile_groups(kb, profile)
    allg = list(kb.groups.values())
    per: dict[str, dict[str, list[float]]] = {s: {} for s in STRATEGIES}
    curves: dict[str, list[list[float]]] = {s: [] for s in STRATEGIES}
    n_eval = 0
    for g in groups:
        target = {t for t in g.techniques if t in universe}
        if len(target) < min_target:
            continue
        n_eval += 1
        rel = relevance([x for x in groups if x.id != g.id])
        prev = prevalence([x for x in allg if x.id != g.id])
        for s in STRATEGIES:
            seeds = range(random_seeds) if s == "random" else [0]
            for seed in seeds:
                order = [x.technique for x in rank(universe, rel, prev, s, seed)]
                curve = recall_curve(order, target)
                curves[s].append(curve[:curve_len])
                m = per[s]
                for k in ks:
                    m.setdefault(f"recall@{k}", []).append(curve[min(k, len(curve)) - 1])
                m.setdefault("steps_to_50%", []).append(steps_to(curve, 0.5))
                m.setdefault("steps_to_80%", []).append(steps_to(curve, 0.8))
                m.setdefault("auc", []).append(sum(curve) / len(curve))
    summary = {s: {k: round(statistics.fmean(v), 4) for k, v in m.items()} for s, m in per.items() if m}
    # per-group values (random: mean over its seeds) -> bootstrap CIs over held-out groups
    per_group: dict[str, dict[str, list[float]]] = {}
    for s, m in per.items():
        step = random_seeds if s == "random" else 1
        per_group[s] = {k: [statistics.fmean(v[i:i + step]) for i in range(0, len(v), step)] for k, v in m.items()}
    ci = {s: {k: list(stats.bootstrap_ci(v)) for k, v in m.items() if k in ("steps_to_80%", "auc", "recall@25")}
          for s, m in per_group.items() if m}
    paired = {}
    if n_eval:
        for other in ("breadth", "prevalence", "random"):
            paired[f"cti_minus_{other}"] = {
                k: stats.paired_bootstrap_ci(per_group["cti"][k], per_group[other][k])
                for k in ("steps_to_80%", "auc")}
    mean_curves = {s: [round(statistics.fmean(c[i] for c in cs), 4) for i in range(min(map(len, cs)))]
                   for s, cs in curves.items() if cs}
    return {"profile": profile, "groups_in_profile": len(groups), "groups_evaluated": n_eval,
            "universe": len(universe), "strategies": summary, "ci95": ci, "paired": paired,
            "mean_curves": mean_curves}
