"""Technique co-occurrence model: "given what we've seen, what comes next?"

Item-item collaborative filtering over ATT&CK group -> technique sets. For an
observed set S, a candidate technique t scores

    score(t | S) = sum_{s in S} cooc(s, t) / sqrt(n(s) * n(t))   (cosine)

plus a tiny popularity prior to break ties. Evaluated with leave-one-group-out:
hide half of a group's techniques, predict them from the other half using a
model trained on every *other* group, compare with a popularity baseline.
"""
from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence


class CooccurrenceModel:
    def __init__(self, sets: Iterable[set[str]]):
        self.n: Counter = Counter()
        self.co: dict[str, Counter] = defaultdict(Counter)
        self.n_sets = 0
        for s in sets:
            self.add(s, +1)

    def add(self, s: set[str], sign: int = 1) -> None:
        self.n_sets += sign
        items = sorted(s)
        for a in items:
            self.n[a] += sign
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                self.co[a][b] += sign
                self.co[b][a] += sign

    def predict(self, observed: set[str], k: int = 10, exclude: set[str] | None = None) -> list[tuple[str, float]]:
        exclude = (exclude or set()) | observed
        scores: dict[str, float] = defaultdict(float)
        for s in observed:
            ns = self.n.get(s, 0)
            if ns <= 0:
                continue
            for t, c in self.co[s].items():
                if c > 0 and t not in exclude and self.n[t] > 0:
                    scores[t] += c / math.sqrt(ns * self.n[t])
        denom = max(self.n_sets, 1)
        for t, c in self.n.items():
            if c > 0 and t not in exclude:
                scores[t] += 1e-3 * c / denom
        return sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:k]

    def popularity(self, k: int = 10, exclude: set[str] | None = None) -> list[tuple[str, float]]:
        exclude = exclude or set()
        items = [(t, c / max(self.n_sets, 1)) for t, c in self.n.items() if c > 0 and t not in exclude]
        return sorted(items, key=lambda x: (-x[1], x[0]))[:k]


def evaluate(sets: Sequence[set[str]], ks=(5, 10, 20), hide: float = 0.5, seed: int = 0,
             min_size: int = 10) -> dict:
    """Leave-one-group-out recall@k / MRR, co-occurrence vs popularity."""
    rnd = random.Random(seed)
    model = CooccurrenceModel(sets)
    res: dict[str, dict[str, list[float]]] = {"cooccurrence": {}, "popularity": {}}
    n_eval = 0
    for s in sets:
        if len(s) < min_size:
            continue
        n_eval += 1
        items = sorted(s)
        rnd.shuffle(items)
        cut = max(1, int(len(items) * (1 - hide)))
        seen, hidden = set(items[:cut]), set(items[cut:])
        model.add(s, -1)
        kmax = max(ks)
        preds = {"cooccurrence": [t for t, _ in model.predict(seen, k=kmax)],
                 "popularity": [t for t, _ in model.popularity(k=kmax, exclude=seen)]}
        full = {"cooccurrence": [t for t, _ in model.predict(seen, k=10_000)],
                "popularity": [t for t, _ in model.popularity(k=10_000, exclude=seen)]}
        model.add(s, +1)
        for name, p in preds.items():
            m = res[name]
            for k in ks:
                m.setdefault(f"recall@{k}", []).append(len(set(p[:k]) & hidden) / len(hidden))
                m.setdefault(f"precision@{k}", []).append(len(set(p[:k]) & hidden) / k)
            rr = next((1 / i for i, t in enumerate(full[name], 1) if t in hidden), 0.0)
            m.setdefault("mrr", []).append(rr)
    return {"groups_evaluated": n_eval, "hide_fraction": hide,
            "models": {k: {m: round(statistics.fmean(v), 4) for m, v in d.items()} for k, d in res.items()}}
