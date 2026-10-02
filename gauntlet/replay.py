"""Replay recorded telemetry through a rule set (the real-data 'OBSERVE + DETECT' stage).

Instead of executing techniques, GAUNTLET replays public recordings of them
(OTRF Security-Datasets) through Sigma rules. Rules are indexed by
(channel, EventID) so each event is only tested against rules whose logsource
can apply to it.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import mordor, sigma
from .sigma import LINUX_PREFIXES, SECURITY, SECURITY_4688_MAP, WINDOWS_PREFIXES, EventView, SigmaRule


@dataclass
class ReplayResult:
    dataset_id: str
    techniques: tuple[str, ...]
    n_events: int
    channels: dict[str, int]
    # rule id -> channel -> number of matching events
    hits: dict[str, dict[str, int]] = field(default_factory=dict)

    def fired(self, drop_channels: Iterable[str] = ()) -> set[str]:
        drop = {c.lower() for c in drop_channels}
        return {r for r, chans in self.hits.items() if any(c not in drop for c in chans)}

    def to_json(self) -> dict[str, Any]:
        return {"dataset": self.dataset_id, "techniques": list(self.techniques),
                "n_events": self.n_events, "channels": self.channels, "hits": self.hits}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> ReplayResult:
        return cls(d["dataset"], tuple(d["techniques"]), d["n_events"], d["channels"], d["hits"])


class RuleIndex:
    def __init__(self, rules: list[SigmaRule]):
        self.rules = rules
        self.by_target: dict[tuple[str, int | None], list[SigmaRule]] = defaultdict(list)
        for r in rules:
            for t in dict.fromkeys(r.targets):
                self.by_target[t].append(r)
        self.errors: Counter = Counter()

    def candidates(self, channel: str, eid: int | None) -> list[SigmaRule]:
        a = self.by_target.get((channel, eid), [])
        b = self.by_target.get((channel, None), [])
        return a + b if b else a

    def evaluate(self, events: Iterable[dict[str, Any]]) -> tuple[int, Counter, dict[str, dict[str, int]]]:
        n = 0
        chans: Counter = Counter()
        hits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for raw in events:
            n += 1
            ch, eid, rec = mordor.normalize(raw)
            chans[ch] += 1
            cand = self.candidates(ch, eid)
            if not cand:
                continue
            view = EventView(rec, SECURITY_4688_MAP if (ch == SECURITY and eid == 4688) else None)
            for r in cand:
                try:
                    ok = r.match(view)
                except Exception:  # noqa: BLE001 - a buggy rule must not kill the run
                    self.errors[r.id] += 1
                    continue
                if ok:
                    hits[r.id][ch] += 1
        return n, chans, {k: dict(v) for k, v in hits.items()}


def replay_dataset(index: RuleIndex, ds: mordor.Dataset) -> ReplayResult:
    total, chans, hits = 0, Counter(), {}
    for f in ds.files:
        if not f.exists():
            continue
        n, c, h = index.evaluate(mordor.iter_events(f))
        total += n
        chans.update(c)
        for rid, per in h.items():
            dst = hits.setdefault(rid, {})
            for ch, k in per.items():
                dst[ch] = dst.get(ch, 0) + k
    return ReplayResult(ds.id, ds.techniques, total, dict(chans), hits)


# ---------------------------------------------------------------- rule-set specs
def load_ruleset(spec: str) -> list[SigmaRule]:
    """Rule-set spec: ``sigma-all:<zip-or-dir>``, ``sigma-core:<zip-or-dir>``,
    ``sigma-linux:<zip-or-dir>`` (rules/linux only) or ``legacy:<dir>``.

    ``sigma-core`` keeps rules with status stable/test and level high/critical --
    roughly what a SOC would page on.
    """
    kind, _, path = spec.partition(":")
    if kind == "legacy":
        from .detect import legacy_as_sigma, load_rules

        return [r for r in (legacy_as_sigma(x) for x in load_rules(path)) if r is not None]
    if kind not in ("sigma-all", "sigma-core", "sigma-linux"):
        raise ValueError(f"unknown ruleset kind {kind!r}")
    prefixes = LINUX_PREFIXES if kind == "sigma-linux" else WINDOWS_PREFIXES
    rs = sigma.load_rules(path, subdir_prefix=prefixes if path.endswith(".zip") else "")
    rules = rs.rules
    if kind == "sigma-core":
        rules = [r for r in rules if r.status in ("stable", "test") and r.level in ("high", "critical")]
    return rules


_WORKER: dict[str, RuleIndex] = {}


def _init(spec: str) -> None:
    _WORKER["idx"] = RuleIndex(load_ruleset(spec))


def _work(ds: mordor.Dataset) -> dict[str, Any]:
    return replay_dataset(_WORKER["idx"], ds).to_json()


def replay_many(spec: str, datasets: list[mordor.Dataset], workers: int | None = None,
                cache: Path | None = None, progress: bool = True) -> list[ReplayResult]:
    """Replay many datasets in parallel; results cached to ``cache`` (JSON) if given."""
    done: dict[str, ReplayResult] = {}
    if cache and cache.exists():
        for d in json.loads(cache.read_text(encoding="utf-8"))["results"]:
            done[d["dataset"]] = ReplayResult.from_json(d)
    todo = [d for d in datasets if d.id not in done and d.available]
    if todo:
        workers = workers or max(1, min(len(todo), (os.cpu_count() or 2) - 1))
        with ProcessPoolExecutor(workers, initializer=_init, initargs=(spec,)) as ex:
            for i, res in enumerate(ex.map(_work, todo), 1):
                r = ReplayResult.from_json(res)
                done[r.dataset_id] = r
                if progress:
                    print(f"  [{i}/{len(todo)}] {r.dataset_id} events={r.n_events} rules_fired={len(r.hits)}",
                          flush=True)
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"spec": spec, "results": [v.to_json() for v in done.values()]}),
                             encoding="utf-8")
    return [done[d.id] for d in datasets if d.id in done]
