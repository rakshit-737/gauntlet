"""Cross-dataset benchmark and the *claimed vs measured* coverage analysis.

Sources (each scored separately, never pooled, because label granularity and lab
background differ):

* ``otrf`` -- OTRF Security-Datasets atomic Windows recordings (the v1.0 benchmark);
* ``otrf-compound`` -- OTRF compound LSASS campaigns (multi-technique recordings);
* ``splunk-windows`` / ``splunk-linux`` -- Splunk attack_data recordings selected by
  the committed manifest ``scripts/splunk_attack_data.json`` (labels are per
  recording, taken from each dataset's ``mitre_technique`` list).

For every recorded technique the analysis compares

* **claimed** coverage -- at least one rule in the rule set is *tagged* with the
  technique's family (what a tag-based coverage map, e.g. ATT&CK Navigator
  layers generated from rule tags, would report), with
* **measured** coverage -- at least one such rule actually fired on-target on a
  recording of the technique.

Claimed-but-not-measured techniques are classified from data the replay
already records:

* ``telemetry_gap`` -- no tagged rule's target (channel, EventID) occurs in any
  recording of the technique: the rule could not have fired on this data;
* ``rule_logic_gap`` -- the target telemetry is present but no tagged rule matched.

The paired difference is tested with an exact McNemar test (claimed is never
lower than measured, so all discordant pairs point one way).
"""
from __future__ import annotations

import json
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import coverage, mordor, paths, prioritize, replay, stats
from .attack import KnowledgeBase, load_kb, load_stix, parent
from .sigma import SigmaRule


def _kb(root: Path) -> KnowledgeBase:
    b = paths.attack_bundle(root)
    return load_stix(b) if b.exists() else load_kb()


def claimed_vs_measured(results: Sequence[replay.ReplayResult], rules: dict[str, SigmaRule],
                        kb: KnowledgeBase | None = None) -> dict[str, Any]:
    """Per-technique claimed (rule tags) vs measured (on-target firing) coverage with gap classes."""
    canon = (lambda ids: tuple(sorted({kb.canonical(t) for t in ids}))) if kb else tuple
    summ = coverage.score("x", results, rules, kb)
    measured = {t.technique: t.detected > 0 for t in summ.techniques}
    rfam = {rid: {parent(t) for t in canon(r.techniques)} for rid, r in rules.items()}
    # channels/EventIDs seen per technique: ReplayResult.channels is per channel only, so the
    # (channel, None) wildcard and channel membership are what we can check without re-replaying
    chans: dict[str, set[str]] = {}
    for res in results:
        for t in canon(res.techniques):
            chans.setdefault(t, set()).update(res.channels)
    rows = []
    for t in sorted(measured):
        tagged = [rid for rid, fam in rfam.items() if parent(t) in fam]
        claimed = bool(tagged)
        gap = None
        if claimed and not measured[t]:
            seen = chans.get(t, set())
            reachable = any(c in seen for rid in tagged for c, _ in rules[rid].targets)
            gap = "rule_logic_gap" if reachable else "telemetry_gap"
        rows.append({"technique": t, "name": kb.name_of(t) if kb else t, "claimed": claimed,
                     "tagged_rules": len(tagged), "measured": measured[t], "gap": gap})
    n = len(rows)
    c = sum(r["claimed"] for r in rows)
    m = sum(r["measured"] for r in rows)
    b = sum(r["claimed"] and not r["measured"] for r in rows)
    cc = sum(r["measured"] and not r["claimed"] for r in rows)
    gaps: dict[str, int] = {}
    for r in rows:
        if r["gap"]:
            gaps[r["gap"]] = gaps.get(r["gap"], 0) + 1
    return {"techniques": n,
            "claimed": c, "claimed_rate": round(c / n, 4) if n else 0.0, "claimed_ci95": list(stats.wilson(c, n)),
            "measured": m, "measured_rate": round(m / n, 4) if n else 0.0, "measured_ci95": list(stats.wilson(m, n)),
            "overstatement_points": round(100 * (c - m) / n, 1) if n else 0.0,
            "discordant_claimed_only": b, "discordant_measured_only": cc,
            "mcnemar_p": stats.mcnemar_exact(b, cc), "gap_classes": gaps, "rows": rows}


def _sources(root: Path) -> dict[str, list[mordor.Dataset]]:
    sp = mordor.load_splunk(root)
    out = {"otrf": mordor.load_catalog(root), "otrf-compound": mordor.load_compound(root),
           "splunk-windows": [d for d in sp if d.tactic_dir == "windows"],
           "splunk-linux": [d for d in sp if d.tactic_dir == "linux"]}
    return {k: [d for d in v if d.available and d.techniques] for k, v in out.items()}


def run(root: Path | None = None, out: Path | None = None, workers: int | None = None,
        full_rules: Path | None = None, use_cache: bool = True) -> dict[str, Any]:
    """Replay every source with the matching platform rule set(s); write ``extended.json``/``EXTENDED.md``."""
    root = root or paths.data_dir()
    out = out or Path.cwd() / "results"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    kb = _kb(root)
    srcs = _sources(root)
    zipspec = str(paths.sigma_zip(root))
    specs = {"windows": {"sigma-all": f"sigma-all:{zipspec}"}, "linux": {"sigma-all": f"sigma-linux:{zipspec}"}}
    if full_rules:
        specs["windows"]["sigma-full"] = f"sigma-all:{full_rules}"
        specs["linux"]["sigma-full"] = f"sigma-linux:{full_rules}"
    kept: dict[tuple[str, str], tuple[list[replay.ReplayResult], dict[str, SigmaRule]]] = {}
    report: dict[str, Any] = {"sigma_release": paths.SIGMA_TAG, "attack_version": kb.version,
                              "skipped_unavailable": {}, "sources": {}}
    for k, v in (("otrf", mordor.load_catalog(root)), ("otrf-compound", mordor.load_compound(root)),
                 ("splunk", mordor.load_splunk(root))):
        report["skipped_unavailable"][k] = sorted(d.id for d in v if d.techniques and not d.available)
    for src, ds in srcs.items():
        if not ds:
            report["sources"][src] = {"recordings": 0}
            continue
        plat = "linux" if src.endswith("linux") else "windows"
        entry: dict[str, Any] = {"recordings": len(ds),
                                 "techniques": len({kb.canonical(t) for d in ds for t in d.techniques}),
                                 "rulesets": {}}
        for name, spec in specs[plat].items():
            print(f"[{src}] {name}: {len(ds)} recordings", flush=True)
            rules = {r.id: r for r in replay.load_ruleset(spec)}
            cache = (root / "cache" / f"ext-{src}-{name}-{paths.SIGMA_TAG}.json") if use_cache else None
            res = replay.replay_many(spec, ds, workers=workers, cache=cache, progress=False)
            s = coverage.score(name, res, rules, kb)
            n_cov = sum(t.detected > 0 for t in s.techniques)
            d = {k: v for k, v in s.to_dict().items() if k not in ("by_tactic",)}
            d["ci95"] = {"technique_coverage": list(stats.wilson(n_cov, len(s.techniques))),
                         "dataset_recall": list(stats.wilson(s.datasets_detected, s.datasets))}
            d["fully_detected_coverage"] = round(
                sum(t.outcome == "detected" for t in s.techniques) / max(len(s.techniques), 1), 4)
            d["claimed_vs_measured"] = claimed_vs_measured(res, rules, kb)
            d["record_types"] = _record_types(res)
            entry["rulesets"][name] = d
            kept[(src, name)] = (res, rules)
        report["sources"][src] = entry
    report["cross_dataset"] = _agreement(report)
    if ("otrf", "sigma-all") in kept and ("splunk-windows", "sigma-all") in kept:
        report["held_out_selection"] = held_out_selection(kept[("otrf", "sigma-all")],
                                                          kept[("splunk-windows", "sigma-all")], kb)
    report["runtime_seconds"] = round(time.time() - t0, 1)
    (out / "extended.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    (out / "EXTENDED.md").write_text(render_md(report), encoding="utf-8")
    try:
        from .figures import claimed_vs_measured as fig
        fig(report, out)
    except ImportError as e:  # matplotlib optional
        print(f"skipping figure: {e}")
    print(f"done in {report['runtime_seconds']}s -> {out / 'EXTENDED.md'}")
    return report


def held_out_selection(train: tuple[list[replay.ReplayResult], dict[str, SigmaRule]],
                       test: tuple[list[replay.ReplayResult], dict[str, SigmaRule]],
                       kb: KnowledgeBase, k: int = 10, seeds: int = 200) -> dict[str, Any]:
    """Select k rules on OTRF (train), score them on Splunk Windows recordings (test).

    Compares CTI-weighted greedy (ransomware relevance), unweighted greedy and random draws of k
    rules from those that fired on-target on OTRF. Coverage is technique coverage on the test set.
    """
    import random

    tr_res, rules = train
    te_res, _ = test
    rel = prioritize.relevance(prioritize.profile_groups(kb, "ransomware"))

    def test_cov(ids: set[str]) -> tuple[float, float]:
        s = coverage.score("sel", te_res, {i: rules[i] for i in ids if i in rules}, kb)
        return s.technique_coverage, s.weighted(rel)

    pool = sorted({r for res in tr_res for r in res.fired() if r in rules and coverage.on_target(
        rules[r].techniques, res.techniques)})
    out: dict[str, Any] = {"k": k, "train": "otrf", "test": "splunk-windows", "candidate_rules": len(pool)}
    for name, w in (("greedy_cti_weighted", rel), ("greedy_unweighted", None)):
        sel = {x["id"] for x in coverage.greedy_rule_selection(tr_res, rules, w, top=k, kb=kb)}
        c, cw = test_cov(sel)
        out[name] = {"test_technique_coverage": round(c, 4), "test_ransomware_weighted": round(cw, 4)}
    rnd = random.Random(0)
    draws = [test_cov(set(rnd.sample(pool, min(k, len(pool))))) for _ in range(seeds)]
    cs, ws = sorted(d[0] for d in draws), sorted(d[1] for d in draws)
    q = lambda v, p: v[min(len(v) - 1, int(p * len(v)))]  # noqa: E731
    out["random"] = {"test_technique_coverage_mean": round(sum(cs) / len(cs), 4),
                     "test_technique_coverage_95": [round(q(cs, .025), 4), round(q(cs, .975), 4)],
                     "test_ransomware_weighted_mean": round(sum(ws) / len(ws), 4),
                     "test_ransomware_weighted_95": [round(q(ws, .025), 4), round(q(ws, .975), 4)],
                     "draws": seeds}
    for name in ("greedy_cti_weighted", "greedy_unweighted"):
        v = out[name]["test_ransomware_weighted"]
        out[name]["random_draws_at_or_above"] = round(sum(x >= v for x in ws) / len(ws), 4)
    return out


def _record_types(results: Sequence[replay.ReplayResult]) -> dict[str, int]:
    """How many recordings contain each channel (telemetry completeness, e.g. auditd without EXECVE)."""
    out: dict[str, int] = {}
    for r in results:
        for c in r.channels:
            out[c] = out.get(c, 0) + 1
    return dict(sorted(out.items(), key=lambda x: -x[1])[:15])


def _agreement(report: dict[str, Any]) -> dict[str, Any]:
    """Techniques recorded in both OTRF and Splunk (Windows): does measured coverage agree?"""
    try:
        a = {r["technique"]: r["measured"] for r in
             report["sources"]["otrf"]["rulesets"]["sigma-all"]["claimed_vs_measured"]["rows"]}
        b = {r["technique"]: r["measured"] for r in
             report["sources"]["splunk-windows"]["rulesets"]["sigma-all"]["claimed_vs_measured"]["rows"]}
    except KeyError:
        return {}
    both = sorted(set(a) & set(b))
    agree = sum(a[t] == b[t] for t in both)
    return {"shared_techniques": len(both), "agree": agree,
            "otrf_only_detected": [t for t in both if a[t] and not b[t]],
            "splunk_only_detected": [t for t in both if b[t] and not a[t]]}


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render_md(r: dict[str, Any]) -> str:
    L = ["# Cross-dataset benchmark: claimed vs measured coverage", "",
         f"Generated by `python -m gauntlet extended` (SigmaHQ {r['sigma_release']}, ATT&CK v{r['attack_version']}).",
         "*Claimed* = at least one rule is tagged with the technique (family match); *measured* = such a rule "
         "fired on-target on a recording of it. Technique coverage counts partially detected techniques as "
         "covered; *fully detected* requires every recording of the technique to be detected.", "",
         "| Source | Rule set | Recordings | Techniques | Claimed | Measured [95% CI] | Fully detected "
         "| Overstatement (pts) | McNemar p | Gaps (telemetry / rule logic) |",
         "|---|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for src, e in r["sources"].items():
        for name, d in (e.get("rulesets") or {}).items():
            cm = d["claimed_vs_measured"]
            ci = d["ci95"]["technique_coverage"]
            g = cm["gap_classes"]
            L.append(f"| {src} | {name} | {e['recordings']} | {cm['techniques']} | {_pct(cm['claimed_rate'])} "
                     f"| {_pct(cm['measured_rate'])} [{_pct(ci[0])}, {_pct(ci[1])}] "
                     f"| {_pct(d['fully_detected_coverage'])} | {cm['overstatement_points']} | {cm['mcnemar_p']:.4g} "
                     f"| {g.get('telemetry_gap', 0)} / {g.get('rule_logic_gap', 0)} |")
        if not e.get("rulesets"):
            L.append(f"| {src} | - | 0 | - | - | - | - | - | - | - |")
    x = r.get("cross_dataset") or {}
    if x:
        L += ["", f"OTRF vs Splunk (Windows, sigma-all): {x['shared_techniques']} techniques recorded in both; "
              f"measured outcome agrees on {x['agree']}. Detected only on OTRF: "
              f"{', '.join(x['otrf_only_detected']) or 'none'}; only on Splunk: "
              f"{', '.join(x['splunk_only_detected']) or 'none'}."]
    h = r.get("held_out_selection")
    if h:
        g, u, rn = h["greedy_cti_weighted"], h["greedy_unweighted"], h["random"]
        L += ["", f"## Held-out rule selection: pick {h['k']} rules on OTRF, test on Splunk Windows", "",
              "| Selection on OTRF | Test technique coverage | Test ransomware-weighted coverage "
              "| Random draws at or above |", "|---|---:|---:|---:|",
              f"| CTI-weighted greedy | {_pct(g['test_technique_coverage'])} | {_pct(g['test_ransomware_weighted'])} "
              f"| {_pct(g['random_draws_at_or_above'])} |",
              f"| Unweighted greedy | {_pct(u['test_technique_coverage'])} | {_pct(u['test_ransomware_weighted'])} "
              f"| {_pct(u['random_draws_at_or_above'])} |",
              f"| Random {h['k']} of {h['candidate_rules']} OTRF-firing rules ({rn['draws']} draws, mean "
              f"[2.5, 97.5 pct]) | {_pct(rn['test_technique_coverage_mean'])} "
              f"[{_pct(rn['test_technique_coverage_95'][0])}, {_pct(rn['test_technique_coverage_95'][1])}] "
              f"| {_pct(rn['test_ransomware_weighted_mean'])} [{_pct(rn['test_ransomware_weighted_95'][0])}, "
              f"{_pct(rn['test_ransomware_weighted_95'][1])}] | - |"]
    sk = {k: v for k, v in r.get("skipped_unavailable", {}).items() if v}
    L += ["", "Recordings skipped because a file was missing or unreadable: "
          + ("; ".join(f"{k}: {', '.join(v)}" for k, v in sk.items()) if sk else "none") + "."]
    L += ["", f"Runtime {r.get('runtime_seconds')} s.", ""]
    return "\n".join(L)
