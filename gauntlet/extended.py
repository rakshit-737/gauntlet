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

Claimed-but-not-measured techniques are classified from the per-recording
(channel, EventID) event counts the replay records:

* ``telemetry_gap`` -- no tagged rule's target (channel, EventID) occurs in any
  recording of the technique: the rule could not have fired on this data;
* ``rule_logic_gap`` -- events of a tagged rule's target (channel, EventID) are in a
  recording of the technique, but no tagged rule matched them.

Measured coverage is nested in claimed coverage by construction (a measured
technique needs a rule tagged with it), so every discordant technique points the
same way and a McNemar test would only restate their number. The overstatement is
therefore reported as claimed-only techniques / techniques, in points, with a
95% Wilson interval.
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
    exact_measured = {t.technique: t.detected > 0
                      for t in coverage.score("x", results, rules, kb, exact=True).techniques}
    rtech = {rid: set(canon(r.techniques)) for rid, r in rules.items()}
    rfam = {rid: {parent(t) for t in ts} for rid, ts in rtech.items()}
    recs: dict[str, list[replay.ReplayResult]] = {}
    for res in results:
        for t in canon(res.techniques):
            recs.setdefault(t, []).append(res)
    rows = []
    for t in sorted(measured):
        tagged = [rid for rid, fam in rfam.items() if parent(t) in fam]
        claimed = bool(tagged)
        gap = None
        if claimed and not measured[t]:
            # reachable = a recording of t has events of a tagged rule's (channel, EventID) target
            reachable = any(res.has_target(ch, eid) for rid in tagged for ch, eid in rules[rid].targets
                            for res in recs.get(t, []))
            gap = "rule_logic_gap" if reachable else "telemetry_gap"
        rows.append({"technique": t, "name": kb.name_of(t) if kb else t, "claimed": claimed,
                     "tagged_rules": len(tagged), "measured": measured[t], "gap": gap,
                     "exact_claimed": any(t in ts for ts in rtech.values()),
                     "exact_measured": exact_measured.get(t, False)})
    n = len(rows)
    c = sum(r["claimed"] for r in rows)
    m = sum(r["measured"] for r in rows)
    b = sum(r["claimed"] and not r["measured"] for r in rows)
    cc = sum(r["measured"] and not r["claimed"] for r in rows)  # 0 by construction
    ec = sum(r["exact_claimed"] for r in rows)
    em = sum(r["exact_measured"] for r in rows)
    eb = sum(r["exact_claimed"] and not r["exact_measured"] for r in rows)
    gaps: dict[str, int] = {}
    for r in rows:
        if r["gap"]:
            gaps[r["gap"]] = gaps.get(r["gap"], 0) + 1
    return {"techniques": n,
            "claimed": c, "claimed_rate": c / n if n else 0.0, "claimed_ci95": list(stats.wilson(c, n)),
            "measured": m, "measured_rate": m / n if n else 0.0, "measured_ci95": list(stats.wilson(m, n)),
            "overstatement_points": 100 * (c - m) / n if n else 0.0,
            "overstatement_ci95": list(stats.wilson(b, n)),
            "discordant_claimed_only": b, "discordant_measured_only": cc,
            "exact_id": {"claimed": ec, "measured": em, "claimed_only": eb,
                         "claimed_rate": ec / n if n else 0.0, "claimed_ci95": list(stats.wilson(ec, n)),
                         "measured_rate": em / n if n else 0.0,
                         "measured_ci95": list(stats.wilson(em, n)),
                         "overstatement_points": 100 * eb / n if n else 0.0,
                         "overstatement_ci95": list(stats.wilson(eb, n))},
            "gap_classes": gaps, "rows": rows}


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
    report: dict[str, Any] = {**paths.provenance(), "sigma_release": paths.SIGMA_TAG, "attack_version": kb.version,
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
                         "dataset_recall": list(stats.wilson(s.datasets_detected, s.datasets)),
                         "fully_detected_coverage": list(stats.wilson(
                             sum(t.outcome == "detected" for t in s.techniques), len(s.techniques)))}
            d["fully_detected_coverage"] = (
                sum(t.outcome == "detected" for t in s.techniques) / max(len(s.techniques), 1))
            d["claimed_vs_measured"] = claimed_vs_measured(res, rules, kb)
            d["record_types"] = _record_types(res)
            # events whose channel could not be parsed can never match a rule (RuleIndex keys on channel)
            d["unparsed_channel"] = {"events": sum(r.channels.get("", 0) for r in res),
                                     "recordings": sum(r.channels.get("", 0) > 0 for r in res),
                                     "events_total": sum(r.n_events for r in res)}
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

    def test_weighted_ci(ids: set[str]) -> list[float]:
        return list(coverage.score("sel", te_res, {i: rules[i] for i in ids if i in rules}, kb).weighted_ci(rel))

    pool = sorted({r for res in tr_res for r in res.fired() if r in rules and coverage.on_target(
        rules[r].techniques, res.techniques)})
    out: dict[str, Any] = {"k": k, "train": "otrf", "test": "splunk-windows", "candidate_rules": len(pool)}
    n_test = len(coverage.score("all", te_res, {}, kb).techniques)
    out["test_techniques"] = n_test
    for name, w in (("greedy_cti_weighted", rel), ("greedy_unweighted", None)):
        sel = {x["id"] for x in coverage.greedy_rule_selection(tr_res, rules, w, top=k, kb=kb)}
        c, cw = test_cov(sel)
        hit = round(c * n_test)
        out[name] = {"test_technique_coverage": c, "test_techniques_covered": hit,
                     "test_technique_coverage_ci95": list(stats.wilson(hit, n_test)),
                     "test_ransomware_weighted": cw, "test_ransomware_weighted_ci95": test_weighted_ci(sel)}
    rnd = random.Random(0)
    draws = [test_cov(set(rnd.sample(pool, min(k, len(pool))))) for _ in range(seeds)]
    cs, ws = sorted(d[0] for d in draws), sorted(d[1] for d in draws)
    q = lambda v, p: v[min(len(v) - 1, int(p * len(v)))]  # noqa: E731
    out["random"] = {"test_technique_coverage_mean": sum(cs) / len(cs),
                     "test_technique_coverage_95": [q(cs, .025), q(cs, .975)],
                     "test_ransomware_weighted_mean": sum(ws) / len(ws),
                     "test_ransomware_weighted_95": [q(ws, .025), q(ws, .975)],
                     "draws": seeds}
    for name in ("greedy_cti_weighted", "greedy_unweighted"):
        v = out[name]["test_ransomware_weighted"]
        out[name]["random_draws_at_or_above"] = sum(x >= v for x in ws) / len(ws)
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
    oo = [t for t in both if a[t] and not b[t]]
    so = [t for t in both if b[t] and not a[t]]
    # not nested (different recordings of the same technique), so an exact McNemar test is meaningful
    return {"shared_techniques": len(both), "agree": agree, "agree_ci95": list(stats.wilson(agree, len(both))),
            "otrf_only_detected": oo, "splunk_only_detected": so,
            "mcnemar_p": stats.mcnemar_exact(len(oo), len(so))}


def _pct(x: float) -> str:
    return f"{stats.pct(x)}%"


def _ci(ci) -> str:
    return stats.fmt_ci(ci)


def render_md(r: dict[str, Any]) -> str:
    L = ["# Cross-dataset benchmark: claimed vs measured coverage", "",
         f"Generated by `python -m gauntlet extended` (SigmaHQ {r['sigma_release']}, ATT&CK v{r['attack_version']}). "
         + paths.provenance_line(r),
         "*Claimed* = at least one rule is tagged with the technique (family match); *measured* = such a rule "
         "fired on-target on a recording of it. Technique coverage counts partially detected techniques as "
         "covered; *fully detected* requires every recording of the technique to be detected. Brackets are 95% "
         "Wilson intervals computed from the raw counts and rounded once.", "",
         "Measured is a subset of claimed by construction (a technique can only be measured by a rule tagged "
         "with it), so every discordant technique points the same way and a McNemar test would only restate "
         "their count. The overstatement is therefore reported as claimed-but-not-measured techniques / "
         "techniques, in points, with a Wilson interval. *Gaps*: a tagged rule's (channel, EventID) target "
         "never occurs in a recording of the technique (telemetry) or does occur but no tagged rule matched "
         "(rule logic).", "",
         "| Source | Rule set | Recordings | Techniques | Claimed [95% CI] | Measured [95% CI] "
         "| Fully detected [95% CI] | Claimed, not measured | Overstatement, pts [95% CI] "
         "| Gaps (telemetry / rule logic) |",
         "|---|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for src, e in r["sources"].items():
        for name, d in (e.get("rulesets") or {}).items():
            cm = d["claimed_vs_measured"]
            ci = d["ci95"]["technique_coverage"]
            g = cm["gap_classes"]
            L.append(f"| {src} | {name} | {e['recordings']} | {cm['techniques']} | {_pct(cm['claimed_rate'])}"
                     f"{_ci(cm.get('claimed_ci95'))} | {_pct(cm['measured_rate'])}{_ci(ci)} "
                     f"| {_pct(d['fully_detected_coverage'])}{_ci(d['ci95'].get('fully_detected_coverage'))} "
                     f"| {cm['discordant_claimed_only']} "
                     f"| {stats.pct(cm['overstatement_points'] / 100)}{_ci(cm.get('overstatement_ci95'))} "
                     f"| {g.get('telemetry_gap', 0)} / {g.get('rule_logic_gap', 0)} |")
        if not e.get("rulesets"):
            L.append(f"| {src} | - | 0 | - | - | - | - | - | - | - |")
    L += ["", "Exact-ID variant (a rule tagged with exactly the recorded ID, not just its family):", "",
          "| Source | Rule set | Claimed (exact ID) [95% CI] | Measured (exact ID) [95% CI] "
          "| Overstatement, pts [95% CI] |",
          "|---|---|---:|---:|---:|"]
    for src, e in r["sources"].items():
        for name, d in (e.get("rulesets") or {}).items():
            x = d["claimed_vs_measured"].get("exact_id")
            if x:
                L.append(f"| {src} | {name} | {_pct(x['claimed_rate'])}{_ci(x.get('claimed_ci95'))} "
                         f"| {_pct(x['measured_rate'])}"
                         f"{_ci(x['measured_ci95'])} | {stats.pct(x['overstatement_points'] / 100)}"
                         f"{_ci(x['overstatement_ci95'])} |")
    up = [(src, name, d["unparsed_channel"]) for src, e in r["sources"].items()
          for name, d in (e.get("rulesets") or {}).items() if d.get("unparsed_channel") and name == "sigma-all"]
    if up:
        L += ["", "Events whose channel could not be parsed (no rule can match them): " + "; ".join(
            f"{src} {u['events']} of {u['events_total']} events in {u['recordings']} recordings"
            for src, _, u in up) + "."]
    x = r.get("cross_dataset") or {}
    if x:
        p_s = f"; exact McNemar p = {x['mcnemar_p']:.3g} for the {len(x['otrf_only_detected'])} vs " \
              f"{len(x['splunk_only_detected'])} discordant techniques" if "mcnemar_p" in x else ""
        n_x = max(x["shared_techniques"], 1)
        L += ["", f"OTRF vs Splunk (Windows, sigma-all): {x['shared_techniques']} techniques recorded in both; "
              f"measured outcome agrees on {x['agree']} of them ({_pct(x['agree'] / n_x)}, 95% Wilson"
              f"{_ci(x.get('agree_ci95'))}){p_s}. Detected only on OTRF: "
              f"{', '.join(x['otrf_only_detected']) or 'none'}; only on Splunk: "
              f"{', '.join(x['splunk_only_detected']) or 'none'}."]
    h = r.get("held_out_selection")
    if h:
        g, u, rn = h["greedy_cti_weighted"], h["greedy_unweighted"], h["random"]
        nt = h.get("test_techniques")

        def gcov(x):
            if "test_techniques_covered" not in x:
                return _pct(x["test_technique_coverage"])
            return (f"{_pct(x['test_technique_coverage'])} ({x['test_techniques_covered']} of {nt}, 95% Wilson"
                    f"{_ci(x['test_technique_coverage_ci95'])})")
        L += ["", f"## Held-out rule selection: pick {h['k']} rules on OTRF, test on Splunk Windows", "",
              "Weighted coverage brackets are 95% percentile bootstrap intervals over test techniques. The last "
              "column is the share of random draws whose test ransomware-weighted coverage is at or above the "
              "selection's (a one-sided permutation p-value).", "",
              "| Selection on OTRF | Test technique coverage | Test ransomware-weighted coverage "
              "| Random draws at or above |", "|---|---:|---:|---:|",
              f"| CTI-weighted greedy | {gcov(g)} | {_pct(g['test_ransomware_weighted'])}"
              f"{_ci(g.get('test_ransomware_weighted_ci95'))} | {_pct(g['random_draws_at_or_above'])} |",
              f"| Unweighted greedy | {gcov(u)} | {_pct(u['test_ransomware_weighted'])}"
              f"{_ci(u.get('test_ransomware_weighted_ci95'))} | {_pct(u['random_draws_at_or_above'])} |",
              f"| Random {h['k']} of {h['candidate_rules']} OTRF-firing rules ({rn['draws']} draws, mean "
              f"[2.5-97.5 percentile of the draws]) | {_pct(rn['test_technique_coverage_mean'])} "
              f"[{_pct(rn['test_technique_coverage_95'][0])}, {_pct(rn['test_technique_coverage_95'][1])}] "
              f"| {_pct(rn['test_ransomware_weighted_mean'])} [{_pct(rn['test_ransomware_weighted_95'][0])}, "
              f"{_pct(rn['test_ransomware_weighted_95'][1])}] | - |"]
    sk = {k: v for k, v in r.get("skipped_unavailable", {}).items() if v}
    L += ["", "Recordings skipped because a file was missing or unreadable: "
          + ("; ".join(f"{k}: {', '.join(v)}" for k, v in sk.items()) if sk else "none") + "."]
    L += ["", f"Runtime {r.get('runtime_seconds')} s.", ""]
    return "\n".join(L)
