"""End-to-end real-data benchmark (``python -m gauntlet bench``).

1. Detection coverage: replay every OTRF Windows atomic recording through three
   rule sets -- GAUNTLET's original hand-written rules (baseline), SigmaHQ
   "core" (stable/test, high/critical) and all SigmaHQ Windows rules.
2. Threat-weighted coverage per CTI profile, per-tactic breakdown, cheapest-win
   rule ranking, telemetry-channel ablation, ATT&CK Navigator layers.
3. Prioritization research question (leave-one-group-out): CTI-prioritized vs
   breadth-first / random / prevalence-only / relevance-only orderings.
4. Next-technique prediction: co-occurrence model vs popularity baseline.

Everything is written to ``results/`` (small JSON / Markdown / PNG artefacts).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import atomics, coverage, mordor, paths, predict, prioritize, replay, stats
from .attack import KnowledgeBase, load_kb, load_stix, parent

RULESETS = ("legacy", "sigma-core", "sigma-all")
# Rules whose references/description point at the OTRF datasets / Threat Hunter Playbook were
# (possibly) written against the very recordings we replay -> report coverage without them too.
# Broadened in 1.1: also the OTRF co-founder's blog/handles and the old org name.
LEAKAGE_PATTERN = (r"OTRF|mordor|securitydatasets|security-datasets|threathunterplaybook|threathunter-playbook"
                   r"|cyb3rward0g|cyberwardog|hunters-forge")
LEAKAGE_PATTERN_NARROW = r"OTRF|mordor|securitydatasets|security-datasets|threathunterplaybook"
CHANNELS = ("microsoft-windows-sysmon/operational", "security",
            "microsoft-windows-powershell/operational", "windows powershell", "system")


def ruleset_spec(name: str, root: Path) -> str:
    if name == "legacy":
        return f"legacy:{paths.LEGACY_RULES}"
    return f"{name}:{paths.sigma_zip(root)}"


def _kb(root: Path) -> KnowledgeBase:
    b = paths.attack_bundle(root)
    return load_stix(b) if b.exists() else load_kb()


def run(root: Path | None = None, out: Path | None = None, workers: int | None = None,
        rulesets: tuple[str, ...] = RULESETS, figures: bool = True,
        use_cache: bool = True) -> dict[str, Any]:
    root = root or paths.data_dir()
    out = out or Path.cwd() / "results"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    kb = _kb(root)
    art = atomics.load_index(paths.art_csv(root)) if paths.art_csv(root).exists() else atomics.load_index()
    catalog = [d for d in mordor.load_catalog(root) if d.techniques]
    datasets = [d for d in catalog if d.available]
    print(f"ATT&CK v{kb.version}: {len(kb.techniques)} techniques, {len(kb.groups)} groups; "
          f"{len(datasets)} recordings; ART tests for {len(art)} techniques")

    report: dict[str, Any] = {
        **paths.provenance(),
        "attack_version": kb.version, "sigma_release": paths.SIGMA_TAG,
        "recordings": len(datasets),
        "skipped_recordings": sorted(d.id for d in catalog if not d.available),
        "recorded_techniques": len({kb.canonical(t) for d in datasets for t in d.techniques}),
    }

    # ---------------------------------------------------------------- detection
    summaries: dict[str, coverage.CoverageSummary] = {}
    replays: dict[str, list[replay.ReplayResult]] = {}
    rule_objs: dict[str, dict] = {}
    for name in rulesets:
        spec = ruleset_spec(name, root)
        print(f"[replay] {name}")
        t1 = time.time()
        rules = {r.id: r for r in replay.load_ruleset(spec)}
        res = replay.replay_many(spec, datasets, workers=workers,
                                 cache=(root / "cache" / f"replay-v3-{name}-{paths.SIGMA_TAG}.json")
                                 if use_cache else None)
        replays[name], rule_objs[name] = res, rules
        s = coverage.score(name, res, rules, kb)
        summaries[name] = s
        d = s.to_dict()
        d["exact_id_technique_coverage"] = coverage.score(name, res, rules, kb, exact=True).technique_coverage
        d["seconds"] = round(time.time() - t1, 1)
        n_cov = sum(t.detected > 0 for t in s.techniques)
        n_full = sum(t.outcome == "detected" for t in s.techniques)
        n_exact = sum(t.detected > 0 for t in coverage.score(name, res, rules, kb, exact=True).techniques)
        d["fully_detected_coverage"] = n_full / max(len(s.techniques), 1)
        d["outcomes"] = {"detected": n_full, "partial": n_cov - n_full, "missed": len(s.techniques) - n_cov}
        d["ci95"] = {"technique_coverage": list(stats.wilson(n_cov, len(s.techniques))),
                     "fully_detected_coverage": list(stats.wilson(n_full, len(s.techniques))),
                     "exact_id_technique_coverage": list(stats.wilson(n_exact, len(s.techniques))),
                     "dataset_recall": list(stats.wilson(s.datasets_detected, s.datasets))}
        if name.startswith("sigma"):
            clean = {k: v for k, v in rules.items() if not v.cites(LEAKAGE_PATTERN)}
            sc = coverage.score(name, res, clean, kb)
            narrow = {k: v for k, v in rules.items() if not v.cites(LEAKAGE_PATTERN_NARROW)}
            sn = coverage.score(name, res, narrow, kb)
            n_lc = sum(t.detected > 0 for t in sc.techniques)
            # nested: removing rules can only lose techniques, so the drop is a proportion of techniques
            lost = n_cov - n_lc
            d["leakage_controlled"] = {"rules_removed": len(rules) - len(clean),
                                       "technique_coverage": sc.technique_coverage,
                                       "technique_coverage_ci95": list(stats.wilson(n_lc, len(sc.techniques))),
                                       "techniques_lost": lost,
                                       "drop_ci95": list(stats.wilson(lost, len(s.techniques))),
                                       "dataset_recall": sc.dataset_recall,
                                       "narrow_pattern_rules_removed": len(rules) - len(narrow),
                                       "narrow_pattern_technique_coverage": sn.technique_coverage}
        report.setdefault("detection", {})[name] = {k: v for k, v in d.items() if k != "results"}
        (out / f"coverage-{name}.json").write_text(json.dumps(d, indent=1), encoding="utf-8")
        (out / f"navigator-{name}.json").write_text(
            json.dumps(coverage.navigator_layer(s, kb.version), indent=1), encoding="utf-8")
        print(f"  techniques covered {s.technique_coverage:.1%}, recordings detected {s.dataset_recall:.1%}, "
              f"off-target rules/recording {s.off_target_rules_per_dataset:.1f}")
    if "sigma-all" in rulesets:
        from .sigma import WINDOWS_PREFIXES, load_rules
        rs = load_rules(paths.sigma_zip(root), subdir_prefix=WINDOWS_PREFIXES)
        reasons: dict[str, int] = {}
        windows_unsupported = [w for w in rs.unsupported.values() if not w.startswith(("product", "linux"))]
        windows_rules = [r for r in rs.rules if str(r.logsource.get("product", "")).lower() == "windows"]
        for why in windows_unsupported:
            reasons[why] = reasons.get(why, 0) + 1
        report["sigma_parse"] = {"supported": len(windows_rules), "unsupported": len(windows_unsupported),
                                 "top_unsupported_reasons": dict(sorted(reasons.items(), key=lambda x: -x[1])[:8])}

    # ---------------------------------------------------------------- CTI weighting
    profiles: dict[str, Any] = {}
    for p in prioritize.PROFILE_PATTERNS:
        groups = prioritize.profile_groups(kb, p)
        rel = prioritize.relevance(groups)
        profiles[p] = {"groups": len(groups), "example_groups": [g.name for g in groups[:8]],
                       "weighted_coverage": {n: s.weighted(rel) for n, s in summaries.items()}}
    report["profiles"] = profiles

    main = "sigma-core" if "sigma-core" in summaries else next(iter(summaries))
    s_main = summaries[main]
    rel_r = prioritize.relevance(prioritize.profile_groups(kb, "ransomware"))
    report["by_tactic"] = {n: {k: f"{a}/{b}" for k, (a, b) in s.by_tactic().items()} for n, s in summaries.items()}
    report["cheapest_wins"] = coverage.greedy_rule_selection(replays[main], rule_objs[main], rel_r, top=10, kb=kb)
    if "sigma-all" in replays:
        report["cheapest_wins_all"] = coverage.greedy_rule_selection(
            replays["sigma-all"], rule_objs["sigma-all"], rel_r, top=10, kb=kb)
    report["channel_ablation"] = coverage.channel_ablation(replays[main], rule_objs[main], CHANNELS, kb)
    n_main = len(s_main.techniques)
    for a in report["channel_ablation"]:
        # nested (dropping a channel can only lose detections): report the loss as a proportion of
        # techniques with a Wilson interval; a McNemar test would only restate the count
        a["lost_ci95"] = list(stats.wilson(a["techniques_lost"], n_main))
    if "sigma-core" in summaries and "sigma-all" in summaries:
        c = {t.technique: t.detected > 0 for t in summaries["sigma-core"].techniques}
        al = {t.technique: t.detected > 0 for t in summaries["sigma-all"].techniques}
        gained = sum(al[t] and not c.get(t, False) for t in al)
        lost = sum(c[t] and not al.get(t, False) for t in c)
        # sigma-core is a filter of sigma-all, so lost is 0 by construction
        report["core_vs_all"] = {"gained": gained, "lost": lost, "techniques": len(al),
                                 "gain_ci95": list(stats.wilson(gained, len(al)))}

    # before/after sprint: baseline hand-written rules + the top-10 cheapest Sigma rules
    if "legacy" in replays and "sigma-all" in replays:
        top_ids = {x["id"] for x in report.get("cheapest_wins_all", [])}
        merged = []
        for a, b in zip(replays["legacy"], replays["sigma-all"], strict=False):
            hits = dict(a.hits)
            hits.update({k: v for k, v in b.hits.items() if k in top_ids})
            merged.append(replay.ReplayResult(a.dataset_id, a.techniques, a.n_events, a.channels, hits))
        rules = {**rule_objs["legacy"], **{k: v for k, v in rule_objs["sigma-all"].items() if k in top_ids}}
        after = coverage.score("legacy+top10", merged, rules, kb)
        report["sprint"] = {"rules": "legacy + top-10 greedy cheapest-win rules from sigma-all",
                            "in_sample": True,
                            "before": summaries["legacy"].technique_coverage,
                            "after_top10_sigma_rules": after.technique_coverage,
                            "before_weighted_ransomware": summaries["legacy"].weighted(rel_r),
                            "after_weighted_ransomware": after.weighted(rel_r)}

    # ---------------------------------------------------------------- prioritization
    timings = {"detection": round(time.time() - t0, 1)}
    t1 = time.time()
    universe = {t for t in art if t in kb.techniques}
    report["prioritization"] = {p: prioritize.evaluate_logo(kb, p, universe) for p in prioritize.PROFILE_PATTERNS}

    # ---------------------------------------------------------------- prediction
    timings["prioritization"] = round(time.time() - t1, 1)
    t1 = time.time()
    sets = [g.techniques for g in kb.groups.values() if g.techniques]
    report["prediction"] = {
        "sub_technique_level": predict.evaluate_seeds(sets),
        "technique_level": predict.evaluate_seeds([{parent(t) for t in s} for s in sets], min_size=8),
    }
    timings["prediction"] = round(time.time() - t1, 1)
    report["stage_seconds"] = timings
    report["runtime_seconds"] = round(time.time() - t0, 1)
    (out / "results.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    (out / "RESULTS.md").write_text(render_markdown(report, s_main), encoding="utf-8")
    if figures:
        try:
            from . import figures as fig
            fig.make_all(report, summaries, out)
        except ImportError as e:  # matplotlib optional
            print(f"skipping figures: {e}")
    print(f"done in {report['runtime_seconds']}s -> {out}")
    return report


def _pct(x: float) -> str:
    return f"{stats.pct(x)}%"


def _p(p: float | None) -> str:
    if p is None:
        return "n/a"
    return "<0.0001" if p < 1e-4 else f"{p:.3g}"


def _ci(ci) -> str:
    """Wilson interval from unrounded bounds, rounded once to 0.1 point."""
    return stats.fmt_ci(ci)


def render_markdown(r: dict[str, Any], main: coverage.CoverageSummary) -> str:
    L = ["# GAUNTLET benchmark results", "",
         f"ATT&CK Enterprise v{r['attack_version']} - SigmaHQ {r['sigma_release']} - "
         f"{r['recordings']} OTRF Security-Datasets Windows recordings covering "
         f"{r['recorded_techniques']} techniques. Generated by `python -m gauntlet bench`"
         + (f"; skipped (file missing or unreadable): {', '.join(r['skipped_recordings'])}"
            if r.get("skipped_recordings") else "") + ". " + paths.provenance_line(r), "",
         "## Detection coverage on real recorded attack telemetry", "",
         f"Brackets are 95% Wilson intervals, computed from the raw counts and rounded once "
         f"({r['recorded_techniques']} techniques / {r['recordings']} "
         "recordings are small samples; recordings are treated as independent). *Technique coverage* = at "
         "least one recording of the technique has an on-target alert (partially detected techniques count); "
         "*fully detected* = every recording of it does.", "",
         "| Rule set | Rules | Technique coverage | Fully detected | Exact-ID coverage | "
         "Coverage w/o OTRF-citing rules | Recordings detected | Off-target rules / recording "
         "| Off-target alerts / 10k events |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for n, d in r["detection"].items():
        lc = d.get("leakage_controlled")
        lc_s = (f"{_pct(lc['technique_coverage'])}{_ci(lc.get('technique_coverage_ci95'))} "
                f"(-{lc['rules_removed']} rules)") if lc else "n/a"
        ci = d.get("ci95", {})
        L.append(f"| {n} | {d['rules']} | {_pct(d['technique_coverage'])}{_ci(ci.get('technique_coverage'))} "
                 f"| {_pct(d['fully_detected_coverage'])}{_ci(ci.get('fully_detected_coverage'))} "
                 f"| {_pct(d['exact_id_technique_coverage'])}{_ci(ci.get('exact_id_technique_coverage'))} "
                 f"| {lc_s} | {_pct(d['dataset_recall'])}{_ci(ci.get('dataset_recall'))} "
                 f"| {d['off_target_rules_per_dataset']} "
                 f"| {d['off_target_alerts_per_10k_events']} |")
    if "core_vs_all" in r:
        c = r["core_vs_all"]
        L += ["", f"sigma-core to sigma-all: {c['gained']} of {c['techniques']} techniques gained "
              f"(+{stats.pct(c['gained'] / c['techniques'])} points, 95% Wilson{_ci(c['gain_ci95'])}), "
              f"{c['lost']} lost. sigma-core is a filter of sigma-all, so no technique can be lost and a "
              "McNemar test would only restate the count; the interval on the gain is reported instead."]
    lc = r["detection"].get("sigma-core", {}).get("leakage_controlled")
    if lc:
        n_t = r["recorded_techniques"]
        L += ["", "Leakage control removes rules whose references or description cite OTRF / Security-Datasets / "
              "Threat Hunter Playbook or the OTRF co-founder's blog and handles. For sigma-core it loses "
              f"{lc['techniques_lost']} of {n_t} techniques (-{stats.pct(lc['techniques_lost'] / n_t)} points, "
              f"95% Wilson{_ci(lc['drop_ci95'])}). With the narrower v1.0 pattern (OTRF names only) sigma-core "
              f"coverage would be {_pct(lc['narrow_pattern_technique_coverage'])}."]
    L += ["", "## Threat-weighted coverage per CTI profile", "",
          "| Profile | ATT&CK groups | " + " | ".join(r["detection"]) + " |",
          "|---|---:|" + "---:|" * len(r["detection"])]
    for p, d in r["profiles"].items():
        cells = " | ".join(_pct(d["weighted_coverage"][n]) for n in r["detection"])
        L.append(f"| {p} | {d['groups']} | {cells} |")
    if "sprint" in r:
        s = r["sprint"]
        L += ["", "## Coverage sprint (demo scenario 5)", "",
              f"Hand-written baseline rules: **{_pct(s['before'])}** technique coverage "
              f"({_pct(s['before_weighted_ransomware'])} ransomware-weighted). Adding only the top-10 "
              f"greedy cheapest-win rules **from sigma-all** (listed below): **{_pct(s['after_top10_sigma_rules'])}** "
              f"({_pct(s['after_weighted_ransomware'])} ransomware-weighted). In-sample: the rules are selected "
              "and scored on the same recordings, so this is optimistic."]
    for title, key in (("sigma-all (used by the sprint)", "cheapest_wins_all"), ("sigma-core", "cheapest_wins")):
        if key not in r:
            continue
        L += ["", f"## Cheapest wins (greedy, ransomware-weighted, {title})", "",
              "| # | Rule | New techniques | Cumulative weighted coverage |", "|---:|---|---|---:|"]
        for i, w in enumerate(r[key], 1):
            L.append(f"| {i} | {w['rule']} | {', '.join(w['new_techniques'])} "
                     f"| {_pct(w['cumulative_weighted_coverage'])} |")
    L += ["", "## Telemetry ablation (sigma-core): techniques lost if a channel is not collected", "",
          "Dropping a channel can only lose detections, so the loss is reported as points of technique "
          "coverage with a 95% Wilson interval on lost / recorded techniques.", "",
          "| Channel | Techniques lost | Coverage lost, points [95% Wilson] | Coverage without |",
          "|---|---:|---:|---:|"]
    n_t = r["recorded_techniques"]
    for a in r["channel_ablation"]:
        L.append(f"| {a['channel']} | {a['techniques_lost']} | {stats.pct(a['techniques_lost'] / n_t)}"
                 f"{_ci(a.get('lost_ci95'))} | {_pct(a['coverage_without'])} |")
    L += ["", "## Per-tactic coverage (sigma-core)", "", "| Tactic | Covered / recorded techniques |", "|---|---:|"]
    for k, (a, b) in main.by_tactic().items():
        L.append(f"| {k} | {a}/{b} |")
    L += ["", "## Prioritization: CTI-ranked vs breadth-first emulation (leave-one-group-out)", "",
          "Recall of a held-out actor's techniques after k emulations, universe = Windows techniques "
          "with an Atomic Red Team test. Lower `steps to 80%` is better.", "",
          "| Profile | Strategy | recall@10 | recall@25 | recall@50 | steps to 50% | steps to 80% | AUC |",
          "|---|---|---:|---:|---:|---:|---:|---:|"]
    for p, d in r["prioritization"].items():
        for s, m in d["strategies"].items():
            L.append(f"| {p} (n={d['groups_evaluated']}) | {s} | {m['recall@10']:.3f} | {m['recall@25']:.3f} "
                     f"| {m['recall@50']:.3f} | {m['steps_to_50%']:.1f} | {m['steps_to_80%']:.1f} | {m['auc']:.3f} |")
    L += ["", "Paired comparison over held-out groups (mean difference, 95% paired percentile bootstrap CI and "
          "exact sign-test p; negative steps = the first strategy needs fewer emulations). With fewer than 10 "
          "held-out groups the bootstrap CI is not reported; the per-group differences are shown instead.", "",
          "| Profile | Comparison | Δ steps to 80% | sign p | Δ AUC |", "|---|---|---:|---:|---:|"]
    for p, d in r["prioritization"].items():
        for c, v in d.get("paired", {}).items():
            a, b = v["steps_to_80%"], v["auc"]
            if a.get("ci_reliable", True):
                a_s = f"{a['mean_diff']:+.1f} [{a['ci95'][0]:+.1f}, {a['ci95'][1]:+.1f}]"
                b_s = f"{b['mean_diff']:+.3f} [{b['ci95'][0]:+.3f}, {b['ci95'][1]:+.3f}]"
            else:
                a_s = f"{a['mean_diff']:+.1f} (per group: {', '.join(f'{x:+.0f}' for x in a['per_unit_diffs'])})"
                b_s = f"{b['mean_diff']:+.3f}"
            L.append(f"| {p} (n={d['groups_evaluated']}) | {c.replace('_', ' ')} | {a_s} "
                     f"| {_p(a.get('sign_test_p'))} | {b_s} |")
    L += ["", "## Next-technique prediction (co-occurrence vs popularity, leave-one-group-out)", "",
          "| Level | Model | recall@5 | recall@10 | recall@20 | MRR |", "|---|---|---:|---:|---:|---:|"]
    for lvl, d in r["prediction"].items():
        for m, v in d["models"].items():
            L.append(f"| {lvl} (n={d['groups_evaluated']}) | {m} | {v['recall@5']:.3f} | {v['recall@10']:.3f} "
                     f"| {v['recall@20']:.3f} | {v['mrr']:.3f} |")
    L += ["", "| Level | co-occurrence − popularity recall@10 (95% paired bootstrap CI) "
          "| co-occurrence − popularity MRR (95% paired bootstrap CI) "
          "| recall@10 mean ± sd over 5 hide-split seeds |",
          "|---|---:|---:|---|"]
    for lvl, d in r["prediction"].items():
        pr, pm, sd = d.get("paired_recall@10"), d.get("paired_mrr"), d.get("across_seeds", {})
        if pr:
            seeds_s = "; ".join(f"{m} {v['recall@10_mean']:.3f} ± {v['recall@10_sd']:.3f}"
                                for m, v in sd.items() if isinstance(v, dict))
            pm_s = f"{pm['mean_diff']:+.3f} [{pm['ci95'][0]:+.3f}, {pm['ci95'][1]:+.3f}]" if pm else "n/a"
            L.append(f"| {lvl} | {pr['mean_diff']:+.3f} [{pr['ci95'][0]:+.3f}, {pr['ci95'][1]:+.3f}] "
                     f"| {pm_s} | {seeds_s} |")
    if "sigma_parse" in r:
        sp = r["sigma_parse"]
        L += ["", "## Sigma evaluator support", "",
              f"{sp['supported']} Windows rules evaluated, {sp['unsupported']} skipped as unsupported. "
              "Top reasons: " + ", ".join(f"{k} ({v})" for k, v in sp["top_unsupported_reasons"].items()) + "."]
    if "stage_seconds" in r:
        L += ["", "Runtime: " + ", ".join(f"{k} {v} s" for k, v in r["stage_seconds"].items())
              + f"; total {r['runtime_seconds']} s."]
    L.append("")
    return "\n".join(L)
