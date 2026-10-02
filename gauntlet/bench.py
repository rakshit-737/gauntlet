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
LEAKAGE_PATTERN = r"OTRF|mordor|securitydatasets|security-datasets|threathunterplaybook"
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
        rulesets: tuple[str, ...] = RULESETS, figures: bool = True) -> dict[str, Any]:
    root = root or paths.data_dir()
    out = out or Path.cwd() / "results"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    kb = _kb(root)
    art = atomics.load_index(paths.art_csv(root)) if paths.art_csv(root).exists() else atomics.load_index()
    datasets = [d for d in mordor.load_catalog(root) if d.available and d.techniques]
    print(f"ATT&CK v{kb.version}: {len(kb.techniques)} techniques, {len(kb.groups)} groups; "
          f"{len(datasets)} recordings; ART tests for {len(art)} techniques")

    report: dict[str, Any] = {
        "attack_version": kb.version, "sigma_release": paths.SIGMA_TAG,
        "recordings": len(datasets),
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
                                 cache=root / "cache" / f"replay-v2-{name}-{paths.SIGMA_TAG}.json")
        replays[name], rule_objs[name] = res, rules
        s = coverage.score(name, res, rules, kb)
        summaries[name] = s
        d = s.to_dict()
        d["exact_id_technique_coverage"] = round(
            coverage.score(name, res, rules, kb, exact=True).technique_coverage, 4)
        d["seconds"] = round(time.time() - t1, 1)
        n_cov = sum(t.detected > 0 for t in s.techniques)
        d["ci95"] = {"technique_coverage": list(stats.wilson(n_cov, len(s.techniques))),
                     "dataset_recall": list(stats.wilson(s.datasets_detected, s.datasets))}
        if name.startswith("sigma"):
            clean = {k: v for k, v in rules.items() if not v.cites(LEAKAGE_PATTERN)}
            sc = coverage.score(name, res, clean, kb)
            d["leakage_controlled"] = {"rules_removed": len(rules) - len(clean),
                                       "technique_coverage": round(sc.technique_coverage, 4),
                                       "dataset_recall": round(sc.dataset_recall, 4)}
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
        windows_unsupported = [w for w in rs.unsupported.values() if not w.startswith("product")]
        for why in windows_unsupported:
            reasons[why] = reasons.get(why, 0) + 1
        report["sigma_parse"] = {"supported": len(rs.rules), "unsupported": len(windows_unsupported),
                                 "top_unsupported_reasons": dict(sorted(reasons.items(), key=lambda x: -x[1])[:8])}

    # ---------------------------------------------------------------- CTI weighting
    profiles: dict[str, Any] = {}
    for p in prioritize.PROFILE_PATTERNS:
        groups = prioritize.profile_groups(kb, p)
        rel = prioritize.relevance(groups)
        profiles[p] = {"groups": len(groups), "example_groups": [g.name for g in groups[:8]],
                       "weighted_coverage": {n: round(s.weighted(rel), 4) for n, s in summaries.items()}}
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
        report["sprint"] = {"before": round(summaries["legacy"].technique_coverage, 4),
                            "after_top10_sigma_rules": round(after.technique_coverage, 4),
                            "before_weighted_ransomware": round(summaries["legacy"].weighted(rel_r), 4),
                            "after_weighted_ransomware": round(after.weighted(rel_r), 4)}

    # ---------------------------------------------------------------- prioritization
    universe = {t for t in art if t in kb.techniques}
    report["prioritization"] = {p: prioritize.evaluate_logo(kb, p, universe) for p in prioritize.PROFILE_PATTERNS}

    # ---------------------------------------------------------------- prediction
    sets = [g.techniques for g in kb.groups.values() if g.techniques]
    report["prediction"] = {
        "sub_technique_level": predict.evaluate_seeds(sets),
        "technique_level": predict.evaluate_seeds([{parent(t) for t in s} for s in sets], min_size=8),
    }
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
    return f"{100 * x:.1f}%"


def _ci(ci) -> str:
    return f" [{100 * ci[0]:.1f}, {100 * ci[1]:.1f}]" if ci else ""


def render_markdown(r: dict[str, Any], main: coverage.CoverageSummary) -> str:
    L = ["# GAUNTLET benchmark results", "",
         f"ATT&CK Enterprise v{r['attack_version']} - SigmaHQ {r['sigma_release']} - "
         f"{r['recordings']} OTRF Security-Datasets Windows recordings covering "
         f"{r['recorded_techniques']} techniques. Generated by `python -m gauntlet bench`.", "",
         "## Detection coverage on real recorded attack telemetry", "",
         "Brackets are 95% Wilson intervals (54 techniques / 96 recordings are small samples).", "",
         "| Rule set | Rules | Technique coverage | Exact-ID coverage | Coverage w/o OTRF-citing rules | "
         "Recordings detected | Off-target rules / recording | Off-target alerts / 10k events |",
         "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for n, d in r["detection"].items():
        lc = d.get("leakage_controlled")
        lc_s = f"{_pct(lc['technique_coverage'])} (-{lc['rules_removed']} rules)" if lc else "n/a"
        ci = d.get("ci95", {})
        L.append(f"| {n} | {d['rules']} | {_pct(d['technique_coverage'])}{_ci(ci.get('technique_coverage'))} "
                 f"| {_pct(d['exact_id_technique_coverage'])} "
                 f"| {lc_s} | {_pct(d['dataset_recall'])}{_ci(ci.get('dataset_recall'))} "
                 f"| {d['off_target_rules_per_dataset']} "
                 f"| {d['off_target_alerts_per_10k_events']} |")
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
              f"({_pct(s['before_weighted_ransomware'])} ransomware-weighted). Adding only the 10 "
              f"cheapest-win SigmaHQ rules: **{_pct(s['after_top10_sigma_rules'])}** "
              f"({_pct(s['after_weighted_ransomware'])} ransomware-weighted)."]
    L += ["", "## Cheapest wins (greedy, ransomware-weighted, sigma-core)", "",
          "| # | Rule | New techniques | Cumulative weighted coverage |", "|---:|---|---|---:|"]
    for i, w in enumerate(r["cheapest_wins"], 1):
        cum = _pct(w["cumulative_weighted_coverage"])
        L.append(f"| {i} | {w['rule']} | {', '.join(w['new_techniques'])} | {cum} |")
    L += ["", "## Telemetry ablation (sigma-core): techniques lost if a channel is not collected", "",
          "| Channel | Techniques lost | Coverage without |", "|---|---:|---:|"]
    for a in r["channel_ablation"]:
        L.append(f"| {a['channel']} | {a['techniques_lost']} | {_pct(a['coverage_without'])} |")
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
    L += ["", "Paired comparison over held-out groups (mean difference, 95% bootstrap CI; negative steps = CTI "
          "needs fewer emulations):", "",
          "| Profile | Comparison | Δ steps to 80% | Δ AUC |", "|---|---|---:|---:|"]
    for p, d in r["prioritization"].items():
        for c, v in d.get("paired", {}).items():
            a, b = v["steps_to_80%"], v["auc"]
            L.append(f"| {p} | {c.replace('_', ' ')} "
                     f"| {a['mean_diff']:+.1f} [{a['ci95'][0]:+.1f}, {a['ci95'][1]:+.1f}] "
                     f"| {b['mean_diff']:+.3f} [{b['ci95'][0]:+.3f}, {b['ci95'][1]:+.3f}] |")
    L += ["", "## Next-technique prediction (co-occurrence vs popularity, leave-one-group-out)", "",
          "| Level | Model | recall@5 | recall@10 | recall@20 | MRR |", "|---|---|---:|---:|---:|---:|"]
    for lvl, d in r["prediction"].items():
        for m, v in d["models"].items():
            L.append(f"| {lvl} (n={d['groups_evaluated']}) | {m} | {v['recall@5']:.3f} | {v['recall@10']:.3f} "
                     f"| {v['recall@20']:.3f} | {v['mrr']:.3f} |")
    L += ["", "| Level | co-occurrence − popularity recall@10 (95% CI) | recall@10 mean ± sd over 5 hide-split seeds |",
          "|---|---:|---|"]
    for lvl, d in r["prediction"].items():
        pr, sd = d.get("paired_recall@10"), d.get("across_seeds", {})
        if pr:
            seeds_s = "; ".join(f"{m} {v['recall@10_mean']:.3f} ± {v['recall@10_sd']:.3f}"
                                for m, v in sd.items() if isinstance(v, dict))
            L.append(f"| {lvl} | {pr['mean_diff']:+.3f} [{pr['ci95'][0]:+.3f}, {pr['ci95'][1]:+.3f}] | {seeds_s} |")
    if "sigma_parse" in r:
        sp = r["sigma_parse"]
        L += ["", "## Sigma evaluator support", "",
              f"{sp['supported']} Windows rules evaluated, {sp['unsupported']} skipped as unsupported. "
              "Top reasons: " + ", ".join(f"{k} ({v})" for k, v in sp["top_unsupported_reasons"].items()) + "."]
    L.append("")
    return "\n".join(L)
