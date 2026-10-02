"""GAUNTLET CLI: CTI prioritize -> emulate/replay -> detect -> score coverage.

Real-data commands (ATT&CK KB shipped; recordings/rules via scripts/download_data.py):
  profiles, plan, manifest, predict, replay, bench, kb
Offline simulation (no downloads, used by the regression demo): run / sim
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import atomics, cti, detect, paths, plans, prioritize, range_sim, score
from .attack import load_kb
from .models import CoverageReport, Outcome

DEFAULT_RULES = paths.LEGACY_RULES
_ICON = {Outcome.DETECTED: "[+]", Outcome.PARTIAL: "[~]", Outcome.MISSED: "[-]"}


# ------------------------------------------------------------------ simulation (offline)
def run_pipeline(profile: str, rules_dir: Path, top: int | None = None, seed: int = 7,
                 noise: int = 50, rng=range_sim.DEFAULT_RANGE):
    prof = cti.PROFILES[profile]
    ranked = cti.prioritize(prof, top_n=top)
    plan = plans.build_plan(ranked)
    events = range_sim.generate(plan, rng, seed=seed, noise=noise)
    rules = detect.load_rules(rules_dir)
    alerts = detect.run(rules, events)
    report = score.score(profile, ranked, plan, events, alerts, rng)
    return ranked, report


def _print_report(report: CoverageReport, ranked) -> None:
    print(f"\nGAUNTLET coverage -- profile '{report.profile}' (SIMULATED telemetry)\n")
    print(f"{'':4}{'technique':<11}{'tactic':<22}{'outcome':<9}rules")
    for r in report.results:
        extra = f" (no telemetry: {', '.join(r.missing_sources)})" if r.missing_sources else ""
        print(f"{_ICON[r.outcome]} {r.technique_id:<11}{r.tactic:<22}{r.outcome.value:<9}"
              f"{','.join(r.rules_fired) or '-'}{extra}")
    print(f"\nCoverage: {report.coverage:.0%}   false positives on benign noise: {report.false_positives}")
    print("Per tactic: " + ", ".join(f"{k}={v:.0%}" for k, v in report.by_tactic().items()))
    recs = score.gap_recommendations(report, ranked)
    if recs:
        print("\nCheapest wins:")
        for i, rec in enumerate(recs[:5], 1):
            print(f"  {i}. {rec['action']}  -> {len(rec['techniques'])} technique(s), value {rec['value']}")


def _check_baseline(baseline: Path | None, data: dict) -> int:
    if not baseline:
        return 0
    regs = score.diff(json.loads(baseline.read_text(encoding="utf-8")), data)
    if regs:
        print("\nREGRESSIONS:\n  " + "\n  ".join(regs), file=sys.stderr)
        return 2
    print("\nNo coverage regressions vs baseline.")
    return 0


def cmd_sim(a) -> int:
    if a.profile not in cti.PROFILES:
        print(f"unknown simulated profile; choose from {list(cti.PROFILES)}", file=sys.stderr)
        return 1
    rng = range_sim.without_sources(range_sim.DEFAULT_RANGE, set(a.disable_source))
    ranked, report = run_pipeline(a.profile, a.rules, a.top, a.seed, rng=rng)
    _print_report(report, ranked)
    data = report.to_dict()
    if a.json:
        a.json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return _check_baseline(a.baseline, data)


# ------------------------------------------------------------------ real data
def _kb(a):
    b = paths.attack_bundle(a.data_dir) if a.data_dir else None
    return load_kb(b if b and b.exists() else None)


def _ranked(a, kb, candidates=None):
    groups = prioritize.profile_groups(kb, a.profile)
    rel = prioritize.relevance(groups)
    prev = prioritize.prevalence(list(kb.groups.values()))
    cands = candidates if candidates is not None else [t for t in rel if t in kb.techniques]
    ranked = prioritize.rank(cands, rel, prev, a.strategy)
    if a.strategy not in ("breadth", "random"):
        ranked = [r for r in ranked if r.relevance > 0]
    return groups, rel, ranked[: a.top] if a.top else ranked


def cmd_profiles(a) -> int:
    kb = _kb(a)
    print(f"ATT&CK Enterprise v{kb.version}: {len(kb.groups)} groups\n")
    for name, (_, desc) in prioritize.PROFILE_PATTERNS.items():
        gs = prioritize.profile_groups(kb, name)
        print(f"{name:<12}{len(gs):>3} groups  {desc}")
        print(f"{'':15}e.g. {', '.join(g.name for g in gs[:6])}")
    print("\nCustom profile: --profile G0016,G0007  (group ids, names or aliases)")
    return 0


def cmd_plan(a) -> int:
    kb = _kb(a)
    art = atomics.load_index()
    universe = [t for t in art if t in kb.techniques] if a.universe == "art" else None
    groups, _, ranked = _ranked(a, kb, universe)
    print(f"Profile '{a.profile}': {len(groups)} ATT&CK groups; strategy={a.strategy}\n")
    print(f"{'#':>3} {'technique':<11}{'score':>7}{'rel':>6}{'prev':>6}  {'ART':>3}  name")
    for i, r in enumerate(ranked, 1):
        print(f"{i:>3} {r.technique:<11}{r.score:>7.3f}{r.relevance:>6.2f}{r.prevalence:>6.2f}  "
              f"{len(art.get(r.technique, [])):>3}  {kb.name_of(r.technique)}")
    return 0


def cmd_manifest(a) -> int:
    kb = _kb(a)
    art = atomics.load_index()
    _, _, ranked = _ranked(a, kb, [t for t in art if t in kb.techniques])
    steps = atomics.manifest([r.technique for r in ranked], art)
    doc = {"profile": a.profile,
           "safety": "DRY RUN ONLY. Execute exclusively inside an isolated, no-egress lab range you own "
                     "(see range/docker-compose.yml and THREAT_MODEL.md).",
           "steps": steps}
    text = json.dumps(doc, indent=2)
    if a.out:
        a.out.write_text(text, encoding="utf-8")
        print(f"wrote {len(steps)} steps -> {a.out}")
    else:
        print(text)
    return 0


def cmd_predict(a) -> int:
    from .predict import CooccurrenceModel

    kb = _kb(a)
    obs = {t.strip().upper() for t in a.observed.split(",") if t.strip()}
    model = CooccurrenceModel([g.techniques for g in kb.groups.values() if g.techniques])
    print(f"Observed: {', '.join(sorted(obs))}\nLikely next techniques (co-occurrence across "
          f"{model.n_sets} ATT&CK groups):")
    for t, sc in model.predict(obs, k=a.k):
        print(f"  {t:<11}{sc:6.2f}  {kb.name_of(t)}")
    return 0


def cmd_replay(a) -> int:
    from . import coverage, mordor, replay

    root = a.data_dir or paths.data_dir()
    if not paths.have_real_data(root):
        print(f"no datasets under {root}; run scripts/download_data.py first", file=sys.stderr)
        return 1
    kb = _kb(a)
    datasets = [d for d in mordor.load_catalog(root) if d.available and d.techniques]
    recorded = sorted({kb.canonical(t) for d in datasets for t in d.techniques})
    groups, rel, ranked = _ranked(a, kb, recorded)
    order = {r.technique for r in ranked}
    chosen = [d for d in datasets if {kb.canonical(t) for t in d.techniques} & order]
    if a.ruleset == "legacy":
        spec = f"legacy:{a.rules}"
    elif a.ruleset in ("sigma-core", "sigma-all"):
        spec = f"{a.ruleset}:{paths.sigma_zip(root)}"
    else:
        spec = a.ruleset
    print(f"Replaying {len(chosen)} recordings for {len(order)} prioritized techniques "
          f"(profile '{a.profile}', {len(groups)} groups) through {spec.split(':')[0]} ...")
    rules = {r.id: r for r in replay.load_ruleset(spec)}
    res = replay.replay_many(spec, chosen, workers=a.workers, progress=False)
    summ = coverage.score(spec.split(":")[0], res, rules, kb)
    icon = {"detected": "[+]", "partial": "[~]", "missed": "[-]"}
    byt = {t.technique: t for t in summ.techniques}
    print(f"\n{'':4}{'technique':<11}{'prio':>6}  {'tactic':<22}{'result':<9}detections")
    for r in ranked:
        t = byt.get(r.technique)
        if t:
            print(f"{icon[t.outcome]} {t.technique:<11}{r.score:>6.3f}  {t.tactic:<22}{t.outcome:<9}"
                  f"{'; '.join(t.rules[:2]) or '-'}")
    print(f"\nTechnique coverage: {summ.technique_coverage:.0%}  threat-weighted: {summ.weighted(rel):.0%}  "
          f"off-target rules/recording: {summ.off_target_rules_per_dataset:.1f}")
    data = summ.to_dict()
    data["profile"] = a.profile
    if a.json:
        a.json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if a.navigator:
        layer = coverage.navigator_layer(summ, kb.version, weights=rel)
        a.navigator.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        print(f"ATT&CK Navigator layer -> {a.navigator}")
    return _check_baseline(a.baseline, data)


def cmd_bench(a) -> int:
    from . import bench

    root = a.data_dir or paths.data_dir()
    if not paths.have_real_data(root):
        print(f"no datasets under {root}; run scripts/download_data.py first", file=sys.stderr)
        return 1
    bench.run(root, a.out, workers=a.workers, rulesets=tuple(a.rulesets.split(",")), figures=not a.no_figures)
    return 0


def cmd_kb(a) -> int:
    from .attack import load_stix, write_kb

    root = a.data_dir or paths.data_dir()
    kb = load_stix(a.stix or paths.attack_bundle(root))
    print(f"ATT&CK v{kb.version}: {len(kb.techniques)} techniques, {len(kb.groups)} groups -> {write_kb(kb)}")
    csv = a.art_csv or paths.art_csv(root)
    if csv.exists():
        idx = atomics.load_index(csv)
        print(f"ART index: {sum(map(len, idx.values()))} tests / {len(idx)} techniques -> "
              f"{atomics.write_index(idx)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gauntlet", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", type=Path, default=None,
                   help="datasets dir (default $GAUNTLET_DATA_DIR or ./data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def prof(sp):
        sp.add_argument("--profile", default="ransomware",
                        help="profile name (see `profiles`) or comma list of ATT&CK groups")
        sp.add_argument("--strategy", default="cti", choices=prioritize.STRATEGIES)
        sp.add_argument("--top", type=int)

    sub.add_parser("profiles", help="list CTI threat profiles (real ATT&CK groups)")
    pp = sub.add_parser("plan", help="CTI-prioritized emulation plan")
    prof(pp)
    pp.add_argument("--universe", choices=["art", "all"], default="art",
                    help="art = only techniques with an Atomic Red Team Windows test")
    pm = sub.add_parser("manifest", help="dry-run Atomic Red Team manifest in priority order")
    prof(pm)
    pm.add_argument("--out", type=Path)
    pd = sub.add_parser("predict", help="likely next techniques given observed ones")
    pd.add_argument("--observed", required=True, help="comma list, e.g. T1566.001,T1059.001")
    pd.add_argument("-k", type=int, default=10)
    pr = sub.add_parser("replay", help="replay real recorded attacks through detections and score coverage")
    prof(pr)
    pr.add_argument("--ruleset", default="sigma-core", help="sigma-core | sigma-all | legacy | <kind>:<path>")
    pr.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rules dir for --ruleset legacy")
    pr.add_argument("--workers", type=int)
    pr.add_argument("--json", type=Path)
    pr.add_argument("--navigator", type=Path, help="write an ATT&CK Navigator layer here")
    pr.add_argument("--baseline", type=Path, help="exit 2 if coverage regressed vs this JSON")
    pb = sub.add_parser("bench", help="full real-data benchmark -> results/")
    pb.add_argument("--out", type=Path, default=Path("results"))
    pb.add_argument("--workers", type=int)
    pb.add_argument("--rulesets", default="legacy,sigma-core,sigma-all")
    pb.add_argument("--no-figures", action="store_true")
    pk = sub.add_parser("kb", help="rebuild the shipped ATT&CK / ART derivatives from the downloads")
    pk.add_argument("--stix", type=Path)
    pk.add_argument("--art-csv", type=Path)
    for name in ("run", "sim"):
        ps = sub.add_parser(name, help="offline SIMULATED loop (synthetic telemetry)")
        ps.add_argument("--profile", default="ransomware")
        ps.add_argument("--rules", type=Path, default=DEFAULT_RULES)
        ps.add_argument("--top", type=int)
        ps.add_argument("--seed", type=int, default=7)
        ps.add_argument("--disable-source", action="append", default=[],
                        help="simulate a telemetry gap by removing a log source from all hosts")
        ps.add_argument("--json", type=Path, help="write report JSON here")
        ps.add_argument("--baseline", type=Path, help="fail (exit 2) if coverage regressed vs this JSON")
    a = p.parse_args(argv)
    handlers = {"profiles": cmd_profiles, "plan": cmd_plan, "manifest": cmd_manifest, "predict": cmd_predict,
                "replay": cmd_replay, "bench": cmd_bench, "kb": cmd_kb, "run": cmd_sim, "sim": cmd_sim}
    try:
        return handlers[a.cmd](a)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
