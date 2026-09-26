"""GAUNTLET CLI: prioritize -> emulate (simulated) -> detect -> score."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import cti, detect, plans, range_sim, score
from .models import CoverageReport, Outcome

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"
_ICON = {Outcome.DETECTED: "[+]", Outcome.PARTIAL: "[~]", Outcome.MISSED: "[-]"}


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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gauntlet", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("profiles", help="list threat profiles")
    pp = sub.add_parser("plan", help="show prioritized emulation plan")
    pp.add_argument("--profile", default="ransomware")
    pp.add_argument("--top", type=int)
    pr = sub.add_parser("run", help="run full simulated loop and score coverage")
    pr.add_argument("--profile", default="ransomware")
    pr.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    pr.add_argument("--top", type=int)
    pr.add_argument("--seed", type=int, default=7)
    pr.add_argument("--disable-source", action="append", default=[],
                    help="simulate a telemetry gap by removing a log source from all hosts")
    pr.add_argument("--json", type=Path, help="write report JSON here")
    pr.add_argument("--baseline", type=Path, help="fail (exit 2) if coverage regressed vs this JSON")
    a = p.parse_args(argv)

    if a.cmd == "profiles":
        for name, prof in cti.PROFILES.items():
            print(f"{name:<18}{prof.description}")
        return 0
    if a.profile not in cti.PROFILES:
        print(f"unknown profile; choose from {list(cti.PROFILES)}", file=sys.stderr)
        return 1
    if a.cmd == "plan":
        for i, r in enumerate(cti.prioritize(cti.PROFILES[a.profile], top_n=a.top), 1):
            step = plans.STEPS.get(r.technique.id)
            print(f"{i:>2}. {r.technique.id:<11}{r.score:<7}{r.technique.name}"
                  f"  [{step.description if step else 'no simulated step'}]")
        return 0

    rng = range_sim.without_sources(range_sim.DEFAULT_RANGE, set(a.disable_source))
    ranked, report = run_pipeline(a.profile, a.rules, a.top, a.seed, rng=rng)
    _print_report(report, ranked)
    data = report.to_dict()
    if a.json:
        a.json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if a.baseline:
        regs = score.diff(json.loads(a.baseline.read_text(encoding="utf-8")), data)
        if regs:
            print("\nREGRESSIONS:\n  " + "\n  ".join(regs), file=sys.stderr)
            return 2
        print("\nNo coverage regressions vs baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
