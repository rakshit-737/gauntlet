#!/usr/bin/env python3
"""Do repeated live-telemetry runs agree? Summarise per-command outcomes across live.json files.

Each ``live.json`` comes from one ``live-telemetry`` workflow artefact (download with
``gh run download <run id>``). The output lists, per run, the run id, the labelled-event
count and every (rule set, command) -> detected outcome, and states whether all runs give
identical outcomes. It is the committed evidence behind "identical per-command outcomes on
N runner executions".

Usage:
    python scripts/live_history.py run1/live.json run2/live.json ... --out results/live-history.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def outcomes(rep: dict[str, Any]) -> dict[str, bool]:
    return {f"{name} | {c['command']}": bool(c["measured"])
            for name, r in sorted(rep["rulesets"].items()) for c in r["commands"]}


def summarise(reports: list[dict[str, Any]]) -> dict[str, Any]:
    runs = [{"run_id": r.get("run_id"), "commit": r.get("commit"),
             "labelled_events": {n: x["labelled_events"] for n, x in sorted(r["rulesets"].items())},
             "outcomes": outcomes(r)} for r in reports]
    keys = sorted({k for r in runs for k in r["outcomes"]})
    differing = [k for k in keys if len({r["outcomes"].get(k) for r in runs}) > 1]
    return {"runs": len(runs), "run_ids": [r["run_id"] for r in runs],
            "identical_outcomes": not differing, "differing": differing, "per_run": runs}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("live_json", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    reps = [json.loads(p.read_text(encoding="utf-8")) for p in a.live_json]
    reps.sort(key=lambda r: int(r.get("run_id") or 0))
    s = summarise(reps)
    a.out.write_text(json.dumps(s, indent=1) + "\n", encoding="utf-8")
    print(f"{s['runs']} runs {s['run_ids']}: identical per-command outcomes = {s['identical_outcomes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
