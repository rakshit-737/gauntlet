#!/usr/bin/env python3
"""Compare a fresh results directory with the committed one, field by field.

Every JSON file present in both directories is compared recursively. Timing fields and
provenance (which run produced the file) are ignored; everything else -- counts, rates,
intervals, per-technique outcomes -- must be equal (floats to 1e-9). Exits 1 on any
difference, so a reproduction either matches the published numbers or says exactly where
it does not.

Usage:
    python scripts/verify_results.py results out [--summary FILE]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

IGNORE = {"runtime_seconds", "stage_seconds", "seconds", "run_id", "commit", "inputs"}


def diff(a: Any, b: Any, path: str = "") -> list[str]:
    """Human-readable differences between two JSON values (ignoring IGNORE keys)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k in IGNORE:
                continue
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'fresh' if k in b else 'committed'}")
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: list length {len(a)} != {len(b)}"]
        return [d for i, (x, y) in enumerate(zip(a, b, strict=True)) for d in diff(x, y, f"{path}[{i}]")]
    if isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, int | float) or not isinstance(b, int | float):
        return [] if a == b else [f"{path}: {a!r} != {b!r}"]
    return [] if abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b)) else [f"{path}: {a!r} != {b!r}"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("committed", type=Path, help="committed results directory (results/)")
    ap.add_argument("fresh", type=Path, help="freshly generated results directory")
    ap.add_argument("--summary", type=Path, help="append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    a = ap.parse_args(argv)
    ca = {p.name for p in a.committed.glob("*.json")}
    fr = {p.name for p in a.fresh.glob("*.json")}
    lines, bad = [], 0
    for name in sorted(ca & fr):
        d = diff(json.loads((a.committed / name).read_text(encoding="utf-8")),
                 json.loads((a.fresh / name).read_text(encoding="utf-8")))
        bad += bool(d)
        lines.append(f"- `{name}`: " + ("identical (ignoring timing and provenance)" if not d
                                         else f"{len(d)} differences, e.g. " + "; ".join(d[:5])))
    for name in sorted(ca - fr):
        lines.append(f"- `{name}`: not in the fresh directory (not compared)")
    for name in sorted(fr - ca):
        lines.append(f"- `{name}`: new in the fresh directory (not compared)")
    head = (f"## Fresh vs committed results: {len(ca & fr) - bad} of {len(ca & fr)} JSON files identical"
            + (f", {bad} differ" if bad else ""))
    text = "\n".join([head, "", *lines, ""])
    print(text)
    if a.summary:
        with a.summary.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if not ca & fr:
        print("no JSON file to compare", file=sys.stderr)
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
