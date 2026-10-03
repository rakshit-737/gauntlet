"""Comparison with published detection-coverage numbers (round-3 task C).

Two published sources can be lined up against GAUNTLET's measurements; neither is
like-for-like, and the report says why:

* **CTID Top ATT&CK Techniques** (Center for Threat-Informed Defense, Apache-2.0,
  ``src/data/Techniques.json``) publishes a per-technique ``has_sigma`` flag: "a Sigma
  rule exists for this technique". That is *claimed* coverage. GAUNTLET measures whether
  such rules actually fire on recordings of the technique.
* **RedGap** (MIT) publishes ``docs/benchmarks/coverage.json``: which of 51 Linux
  techniques its benign Docker lab detected with SigmaHQ ``linux/process_creation``
  rules. GAUNTLET's live auditd job runs a similar benign allowlist, so the techniques
  both cover can be compared outcome by outcome (different telemetry source, rule
  pin and lab, so disagreement is expected and informative).

Both files are downloaded into the datasets dir (never committed); only the derived
comparison is.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import paths, stats
from .attack import parent

REDGAP_COMMIT = "a9bcbf2c"  # the pinned RedGap commit whose docs/benchmarks/coverage.json is compared


def ctid_vs_measured(ctid: list[dict[str, Any]], coverage_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """CTID ``has_sigma`` (claimed) vs GAUNTLET measured outcome per recorded technique."""
    flag = {t["tid"]: bool(t.get("has_sigma")) for t in ctid}
    rows = []
    for r in coverage_rows:
        t = r["technique"]
        f = flag.get(t, flag.get(parent(t)))
        if f is None:
            continue
        rows.append({"technique": t, "ctid_has_sigma": f, "measured": r["outcome"] != "missed"})
    n = len(rows)
    claimed = sum(r["ctid_has_sigma"] for r in rows)
    measured = sum(r["measured"] for r in rows)
    b = sum(r["ctid_has_sigma"] and not r["measured"] for r in rows)
    c = sum(r["measured"] and not r["ctid_has_sigma"] for r in rows)
    return {"techniques_compared": n, "ctid_claimed": claimed, "measured": measured,
            "claimed_ci95": list(stats.wilson(claimed, n)), "measured_ci95": list(stats.wilson(measured, n)),
            "claimed_not_measured": sorted(r["technique"] for r in rows if r["ctid_has_sigma"] and not r["measured"]),
            "measured_not_claimed": sorted(r["technique"] for r in rows if r["measured"] and not r["ctid_has_sigma"]),
            "mcnemar_p": stats.mcnemar_exact(b, c)}


def redgap_vs_live(redgap: dict[str, Any], live: dict[str, Any] | None,
                   splunk_linux_rows: list[dict[str, Any]] | None) -> dict[str, Any]:
    """RedGap's published per-technique outcomes vs GAUNTLET live and Splunk-replay outcomes."""
    rg = {t["id"]: t for t in redgap["techniques"]}
    out: dict[str, Any] = {"redgap_summary": redgap.get("summary", {}), "rows": []}
    live_t: dict[str, dict[str, bool]] = {}
    if live:
        for name, r in live["rulesets"].items():
            for t, v in r["techniques"].items():
                live_t.setdefault(t, {})[name] = v["measured"]
    sp = {r["technique"]: r["measured"] for r in splunk_linux_rows or []}
    for t in sorted(set(rg) & (set(live_t) | set(sp))):
        out["rows"].append({"technique": t, "name": rg[t]["name"], "redgap_detected": rg[t]["detected"],
                            "redgap_gap_type": rg[t].get("gap_type"),
                            "gauntlet_live": live_t.get(t), "gauntlet_splunk_replay": sp.get(t)})
    return out


def run(ctid_path: Path, redgap_path: Path, results: Path, live_path: Path | None = None,
        extended_path: Path | None = None, out: Path | None = None) -> dict[str, Any]:
    out = out or results
    cov = json.loads((results / "coverage-sigma-all.json").read_text(encoding="utf-8"))
    ctid = json.loads(Path(ctid_path).read_text(encoding="utf-8"))
    redgap = json.loads(Path(redgap_path).read_text(encoding="utf-8"))
    live = json.loads(Path(live_path).read_text(encoding="utf-8")) if live_path and Path(live_path).exists() else None
    sl = None
    ext: dict[str, Any] = {}
    if extended_path and Path(extended_path).exists():
        ext = json.loads(Path(extended_path).read_text(encoding="utf-8"))
        try:
            sl = ext["sources"]["splunk-linux"]["rulesets"]["sigma-full"]["claimed_vs_measured"]["rows"]
        except KeyError:
            sl = None
    rep = {**paths.provenance(), "ctid": ctid_vs_measured(ctid, cov["results"]),
           "redgap": redgap_vs_live(redgap, live, sl),
           "inputs": {"live_run_id": (live or {}).get("run_id"),
                      "extended_run_id": ext.get("run_id") if sl is not None else None}}
    (out / "published.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (out / "PUBLISHED.md").write_text(render_md(rep), encoding="utf-8")
    return rep


def _yn(v: bool | None) -> str:
    return "n/a" if v is None else ("yes" if v else "no")


def render_md(rep: dict[str, Any]) -> str:
    c = rep["ctid"]
    n = c["techniques_compared"]
    inp = rep.get("inputs") or {}
    used = ", ".join(f"{k.replace('_run_id', '')} run {v}" for k, v in inp.items() if v)
    L = ["# Comparison with published coverage numbers", "",
         "Generated by `python -m gauntlet compare`. " + paths.provenance_line(rep)
         + (f" Inputs: {used}." if used else ""), "",
         "## CTID Top ATT&CK Techniques: `has_sigma` (claimed) vs measured on OTRF (sigma-all)", "",
         f"Of the {n} OTRF-recorded techniques listed by CTID, CTID flags {c['ctid_claimed']} "
         f"({stats.pct(c['ctid_claimed'] / max(n, 1))}%, 95% Wilson{stats.fmt_ci(c['claimed_ci95'])}) as having a "
         f"Sigma rule; GAUNTLET measures an on-target detection for {c['measured']} "
         f"({stats.pct(c['measured'] / max(n, 1))}%{stats.fmt_ci(c['measured_ci95'])}) "
         f"(exact McNemar p = {c['mcnemar_p']:.3g}, {len(c['claimed_not_measured'])} vs "
         f"{len(c['measured_not_claimed'])} discordant techniques; the two are not nested, so the test applies). "
         "Claimed but not measured: "
         f"{', '.join(c['claimed_not_measured']) or 'none'}. Measured but not flagged by CTID: "
         f"{', '.join(c['measured_not_claimed']) or 'none'}.", "",
         "Not like-for-like: CTID's flag dates from its own Sigma snapshot and says a rule *exists*; "
         "GAUNTLET pins SigmaHQ r2026-07-01 and requires the rule to fire on recorded telemetry.", "",
         "## RedGap (benign Linux lab, SigmaHQ linux/process_creation) vs GAUNTLET live auditd and Splunk replay", ""]
    s = rep["redgap"]["redgap_summary"]
    if s:
        L.append(f"RedGap's `docs/benchmarks/coverage.json` at commit `{REDGAP_COMMIT}` reports "
                 f"{s.get('detected')}/{s.get('techniques')} techniques detected (its README headline may cite a "
                 "later run). Techniques both projects exercise:")
    L += ["", "| Technique | RedGap detected (gap type) | GAUNTLET live | GAUNTLET Splunk replay (sigma-full) |",
          "|---|:---:|:---:|:---:|"]
    for r in rep["redgap"]["rows"]:
        lv = r["gauntlet_live"]
        lv_s = "n/a" if lv is None else "; ".join(f"{k}: {_yn(v)}" for k, v in lv.items())
        L.append(f"| {r['technique']} {r['name']} | {_yn(r['redgap_detected'])} ({r['redgap_gap_type']}) "
                 f"| {lv_s} | {_yn(r['gauntlet_splunk_replay'])} |")
    L += ["", "Not like-for-like: RedGap uses its own fixture telemetry mapped to Sysmon-for-Linux process "
          "events and a different SigmaHQ commit; GAUNTLET's live job uses raw auditd. No published "
          "technique-coverage figure exists for SigmaHQ on OTRF or Splunk attack_data recordings, and "
          "MITRE ATT&CK Evaluations score vendor products, not open rule sets, so they are not compared.", ""]
    return "\n".join(L)
