"""Evaluator fidelity control: SigmaHQ's own regression samples through GAUNTLET's evaluator.

SigmaHQ ships positive regression samples for some rules (``regression_data/**/info.yml``
naming the rule id and an event log sample; the same events are committed as an
``evtx_dump``-style ``.json`` next to the ``.evtx``). If GAUNTLET's in-house evaluator is
faithful, every supported rule must fire on its own positive sample. The share that does
(with a 95% Wilson interval) separates "the rule logic misses the recording" from "our
evaluator misses what a production backend would match" -- the control for the
claimed-vs-measured gap. Only the ``.json`` samples are read; no ``.evtx`` parser is needed.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from . import paths, replay, sigma, stats

RULE_DIRS = ("rules/", "rules-threat-hunting/", "rules-emerging-threats/")


def _text(v: Any) -> Any:
    if isinstance(v, dict) and "#text" in v:
        return v["#text"]
    return v


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    """An ``evtx_dump`` JSON event -> the flat ``Channel``/``EventID``/field shape the evaluator reads."""
    ev = doc.get("Event", doc)
    sysd = ev.get("System") or {}
    out: dict[str, Any] = {"Channel": _text(sysd.get("Channel")), "EventID": _text(sysd.get("EventID"))}
    prov = (sysd.get("Provider") or {}).get("#attributes", {})
    if prov.get("Name"):
        out["Provider_Name"] = prov["Name"]
    if sysd.get("Computer"):
        out["Computer"] = sysd["Computer"]
    for sec in ("EventData", "UserData"):
        d = ev.get(sec)
        if not isinstance(d, dict):
            continue
        inner = [v for k, v in d.items() if k != "#attributes"]
        if sec == "UserData" and len(inner) == 1 and isinstance(inner[0], dict):
            d = inner[0]
        for k, v in d.items():
            if k != "#attributes":
                out.setdefault(k, _text(v))
    return out


def load_events(path: Path) -> list[dict[str, Any]]:
    """Read one JSON document, a JSON list, or several concatenated documents."""
    txt = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = json.loads(txt)
        docs = doc if isinstance(doc, list) else [doc]
    except ValueError:
        dec, docs, i = json.JSONDecoder(), [], 0
        while True:
            j = txt.find("{", i)
            if j < 0:
                break
            try:
                d, i = dec.raw_decode(txt, j)
                docs.append(d)
            except ValueError:
                i = j + 1
    return [flatten(d) for d in docs if isinstance(d, dict)]


def run(checkout: Path, out: Path | None = None) -> dict[str, Any]:
    """Score every regression sample under ``<checkout>/regression_data`` and write ``selftest.json``."""
    checkout = Path(checkout)
    rs = sigma.load_rules(checkout, subdir_prefix=RULE_DIRS)
    by_id = {r.id: r for r in rs.rules}
    unsupported_ids = set()
    for key in rs.unsupported:
        p = checkout / key.split("#", 1)[0]
        try:
            for d in yaml.safe_load_all(p.read_text(encoding="utf-8")):
                if isinstance(d, dict) and d.get("id"):
                    unsupported_ids.add(str(d["id"]))
        except (OSError, yaml.YAMLError):
            continue
    rows = []
    for info in sorted((checkout / "regression_data").rglob("info.yml")):
        meta = yaml.safe_load(info.read_text(encoding="utf-8")) or {}
        for rm in meta.get("rule_metadata") or []:
            rid = str(rm.get("id"))
            for t in meta.get("regression_tests_info") or []:
                sample = (checkout / str(t.get("path", ""))).with_suffix(".json")
                row = {"rule_id": rid, "title": rm.get("title"), "test": t.get("name"),
                       "sample": sample.relative_to(checkout).as_posix(),
                       "expected_matches": t.get("match_count")}
                if rid not in by_id:
                    row["status"] = "unsupported" if rid in unsupported_ids else "rule_not_found"
                elif not sample.exists():
                    row["status"] = "sample_missing"
                else:
                    try:
                        events = load_events(sample)
                    except OSError:  # e.g. local AV blocked the sample
                        row["status"] = "sample_unreadable"
                        rows.append(row)
                        continue
                    idx = replay.RuleIndex([by_id[rid]])
                    _, _, hits = idx.evaluate(events)
                    n = sum(hits.get(rid, {}).values())
                    row.update({"events": len(events), "matches": n,
                                "status": "fired" if n else "missed",
                                "errors": idx.errors.get(rid, 0)})
                rows.append(row)
    status = Counter(r["status"] for r in rows)
    tested = [r for r in rows if r["status"] in ("fired", "missed")]
    k = sum(r["status"] == "fired" for r in tested)
    rep = {**paths.provenance(), "sigma_release": paths.SIGMA_TAG, "samples": len(rows),
           "status": dict(sorted(status.items())), "tested": len(tested), "fired": k,
           "recall": k / len(tested) if tested else 0.0, "recall_ci95": list(stats.wilson(k, len(tested))),
           "exact_match_count": sum(r.get("matches") == r.get("expected_matches") for r in tested),
           "by_category": _by_category(tested), "missed": [r for r in tested if r["status"] == "missed"],
           "untested": [r for r in rows if r["status"] not in ("fired", "missed")]}
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / "selftest.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
        (out / "SELFTEST.md").write_text(render_md(rep), encoding="utf-8")
    return rep


def _by_category(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        parts = r["sample"].split("/")
        cat = "/".join(parts[2:4]) if len(parts) > 4 else "other"
        d = out.setdefault(cat, {"tested": 0, "fired": 0})
        d["tested"] += 1
        d["fired"] += r["status"] == "fired"
    return dict(sorted(out.items(), key=lambda x: -x[1]["tested"]))


def render_md(rep: dict[str, Any]) -> str:
    n, k = rep["tested"], rep["fired"]
    L = ["# Evaluator self-test on SigmaHQ regression data", "",
         f"Generated by `python -m gauntlet selftest` on the SigmaHQ {rep['sigma_release']} checkout. "
         + paths.provenance_line(rep), "",
         f"Each SigmaHQ positive regression sample is replayed through the one rule it was recorded for. "
         f"**{k} of {n}** supported rules fire on their own sample: recall {stats.pct(rep['recall'])}% "
         f"(95% Wilson{stats.fmt_ci(rep['recall_ci95'])}). {rep['exact_match_count']} of {n} also match "
         "exactly the expected number of events. A rule GAUNTLET's evaluator cannot parse is not tested "
         "(see below); this checks evaluator fidelity on the rules it does run, which is what the "
         "claimed-vs-measured gap depends on.", "",
         "| Sample category | Tested | Fired |", "|---|---:|---:|"]
    for cat, d in rep["by_category"].items():
        L.append(f"| {cat} | {d['tested']} | {d['fired']} |")
    L += ["", "Samples not tested: " + (", ".join(f"{k2} {v}" for k2, v in rep["status"].items()
                                                  if k2 not in ("fired", "missed")) or "none") + "."]
    if rep["missed"]:
        L += ["", "Rules that did not fire on their own sample:", ""]
        L += [f"- {r['title']} (`{r['rule_id']}`), {r['events']} events" for r in rep["missed"]]
    L.append("")
    return "\n".join(L)
