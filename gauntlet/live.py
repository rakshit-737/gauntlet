"""Score live auditd telemetry with event-level labels (round-3 live job).

The GitHub Actions workflow ``live-telemetry.yml`` runs ``scripts/live_emulate.py`` on an
ephemeral runner: a fixed allowlist of benign discovery commands (``whoami``, ``id``,
``uname -a`` ...) while auditd records ``execve`` and reads of a few files. The emulator
writes ``labels.json`` (command, ATT&CK technique, child PID). This module

1. parses the raw audit log with :mod:`gauntlet.formats`,
2. labels every audit record group (same audit serial) whose ``SYSCALL`` PID belongs to
   an allowlisted command -- *event-level* ground truth, unlike the recording-level
   labels of OTRF/Splunk -- and leaves everything else as background,
3. evaluates Linux Sigma rules event by event, and
4. reports per command/technique whether a rule tagged with that technique fired on its
   own events (measured), whether any rule is tagged for it at all (claimed), and how
   many rules fired on background events (off-target burden), and
5. profiles the replayed Splunk Linux recordings of the same techniques: sourcetype,
   ``EXECVE``/``SYSCALL`` record counts (auditd) and process-creation events (Sysmon for
   Linux), so a replay miss can be told apart from missing telemetry.

The package itself never runs commands; only the CI emulator script does.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import coverage, formats, mordor, paths, replay, stats
from .attack import parent
from .sigma import LINUX_SYSMON, SigmaRule


def label_events(lines: list[str], labels: list[dict[str, Any]]) -> tuple[list[tuple[dict, int | None]], int]:
    """Return ``[(event, label_index | None)]`` for every auditd record and synthetic exec event."""
    pid2lab = {str(lab["pid"]): i for i, lab in enumerate(labels) if lab.get("pid")}
    recs = [r for r in (formats.parse_audit_line(x) for x in lines if "msg=audit(" in x) if r]
    group_lab: dict[tuple, int | None] = {}
    for r in recs:
        if r.get("type") == "SYSCALL":
            group_lab[(r.get("timestamp"), r.get("serial"))] = pid2lab.get(str(r.get("pid")))
    out: list[tuple[dict, int | None]] = [(r, group_lab.get((r.get("timestamp"), r.get("serial")))) for r in recs]
    for ev in formats.audit_exec_events(recs):
        out.append((ev, pid2lab.get(str(ev.get("ProcessId")))))
    return out, len(recs)


def score(audit_log: Path, labels_path: Path, rules: list[SigmaRule]) -> dict[str, Any]:
    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))["commands"]
    lines = Path(audit_log).read_text(encoding="utf-8", errors="replace").splitlines()
    evs, n_records = label_events(lines, labels)
    idx = replay.RuleIndex(rules)
    by_id = {r.id: r for r in rules}
    fired_on: dict[int, set[str]] = defaultdict(set)
    n_lab: dict[int, int] = defaultdict(int)
    bg_rules: set[str] = set()
    bg_events = 0
    for ev, li in evs:
        _, _, hits = idx.evaluate([ev])
        if li is None:
            bg_events += 1
            bg_rules |= set(hits)
        else:
            n_lab[li] += 1
            fired_on[li] |= set(hits)
    rows = []
    for i, lab in enumerate(labels):
        t = lab["technique"]
        tagged = [r.id for r in rules if parent(t) in {parent(x) for x in r.techniques}]
        on = sorted(by_id[r].title for r in fired_on[i] if parent(t) in {parent(x) for x in by_id[r].techniques})
        off = sorted(by_id[r].title for r in fired_on[i] if r not in {x for x in tagged})
        rows.append({"command": " ".join(lab["argv"]), "technique": t, "labelled_events": n_lab[i],
                     "claimed": bool(tagged), "measured": bool(on), "on_target_rules": on,
                     "other_rules_fired": off})
    techs: dict[str, dict[str, bool]] = {}
    for r in rows:
        d = techs.setdefault(r["technique"], {"claimed": False, "measured": False})
        d["claimed"] |= r["claimed"]
        d["measured"] |= r["measured"]
    m = sum(v["measured"] for v in techs.values())
    c = sum(v["claimed"] for v in techs.values())
    return {"audit_records": n_records, "events": len(evs), "labelled_events": sum(n_lab.values()),
            "background_events": bg_events, "rules": len(rules),
            "background_rules_fired": sorted(by_id[r].title for r in bg_rules),
            "commands": rows, "techniques": techs,
            "techniques_measured": m, "techniques_claimed": c,
            "technique_coverage": m / len(techs) if techs else 0.0,
            "technique_coverage_ci95": list(stats.wilson(m, len(techs))),
            "claimed_coverage": c / len(techs) if techs else 0.0}


def telemetry_profile(ds: mordor.Dataset, sourcetypes: dict[str, str] | None = None) -> dict[str, Any]:
    """What a Linux recording can show a process_creation rule: auditd record types, Sysmon EventID 1."""
    st = sourcetypes if sourcetypes is not None else mordor.splunk_sourcetypes()
    out: dict[str, Any] = {"sourcetypes": sorted({st.get(_rel(f), "unknown") for f in ds.files}),
                           "events": 0, "execve_records": 0, "syscall_records": 0, "sysmon_process_creation": 0}
    for f in ds.files:
        for ev in mordor.iter_events(f):
            ch, eid, rec = mordor.normalize(ev)
            out["events"] += 1
            if ch == "auditd":
                typ = rec.get("type")
                out["execve_records"] += typ == "EXECVE"
                out["syscall_records"] += typ == "SYSCALL"
            elif ch == LINUX_SYSMON and eid == 1:
                out["sysmon_process_creation"] += 1
    return out


def _rel(f: Path) -> str:
    p = f.as_posix()
    return p.split("/splunk/", 1)[1] if "/splunk/" in p else p


def replayed_recordings(techniques: list[str], datasets: list[mordor.Dataset],
                        results: dict[str, list[replay.ReplayResult]], rules: dict[str, dict[str, SigmaRule]],
                        kb) -> list[dict[str, Any]]:
    """Per Splunk Linux recording of a live technique: telemetry profile and, per rule set, whether a rule
    tagged with the technique fired (on-target) and which other rules fired (with their ATT&CK tags)."""
    st = mordor.splunk_sourcetypes()
    want = set(techniques)
    out = []
    for ds in datasets:
        labels = {kb.canonical(t) for t in ds.techniques}
        hit = sorted(labels & want)
        if not hit:
            continue
        row: dict[str, Any] = {"id": ds.id, "techniques": hit, **telemetry_profile(ds, st),
                               "detected": {}, "other_rules_fired": {}}
        for name, res_list in results.items():
            res = next((r for r in res_list if r.dataset_id == ds.id), None)
            fired = sorted(res.fired()) if res else []
            rs = rules[name]
            on = [r for r in fired if r in rs and any(coverage.on_target(rs[r].techniques, [t]) for t in hit)]
            row["detected"][name] = bool(on)
            row["other_rules_fired"][name] = sorted(
                f"{rs[r].title} ({', '.join(sorted(rs[r].techniques)) or 'untagged'})"
                for r in fired if r in rs and r not in on)
        out.append(row)
    return out


def completeness(recs: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Per technique: how many replayed recordings could show a process creation at all."""
    out: dict[str, dict[str, int]] = {}
    for r in recs:
        for t in r["techniques"]:
            d = out.setdefault(t, {"recordings": 0, "auditd": 0, "auditd_with_execve": 0,
                                   "sysmon_linux": 0, "sysmon_with_process_creation": 0})
            d["recordings"] += 1
            if "auditd" in r["sourcetypes"]:
                d["auditd"] += 1
                d["auditd_with_execve"] += r["execve_records"] > 0
            if "sysmon:linux" in r["sourcetypes"]:
                d["sysmon_linux"] += 1
                d["sysmon_with_process_creation"] += r["sysmon_process_creation"] > 0
    return dict(sorted(out.items()))


def _kind(r: dict[str, Any]) -> str:
    return "sysmon" if "sysmon:linux" in r["sourcetypes"] else "auditd"


def render_md(rep: dict[str, Any]) -> str:
    L = ["# Live auditd telemetry vs replayed recordings", "",
         "Generated by `python -m gauntlet live` in the `live-telemetry` workflow. " + paths.provenance_line(rep), ""]
    recs = rep.get("replayed_recordings") or []
    for name, r in rep["rulesets"].items():
        n_t = len(r["techniques"])
        m = r.get("techniques_measured", round(r["technique_coverage"] * n_t))
        L += [f"## Rule set: {name} ({r['rules']} Linux rules)", "",
              f"{r['audit_records']} audit records -> {r['labelled_events'] + r['background_events']} events "
              f"({r['labelled_events']} labelled to allowlisted commands, {r['background_events']} background). "
              f"Live: {m} of {n_t} techniques detected (n = {n_t}, 95% Wilson"
              f"{stats.fmt_ci(r['technique_coverage_ci95'])}; claimed by tags: "
              f"{r.get('techniques_claimed', round(r['claimed_coverage'] * n_t))} of {n_t}). "
              f"Rules firing on background: {len(r['background_rules_fired'])}.", ""]
        if recs:
            L += ["| Command | Technique | Labelled events | Claimed | Live: detected "
                  "| Replayed Splunk auditd: detected | Replayed Splunk Sysmon for Linux: detected |",
                  "|---|---|---:|:---:|:---:|:---:|:---:|"]
        else:
            L += ["| Command | Technique | Labelled events | Claimed | Live: detected | Replayed (Splunk): detected |",
                  "|---|---|---:|:---:|:---:|:---:|"]
        rp = rep.get("replayed", {}).get(name, {})
        for c in r["commands"]:
            head = (f"| `{c['command']}` | {c['technique']} | {c['labelled_events']} | "
                    f"{'yes' if c['claimed'] else 'no'} | {'yes' if c['measured'] else 'no'} | ")
            if recs:
                cells = []
                for kind in ("auditd", "sysmon"):
                    rr = [x for x in recs if c["technique"] in x["techniques"] and _kind(x) == kind]
                    cells.append(f"{sum(x['detected'].get(name, False) for x in rr)} of {len(rr)}" if rr
                                 else "n/a (no recording)")
                L.append(head + " | ".join(cells) + " |")
            else:
                rv = rp.get(c["technique"])
                L.append(head + ("n/a (no recording)" if rv is None else ("yes" if rv else "no")) + " |")
        L.append("")
    if recs:
        L += _render_completeness(rep, recs)
    return "\n".join(L)


def _render_completeness(rep: dict[str, Any], recs: list[dict[str, Any]]) -> list[str]:
    names = list(rep["rulesets"])
    aud = [r for r in recs if _kind(r) == "auditd"]
    sym = [r for r in recs if _kind(r) == "sysmon"]
    aud_x = sum(r["execve_records"] > 0 for r in aud)
    sym_p = sum(r["sysmon_process_creation"] > 0 for r in sym)
    det = {n: sum(r["detected"].get(n, False) for r in recs) for n in names}
    no_x = len(aud) - aud_x
    aud_s = (f"{aud_x} of them contain an `EXECVE` record" + (
        f", so on the other {no_x} no command line exists for a process_creation rule to match" if aud_x and no_x
        else ", so no command line exists for a process_creation rule to match" if no_x else ""))
    L = ["## Splunk EXECVE completeness: why the replayed recordings miss", "",
         f"{len(recs)} Splunk Linux recordings are labelled with these techniques. {len(aud)} are auditd extracts; "
         f"{aud_s}. {len(sym)} are Sysmon for Linux recordings; {sym_p} of them contain "
         "process-creation events (EventID 1). Recordings detected by a rule tagged with the recorded technique: "
         + ", ".join(f"{n} {det[n]} of {len(recs)}" for n in names)
         + ". Where other rules fired, they are tagged with a different technique (listed below), so the miss on "
         "those recordings is a labelling or tagging difference, not missing telemetry.", "",
         "| Recording | Technique | Sourcetype | Events | EXECVE | SYSCALL | Sysmon EventID 1 | "
         + " | ".join(f"{n}: detected" for n in names) + " | Other rules fired (sigma-full if present) |",
         "|---|---|---|---:|---:|---:|---:|" + ":---:|" * len(names) + "---|"]
    other = "sigma-full" if "sigma-full" in names else names[-1]
    for r in sorted(recs, key=lambda x: (x["techniques"], _kind(x), x["id"])):
        L.append(f"| {r['id']} | {', '.join(r['techniques'])} | {', '.join(r['sourcetypes'])} | {r['events']} "
                 f"| {r['execve_records']} | {r['syscall_records']} | {r['sysmon_process_creation']} | "
                 + " | ".join("yes" if r["detected"].get(n) else "no" for n in names)
                 + f" | {'; '.join(r['other_rules_fired'].get(other, [])) or '-'} |")
    L.append("")
    return L
