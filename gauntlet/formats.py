"""Parsers for non-JSON telemetry: Windows/Sysmon-for-Linux XML events and raw auditd logs.

* **XML events** (Splunk ``XmlWinEventLog`` exports, Sysmon for Linux syslog output):
  one ``<Event>...</Event>`` per line. Flattened to ``Channel``, ``EventID``,
  ``Computer``, ``TimeCreated`` plus every ``<Data Name=...>`` field, i.e. the same
  shape as the OTRF JSON records the Sigma evaluator already understands.
* **auditd**: every record line becomes one event on the ``auditd`` channel with
  its ``key=value`` fields (hex-encoded EXECVE arguments decoded, as ``ausearch -i``
  would). Records sharing an audit serial that contain an ``EXECVE`` are also
  merged into one synthetic process-creation event on channel ``auditd-exec``
  (``Image`` = ``exe``, ``CommandLine`` = joined argv, ``CurrentDirectory`` = CWD,
  ``ProcessId``/``ParentProcessId``/``User``). auditd does not record the parent's
  image, so Sigma rules conditioned on ``ParentImage`` cannot match this view.
"""
from __future__ import annotations

import html
import re
from collections.abc import Iterable, Iterator
from typing import Any

_TAG = re.compile(r"<(EventID|Channel|Computer)\b[^<>]*>([^<]*)</\1>")
_TIME = re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]")
_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]\s*(?:/>|>([^<]*)</Data>)")


def parse_xml_event(line: str) -> dict[str, Any] | None:
    if "<Event" not in line:
        return None
    ev: dict[str, Any] = {}
    for k, v in _TAG.findall(line):
        ev[k] = html.unescape(v)
    if "EventID" not in ev:
        return None
    m = _TIME.search(line)
    if m:
        ev["TimeCreated"] = m.group(1)
    for k, v in _DATA.findall(line):
        ev[k] = html.unescape(v or "")
    return ev


_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
MAX_ARGS = 4096
MAX_LINE = 1 << 20  # lines over 1 MiB are skipped (malformed or hostile input)
_MSG = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")


def _unhex(v: str) -> str:
    if len(v) >= 2 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            b = bytes.fromhex(v)
            if b and all(32 <= c < 127 or c in (9, 10, 0) for c in b):
                return b.replace(b"\x00", b" ").decode("ascii").strip()
        except ValueError:
            pass
    return v


def parse_audit_line(line: str) -> dict[str, Any] | None:
    i = line.find("type=")
    if i < 0:
        return None
    line = line[i:]
    m = _MSG.search(line)
    ev: dict[str, Any] = {"Channel": "auditd"}
    if m:
        ev["timestamp"], ev["serial"] = float(m.group(1)), int(m.group(2))
    for k, v in _KV.findall(line.replace("\x1d", " ")):
        if k == "msg":
            continue
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1]
        elif ev.get("type") in ("EXECVE", "PROCTITLE") and (re.fullmatch(r"a\d+", k) or k == "proctitle"):
            v = _unhex(v)
        elif k in ("name", "cwd", "exe", "comm"):
            v = _unhex(v)
        ev.setdefault(k, v)
    return ev if "type" in ev else None


def audit_exec_events(records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Merge SYSCALL/EXECVE/CWD records per audit serial into process-creation events."""
    groups: dict[tuple, dict[str, dict[str, Any]]] = {}
    for r in records:
        key = (r.get("timestamp"), r.get("serial"))
        groups.setdefault(key, {})[r["type"]] = r
    for (ts, _), g in groups.items():
        ex = g.get("EXECVE")
        if not ex:
            continue
        sc, cwd = g.get("SYSCALL", {}), g.get("CWD", {})
        try:
            argc = int(ex.get("argc", 0))
        except ValueError:
            argc = 0
        present = sorted((int(k[1:]), str(v)) for k, v in ex.items() if re.fullmatch(r"a\d+", k))
        argv = [v for i, v in present if i < min(argc, MAX_ARGS)] if argc else [v for _, v in present[:MAX_ARGS]]
        img = sc.get("exe") or (argv[0] if argv else "")
        yield {"Channel": "auditd-exec", "EventID": 1, "timestamp": ts, "Image": img,
               "CommandLine": " ".join(argv), "CurrentDirectory": cwd.get("cwd", ""),
               "ProcessId": sc.get("pid"), "ParentProcessId": sc.get("ppid"),
               "User": sc.get("UID") or sc.get("uid"), "LogonId": sc.get("auid")}


def iter_text_lines(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Sniff each line (JSON / XML event / auditd) and yield event dicts.

    auditd lines additionally produce the synthetic ``auditd-exec`` events at the end.
    """
    import json

    audit: list[dict[str, Any]] = []
    for raw in lines:
        s = raw.strip().lstrip("\ufeff")
        if not s or len(s) > MAX_LINE:
            continue
        if s[0] == "{":
            try:
                d = json.loads(s)
            except ValueError:
                continue
            if isinstance(d, dict):
                yield d
        elif "<Event" in s:
            ev = parse_xml_event(s)
            if ev:
                yield ev
        elif "type=" in s and "msg=audit(" in s:
            ev = parse_audit_line(s)
            if ev:
                audit.append(ev)
                yield ev
    if audit:
        yield from audit_exec_events(audit)
