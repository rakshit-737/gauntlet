"""Minimal Sigma-like detection engine.

Supported rule format (JSON, a strict subset of Sigma semantics):
  {"id", "title", "techniques": [...], "logsource": "sysmon",
   "detection": {"selection": {field|modifier: value|[values]}, "filter": {...},
                 "condition": "selection" | "selection and not filter"},
   "threshold": {"count": N, "group_by": "src_ip", "distinct": "user"}  # optional
  }
Modifiers: contains, startswith, endswith, re, gte. Lists are OR; keys are AND.
Case-insensitive string matching, like Sigma.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .models import Alert, Event, Rule

_CONDITIONS = {"selection", "selection and not filter"}


def load_rule(d: dict[str, Any]) -> Rule:
    det = d["detection"]
    cond = det.get("condition", "selection")
    if cond not in _CONDITIONS:
        raise ValueError(f"unsupported condition in {d.get('id')}: {cond}")
    rule = Rule(d["id"], d["title"], tuple(d["techniques"]), d["logsource"],
                det["selection"], cond, det.get("filter", {}))
    object.__setattr__(rule, "threshold", d.get("threshold"))  # optional extra
    return rule


def load_rules(directory: str | Path) -> list[Rule]:
    """Load every ``*.json`` rule in ``directory``; raise if there are none (avoids silent 0% coverage)."""
    files = sorted(Path(directory).glob("*.json"))
    if not files:
        raise FileNotFoundError(f"no *.json rules in {directory}")
    return [load_rule(json.loads(p.read_text(encoding="utf-8"))) for p in files]


def _match_value(actual: Any, mod: str | None, expected: Any) -> bool:
    if actual is None:
        return False
    if mod == "gte":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual).lower(), str(expected).lower()
    if mod is None:
        return a == e
    if mod == "contains":
        return e in a
    if mod == "startswith":
        return a.startswith(e)
    if mod == "endswith":
        return a.endswith(e)
    if mod == "re":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    raise ValueError(f"unknown modifier: {mod}")


def _match_block(fields: dict[str, Any], block: dict[str, Any]) -> bool:
    for key, expected in block.items():
        name, _, mod = key.partition("|")
        vals = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(fields.get(name), mod or None, v) for v in vals):
            return False
    return True


def matches(rule: Rule, event: Event) -> bool:
    if event.source != rule.source:
        return False
    if not _match_block(event.fields, rule.selection):
        return False
    if rule.condition == "selection and not filter" and rule.filter and _match_block(event.fields, rule.filter):
        return False
    return True


def run(rules: list[Rule], events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        hits = [e for e in events if matches(rule, e)]
        th = getattr(rule, "threshold", None)
        if th:
            key = th.get("group_by")
            distinct = th.get("distinct")
            if distinct:  # count distinct values of `distinct` per group
                seen: dict[Any, set] = {}
                for e in hits:
                    seen.setdefault(e.fields.get(key), set()).add(e.fields.get(distinct))
                counts = Counter({k: len(v) for k, v in seen.items()})
            else:
                counts = Counter(e.fields.get(key) for e in hits)
            hits = [e for e in hits if counts[e.fields.get(key)] >= th["count"]]
        alerts.extend(Alert(rule.id, e) for e in hits)
    return alerts


_LEGACY_CHANNELS = {"sysmon": "microsoft-windows-sysmon/operational", "security": "security"}


def legacy_as_sigma(rule: Rule):
    """Adapt a legacy JSON rule so it can run on real recorded telemetry.

    Only rules on log sources that exist in Windows recordings (sysmon, security)
    and without thresholds are adapted; others return ``None``.
    """
    from .sigma import SigmaRule

    ch = _LEGACY_CHANNELS.get(rule.source)
    if ch is None or getattr(rule, "threshold", None):
        return None

    def match(ev) -> bool:  # ev is a sigma.EventView (case-insensitive .get)
        if not _match_block(ev, rule.selection):
            return False
        return not (rule.condition == "selection and not filter" and rule.filter
                    and _match_block(ev, rule.filter))

    return SigmaRule(rule.id, rule.title, "high", "legacy", rule.techniques, (),
                     {"product": "windows", "service": rule.source}, ((ch, None),), match,
                     f"rules/{rule.id}.json")
