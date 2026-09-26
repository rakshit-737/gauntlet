"""A dependency-light Sigma rule evaluator for Windows event logs.

This is not a SIEM backend: it *evaluates* SigmaHQ YAML rules directly against
JSON event records (e.g. OTRF Security-Datasets / Mordor recordings), which is
what a coverage benchmark needs. Supported:

* detection items: field maps (AND of keys, OR of list values), lists of maps
  (OR), keyword lists (match anywhere in the event), ``null`` values
* value modifiers: contains, startswith, endswith, all, windash, re (+ i/m/s),
  base64, base64offset, utf16le/utf16be/utf16/wide, cased, cidr, exists,
  gt/gte/lt/lte, fieldref; plain values support ``*``/``?`` wildcards
* conditions: and / or / not / parentheses, ``1 of X*``, ``all of X*``,
  ``1 of them``, ``all of them``
* logsources: Sysmon categories, Security 4688 process creation (with field
  mapping), PowerShell script/module/classic logs and a set of Windows services

Not supported (the rule is reported as *unsupported* rather than silently
passing): aggregations (``| count()``), correlation rules, ``expand``
placeholders, non-Windows products. See docs/adr/0002-sigma-evaluator.md.
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
PS_OP = "microsoft-windows-powershell/operational"
PS_CLASSIC = "windows powershell"

SERVICE_CHANNELS: dict[str, str] = {
    "sysmon": SYSMON,
    "security": SECURITY,
    "system": "system",
    "application": "application",
    "powershell": PS_OP,
    "powershell-classic": PS_CLASSIC,
    "wmi": "microsoft-windows-wmi-activity/operational",
    "taskscheduler": "microsoft-windows-taskscheduler/operational",
    "windefend": "microsoft-windows-windows defender/operational",
    "bits-client": "microsoft-windows-bits-client/operational",
    "ntlm": "microsoft-windows-ntlm/operational",
    "dns-client": "microsoft-windows-dns-client/operational",
    "codeintegrity-operational": "microsoft-windows-codeintegrity/operational",
    "firewall-as": "microsoft-windows-windows firewall with advanced security/firewall",
    "smbclient-security": "microsoft-windows-smbclient/security",
    "security-mitigations": "microsoft-windows-security-mitigations/kernel mode",
    "terminalservices-localsessionmanager":
        "microsoft-windows-terminalservices-localsessionmanager/operational",
    "capi2": "microsoft-windows-capi2/operational",
    "ldap": "microsoft-windows-ldap-client/debug",
    "openssh": "openssh/operational",
    "printservice-admin": "microsoft-windows-printservice/admin",
    "printservice-operational": "microsoft-windows-printservice/operational",
    "lsa-server": "microsoft-windows-lsa/operational",
    "applocker": "microsoft-windows-applocker/exe and dll",
    "shell-core": "microsoft-windows-shell-core/operational",
    "dns-server": "dns server",
    "driver-framework": "microsoft-windows-driverframeworks-usermode/operational",
}

# Sigma windows category -> list of (channel, event ids) it covers
CATEGORY_TARGETS: dict[str, list[tuple[str, tuple[int, ...]]]] = {
    "process_creation": [(SYSMON, (1,)), (SECURITY, (4688,))],
    "file_change": [(SYSMON, (2,))],
    "network_connection": [(SYSMON, (3,))],
    "process_termination": [(SYSMON, (5,))],
    "driver_load": [(SYSMON, (6,))],
    "image_load": [(SYSMON, (7,))],
    "create_remote_thread": [(SYSMON, (8,))],
    "raw_access_thread": [(SYSMON, (9,))],
    "process_access": [(SYSMON, (10,))],
    "file_event": [(SYSMON, (11,))],
    "registry_add": [(SYSMON, (12,))],
    "registry_delete": [(SYSMON, (12,))],
    "registry_set": [(SYSMON, (13,))],
    "registry_rename": [(SYSMON, (14,))],
    "registry_event": [(SYSMON, (12, 13, 14))],
    "create_stream_hash": [(SYSMON, (15,))],
    "pipe_created": [(SYSMON, (17, 18))],
    "wmi_event": [(SYSMON, (19, 20, 21))],
    "dns_query": [(SYSMON, (22,))],
    "file_delete": [(SYSMON, (23, 26))],
    "clipboard_capture": [(SYSMON, (24,))],
    "process_tampering": [(SYSMON, (25,))],
    "file_executable_detected": [(SYSMON, (29,))],
    "sysmon_status": [(SYSMON, (4, 16))],
    "sysmon_error": [(SYSMON, (255,))],
    "ps_script": [(PS_OP, (4104,))],
    "ps_module": [(PS_OP, (4103,))],
    "ps_classic_start": [(PS_CLASSIC, (400,))],
    "ps_classic_provider_start": [(PS_CLASSIC, (600,))],
    "ps_classic_script": [(PS_CLASSIC, (800,))],
}

# Sysmon-style field names -> Security 4688 names (pySigma windows audit mapping)
WINDOWS_PREFIXES = ("rules/windows/", "rules-emerging-threats/")

SECURITY_4688_MAP = {
    "image": "newprocessname",
    "parentimage": "parentprocessname",
    "processid": "newprocessid",
    "parentprocessid": "processid",
    "user": "subjectusername",
    "integritylevel": "mandatorylabel",
}


class UnsupportedRule(ValueError):
    """Raised when a rule uses a feature this evaluator deliberately does not implement."""


# --------------------------------------------------------------------------- events
class EventView:
    """Case-insensitive, lazily lower-cased view over one event record."""

    __slots__ = ("raw", "_low", "_blob", "alias")

    def __init__(self, raw: dict[str, Any], alias: dict[str, str] | None = None):
        self.raw = {str(k).lower(): v for k, v in raw.items()}
        self._low: dict[str, str | None] = {}
        self._blob: str | None = None
        self.alias = alias or {}

    def _key(self, name: str) -> str:
        k = name.lower()
        return self.alias.get(k, k) if self.alias and k not in self.raw else k

    def get(self, name: str) -> Any:
        return self.raw.get(self._key(name))

    def low(self, name: str) -> str | None:
        k = self._key(name)
        if k not in self._low:
            v = self.raw.get(k)
            self._low[k] = None if v is None else str(v).lower()
        return self._low[k]

    def blob(self) -> str:
        if self._blob is None:
            self._blob = "\x00".join(str(v).lower() for v in self.raw.values() if v is not None)
        return self._blob


# --------------------------------------------------------------------------- values
def _wild_to_regex(pattern: str) -> str:
    """Sigma wildcard string -> regex body (``*``, ``?``; backslash escapes them)."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _has_wild(s: str) -> bool:
    return bool(re.search(r"(?<!\\)[*?]", s))


def _unescape(s: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", s)


_DASHES = ("-", "/", "–", "—", "―")


def _windash(v: str) -> list[str]:
    if "-" not in v:
        return [v]
    return list(dict.fromkeys(v.replace("-", d) for d in _DASHES))


def _encode(v: str, enc: str | None) -> bytes:
    if enc in ("utf16le", "wide", "utf16"):
        return v.encode("utf-16-le")
    if enc == "utf16be":
        return v.encode("utf-16-be")
    return v.encode()


def _b64offsets(b: bytes) -> list[str]:
    """Standard Sigma base64offset: the three shift-invariant substrings."""
    start, end = (0, 2, 3), (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + b).decode()
        s, e = start[i], end[(len(b) + i) % 3]
        out.append(enc[s:e] if e is not None else enc[s:])
    return out


Matcher = Callable[[EventView], bool]


def _string_matcher(fname: str, values: list[str], mode: str, cased: bool, all_: bool) -> Matcher:
    """mode in {'eq','contains','startswith','endswith'}; values may contain wildcards.

    Plain values are matched with C-level string ops (set lookup, tuple
    startswith/endswith, substring loop for contains) - this is the hot
    path of the whole replay.
    """
    plain: list[str] = []
    regs: list[re.Pattern[str]] = []
    for v in values:
        if _has_wild(v):
            body = _wild_to_regex(v)
            if mode in ("contains", "endswith"):
                body = ".*" + body
            if mode in ("contains", "startswith"):
                body = body + ".*"
            regs.append(re.compile("^" + body + "$", re.S | (0 if cased else re.I)))
        else:
            v = _unescape(v)
            plain.append(v if cased else v.lower())

    def value(ev: EventView) -> str | None:
        if cased:
            raw = ev.get(fname)
            return None if raw is None else str(raw)
        return ev.low(fname)

    if all_:
        def m_all(ev: EventView) -> bool:
            val = value(ev)
            if val is None:
                return False
            if mode == "eq":
                ok = all(val == p for p in plain)
            elif mode == "contains":
                ok = all(p in val for p in plain)
            elif mode == "startswith":
                ok = all(val.startswith(p) for p in plain)
            else:
                ok = all(val.endswith(p) for p in plain)
            return ok and all(r.match(val) is not None for r in regs)
        return m_all

    if mode == "eq":
        pset = frozenset(plain)
        test = pset.__contains__
    elif mode == "startswith":
        ptup = tuple(plain)
        test = lambda val: val.startswith(ptup)
    elif mode == "endswith":
        ptup = tuple(plain)
        test = lambda val: val.endswith(ptup)
    elif len(plain) == 1:
        p0 = plain[0]
        test = lambda val: p0 in val
    else:
        ptup = tuple(plain)

        def test(val: str) -> bool:
            for p in ptup:
                if p in val:
                    return True
            return False

    if not plain:
        test = lambda val: False
    if not regs:
        def m(ev: EventView) -> bool:
            val = value(ev)
            return val is not None and test(val)
        return m

    def m_re(ev: EventView) -> bool:
        val = value(ev)
        if val is None:
            return False
        return test(val) or any(r.match(val) is not None for r in regs)
    return m_re


def _keyword_matcher(values: list[str], all_: bool) -> Matcher:
    pats = []
    for v in values:
        v = str(v)
        body = _wild_to_regex(v) if _has_wild(v) else None
        pats.append(re.compile(body, re.I | re.S) if body else _unescape(v).lower())

    def one(blob: str, p: Any) -> bool:
        return p.search(blob) is not None if isinstance(p, re.Pattern) else p in blob

    def m(ev: EventView) -> bool:
        b = ev.blob()
        return all(one(b, p) for p in pats) if all_ else any(one(b, p) for p in pats)

    return m


def _field_matcher(key: str, raw_values: Any) -> Matcher:
    fname, *mods = key.split("|")
    mods = [x.lower() for x in mods]
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    all_ = "all" in mods
    cased = "cased" in mods
    known = {"contains", "startswith", "endswith", "all", "windash", "re", "i", "m", "s",
             "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "cased",
             "cidr", "exists", "gt", "gte", "lt", "lte", "fieldref"}
    bad = [x for x in mods if x not in known]
    if bad:
        raise UnsupportedRule(f"modifier(s) {bad}")

    if "exists" in mods:
        want = bool(values[0])
        return lambda ev: (ev.get(fname) not in (None, "")) == want

    if any(v is None for v in values):
        others = [v for v in values if v is not None]
        rest = _field_matcher(key, others) if others else (lambda ev: False)
        return lambda ev: ev.get(fname) in (None, "") or rest(ev)

    if "fieldref" in mods:
        refs = [str(v) for v in values]
        return lambda ev: ev.low(fname) is not None and any(
            ev.low(fname) == ev.low(r) for r in refs)

    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            nums = [float(v) for v in values]
            cmp = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[op]

            def m(ev: EventView, nums=nums, cmp=cmp) -> bool:
                try:
                    x = float(ev.get(fname))
                except (TypeError, ValueError):
                    return False
                return any(cmp(x, n) for n in nums)
            return m

    if "cidr" in mods:
        nets = [ipaddress.ip_network(str(v), strict=False) for v in values]

        def m(ev: EventView) -> bool:
            try:
                ip = ipaddress.ip_address(str(ev.get(fname)).strip())
            except ValueError:
                return False
            return any(ip in n for n in nets)
        return m

    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        try:
            regs = [re.compile(str(v), flags) for v in values]
        except re.error as e:
            raise UnsupportedRule(f"regex: {e}") from e

        def m(ev: EventView) -> bool:
            v = ev.get(fname)
            if v is None:
                return False
            s = str(v)
            return (all if all_ else any)(r.search(s) is not None for r in regs)
        return m

    strs = [str(v) if not isinstance(v, bool) else str(v).lower() for v in values]
    if "windash" in mods:
        strs = [w for s in strs for w in _windash(s)]
    enc = next((x for x in mods if x in ("utf16le", "utf16be", "utf16", "wide")), None)
    if "base64offset" in mods:
        strs = [o for s in strs for o in _b64offsets(_encode(s, enc))]
        cased = True
    elif "base64" in mods:
        strs = [base64.b64encode(_encode(s, enc)).decode() for s in strs]
        cased = True
    mode = next((x for x in ("contains", "startswith", "endswith") if x in mods), "eq")
    if all_ and ("windash" in mods or "base64offset" in mods):
        # 'all' applies to the original values, each of which expanded to alternatives
        groups = [[w for w in (_windash(str(v)) if "windash" in mods else [str(v)])] for v in values]
        if "base64offset" in mods:
            groups = [[o for w in g for o in _b64offsets(_encode(w, enc))] for g in groups]
        subs = [_string_matcher(fname, g, mode, cased, False) for g in groups]
        return lambda ev: all(s(ev) for s in subs)
    return _string_matcher(fname, strs, mode, cased, all_)


def _map_matcher(d: dict[str, Any]) -> Matcher:
    parts: list[Matcher] = []
    for k, v in d.items():
        k = str(k)
        if k.split("|")[0] == "" or k.startswith("|"):
            mods = k.split("|")[1:]
            parts.append(_keyword_matcher([str(x) for x in (v if isinstance(v, list) else [v])],
                                          "all" in mods))
        else:
            parts.append(_field_matcher(k, v))
    if len(parts) == 1:
        return parts[0]

    def m(ev: EventView) -> bool:
        for p in parts:
            if not p(ev):
                return False
        return True
    return m


def compile_search(item: Any) -> Matcher:
    if isinstance(item, dict):
        return _map_matcher(item)
    if isinstance(item, list):
        if all(isinstance(x, dict) for x in item):
            subs = [_map_matcher(x) for x in item]
            return lambda ev: any(s(ev) for s in subs)
        if all(not isinstance(x, (dict, list)) for x in item):
            return _keyword_matcher([str(x) for x in item], False)
        raise UnsupportedRule("mixed list in detection item")
    if isinstance(item, (str, int)):
        return _keyword_matcher([str(item)], False)
    raise UnsupportedRule(f"detection item type {type(item).__name__}")


# --------------------------------------------------------------------------- condition
_TOKEN = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\b(?:1|all|any)\s+of\s+[\w*]+|[\w*]+)", re.I)


def _tokenize(cond: str) -> list[str]:
    toks, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m or m.end() == pos:
            raise UnsupportedRule(f"condition syntax near {cond[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
        while pos < len(cond) and cond[pos].isspace():
            pos += 1
    return toks


def compile_condition(cond: str, searches: dict[str, Matcher]) -> Matcher:
    if "|" in cond:
        raise UnsupportedRule("aggregation in condition")
    toks = _tokenize(cond)
    i = 0

    def peek() -> str | None:
        return toks[i].lower() if i < len(toks) else None

    def eat() -> str:
        nonlocal i
        i += 1
        return toks[i - 1]

    def group(expr: str) -> Matcher:
        q, _, pat = expr.split(None, 2)
        q = q.lower()
        names = [n for n in searches if pat.lower() == "them" or fnmatch.fnmatchcase(n, pat)]
        names = [n for n in names if not n.startswith("_")]
        if not names:
            raise UnsupportedRule(f"no search matches {pat!r}")
        ms = [searches[n] for n in names]
        if q == "all":
            return lambda ev: all(m(ev) for m in ms)
        return lambda ev: any(m(ev) for m in ms)

    def atom() -> Matcher:
        t = peek()
        if t is None:
            raise UnsupportedRule("unexpected end of condition")
        if t == "(":
            eat()
            m = expr_or()
            if peek() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            eat()
            return m
        if t == "not":
            eat()
            inner = atom()
            return lambda ev: not inner(ev)
        tok = eat()
        if re.match(r"(1|all|any)\s+of\s+", tok, re.I):
            return group(tok)
        if tok not in searches:
            raise UnsupportedRule(f"unknown search identifier {tok!r}")
        return searches[tok]

    def expr_and() -> Matcher:
        parts = [atom()]
        while peek() == "and":
            eat()
            parts.append(atom())
        return parts[0] if len(parts) == 1 else (lambda ev: all(p(ev) for p in parts))

    def expr_or() -> Matcher:
        parts = [expr_and()]
        while peek() == "or":
            eat()
            parts.append(expr_and())
        return parts[0] if len(parts) == 1 else (lambda ev: any(p(ev) for p in parts))

    m = expr_or()
    if i != len(toks):
        raise UnsupportedRule(f"trailing tokens in condition: {toks[i:]}")
    return m


# --------------------------------------------------------------------------- rules
Target = tuple[str, int | None]  # (channel lower-case, event id or None = any)


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    logsource: dict[str, str]
    targets: tuple[Target, ...]
    match: Matcher = field(repr=False)
    path: str = ""

    def applies(self, channel: str, event_id: int | None) -> bool:
        return any(c == channel and (e is None or e == event_id) for c, e in self.targets)


def resolve_logsource(ls: dict[str, Any]) -> tuple[Target, ...]:
    product = str(ls.get("product", "")).lower()
    cat = str(ls.get("category", "")).lower() if ls.get("category") else ""
    svc = str(ls.get("service", "")).lower() if ls.get("service") else ""
    if product != "windows":
        raise UnsupportedRule(f"product {product or '?'}")
    if cat:
        if cat not in CATEGORY_TARGETS:
            raise UnsupportedRule(f"category {cat}")
        return tuple((c, e) for c, eids in CATEGORY_TARGETS[cat] for e in eids)
    if svc:
        if svc not in SERVICE_CHANNELS:
            raise UnsupportedRule(f"service {svc}")
        return ((SERVICE_CHANNELS[svc], None),)
    raise UnsupportedRule("no category/service")


_TECH_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def parse_rule(doc: dict[str, Any], path: str = "") -> SigmaRule:
    if "correlation" in doc or doc.get("type") == "correlation":
        raise UnsupportedRule("correlation rule")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise UnsupportedRule("missing detection/condition")
    targets = resolve_logsource(doc.get("logsource") or {})
    searches = {k: compile_search(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    cond = det["condition"]
    if isinstance(cond, list):
        subs = [compile_condition(str(c), searches) for c in cond]
        match: Matcher = lambda ev: any(s(ev) for s in subs)
    else:
        match = compile_condition(str(cond), searches)
    tags = [str(t) for t in doc.get("tags") or []]
    techs = tuple(sorted({m.group(1).upper() for t in tags if (m := _TECH_TAG.match(t))}))
    tactics = tuple(t.split(".", 1)[1].replace("_", "-") for t in tags
                    if t.lower().startswith("attack.") and not _TECH_TAG.match(t)
                    and not re.match(r"attack\.[gs]\d{4}", t, re.I))
    return SigmaRule(str(doc.get("id", path)), str(doc.get("title", "")),
                     str(doc.get("level", "")).lower(), str(doc.get("status", "")).lower(),
                     techs, tactics, dict(doc.get("logsource") or {}), targets, match, path)


@dataclass
class RuleSet:
    rules: list[SigmaRule]
    unsupported: dict[str, str]  # path -> reason

    def filter(self, pred: Callable[[SigmaRule], bool]) -> RuleSet:
        return RuleSet([r for r in self.rules if pred(r)], self.unsupported)


def _iter_docs(text: str) -> Iterator[dict[str, Any]]:
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    if len(docs) <= 1:
        yield from docs
        return
    # Sigma multi-document "collection": first doc may be a global action template
    base: dict[str, Any] = {}
    for d in docs:
        if d.get("action") == "global":
            base = {k: v for k, v in d.items() if k != "action"}
            continue
        merged = dict(base)
        for k, v in d.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k] = {**merged[k], **v}
            else:
                merged[k] = v
        yield merged


def load_rules_from_texts(items: Iterable[tuple[str, str]]) -> RuleSet:
    rules, unsupported = [], {}
    for path, text in items:
        try:
            docs = list(_iter_docs(text))
        except yaml.YAMLError as e:
            unsupported[path] = f"yaml: {e.__class__.__name__}"
            continue
        for n, d in enumerate(docs):
            key = path if len(docs) == 1 else f"{path}#{n}"
            try:
                rules.append(parse_rule(d, key))
            except (UnsupportedRule, ValueError, TypeError) as e:
                unsupported[key] = str(e)
    return RuleSet(rules, unsupported)


def load_rules(source: str | Path, subdir_prefix: str | tuple[str, ...] = "") -> RuleSet:
    """Load Sigma rules from a directory of .yml files or a SigmaHQ release zip.

    ``subdir_prefix`` restricts to paths under e.g. ``rules/windows``.
    """
    p = Path(source)
    if p.suffix == ".zip":
        import zipfile

        with zipfile.ZipFile(p) as z:
            items = [(n, z.read(n).decode("utf-8", "replace")) for n in sorted(z.namelist())
                     if n.endswith((".yml", ".yaml")) and n.startswith(subdir_prefix)]
    else:
        items = [(str(q.relative_to(p)).replace("\\", "/"), q.read_text(encoding="utf-8"))
                 for q in sorted(p.rglob("*.yml"))
                 if str(q.relative_to(p)).replace("\\", "/").startswith(subdir_prefix)]
    return load_rules_from_texts(items)
