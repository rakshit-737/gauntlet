"""Synthetic range + telemetry generator (pure simulation, deterministic by seed)."""
from __future__ import annotations

import random

from .models import EmulationStep, Event, Host, Range

DEFAULT_RANGE = Range("acme-lab", (
    Host("WS01", "windows", "workstation", frozenset({"sysmon", "security"})),
    Host("WS02", "windows", "workstation", frozenset({"sysmon", "security"})),
    Host("FS01", "windows", "fileserver", frozenset({"sysmon", "security"})),
    Host("DC01", "windows", "domain-controller", frozenset({"security", "auth"})),
    Host("GW01", "linux", "gateway", frozenset({"dns", "proxy", "mail"})),
))

_BENIGN = [
    ("sysmon", {"EventID": 1, "Image": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "CommandLine": "WINWORD.EXE /n report.docx", "ParentImage": "C:\\Windows\\explorer.exe"}),
    ("sysmon", {"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -File C:\\IT\\inventory.ps1", "ParentImage": "C:\\Windows\\System32\\svchost.exe"}),
    ("sysmon", {"EventID": 11, "TargetFilename": "C:\\Users\\alice\\Documents\\notes.txt",
                "Image": "C:\\Windows\\System32\\notepad.exe"}),
    ("sysmon", {"EventID": 10, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "SourceImage": "C:\\Windows\\System32\\svchost.exe", "GrantedAccess": "0x1000"}),
    ("security", {"EventID": 4624, "SubjectUserName": "alice"}),
    ("auth", {"result": "success", "user": "alice", "src_ip": "10.66.0.21", "logon_type": 2}),
    ("auth", {"result": "failure", "user": "bob", "src_ip": "10.66.0.22"}),
    ("dns", {"query": "www.example.com"}),
    ("mail", {"attachment": "agenda.pdf", "sender_domain": "example.com"}),
]


def without_sources(rng: Range, disabled: set[str]) -> Range:
    """Return a copy of the range with some log sources switched off (telemetry gap)."""
    return Range(rng.name, tuple(Host(h.name, h.os, h.role, h.log_sources - disabled) for h in rng.hosts))


def _target_host(rng: Range, source: str, r: random.Random) -> Host | None:
    candidates = [h for h in rng.hosts if source in h.log_sources]
    return r.choice(candidates) if candidates else None


def generate(plan: list[EmulationStep], rng: Range = DEFAULT_RANGE, seed: int = 7,
             noise: int = 50) -> list[Event]:
    """Emit labelled emulation events + unlabelled benign noise.

    If no host in the range collects the step's required log source, the step emits
    nothing observable -- modelling a telemetry gap (a 'cheapest win' candidate).
    """
    r = random.Random(seed)
    events: list[Event] = []
    t = 0.0
    for step in plan:
        host = _target_host(rng, step.requires_source, r)
        if host is None:
            continue
        for tmpl in step.events:
            t += 1.0
            events.append(Event(host.name, step.requires_source, dict(tmpl), step.technique_id, t))
    for _ in range(noise):
        src, tmpl = r.choice(_BENIGN)
        host = _target_host(rng, src, r)
        if host:
            events.append(Event(host.name, src, dict(tmpl), None, r.uniform(0, t + 1)))
    events.sort(key=lambda e: e.ts)
    return events
