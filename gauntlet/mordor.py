"""Loader for OTRF Security-Datasets (a.k.a. Mordor) atomic Windows recordings.

Each dataset is a zip of JSON-lines Windows events recorded while a single
technique was executed in the OTRF "shire" lab (Sysmon, Security, PowerShell,
... channels). The ``_metadata/SDWIN-*.yaml`` files map every recording to
ATT&CK technique(s); that mapping is the ground truth for coverage scoring.

Recordings contain the attack *and* the lab's background activity, which is
what makes them useful for estimating both recall and alert noise.
"""
from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Dataset:
    id: str                      # SDWIN-...
    title: str
    techniques: tuple[str, ...]  # ATT&CK ids, e.g. ("T1003.001",)
    files: tuple[Path, ...]      # local host recordings (zip)
    tactic_dir: str = ""         # e.g. credential_access

    @property
    def available(self) -> bool:
        """All host recordings present *and readable* (local AV may quarantine some)."""
        return bool(self.files) and all(_readable(f) for f in self.files)


def _readable(p: Path) -> bool:
    try:
        with p.open("rb") as fh:
            fh.read(4)
        return True
    except OSError:
        return False


def _techniques(meta: dict[str, Any]) -> tuple[str, ...]:
    out = []
    for m in meta.get("attack_mappings") or []:
        t = str(m.get("technique") or "").strip().upper()
        if not t.startswith("T"):
            continue
        sub = m.get("sub-technique")
        if sub not in (None, "", "null"):
            t = f"{t}.{str(sub).zfill(3)}"
        out.append(t)
    return tuple(sorted(set(out)))


def load_catalog(root: str | Path) -> list[Dataset]:
    """Parse all Windows atomic metadata under ``<root>/mordor/_metadata``."""
    root = Path(root)
    mdir = root / "mordor" / "_metadata"
    out = []
    for p in sorted(mdir.glob("SDWIN-*.yaml")):
        meta = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        files = []
        tactic_dir = ""
        for f in meta.get("files") or []:
            if str(f.get("type", "")).lower() != "host":
                continue
            rel = f["link"].split("/datasets/atomic/", 1)[-1]
            files.append(root / "mordor" / rel)
            tactic_dir = rel.split("/")[1] if rel.count("/") >= 2 else ""
        out.append(Dataset(str(meta.get("id", p.stem)), str(meta.get("title", "")),
                           _techniques(meta), tuple(files), tactic_dir))
    return out


def normalize(ev: dict[str, Any]) -> tuple[str, int | None, dict[str, Any]]:
    """Return (channel lower-case, event id, record) for a raw event dict."""
    ch = ev.get("Channel") or ev.get("channel") or ev.get("log_name") or ""
    eid = ev.get("EventID", ev.get("event_id"))
    try:
        eid = int(eid) if eid is not None else None
    except (TypeError, ValueError):
        eid = None
    return str(ch).lower(), eid, ev


def iter_events(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield raw event dicts from a recording (.zip of .json lines, or a .json/.jsonl file)."""
    p = Path(path)
    if p.suffix == ".zip":
        with zipfile.ZipFile(p) as z:
            for name in z.namelist():
                if name.endswith("/"):
                    continue
                with z.open(name) as fh:
                    yield from _iter_lines(fh)
    else:
        with p.open("rb") as fh:
            yield from _iter_lines(fh)


def _iter_lines(fh) -> Iterator[dict[str, Any]]:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        if isinstance(d, dict):
            yield d
