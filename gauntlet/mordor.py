"""Loader for OTRF Security-Datasets (a.k.a. Mordor) atomic Windows recordings.

Each dataset is a zip of JSON-lines Windows events recorded while a single
technique was executed in the OTRF "shire" lab (Sysmon, Security, PowerShell,
... channels). The ``_metadata/SDWIN-*.yaml`` files map every recording to
ATT&CK technique(s); that mapping is the ground truth for coverage scoring.

Recordings contain the attack *and* the lab's background activity, which is
what makes them useful for estimating both recall and alert noise.
"""
from __future__ import annotations

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
    tactic_dir: str = ""         # e.g. credential_access (OTRF atomic), "compound", or platform (Splunk)
    source: str = "otrf"         # otrf | otrf-compound | splunk | live

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
        if not t.startswith("T") or not t[1:].isdigit() or t == "T0000":  # T0000 = unmapped placeholder
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
    """Yield raw event dicts from a recording (.zip / .tar.gz of JSON lines, or a plain .json file)."""
    p = Path(path)
    if p.name.endswith((".tar.gz", ".tgz")):
        import tarfile

        with tarfile.open(p, "r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    fh = tf.extractfile(m)
                    if fh is not None:
                        yield from _iter_lines(fh)
    elif p.suffix == ".zip":
        with zipfile.ZipFile(p) as z:
            for name in z.namelist():
                if name.endswith("/"):
                    continue
                with z.open(name) as fh:
                    yield from _iter_lines(fh)
    else:
        with p.open("rb") as fh:
            yield from _iter_lines(fh)


def _iter_lines(fh) -> Iterator[dict[str, Any]]:  # noqa: D401
    """JSON lines (OTRF), XML event lines (Splunk / Sysmon for Linux) or raw auditd lines."""
    from .formats import iter_text_lines

    yield from iter_text_lines(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw for raw in fh)


def load_compound(root: str | Path) -> list[Dataset]:
    """OTRF *compound* campaigns (``<root>/mordor-compound/_metadata/*.yaml``): multi-technique recordings."""
    root = Path(root)
    out = []
    for p in sorted((root / "mordor-compound" / "_metadata").glob("*.yaml")):
        meta = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        files = [root / "mordor-compound" / f["link"].split("/datasets/compound/", 1)[-1]
                 for f in meta.get("files") or [] if str(f.get("type", "")).lower() == "host"]
        out.append(Dataset(str(meta.get("id", p.stem)), str(meta.get("title", "")),
                           _techniques(meta), tuple(files), "compound", source="otrf-compound"))
    return out


def load_splunk(root: str | Path, manifest: str | Path | None = None) -> list[Dataset]:
    """Splunk attack_data recordings listed in the committed manifest (recording-level labels)."""
    import json

    root = Path(root)
    mp = Path(manifest) if manifest else paths_manifest()
    if not mp.exists():
        return []
    man = json.loads(mp.read_text(encoding="utf-8"))
    out = []
    for r in man["recordings"]:
        techs = tuple(sorted({t for t in r["techniques"] if t[1:].replace(".", "").isdigit()}))
        files = tuple(root / "splunk" / f["path"].split("datasets/", 1)[1] for f in r["files"])
        st = {f["sourcetype"] for f in r["files"]}
        platform = "linux" if st & {"auditd", "sysmon:linux"} else "windows"
        out.append(Dataset(r["id"], r["title"], techs, files, platform, source="splunk"))
    return out


def paths_manifest() -> Path:
    """Location of the Splunk manifest: next to the package in a checkout (scripts/)."""
    return Path(__file__).resolve().parent.parent / "scripts" / "splunk_attack_data.json"
