"""Atomic Red Team test index: which emulation tests exist per ATT&CK technique.

GAUNTLET never runs these tests itself. The index is used to (a) define the
universe of techniques that *can* be emulated on Windows and (b) emit a dry-run
emulation manifest (test names + GUIDs) that an operator can execute with
Invoke-AtomicRedTeam **inside an isolated lab only**.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ART_PATH = Path(__file__).resolve().parent / "data" / "art_windows.json"


def parse_index_csv(text: str) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    seen: set[str] = set()
    for row in csv.DictReader(io.StringIO(text)):
        tid = (row.get("Technique #") or "").strip().upper()
        guid = (row.get("Test GUID") or "").strip()
        if not tid.startswith("T") or guid in seen:
            continue
        seen.add(guid)
        out.setdefault(tid, []).append({"name": (row.get("Test Name") or "").strip(), "guid": guid,
                                        "executor": (row.get("Executor Name") or "").strip()})
    return dict(sorted(out.items()))


def load_index(path: str | Path | None = None) -> dict[str, list[dict[str, str]]]:
    p = Path(path) if path else ART_PATH
    if p.suffix == ".csv":
        return parse_index_csv(p.read_text(encoding="utf-8"))
    return json.loads(p.read_text(encoding="utf-8"))


def write_index(index: dict[str, list[dict[str, str]]], path: str | Path = ART_PATH) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    return p


def manifest(techniques: list[str], index: dict[str, list[dict[str, str]]], per_technique: int = 2) -> list[dict]:
    """Dry-run emulation manifest in priority order (nothing is executed)."""
    out = []
    for i, t in enumerate(techniques, 1):
        tests = index.get(t, [])[:per_technique]
        out.append({"order": i, "technique": t, "atomic_tests": tests,
                    "invoke": [f"Invoke-AtomicTest {t} -TestGuids {x['guid']}" for x in tests]})
    return out
