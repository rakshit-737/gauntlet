#!/usr/bin/env python3
"""Download the real public datasets GAUNTLET benchmarks against.

All sources are pinned (git commit / release tag / versioned
file) and every file is verified against ``scripts/checksums.sha256`` when an
entry exists. Run with ``--write-checksums`` once to (re)generate the manifest.

Sources (see docs/DATASETS.md for licences and citations):
  * MITRE ATT&CK Enterprise STIX 2.1 bundle (v19.2)          ~50 MB
  * SigmaHQ rule release r2026-07-01 (sigma_all_rules.zip)    ~3 MB
  * OTRF Security-Datasets (Mordor) Windows *atomic* host
    recordings + metadata, pinned commit                      ~60 MB
  * Red Canary Atomic Red Team Windows test index (CSV)       ~0.2 MB

Nothing here is executable attack tooling: the datasets are recorded Windows
event logs (JSON), YAML detection rules, a STIX JSON knowledge base and a CSV
index of test *names*. No malware binaries are fetched.

Usage:
    python scripts/download_data.py [--data-dir DIR] [--only attack,sigma,mordor,art]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ATTACK_VERSION = "19.2"
SIGMA_TAG = "r2026-07-01"
OTRF_SHA = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
ART_SHA = "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json")
SIGMA_URL = f"https://github.com/SigmaHQ/sigma/releases/download/{SIGMA_TAG}/sigma_all_rules.zip"
ART_URL = (f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ART_SHA}/"
           "atomics/Indexes/Indexes-CSV/windows-index.csv")
OTRF_RAW = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_SHA}/"
OTRF_TREE = (f"https://api.github.com/repos/OTRF/Security-Datasets/git/trees/{OTRF_SHA}"
             "?recursive=1")

CHECKSUMS = Path(__file__).resolve().parent / "checksums.sha256"


def default_data_dir() -> Path:
    env = os.environ.get("GAUNTLET_DATA_DIR")
    return Path(env) if env else Path(__file__).resolve().parent.parent / "data"


def _get(url: str, retries: int = 4) -> bytes:
    last: Exception | None = None
    for i in range(retries):
        try:
            headers = {"User-Agent": "gauntlet-downloader"}
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if token and url.startswith("https://api.github.com/"):
                headers["Authorization"] = f"Bearer {token}"  # optional: avoids API rate limits
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (pinned https URLs)
                return r.read()
        except Exception as e:  # pragma: no cover - network
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _stream(url: str, dest: Path, retries: int = 6) -> None:
    """Stream to ``dest`` in chunks, resuming a partial file with HTTP Range when possible."""
    last: Exception | None = None
    for i in range(retries):
        try:
            have = dest.stat().st_size if dest.exists() else 0
            headers = {"User-Agent": "gauntlet-downloader"}
            if have:
                headers["Range"] = f"bytes={have}-"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (pinned https URLs)
                mode = "ab" if have and r.status == 206 else "wb"
                with dest.open(mode) as fh:
                    for chunk in iter(lambda: r.read(1 << 16), b""):
                        fh.write(chunk)
            return
        except Exception as e:  # pragma: no cover - network
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"failed to fetch {url}: {last}")


def _sha256(p: Path, retries: int = 10) -> str:
    # Windows: AV scanners can briefly lock a freshly written zip (EINVAL/EACCES) -> retry
    for i in range(retries):
        try:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            if i == retries - 1:
                raise
            time.sleep(0.5 * (i + 1))
    raise AssertionError("unreachable")


def load_checksums() -> dict[str, str]:
    if not CHECKSUMS.exists():
        return {}
    out = {}
    for line in CHECKSUMS.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, rel = line.split(maxsplit=1)
            out[rel.strip()] = digest
    return out


class Fetcher:
    def __init__(self, root: Path, sums: dict[str, str], force: bool = False):
        self.root, self.sums, self.force = root, sums, force
        self.seen: dict[str, str] = {}
        self.bad: list[str] = []
        self.unreadable: list[str] = []

    def fetch(self, url: str, rel: str) -> Path:
        dest = self.root / rel
        if self.force or not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".part")
            _stream(url, tmp)
            tmp.replace(dest)
            print(f"  downloaded {rel} ({dest.stat().st_size / 1e6:.2f} MB)")
        try:
            digest = _sha256(dest, retries=4)
        except OSError as e:
            # e.g. Windows Defender blocks recordings that contain attack-tool strings
            self.unreadable.append(rel)
            print(f"  UNREADABLE {rel}: {e.__class__.__name__} (likely local AV quarantine) - skipped",
                  file=sys.stderr)
            return dest
        self.seen[rel] = digest
        want = self.sums.get(rel)
        if want and want != digest:
            self.bad.append(rel)
            print(f"  CHECKSUM MISMATCH {rel}", file=sys.stderr)
        return dest


def get_attack(f: Fetcher) -> None:
    print("[attack] MITRE ATT&CK Enterprise", ATTACK_VERSION)
    f.fetch(ATTACK_URL, f"attack/enterprise-attack-{ATTACK_VERSION}.json")


def get_sigma(f: Fetcher) -> None:
    print("[sigma] SigmaHQ", SIGMA_TAG)
    f.fetch(SIGMA_URL, f"sigma/sigma_all_rules-{SIGMA_TAG}.zip")


def get_art(f: Fetcher) -> None:
    print("[art] Atomic Red Team windows index", ART_SHA[:10])
    f.fetch(ART_URL, "art/windows-index.csv")


def get_mordor(f: Fetcher) -> None:
    """Windows atomic metadata + every *Host* recording it references."""
    print("[mordor] OTRF Security-Datasets", OTRF_SHA[:10])
    tree_path = f.root / "mordor" / "tree.json"
    if not tree_path.exists() or f.force:
        tree_path.parent.mkdir(parents=True, exist_ok=True)
        tree_path.write_bytes(_get(OTRF_TREE))
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    import yaml  # local import: only needed here

    metas = sorted(t["path"] for t in tree["tree"]
                   if t["path"].startswith("datasets/atomic/_metadata/SDWIN-")
                   and t["path"].endswith(".yaml"))
    have = {t["path"] for t in tree["tree"]}
    n_files = 0
    for m in metas:
        rel = "mordor/" + m.split("datasets/atomic/", 1)[1]
        p = f.fetch(OTRF_RAW + m, rel)
        meta = yaml.safe_load(p.read_text(encoding="utf-8"))
        for file in meta.get("files") or []:
            if str(file.get("type", "")).lower() != "host":
                continue
            link = file["link"]
            path = link.split("/master/", 1)[-1]
            if path not in have:  # dead link in upstream metadata
                continue
            f.fetch(OTRF_RAW + path, "mordor/" + path.split("datasets/atomic/", 1)[1])
            n_files += 1
    print(f"  {len(metas)} metadata files, {n_files} host recordings")


SOURCES = {"attack": get_attack, "sigma": get_sigma, "art": get_art, "mordor": get_mordor}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", type=Path, default=default_data_dir())
    ap.add_argument("--only", default=",".join(SOURCES), help="comma list of " + ",".join(SOURCES))
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    ap.add_argument("--write-checksums", action="store_true",
                    help="write scripts/checksums.sha256 from what is on disk")
    a = ap.parse_args(argv)
    root = a.data_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    print(f"data dir: {root}")
    f = Fetcher(root, {} if a.write_checksums else load_checksums(), a.force)
    for name in a.only.split(","):
        SOURCES[name.strip()](f)
    if a.write_checksums:
        merged = load_checksums()
        merged.update(f.seen)
        CHECKSUMS.write_text("# sha256  path-relative-to-data-dir\n" + "".join(
            f"{d}  {r}\n" for r, d in sorted(merged.items())), encoding="utf-8")
        print(f"wrote {len(merged)} checksums -> {CHECKSUMS}")
    total = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    print(f"total on disk: {total / 1e6:.1f} MB")
    if f.unreadable:
        print(f"{len(f.unreadable)} files unreadable (see above); benchmarks skip them", file=sys.stderr)
    if f.bad:
        print(f"{len(f.bad)} checksum mismatches", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
