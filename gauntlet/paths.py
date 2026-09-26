"""Where the downloaded datasets live (outside git)."""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ATTACK_VERSION = "19.2"
SIGMA_TAG = "r2026-07-01"


def data_dir() -> Path:
    env = os.environ.get("GAUNTLET_DATA_DIR")
    return Path(env) if env else REPO / "data"


def attack_bundle(root: Path | None = None) -> Path:
    return (root or data_dir()) / "attack" / f"enterprise-attack-{ATTACK_VERSION}.json"


def sigma_zip(root: Path | None = None) -> Path:
    return (root or data_dir()) / "sigma" / f"sigma_all_rules-{SIGMA_TAG}.zip"


def art_csv(root: Path | None = None) -> Path:
    return (root or data_dir()) / "art" / "windows-index.csv"


def mordor_root(root: Path | None = None) -> Path:
    return root or data_dir()


def have_real_data(root: Path | None = None) -> bool:
    r = root or data_dir()
    return sigma_zip(r).exists() and (r / "mordor" / "_metadata").is_dir()
