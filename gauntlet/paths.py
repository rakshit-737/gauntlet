"""Where the downloaded datasets live (outside git), and which CI run produced a result."""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
LEGACY_RULES = PACKAGE / "data" / "rules"  # the 7 v0.1 rules, shipped as package data
ATTACK_VERSION = "19.2"
SIGMA_TAG = "r2026-07-01"


def data_dir() -> Path:
    """``$GAUNTLET_DATA_DIR`` if set, else ``./data`` relative to the working directory."""
    env = os.environ.get("GAUNTLET_DATA_DIR")
    return Path(env) if env else Path.cwd() / "data"


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


REPO_URL = "https://github.com/rakshit-737/gauntlet"


def provenance() -> dict[str, str | None]:
    """Workflow run id and commit (GitHub Actions env) that produced a result file; None locally."""
    return {"run_id": os.environ.get("GITHUB_RUN_ID"), "commit": os.environ.get("GITHUB_SHA")}


def provenance_line(r: dict) -> str:
    """Markdown sentence naming the run and commit a result file came from."""
    if r.get("run_id"):
        c = f" at commit `{r['commit'][:7]}`" if r.get("commit") else ""
        return f"Source: GitHub Actions run [{r['run_id']}]({REPO_URL}/actions/runs/{r['run_id']}){c}."
    return "Source: local run (no GitHub Actions run id)."
