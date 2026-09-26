"""Copy committed benchmark artefacts from results/ into the docs tree before `mkdocs build`.

Keeps a single source of truth (results/) while the site and the static demo
(docs/demo/) can serve the same JSON and PNG files.
"""
from __future__ import annotations

import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    res = REPO / "results"
    img = REPO / "docs" / "assets" / "results"
    data = REPO / "docs" / "demo" / "data"
    for d in (img, data):
        d.mkdir(parents=True, exist_ok=True)
    for f in res.glob("*.png"):
        shutil.copy2(f, img / f.name)
    for f in res.glob("*.json"):
        shutil.copy2(f, data / f.name)
    print(f"copied results -> {img.relative_to(REPO)}, {data.relative_to(REPO)}")


if __name__ == "__main__":
    main()
