"""README and docs stay in sync (skipped in an sdist, which ships no docs/)."""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DIAGRAMS = REPO / "docs" / "assets" / "diagrams"
pytestmark = pytest.mark.skipif(not DIAGRAMS.is_dir(), reason="docs/ not shipped (sdist)")


def _mermaid(text: str) -> list[str]:
    return [b.strip() for b in re.findall(r"```mermaid\n(.*?)```", text, re.S)]


def test_readme_architecture_diagrams_match_the_docs_sources():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    want = [(DIAGRAMS / f"{n}.mmd").read_text(encoding="utf-8").strip() for n in ("plan", "measure")]
    assert _mermaid(readme) == want
    arch = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    assert '--8<-- "docs/assets/diagrams/plan.mmd"' in arch and '--8<-- "docs/assets/diagrams/measure.mmd"' in arch


def test_architecture_diagrams_stay_small():
    # readable at content width: few nodes, module-name labels (descriptions live in the module table)
    for p in DIAGRAMS.glob("*.mmd"):
        nodes = set(re.findall(r"\b([A-Z]{2,5})[\[(]", p.read_text(encoding="utf-8")))
        assert len(nodes) <= 8, (p.name, nodes)
        for label in re.findall(r'"([^"]+)"', p.read_text(encoding="utf-8")):
            assert all(len(part) <= 24 for part in label.split("<br/>")), label


def test_module_tables_match():
    def table(t):
        return t[t.index("| Module | Purpose |"):].split("\n\n", 1)[0]
    assert table((REPO / "README.md").read_text(encoding="utf-8")) == \
        table((REPO / "docs" / "architecture.md").read_text(encoding="utf-8"))
