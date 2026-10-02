"""MkDocs hook: copy results/ into the docs tree before every build (no manual prepare step)."""
from __future__ import annotations

import importlib.util
from pathlib import Path


def on_pre_build(config, **kwargs) -> None:  # noqa: ARG001 - MkDocs hook signature
    spec = importlib.util.spec_from_file_location("prepare_docs", Path(__file__).with_name("prepare_docs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
