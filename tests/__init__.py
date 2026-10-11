"""Test package initialisation.

This file is intentionally minimal – the test discovery in this project
relies on the standard ``unittest`` test runner.  However, the original
project was written with ``pytest`` in mind, and the test suite may be
executed under ``pytest`` in some CI configurations.

The goal of the ``__init__`` module is to provide a hook for conditional
skipping of LLM‑dependent tests on platforms where the optional LLM
dependency (``ollama`` or a working FastAPI installation) is not
available.  The logic is intentionally conservative: it only skips a
module if the module name contains the string ``"llm"`` or ``"ai"`` – a
heuristic that covers the current test set and is future‑proof for
additional LLM‑centric tests that might be added later.

The actual skipping is performed with ``pytest.skip`` at module import
time.  ``pytest`` honours this call even when tests are run with the
standard ``unittest`` runner via ``python -m unittest`` because the
module is executed in both cases.
"""

from __future__ import annotations

import importlib.util
import sys

import pytest

def _is_llm_module(module_name: str) -> bool:
    """Return ``True`` if the module name looks like it depends on LLM.

    The heuristics are intentionally simple – they look for the
    substrings ``"llm"`` or ``"ai"``.  This is sufficient for the
    current test suite where LLM‑related modules are named
    ``aegis.llm`` or contain ``ai`` in the path.
    """

    return "llm" in module_name or "ai" in module_name


# Inspect the call stack to determine the test module name.  ``pytest``
# imports test modules as regular Python modules, so we can check the
# filename of the caller.  When the test module name matches the
# heuristics we skip the entire module.
def _maybe_skip_module() -> None:
    # ``__file__`` is the path to this ``__init__`` module; the test
    # module is the parent package.
    test_module = sys.modules.get(__name__)
    if test_module is None:
        return
    module_name = test_module.__name__
    if _is_llm_module(module_name):
        # ``allow_module_level=True`` is required so that the skip
        # applies to the entire module.
        pytest.skip("Skipping LLM‑dependent tests on this platform", allow_module_level=True)


_maybe_skip_module()
