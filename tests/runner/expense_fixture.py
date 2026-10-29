"""Load the examples/expense-api fixture app without leaking its module names.

The fixture is a flat directory of top-level modules (``app``, ``auth``, ``db``,
``reports``). Importing it by putting that directory on ``sys.path`` would leave
those names cached in ``sys.modules`` -- and ``reports`` shadows the repository's
own ``reports`` package, breaking any test that imports ``reports.report_renderer``
later in the same run. This loader imports the fixture, then restores both
``sys.path`` and whatever those names meant before. The returned ``app`` module
keeps working: it holds its own references to the fixture modules it imported.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

EXPENSE_API = Path(__file__).resolve().parents[2] / "examples" / "expense-api"
_FIXTURE_MODULES = ("app", "auth", "db", "reports")


def load_expense_app() -> ModuleType:
    saved = {name: sys.modules.pop(name) for name in _FIXTURE_MODULES if name in sys.modules}
    sys.path.insert(0, str(EXPENSE_API))
    try:
        return importlib.import_module("app")
    finally:
        sys.path.remove(str(EXPENSE_API))
        for name in _FIXTURE_MODULES:
            sys.modules.pop(name, None)
        sys.modules.update(saved)
