"""SecHelix scanner-output adapters.

Adapters preserve tool output as untrusted candidate evidence. They never decide
whether a vulnerability exists and never assign a SecHelix severity.
"""

from .base import AdapterError, CANDIDATE, UNASSESSED
from .registry import ADAPTERS, parse

__all__ = ["ADAPTERS", "AdapterError", "CANDIDATE", "UNASSESSED", "parse"]
