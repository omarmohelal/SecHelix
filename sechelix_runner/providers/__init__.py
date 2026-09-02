"""Provider adapters. Optional, swappable, and never named by the contracts."""

from __future__ import annotations

from .base import (
    NODE_OUTPUT_SCHEMA,
    ProviderError,
    ProviderExecutor,
    ProviderResult,
    extract_json,
    validate_node_output,
)
from .reasoning import (
    FORBIDDEN_VERIFIER_FIELDS,
    ReasoningExecutor,
    build_prompt,
    verifier_view,
)

__all__ = [
    "NODE_OUTPUT_SCHEMA",
    "FORBIDDEN_VERIFIER_FIELDS",
    "ProviderError",
    "ProviderExecutor",
    "ProviderResult",
    "ReasoningExecutor",
    "build_prompt",
    "extract_json",
    "validate_node_output",
    "verifier_view",
]
