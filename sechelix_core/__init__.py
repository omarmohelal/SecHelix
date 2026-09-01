"""Deterministic, dependency-free SecHelix core contracts and engines."""

from .applicability import evaluate_applicability
from .attack_surface import render_mermaid, validate_attack_surface
from .contracts import ContractValidationError, validate_contract
from .knowledge import expected_research_confidence, stale_source_ids
from .variant_hunter import VariantSearchError, classify_variant, search_variants

__all__ = [
    "ContractValidationError",
    "VariantSearchError",
    "classify_variant",
    "evaluate_applicability",
    "expected_research_confidence",
    "render_mermaid",
    "stale_source_ids",
    "search_variants",
    "validate_attack_surface",
    "validate_contract",
]
