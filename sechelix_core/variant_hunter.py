"""Deterministic variant classification for authorized review scopes.

The hunter generalizes a verified invariant into sibling hypotheses. It never
promotes a semantic match to a vulnerability: EXACT and VARIANT results retain
HYPOTHESIS claim status until the normal evidence and verification workflow is
complete.
"""

from __future__ import annotations

from typing import Any, Iterable


ANCHOR_FIELDS = ("invariant", "boundary", "action")
VARIANT_FIELDS = (
    "actor",
    "object",
    "identity_state",
    "enforcement_layer",
    "sink_kind",
    "framework",
)
SIGNATURE_FIELDS = ANCHOR_FIELDS + VARIANT_FIELDS


class VariantSearchError(ValueError):
    """Raised when a variant signature is incomplete or contradictory."""


def _validate_signature(signature: dict[str, Any], *, candidate: bool) -> None:
    required = ("candidate_id", "reachability", "control_state") if candidate else ("finding_id",)
    missing = [
        field
        for field in required + SIGNATURE_FIELDS
        if not isinstance(signature.get(field), str) or not signature[field]
    ]
    if missing:
        raise VariantSearchError(f"missing non-empty fields: {', '.join(missing)}")
    if candidate and signature["reachability"] not in {"REACHABLE", "UNREACHABLE", "UNKNOWN"}:
        raise VariantSearchError("reachability must be REACHABLE, UNREACHABLE, or UNKNOWN")
    if candidate and signature["control_state"] not in {"MISSING", "ENFORCED", "UNKNOWN"}:
        raise VariantSearchError("control_state must be MISSING, ENFORCED, or UNKNOWN")


def classify_variant(seed: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Classify one sibling path against a seed invariant.

    Anchor mismatches and evidenced controls are refutations. Missing reachability
    or control evidence is BLOCKED rather than treated as absence.
    """

    _validate_signature(seed, candidate=False)
    _validate_signature(candidate, candidate=True)
    changed = [field for field in VARIANT_FIELDS if seed[field] != candidate[field]]
    anchor_mismatches = [field for field in ANCHOR_FIELDS if seed[field] != candidate[field]]

    if candidate["reachability"] == "UNREACHABLE":
        classification = "REFUTED"
        reasons = ["PATH_UNREACHABLE"]
    elif candidate["control_state"] == "ENFORCED":
        classification = "REFUTED"
        reasons = ["COMPENSATING_CONTROL_ENFORCED"]
    elif anchor_mismatches:
        classification = "REFUTED"
        reasons = [f"ANCHOR_MISMATCH:{field}" for field in anchor_mismatches]
    elif candidate["reachability"] == "UNKNOWN" or candidate["control_state"] == "UNKNOWN":
        classification = "BLOCKED"
        reasons = ["MISSING_REACHABILITY_OR_CONTROL_EVIDENCE"]
    elif changed:
        classification = "VARIANT"
        reasons = ["ANCHORS_MATCH_WITH_CHANGED_DIMENSIONS"]
    else:
        classification = "EXACT"
        reasons = ["FULL_SIGNATURE_MATCH"]

    return {
        "candidate_id": candidate["candidate_id"],
        "seed_finding_id": seed["finding_id"],
        "classification": classification,
        "claim_status": "HYPOTHESIS" if classification in {"EXACT", "VARIANT"} else classification,
        "matched_anchors": [field for field in ANCHOR_FIELDS if field not in anchor_mismatches],
        "changed_dimensions": changed,
        "reason_codes": reasons,
    }


def search_variants(
    seed: dict[str, Any],
    candidates: Iterable[dict[str, Any]],
    *,
    include_refuted: bool = True,
) -> list[dict[str, Any]]:
    """Return stable, review-friendly variant classifications."""

    results = [classify_variant(seed, candidate) for candidate in candidates]
    if not include_refuted:
        results = [item for item in results if item["classification"] != "REFUTED"]
    priority = {"EXACT": 0, "VARIANT": 1, "BLOCKED": 2, "REFUTED": 3}
    return sorted(results, key=lambda item: (priority[item["classification"]], item["candidate_id"]))
