"""Rights-aware source selection and deterministic research confidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "knowledge" / "source-registry.json"
CONFIDENCE_ORDER = ("UNVERIFIED", "SUPPORTED", "HIGH_CONFIDENCE", "CONFIRMED")
ELIGIBLE_SUPPORT_TIERS = {"S", "A", "B"}


def load_source_registry(path: str | Path | None = None) -> dict[str, Any]:
    """Load the checked-in source trust registry."""

    with Path(path or DEFAULT_REGISTRY).open(encoding="utf-8") as handle:
        return json.load(handle)


def source_index(registry: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Index registry entries by their stable source ID."""

    data = registry or load_source_registry()
    return {source["id"]: source for source in data["sources"]}


def source_allows(source: dict[str, Any], operation: str) -> bool:
    """Return whether a registry entry explicitly permits an operation."""

    if operation not in source["allowed_uses"]:
        raise KeyError(f"unknown source operation {operation!r}")
    return bool(source["allowed_uses"][operation])


def expected_research_confidence(
    packet: dict[str, Any], registry: dict[str, Any] | None = None
) -> str:
    """Compute confidence without treating source count as runtime proof.

    CONFIRMED requires both code evidence and a bounded safe reproduction.
    HIGH_CONFIDENCE requires a Tier-S official advisory with an exact version
    match. SUPPORTED requires two independent eligible supporting sources.
    Contradictory current sources block source-only promotion until resolved.
    """

    if packet["code_evidence"]["present"] and packet["safe_reproduction"]["performed"]:
        return "CONFIRMED"

    index = source_index(registry)
    source_rows = []
    for reference in packet["sources"]:
        source = index.get(reference["source_id"])
        if source:
            source_rows.append((reference, source))

    if any(reference["relation"] == "CONTRADICTS" for reference, _ in source_rows):
        return "UNVERIFIED"

    supporting = [
        (reference, source)
        for reference, source in source_rows
        if reference["relation"] == "SUPPORTS"
        and source["trust_tier"] in ELIGIBLE_SUPPORT_TIERS
        and source["access_mode"] != "HUMAN_ONLY"
    ]
    if any(
        reference["official_advisory"]
        and reference["exact_version_match"]
        and source["trust_tier"] == "S"
        and source["source_class"] == "OFFICIAL_ADVISORY"
        for reference, source in supporting
    ):
        return "HIGH_CONFIDENCE"

    independence_groups = {source["independence_group"] for _, source in supporting}
    if len(independence_groups) >= 2:
        return "SUPPORTED"
    return "UNVERIFIED"


def stale_source_ids(
    registry: dict[str, Any] | None = None, *, now: datetime | None = None
) -> list[str]:
    """Return source IDs whose terms/freshness review has exceeded its budget."""

    data = registry or load_source_registry()
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must include a timezone")
    stale: list[str] = []
    for source in data["sources"]:
        reviewed = datetime.fromisoformat(source["freshness"]["reviewed_at"].replace("Z", "+00:00"))
        maximum_age = timedelta(days=source["freshness"]["max_age_days"])
        if current > reviewed + maximum_age:
            stale.append(source["id"])
    return sorted(stale)
