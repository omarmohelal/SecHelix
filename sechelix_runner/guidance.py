"""Generalized guidance learned from *verified dismissals*, never auto-suppression.

A useful false-positive memory should make the next review ask a better question;
it must not turn yesterday's dismissal into today's blind spot.  This module
therefore synthesizes only ``REQUIRE_RECHECK`` guidance.  It has no API capable
of marking a future candidate clean.

Inputs intentionally exclude source snippets, secrets, file contents and raw
customer data.  A dismissal example contains only generalized class/control
metadata plus public-safe reasoning.  At least three examples across at least
two target identities are required before a rule can be synthesized, which
reduces the chance that one repository-specific compensating control becomes a
universal rule.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Any, Iterable


class GuidanceError(ValueError):
    """Raised when learned guidance would overfit or become an auto-dismiss rule."""


class GuidanceEffect(StrEnum):
    REQUIRE_RECHECK = "REQUIRE_RECHECK"


@dataclass(frozen=True, slots=True)
class DismissalExample:
    example_id: str
    target_id: str
    class_key: str
    reason_code: str
    compensating_control: str
    verifier_rationale: str
    framework_tags: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in (
            ("example_id", self.example_id),
            ("target_id", self.target_id),
            ("class_key", self.class_key),
            ("reason_code", self.reason_code),
            ("compensating_control", self.compensating_control),
            ("verifier_rationale", self.verifier_rationale),
        ):
            if not value.strip():
                raise GuidanceError(f"{name} must not be empty")
        if len(self.verifier_rationale) > 800 or len(self.compensating_control) > 400:
            raise GuidanceError("guidance examples must be generalized summaries, not source dumps")
        forbidden = ("-----BEGIN", "api_key=", "authorization: bearer", "password=", "secret=")
        lowered = f"{self.compensating_control}\n{self.verifier_rationale}".lower()
        if any(marker.lower() in lowered for marker in forbidden):
            raise GuidanceError("guidance example appears to contain secret material")


@dataclass(frozen=True, slots=True)
class GuidanceRule:
    rule_id: str
    class_key: str
    reason_code: str
    check: str
    effect: GuidanceEffect
    supporting_example_ids: tuple[str, ...]
    target_count: int
    framework_tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sechelix-guidance/v1",
            "rule_id": self.rule_id,
            "class_key": self.class_key,
            "reason_code": self.reason_code,
            "check": self.check,
            "effect": self.effect.value,
            "supporting_example_ids": list(self.supporting_example_ids),
            "target_count": self.target_count,
            "framework_tags": list(self.framework_tags),
            "auto_dismiss": False,
        }


def _stable_id(class_key: str, reason_code: str, examples: Iterable[str]) -> str:
    material = "\n".join([class_key, reason_code, *sorted(examples)]).encode("utf-8")
    return f"GUIDE-{sha256(material).hexdigest()[:16].upper()}"


def synthesize(
    examples: Iterable[DismissalExample],
    *,
    min_examples: int = 3,
    min_targets: int = 2,
) -> list[GuidanceRule]:
    """Create conservative re-check rules from repeated verified dismissals."""

    if min_examples < 2:
        raise GuidanceError("min_examples below 2 would overfit a single dismissal")
    if min_targets < 2:
        raise GuidanceError("min_targets below 2 would turn repo-local behaviour into global guidance")

    grouped: dict[tuple[str, str], list[DismissalExample]] = defaultdict(list)
    seen_ids: set[str] = set()
    for example in examples:
        if example.example_id in seen_ids:
            raise GuidanceError(f"duplicate dismissal example id: {example.example_id}")
        seen_ids.add(example.example_id)
        grouped[(example.class_key, example.reason_code)].append(example)

    rules: list[GuidanceRule] = []
    for (class_key, reason_code), items in sorted(grouped.items()):
        targets = {item.target_id for item in items}
        if len(items) < min_examples or len(targets) < min_targets:
            continue

        controls = sorted({item.compensating_control.strip() for item in items})
        # Preserve disagreement rather than pretending several controls are one.
        if len(controls) == 1:
            control_text = controls[0]
        else:
            control_text = "one of the repeatedly observed compensating controls: " + "; ".join(controls)

        check = (
            f"Before reporting a {class_key} candidate matching reason {reason_code}, independently "
            f"verify whether {control_text} actually applies on this path. Prior dismissals are "
            "precedent for a question, not evidence for the current target."
        )
        example_ids = tuple(sorted(item.example_id for item in items))
        tags = tuple(sorted({tag for item in items for tag in item.framework_tags}))
        rules.append(
            GuidanceRule(
                rule_id=_stable_id(class_key, reason_code, example_ids),
                class_key=class_key,
                reason_code=reason_code,
                check=check,
                effect=GuidanceEffect.REQUIRE_RECHECK,
                supporting_example_ids=example_ids,
                target_count=len(targets),
                framework_tags=tags,
            )
        )
    return rules


def guidance_for_candidate(rules: Iterable[GuidanceRule], class_key: str) -> list[dict[str, Any]]:
    """Return questions relevant to a candidate; never a verdict."""

    return [rule.to_dict() for rule in rules if rule.class_key == class_key]
