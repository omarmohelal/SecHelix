"""Mapping evidence to control frameworks.

Three rules, and the first two are the reason this module is short.

**It never says "compliant" or "certified".** Those are conclusions an
authorized external process reaches, not conclusions a code audit reaches. The
allowed states are ``EVIDENCED``, ``PARTIAL``, ``NOT_EVIDENCED``,
``NOT_APPLICABLE`` and ``UNKNOWN``, and the vocabulary is closed.

**There is no AI fallback for unmapped controls.** The audit found sec-af asks a
model to invent a mapping for CWEs its table does not cover, swallowing errors
to an empty result -- a hallucination surface pointed directly at a compliance
artifact. Here an unmapped control stays ``UNKNOWN``, which is information. A
guessed one is a liability.

**It owns no mapping table.** ``catalog/checks.json`` already carries
``mappings`` per family (``OWASP-ASVS:V2``, ``NIST-SSDF:PS.3`` and so on). This
module reads those. A second table would drift from the catalog the moment
either changed, and the catalog is the versioned artifact with a validator.

The distinction that matters most is between ``NOT_EVIDENCED`` and ``UNKNOWN``.
A family that was examined and produced nothing is ``NOT_EVIDENCED``. A family
whose lane was blocked -- by budget, by missing context, by a failed dependency
-- is ``UNKNOWN``, because nobody looked. Reporting the second as the first
would turn "we ran out of money" into "we checked and it was fine".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .roles import NodeRole, NodeStatus


class ControlState(str, Enum):
    """The only states a control may be reported in."""

    EVIDENCED = "EVIDENCED"
    PARTIAL = "PARTIAL"
    NOT_EVIDENCED = "NOT_EVIDENCED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


#: Words this module must never emit about a control. Asserted by a test rather
#: than left to reviewer vigilance.
FORBIDDEN_TERMS = ("compliant", "compliance verified", "certified", "attested")

#: Framework prefixes recognised in catalog mappings. A prefix absent here is
#: still reported -- it is simply grouped under its own name rather than being
#: dropped, because silently discarding a mapping is its own kind of lie.
KNOWN_FRAMEWORKS = (
    "OWASP-ASVS",
    "OWASP-API",
    "OWASP-LLM",
    "NIST-SSDF",
    "NIST-CSF",
    "PCI-DSS",
    "SOC2",
    "ISO-27001",
    "CIS-CONTROLS",
)

#: Which reasoner lane answers for which catalog family.
#:
#: Explicit rather than inferred from name similarity, because a wrong guess
#: here silently mis-attributes coverage. Several families share a lane (money,
#: business logic and race conditions are all answered by BUSINESS_LOGIC), and a
#: family with no lane is reported ``UNKNOWN`` rather than being quietly dropped.
FAMILY_TO_ROLE: dict[str, NodeRole] = {
    "AUTH": NodeRole.AUTHENTICATION,
    "SESS": NodeRole.AUTHENTICATION,
    "AUTHZ": NodeRole.AUTHORIZATION,
    "DB": NodeRole.AUTHORIZATION,          # row-level security is authorization
    "INJ": NodeRole.INJECTION_DATAFLOW,
    "API": NodeRole.API_PROTOCOL,
    "FILE": NodeRole.FILES_PARSERS,
    "SSRF": NodeRole.FILES_PARSERS,
    "WEB": NodeRole.BROWSER,
    "BIZ": NodeRole.BUSINESS_LOGIC,
    "MONEY": NodeRole.BUSINESS_LOGIC,
    "RACE": NodeRole.BUSINESS_LOGIC,
    "CRYPTO": NodeRole.ARCHITECTURE,
    "PRIV": NodeRole.ARCHITECTURE,
    "SUPPLY": NodeRole.SUPPLY_CHAIN,
    "CI": NodeRole.CLOUD_CONFIGURATION,
    "CLOUD": NodeRole.CLOUD_CONFIGURATION,
    "OPS": NodeRole.CLOUD_CONFIGURATION,
    "AI": NodeRole.AI_MCP,
    "REL": NodeRole.RELEASE_GATE,
    "MAP": NodeRole.MAPPER,
}


@dataclass
class ControlAssessment:
    """One control, its state, and exactly why it is in that state."""

    control: str
    framework: str
    state: ControlState
    families: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "framework": self.framework,
            "state": self.state.value,
            "families": sorted(self.families),
            "evidence_ids": sorted(self.evidence_ids),
            "rationale": self.rationale,
        }


def load_family_mappings(catalog_path: Path | str) -> dict[str, list[str]]:
    """Family id -> control identifiers, read straight from the catalog."""
    data = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    return {
        family["id"]: list(family.get("mappings", []) or [])
        for family in data.get("families", [])
    }


def framework_of(control: str) -> str:
    """The framework a control identifier belongs to."""
    for prefix in KNOWN_FRAMEWORKS:
        if control.startswith(prefix):
            return prefix
    return control.split(":", 1)[0] if ":" in control else "OTHER"


def assess(
    family_mappings: dict[str, list[str]],
    node_records: dict[str, Any],
    *,
    verified_evidence_by_family: dict[str, list[str]] | None = None,
    not_applicable_families: Iterable[str] = (),
) -> list[ControlAssessment]:
    """Assess every control the catalog references.

    ``node_records`` maps node id to something with ``.role`` and ``.status``
    (a :class:`~sechelix_runner.telemetry.NodeRecord` or its dict form).
    """
    verified_evidence_by_family = verified_evidence_by_family or {}
    not_applicable = set(not_applicable_families)

    role_status: dict[NodeRole, set[str]] = {}
    for record in node_records.values():
        role = record.role if hasattr(record, "role") else NodeRole(record["role"])
        status = record.status if hasattr(record, "status") else NodeStatus(record["status"])
        role_status.setdefault(role, set()).add(
            status.value if isinstance(status, NodeStatus) else str(status)
        )

    # control -> the families that reference it
    control_families: dict[str, set[str]] = {}
    for family, controls in family_mappings.items():
        for control in controls:
            control_families.setdefault(control, set()).add(family)

    assessments: list[ControlAssessment] = []
    for control in sorted(control_families):
        families = sorted(control_families[control])
        assessments.append(
            _assess_one(control, families, role_status, verified_evidence_by_family, not_applicable)
        )
    return assessments


def _assess_one(
    control: str,
    families: list[str],
    role_status: dict[NodeRole, set[str]],
    evidence_by_family: dict[str, list[str]],
    not_applicable: set[str],
) -> ControlAssessment:
    framework = framework_of(control)

    if families and all(family in not_applicable for family in families):
        return ControlAssessment(
            control, framework, ControlState.NOT_APPLICABLE, families,
            rationale="every family mapped to this control is not applicable to the target",
        )

    evidence: list[str] = []
    examined: list[str] = []
    unexamined: list[str] = []

    for family in families:
        if family in not_applicable:
            continue
        evidence.extend(evidence_by_family.get(family, []))
        role = FAMILY_TO_ROLE.get(family)
        statuses = role_status.get(role, set()) if role is not None else set()
        if role is None or not statuses:
            # No lane answers for this family, or the lane never appeared in the
            # graph. Nobody looked, so nothing is known.
            unexamined.append(family)
        elif statuses & {NodeStatus.SUCCEEDED.value, NodeStatus.SKIPPED.value}:
            examined.append(family)
        else:
            unexamined.append(family)

    if evidence and not unexamined:
        return ControlAssessment(
            control, framework, ControlState.EVIDENCED, families, evidence,
            rationale=f"{len(evidence)} verified evidence record(s) across {len(examined)} examined family(ies)",
        )
    if evidence and unexamined:
        return ControlAssessment(
            control, framework, ControlState.PARTIAL, families, evidence,
            rationale=(
                f"evidence exists for part of this control; "
                f"{', '.join(unexamined)} was not examined"
            ),
        )
    if examined and not unexamined:
        return ControlAssessment(
            control, framework, ControlState.NOT_EVIDENCED, families,
            rationale="every mapped family was examined and produced no evidence for this control",
        )
    return ControlAssessment(
        control, framework, ControlState.UNKNOWN, families,
        rationale=(
            f"not examined: {', '.join(unexamined)}. "
            "Nobody looked, so this is unknown rather than clear."
        ),
    )


def summarise(assessments: list[ControlAssessment]) -> dict[str, Any]:
    """A report with an explicit disclaimer attached to the data itself."""
    by_framework: dict[str, dict[str, int]] = {}
    for assessment in assessments:
        bucket = by_framework.setdefault(
            assessment.framework, {state.value: 0 for state in ControlState}
        )
        bucket[assessment.state.value] += 1
    return {
        "disclaimer": (
            "This is supporting evidence, not certification. SecHelix does not "
            "determine compliance; an authorized external assessor does. UNKNOWN "
            "means nobody looked, which is not the same as a control being met."
        ),
        "totals": {
            state.value: sum(1 for a in assessments if a.state is state)
            for state in ControlState
        },
        "by_framework": dict(sorted(by_framework.items())),
        "controls": [a.to_dict() for a in assessments],
    }
