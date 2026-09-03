"""Grounded threat modelling for the optional V4 runner.

The model is deliberately downstream of the SecHelix attack-surface graph.  A
STRIDE label is not evidence: every threat must point at concrete graph nodes
(and, when claiming support, concrete evidence ids).  This prevents a threat
model from becoming a list of generic security prose that looks formal because
it has a category and a risk label.

Two passes are represented explicitly:

* ``CANDIDATE`` / ``UNKNOWN`` -- a threat hypothesis worth investigating;
* ``SUPPORTED`` / ``REFUTED`` -- an adversarial review has grounded or killed it.

A threat that lacks evidence is never silently promoted to ``SUPPORTED``.  A
threat that cannot yet be disproved is never silently rewritten as ``REFUTED``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Iterable

from sechelix_core.attack_surface import validate_attack_surface


class ThreatModelError(ValueError):
    """Raised when a threat model contradicts its attack-surface evidence."""


class Stride(StrEnum):
    SPOOFING = "SPOOFING"
    TAMPERING = "TAMPERING"
    REPUDIATION = "REPUDIATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"


class ThreatState(StrEnum):
    CANDIDATE = "CANDIDATE"
    UNKNOWN = "UNKNOWN"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"


@dataclass(frozen=True, slots=True)
class Threat:
    threat_id: str
    category: Stride
    statement: str
    node_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    state: ThreatState = ThreatState.CANDIDATE
    rationale: str = ""
    source_locations: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.threat_id.startswith("THREAT-") or len(self.threat_id) < 10:
            raise ThreatModelError("threat_id must start with THREAT- and be stable")
        if not self.statement.strip():
            raise ThreatModelError("threat statement must not be empty")
        if not self.node_ids:
            raise ThreatModelError("a threat must reference at least one attack-surface node")
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ThreatModelError("threat node_ids must be unique")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ThreatModelError("threat evidence_ids must be unique")
        if self.state is ThreatState.SUPPORTED and not self.evidence_ids:
            raise ThreatModelError("SUPPORTED threat requires evidence; a category label is not proof")
        if self.state is ThreatState.REFUTED and not self.rationale.strip():
            raise ThreatModelError("REFUTED threat requires an explicit refutation rationale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "category": self.category.value,
            "statement": self.statement,
            "node_ids": list(self.node_ids),
            "evidence_ids": list(self.evidence_ids),
            "state": self.state.value,
            "rationale": self.rationale,
            "source_locations": list(self.source_locations),
            "mitigations": list(self.mitigations),
        }


@dataclass(frozen=True, slots=True)
class ThreatModel:
    model_id: str
    graph_id: str
    scope_id: str
    threats: tuple[Threat, ...]
    unknowns: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    methodology: str = "STRIDE"

    def __post_init__(self) -> None:
        if not self.model_id.startswith("TM-"):
            raise ThreatModelError("model_id must start with TM-")
        ids = [threat.threat_id for threat in self.threats]
        if len(set(ids)) != len(ids):
            raise ThreatModelError("threat ids must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sechelix-threat-model/v1",
            "model_id": self.model_id,
            "graph_id": self.graph_id,
            "scope_id": self.scope_id,
            "methodology": self.methodology,
            "threats": [threat.to_dict() for threat in self.threats],
            "unknowns": list(self.unknowns),
            "assumptions": list(self.assumptions),
        }


def validate_against_surface(model: ThreatModel, graph: dict[str, Any]) -> None:
    """Require every threat reference to resolve against the validated graph."""

    validate_attack_surface(graph)
    if model.graph_id != graph["graph_id"]:
        raise ThreatModelError("threat model graph_id does not match attack-surface graph")
    if model.scope_id != graph["scope_id"]:
        raise ThreatModelError("threat model scope_id does not match attack-surface scope")

    node_ids = {node["id"] for node in graph["nodes"]}
    for threat in model.threats:
        missing = sorted(set(threat.node_ids) - node_ids)
        if missing:
            raise ThreatModelError(
                f"{threat.threat_id} references attack-surface nodes that do not exist: {missing}"
            )


def apply_adversarial_verdict(
    threat: Threat,
    *,
    state: ThreatState,
    rationale: str,
    evidence_ids: Iterable[str] = (),
) -> Threat:
    """Apply a second-pass verdict without hiding unresolved evidence.

    Only ``SUPPORTED``, ``REFUTED`` and ``UNKNOWN`` are terminal outputs of the
    adversarial pass.  ``SUPPORTED`` needs fresh supporting evidence and
    ``REFUTED`` needs a reason.  ``UNKNOWN`` is the correct outcome when the
    reviewer cannot establish either side.
    """

    if state is ThreatState.CANDIDATE:
        raise ThreatModelError("adversarial pass must resolve to SUPPORTED, REFUTED or UNKNOWN")
    evidence = tuple(dict.fromkeys(str(item) for item in evidence_ids if str(item)))
    if state is ThreatState.SUPPORTED and not evidence:
        raise ThreatModelError("adversarial SUPPORTED verdict requires evidence")
    if state is ThreatState.REFUTED and not rationale.strip():
        raise ThreatModelError("adversarial REFUTED verdict requires rationale")
    return replace(
        threat,
        state=state,
        rationale=rationale.strip(),
        evidence_ids=evidence if evidence else threat.evidence_ids,
    )


def registry(model: ThreatModel) -> list[dict[str, Any]]:
    """Return a deterministic risk/threat registry without inventing severity."""

    order = {
        ThreatState.SUPPORTED: 0,
        ThreatState.UNKNOWN: 1,
        ThreatState.CANDIDATE: 2,
        ThreatState.REFUTED: 3,
    }
    return [
        threat.to_dict()
        for threat in sorted(
            model.threats,
            key=lambda threat: (order[threat.state], threat.category.value, threat.threat_id),
        )
    ]
