"""What an AI-enabled repository actually contains, and where each part sits.

You cannot review the authority of a system whose parts you have not listed.
Dependency manifests do not list them: a model pulled by mutable tag, a skill file
that is control rather than content, an MCP server installed by name from a public
index, a vector store restored from a shared snapshot, a memory store shared
across tenants — none of these appear in a lockfile, and all of them are on a
privileged execution path.

An AI-BOM is that list, with two properties attached to every entry that decide
whether the list is useful or actively misleading.

Three rules.

**An asset whose trust boundary cannot be determined is ``UNKNOWN``, never
``INTERNAL``.** This is the failure that matters. "Internal" is the comfortable
default, and defaulting to it is how a third-party inference endpoint, a
community MCP server, and a crawled corpus get treated as inside the boundary and
stop being reviewed. So ``INTERNAL`` is not a value this module will infer: it has
to be stated, and stating it requires writing down the basis, which is the point
at which somebody notices they do not have one.

**Provenance is recorded, and a declared asset is never presented as observed.**
``DECLARED`` means a file says it exists. ``OBSERVED`` means something watched it
happen and left evidence. They answer different questions — a config file listing
four MCP servers tells you nothing about the fifth one a developer connected
locally — and ``OBSERVED`` without an evidence id is refused rather than accepted
and quietly downgraded.

**Secrets appear as references only.** The inventory records that a credential
exists, what it is called, and where it is read from. A reference that itself
looks like a credential is refused, because the usual way a value ends up in an
inventory is somebody pasting it into the name field. Everything exported is also
passed through the redaction in ``proof_bundle``, which is the second line, not
the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .proof_bundle import RedactionLog, redact

SCHEMA_VERSION = "1.0"

#: Asset classes an AI system adds that dependency review does not cover.
KINDS = (
    "MODEL",
    "PROVIDER",
    "AGENT",
    "SKILL",
    "MCP_SERVER",
    "TOOL",
    "RAG_STORE",
    "DATASET",
    "MEMORY_STORE",
    "EXTERNAL_API",
    "PERMISSION",
    "SECRET_REFERENCE",
    "NETWORK_DESTINATION",
)

DECLARED = "DECLARED"
OBSERVED = "OBSERVED"
PROVENANCE = (DECLARED, OBSERVED)

INTERNAL = "INTERNAL"
THIRD_PARTY = "THIRD_PARTY"
PUBLIC = "PUBLIC"
UNKNOWN = "UNKNOWN"
BOUNDARIES = (INTERNAL, THIRD_PARTY, PUBLIC, UNKNOWN)

RELATIONS = (
    "USES",
    "EXPOSES",
    "READS",
    "WRITES",
    "REACHES",
    "AUTHENTICATES_WITH",
    "DERIVED_FROM",
)

#: Redaction categories that describe a filesystem path rather than a credential.
#: A local MCP server legitimately lives under a home directory, so a home path in
#: a locator is not a pasted secret and must not be refused as one.
_PATH_CATEGORIES = frozenset({"windows_home", "posix_home"})


class AiInventoryError(ValueError):
    """The inventory would assert something it has no basis for."""


def credential_shapes(text: str) -> list[str]:
    """Which credential patterns a string matches, using the canonical redactor.

    Home-directory paths are excluded: they are locations, not credentials, and
    refusing them would make the honest locator for a local server unrecordable.
    """
    log = RedactionLog()
    redact(text, log)
    return sorted(name for name in log.counts if name not in _PATH_CATEGORIES)


def classify_boundary(operator_controlled: str, *, basis: str = "") -> tuple[str, str]:
    """Turn a control answer into a boundary, refusing to guess.

    Only an explicit ``YES`` with a stated basis produces ``INTERNAL``. Anything
    else — ``NO``, ``UNKNOWN``, an empty string, a shrug — produces ``THIRD_PARTY``
    or ``UNKNOWN``. There is no input to this function that turns "we did not
    check" into "inside the boundary".
    """
    answer = (operator_controlled or "").strip().upper()
    if answer == "YES":
        if not basis.strip():
            raise AiInventoryError(
                "INTERNAL requires a stated basis; an asset is inside the boundary because "
                "somebody can point at why, not because nobody looked outside it"
            )
        return INTERNAL, basis
    if answer == "NO":
        return THIRD_PARTY, basis or "declared as not operator-controlled"
    return UNKNOWN, basis or "operator control was not established"


@dataclass(frozen=True)
class Asset:
    """One inventoried thing, with where it sits and how we know it is there."""

    asset_id: str
    kind: str
    name: str
    provenance: str = DECLARED
    boundary: str = UNKNOWN
    boundary_basis: str = ""
    locator: str = ""
    evidence_ids: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise AiInventoryError("every asset needs an id")
        if self.kind not in KINDS:
            raise AiInventoryError(f"unknown asset kind {self.kind!r}; choose from {list(KINDS)}")
        if self.provenance not in PROVENANCE:
            raise AiInventoryError(f"unknown provenance {self.provenance!r}")
        if self.boundary not in BOUNDARIES:
            raise AiInventoryError(f"unknown trust boundary {self.boundary!r}")
        if self.provenance == OBSERVED and not self.evidence_ids:
            raise AiInventoryError(
                f"{self.asset_id}: OBSERVED requires an evidence id. Something observed it or "
                "nothing did; an unevidenced sighting is DECLARED"
            )
        if self.boundary != UNKNOWN and not self.boundary_basis.strip():
            raise AiInventoryError(
                f"{self.asset_id}: boundary {self.boundary} requires a basis. UNKNOWN is the "
                "value that needs no justification, and it is the correct one when there is none"
            )

    @property
    def is_observed(self) -> bool:
        return self.provenance == OBSERVED

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "kind": self.kind,
            "name": self.name,
            "provenance": self.provenance,
            "trust_boundary": self.boundary,
            "boundary_basis": self.boundary_basis,
            "locator": self.locator,
            "evidence_ids": list(self.evidence_ids),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class Relationship:
    source: str
    target: str
    relation: str
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "from": self.source,
            "to": self.target,
            "relation": self.relation,
            "note": self.note,
        }


class Inventory:
    """The assets of one AI-enabled target, and how they connect."""

    def __init__(self, bom_id: str, *, subject: str = "") -> None:
        self.bom_id = bom_id
        self.subject = subject
        self.assets: dict[str, Asset] = {}
        self.relationships: list[Relationship] = []
        self.unresolved_questions: list[str] = []

    def add(self, asset: Asset) -> Asset:
        if asset.asset_id in self.assets:
            raise AiInventoryError(f"duplicate asset id {asset.asset_id!r}")
        if asset.kind == "SECRET_REFERENCE":
            self._refuse_values(asset)
        self.assets[asset.asset_id] = asset
        return asset

    @staticmethod
    def _refuse_values(asset: Asset) -> None:
        for field_name, text in (("name", asset.name), ("locator", asset.locator)):
            shapes = credential_shapes(str(text))
            if shapes:
                raise AiInventoryError(
                    f"{asset.asset_id}: the {field_name} matches credential pattern(s) "
                    f"{shapes}. A secret is inventoried by reference — the variable it is read "
                    "from, the vault path, the field name — never by value"
                )

    def add_secret_reference(
        self,
        asset_id: str,
        name: str,
        *,
        read_from: str,
        provenance: str = DECLARED,
        boundary: str = UNKNOWN,
        boundary_basis: str = "",
        evidence_ids: Sequence[str] = (),
        attributes: Mapping[str, Any] | None = None,
    ) -> Asset:
        """Record that a credential exists, without recording the credential."""
        return self.add(Asset(
            asset_id=asset_id,
            kind="SECRET_REFERENCE",
            name=name,
            provenance=provenance,
            boundary=boundary,
            boundary_basis=boundary_basis,
            locator=read_from,
            evidence_ids=tuple(evidence_ids),
            attributes=dict(attributes or {}),
        ))

    def link(self, source: str, target: str, relation: str, *, note: str = "") -> Relationship:
        if relation not in RELATIONS:
            raise AiInventoryError(f"unknown relation {relation!r}; choose from {list(RELATIONS)}")
        for endpoint in (source, target):
            if endpoint not in self.assets:
                raise AiInventoryError(f"relationship refers to unknown asset {endpoint!r}")
        relationship = Relationship(source=source, target=target, relation=relation, note=note)
        self.relationships.append(relationship)
        return relationship

    # -- views ----------------------------------------------------------------

    def unknown_boundary(self) -> list[Asset]:
        """Assets whose side of the boundary nobody established. The real to-do list."""
        return [a for a in self._ordered() if a.boundary == UNKNOWN]

    def declared_only(self) -> list[Asset]:
        """Assets a file claims exist and nothing has observed."""
        return [a for a in self._ordered() if a.provenance == DECLARED]

    def observed(self) -> list[Asset]:
        return [a for a in self._ordered() if a.provenance == OBSERVED]

    def _ordered(self) -> list[Asset]:
        return [self.assets[key] for key in sorted(self.assets)]


def to_ai_bom(inventory: Inventory) -> dict[str, Any]:
    """Export the AI-BOM. Redacted, and counting declared and observed apart."""
    assets = inventory._ordered()

    by_kind: dict[str, int] = {}
    by_boundary: dict[str, int] = {boundary: 0 for boundary in BOUNDARIES}
    by_provenance: dict[str, int] = {value: 0 for value in PROVENANCE}
    for asset in assets:
        by_kind[asset.kind] = by_kind.get(asset.kind, 0) + 1
        by_boundary[asset.boundary] += 1
        by_provenance[asset.provenance] += 1

    limitations = [
        "An inventory is a lower bound. It lists what the declarations and the observations "
        "reached; anything registered at runtime, connected by a developer locally, or pulled "
        "by a mutable tag can be absent without leaving a gap that is visible here.",
        "A DECLARED asset has not been observed in a running system. The two counts are kept "
        "apart because a config file listing four MCP servers says nothing about a fifth.",
        "UNKNOWN trust boundary means nobody established which side the asset sits on. It is "
        "not a synonym for INTERNAL, and treating it as one is how a third-party endpoint stops "
        "being reviewed.",
        "Secrets appear as references. The inventory shows that a credential is used and where "
        "it is read from; it never shows a value, and a reference that looks like a value is "
        "refused at entry.",
    ]
    if inventory.unresolved_questions:
        limitations.extend(inventory.unresolved_questions)

    raw: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bom_id": inventory.bom_id,
        "subject": inventory.subject,
        "generated_by": "sechelix_core.ai_inventory",
        "assets": [asset.as_dict() for asset in assets],
        "relationships": [item.as_dict() for item in inventory.relationships],
        "summary": {
            "total": len(assets),
            "by_kind": by_kind,
            "by_trust_boundary": by_boundary,
            "by_provenance": by_provenance,
        },
        "unknown_boundary_asset_ids": [a.asset_id for a in inventory.unknown_boundary()],
        "declared_only_asset_ids": [a.asset_id for a in inventory.declared_only()],
        "observed_asset_ids": [a.asset_id for a in inventory.observed()],
        "limitations": limitations,
    }

    log = RedactionLog()
    record = redact(raw, log)
    record["redaction"] = log.as_dict()
    return record


def render_markdown(record: Mapping[str, Any]) -> str:
    """Render the BOM, labelling every asset with how it is known."""
    summary = record.get("summary", {})
    provenance = summary.get("by_provenance", {})
    boundaries = summary.get("by_trust_boundary", {})

    lines = [
        f"# AI-BOM — {record.get('subject') or record.get('bom_id', 'unnamed target')}",
        "",
        f"{summary.get('total', 0)} asset(s): "
        f"{provenance.get(OBSERVED, 0)} observed, "
        f"{provenance.get(DECLARED, 0)} declared and not observed.",
        "",
    ]

    unknown = boundaries.get(UNKNOWN, 0)
    if unknown:
        lines += [
            f"**{unknown} asset(s) have an `UNKNOWN` trust boundary.** Nobody established which "
            "side of the boundary they sit on. They are listed as unknown rather than assumed "
            "internal, and until that is resolved they should be reviewed as though they were "
            "outside.",
            "",
        ]

    lines += [
        "| Asset | Kind | Trust boundary | Known by | Read from |",
        "|---|---|---|---|---|",
    ]
    for asset in record.get("assets", []):
        known = "observed" if asset.get("provenance") == OBSERVED else "declaration only"
        lines.append(
            f"| {asset.get('name')} | `{asset.get('kind')}` | "
            f"`{asset.get('trust_boundary')}` | {known} | {asset.get('locator') or '—'} |"
        )

    relationships = record.get("relationships", [])
    if relationships:
        lines += ["", "## Relationships", ""]
        for item in relationships:
            lines.append(f"- `{item['from']}` —{item['relation']}→ `{item['to']}`")

    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in record.get("limitations", [])]
    return "\n".join(lines).rstrip("\n") + "\n"
