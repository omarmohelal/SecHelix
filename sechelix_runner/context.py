"""Least-context views.

Sending the whole repository narrative to every specialist is expensive and it
is also worse review: a dependency reasoner given the full architecture story
has more places to find a pattern that is not there. Each role declares what it
needs, and the runner hands it that projection and nothing else.

The rule that keeps this honest: **a required slice that the world cannot supply
is recorded as missing, never quietly dropped.** A view that silently omits the
ownership model looks identical to a view whose target genuinely has none, and a
specialist cannot tell you it was under-informed if nobody wrote it down. Missing
requirements travel with the view and the runner turns them into a BLOCKED node
rather than an answer nobody should trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .digests import digest
from .roles import NodeRole

#: What each role is entitled to see. A slice named here and absent from the
#: world is a recorded gap; a slice not named here is simply not that role's
#: business, and its absence is not a defect.
#:
#: ``required`` gates the node. ``optional`` enriches it when present.
ROLE_CONTEXT: dict[NodeRole, dict[str, tuple[str, ...]]] = {
    NodeRole.MAPPER: {
        "required": ("target", "file_index"),
        "optional": ("manifests", "config_files"),
    },
    NodeRole.ARCHITECTURE: {
        "required": ("target", "file_index"),
        "optional": ("entrypoints", "services", "trust_boundaries"),
    },
    NodeRole.AUTHENTICATION: {
        "required": ("identities", "auth_middleware"),
        "optional": ("routes", "sessions", "tokens", "federation"),
    },
    NodeRole.AUTHORIZATION: {
        "required": ("identities", "roles", "ownership_model", "auth_middleware"),
        "optional": ("object_lookups", "routes", "tenancy"),
    },
    NodeRole.BUSINESS_LOGIC: {
        "required": ("state_machines", "mutating_routes"),
        "optional": ("invariants", "queues", "webhooks", "retries"),
    },
    NodeRole.INJECTION_DATAFLOW: {
        "required": ("sinks", "sources"),
        "optional": ("sanitizers", "routes", "templates"),
    },
    NodeRole.API_PROTOCOL: {
        "required": ("routes",),
        "optional": ("schemas", "protocols", "middleware"),
    },
    NodeRole.BROWSER: {
        "required": ("client_entrypoints",),
        "optional": ("dom_sinks", "csp", "origins"),
    },
    NodeRole.FILES_PARSERS: {
        "required": ("parsers",),
        "optional": ("upload_routes", "archive_handling", "path_joins"),
    },
    NodeRole.SUPPLY_CHAIN: {
        "required": ("manifests", "lockfiles"),
        "optional": ("import_graph", "reachable_symbols", "advisories"),
    },
    NodeRole.CLOUD_CONFIGURATION: {
        "required": ("config_files",),
        "optional": ("iac", "ci_workflows", "secrets_policy"),
    },
    NodeRole.AI_MCP: {
        "required": ("ai_inventory",),
        "optional": ("mcp_graph", "tool_permissions", "prompt_boundaries"),
    },
    NodeRole.RUNTIME_VERIFICATION: {
        "required": ("runtime_traces",),
        "optional": ("http_captures", "browser_evidence"),
    },
    NodeRole.VARIANT_HUNTER: {
        "required": ("confirmed_findings", "file_index"),
        "optional": ("variant_rules",),
    },
    NodeRole.INDEPENDENT_VERIFIER: {
        "required": ("candidates",),
        "optional": ("evidence", "fixtures"),
    },
    NodeRole.REMEDIATOR: {
        "required": ("verified_findings",),
        "optional": ("root_causes", "compatibility_notes"),
    },
    NodeRole.PATCH_VERIFIER: {
        "required": ("patches", "verified_findings"),
        "optional": ("regression_tests",),
    },
    NodeRole.RELEASE_GATE: {
        "required": ("findings", "node_records"),
        "optional": ("policy", "coverage"),
    },
}


@dataclass
class ContextView:
    """What one node is given, plus the record of what it was denied."""

    role: NodeRole
    node_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    source_ids: list[str] = field(default_factory=list)
    #: Required slices the world could not supply. Non-empty means the node
    #: cannot honestly answer and the runner blocks it.
    missing_required: list[str] = field(default_factory=list)
    omitted_optional: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        return digest(self.payload)

    @property
    def approx_tokens(self) -> int:
        """A cheap size proxy, not a tokenizer.

        Roughly four characters per token is close enough to compare views
        against each other, which is the only thing this number is used for. It
        is never billed against a real budget -- the executor reports actual
        token counts, and where it cannot, the budget records ``None``.
        """
        return max(1, len(digest_source(self.payload)) // 4)

    @property
    def complete(self) -> bool:
        return not self.missing_required

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "node_id": self.node_id,
            "source_ids": sorted(self.source_ids),
            "context_digest": self.digest,
            "approx_tokens": self.approx_tokens,
            "missing_required": sorted(self.missing_required),
            "omitted_optional": sorted(self.omitted_optional),
        }


def digest_source(payload: dict[str, Any]) -> str:
    """Canonical text of the payload, used only for the size proxy."""
    from .digests import canonical_json

    return canonical_json(payload)


class ContextBuilder:
    """Projects a whole-target ``world`` into per-role views."""

    def __init__(self, world: dict[str, Any]) -> None:
        self._world = world

    def build(self, node_id: str, role: NodeRole) -> ContextView:
        spec = ROLE_CONTEXT.get(role, {"required": (), "optional": ()})
        payload: dict[str, Any] = {}
        sources: list[str] = []
        missing: list[str] = []
        omitted: list[str] = []

        for key in spec["required"]:
            if key in self._world and self._world[key] is not None:
                payload[key] = self._world[key]
                sources.append(key)
            else:
                missing.append(key)

        for key in spec["optional"]:
            if key in self._world and self._world[key] is not None:
                payload[key] = self._world[key]
                sources.append(key)
            else:
                omitted.append(key)

        return ContextView(
            role=role,
            node_id=node_id,
            payload=payload,
            source_ids=sources,
            missing_required=missing,
            omitted_optional=omitted,
        )

    def full_world_tokens(self) -> int:
        """Size of the unprojected world, for measuring what views saved."""
        return max(1, len(digest_source(self._world)) // 4)
