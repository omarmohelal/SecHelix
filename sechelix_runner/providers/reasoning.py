"""The executor that turns a graph node into a provider request.

This is where role isolation becomes structural rather than aspirational.

A hunter is asked what it observes. The independent verifier is asked to
*reconstruct* the same question from source, and is deliberately **not told the
hunter's conclusion, confidence, or wording**. :func:`verifier_view` strips
those fields, and a test asserts they cannot reach the verifier prompt.

The reason is simple and was the point of the whole quorum design: a verifier
that reads "HIGH confidence SQL injection, definitely exploitable" before
looking at the code is not verifying, it is agreeing. What survives the strip is
the claim, the location, the minimal source evidence, and the target state --
enough to look, not enough to be led.
"""

from __future__ import annotations

import json
from typing import Any

from ..executor import NodeOutcome
from ..graph import GraphNode
from ..roles import NodeRole, NodeStatus
from .base import (
    NODE_OUTPUT_SCHEMA,
    ProviderError,
    ProviderExecutor,
    extract_json,
    validate_node_output,
)

#: Fields a verifier must never receive from the hunter that raised a candidate.
#: Every one of these carries a conclusion rather than an observation.
FORBIDDEN_VERIFIER_FIELDS = (
    "confidence",
    "severity",
    "verdict",
    "conclusion",
    "assessment",
    "recommendation",
    "exploitability",
    "hunter_notes",
    "votes",
    "vote",
    "other_verifier",
    "prior_verdict",
)


def verifier_view(candidate: dict[str, Any]) -> dict[str, Any]:
    """Strip a candidate down to what an independent verifier may see.

    Keeps the claim and where to look. Removes anything stating how convinced
    somebody already was.
    """
    return {
        key: value
        for key, value in candidate.items()
        if key.lower() not in FORBIDDEN_VERIFIER_FIELDS
    }


_ROLE_TASK: dict[NodeRole, str] = {
    NodeRole.MAPPER: "Map entrypoints, trust boundaries and identities.",
    NodeRole.ARCHITECTURE: "Describe the architecture and where trust changes hands.",
    NodeRole.AUTHENTICATION: "Examine authentication, sessions, tokens and recovery.",
    NodeRole.AUTHORIZATION: "Examine object and function authorization, ownership and tenancy.",
    NodeRole.BUSINESS_LOGIC: "Examine workflow, state machines, money and inventory invariants.",
    NodeRole.INJECTION_DATAFLOW: "Trace attacker-controlled sources to dangerous sinks.",
    NodeRole.API_PROTOCOL: "Examine API surface, protocol handling and middleware.",
    NodeRole.BROWSER: "Examine client-side boundaries, DOM sinks and origins.",
    NodeRole.FILES_PARSERS: "Examine file handling, parsers, uploads and path construction.",
    NodeRole.SUPPLY_CHAIN: "Examine dependencies, lockfiles and install-time inputs.",
    NodeRole.CLOUD_CONFIGURATION: "Examine configuration, CI and deployment inputs.",
    NodeRole.AI_MCP: "Examine AI/agent/MCP tool permissions and untrusted context handling.",
    NodeRole.VARIANT_HUNTER: "Find further instances of an already-confirmed pattern.",
    NodeRole.INDEPENDENT_VERIFIER: (
        "Independently reconstruct each claim from the evidence and try to REFUTE it."
    ),
}

#: Prepended to every node prompt.
#:
#: Measured, not assumed. With ``--disallowed-tools`` alone the model still
#: *attempts* Read/Grep against the files named in its view; each attempt costs a
#: turn, and at ``--max-turns 1`` the CLI returned ``error_max_turns`` with no
#: answer while still charging for it. Raising max_turns to 4 made runs succeed
#: by absorbing the denials. This paragraph exists so those turns are not paid
#: for at all: the flag stops tools working, saying so stops the model trying.
_NO_TOOLS = """
You have NO tools. Do not attempt to read, search, or open any file. Everything
you are permitted to use is in the Evidence block below. If the evidence is
insufficient to support a conclusion, say so in "notes" rather than trying to
gather more.
""".strip()

_SHARED_RULES = """
Rules you must follow:
- Report only what the provided evidence supports. Do not speculate.
- If the evidence does not establish attacker control, say so in "attacker_control".
- Do not assign severity or confidence. That is computed elsewhere from evidence.
- If you find nothing supportable, return an empty candidates list. That is a
  valid and useful answer; inventing a finding is not.

Return ONLY a JSON object of this shape, with no prose around it:
{"candidates": [{"claim": "...", "location": "...", "why": "...",
                 "attacker_control": "...", "hypothesis_ids": []}],
 "examined": ["..."], "notes": "..."}
""".strip()

_VERIFIER_RULES = """
You are an INDEPENDENT VERIFIER. You have deliberately not been told how
confident anyone was, what severity anyone assigned, or what any other verifier
concluded. Do not ask for it and do not assume it.

For each claim: reconstruct it from the evidence and actively try to refute it.
Return a candidate ONLY for claims you could NOT refute, with "why" stating what
the evidence establishes. Refuting a claim is a success, not a failure.

Return ONLY a JSON object of this shape, with no prose around it:
{"candidates": [{"claim": "...", "location": "...", "why": "...",
                 "attacker_control": "...", "hypothesis_ids": []}],
 "examined": ["..."], "notes": "refuted: ..."}
""".strip()


def build_prompt(node: GraphNode, view: dict[str, Any], *, max_chars: int = 24000) -> str:
    """Compose one narrow task. The context is already the least-context view."""
    task = _ROLE_TASK.get(node.role, f"Examine the {node.role.value} surface.")
    rules = (
        _VERIFIER_RULES
        if node.role is NodeRole.INDEPENDENT_VERIFIER
        else _SHARED_RULES
    )

    payload = dict(view)
    if node.role is NodeRole.INDEPENDENT_VERIFIER:
        candidates = payload.get("candidates") or []
        payload["candidates"] = [verifier_view(c) for c in candidates if isinstance(c, dict)]

    body = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n... [context truncated to fit the node budget]"

    return f"{_NO_TOOLS}\n\n{task}\n\n{rules}\n\nEvidence:\n{body}\n"


class ReasoningExecutor:
    """Runs graph nodes through a :class:`ProviderExecutor`.

    Every failure mode lands on a recorded status rather than an exception that
    would take the run down: a provider error, a timeout or a schema violation
    all become ``FAILED`` with the reason attached, and the graph blocks
    everything downstream exactly as it would for any other undelivered node.
    """

    def __init__(
        self,
        provider: ProviderExecutor,
        *,
        timeout: float = 300.0,
        skip_roles: frozenset[NodeRole] = frozenset(
            {NodeRole.RELEASE_GATE, NodeRole.REMEDIATOR, NodeRole.PATCH_VERIFIER}
        ),
    ) -> None:
        self.provider = provider
        self.timeout = timeout
        self.skip_roles = skip_roles
        self.name = f"reasoning:{getattr(provider, 'name', 'provider')}"
        #: Prompts actually sent, for leakage tests and the run record.
        self.prompts: list[tuple[str, str]] = []

    def execute(self, node: GraphNode, view: dict[str, Any]) -> NodeOutcome:
        if node.role in self.skip_roles:
            # These roles are computed from evidence, not reasoned about.
            return NodeOutcome(
                status=NodeStatus.SUCCEEDED, output={"role": node.role.value}
            )

        prompt = build_prompt(node, view)
        self.prompts.append((node.node_id, prompt))

        try:
            result = self.provider.invoke(prompt, timeout=self.timeout)
        except ProviderError as exc:
            return NodeOutcome(status=NodeStatus.FAILED, error=str(exc))

        try:
            payload = extract_json(result.text)
        except ProviderError as exc:
            return NodeOutcome(
                status=NodeStatus.FAILED,
                error=f"unparseable provider output: {exc}",
                model=result.model,
                provider=result.provider,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cost_usd=result.cost_usd,
            )

        problems = validate_node_output(payload)
        if problems:
            # Fail closed. A partially-understood response must never become a
            # candidate: the schema exists precisely so this is detectable.
            return NodeOutcome(
                status=NodeStatus.FAILED,
                error=f"provider output failed schema: {'; '.join(problems[:4])}",
                model=result.model,
                provider=result.provider,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cost_usd=result.cost_usd,
            )

        return NodeOutcome(
            status=NodeStatus.SUCCEEDED,
            output=payload,
            model=result.model,
            provider=result.provider,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=result.cost_usd,
        )


__all__ = [
    "FORBIDDEN_VERIFIER_FIELDS",
    "NODE_OUTPUT_SCHEMA",
    "ReasoningExecutor",
    "build_prompt",
    "verifier_view",
]
