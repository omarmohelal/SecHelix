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

from ..digests import digest
from ..executor import NodeOutcome
from ..graph import GraphNode
from ..roles import NodeRole, NodeStatus
from .base import (
    NODE_OUTPUT_SCHEMA,
    VERIFIER_CLASSIFICATIONS,
    VERIFIER_OUTPUT_SCHEMA,
    ProviderError,
    ProviderExecutor,
    extract_json,
    validate_node_output,
    validate_verifier_output,
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
    stripped = {
        key: value
        for key, value in candidate.items()
        if key.lower() not in FORBIDDEN_VERIFIER_FIELDS
        and key != "candidate_ref"
    }
    # Bind the verifier response to the exact neutralized candidate it received.
    # The reference carries no verdict and cannot promote a finding by itself.
    return {"candidate_ref": digest(stripped), **stripped}


def _evidence_ids(value: Any) -> set[str]:
    """Collect stable evidence identifiers already present in a least-context view."""

    found: set[str] = set()
    if isinstance(value, dict):
        evidence_id = value.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id.strip():
            found.add(evidence_id)
        evidence_ids = value.get("evidence_ids")
        if isinstance(evidence_ids, list):
            found.update(
                item for item in evidence_ids
                if isinstance(item, str) and item.strip()
            )
        for nested in value.values():
            found.update(_evidence_ids(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(_evidence_ids(nested))
    return found


def _validate_verifier_binding(
    payload: dict[str, Any],
    view: dict[str, Any],
) -> list[str]:
    """Require one assessment for every exact neutralized input candidate."""

    raw_candidates = view.get("candidates") or []
    expected_rows = {
        neutral["candidate_ref"]: neutral
        for candidate in raw_candidates
        if isinstance(candidate, dict)
        for neutral in (verifier_view(candidate),)
    }
    assessments = payload.get("assessments")
    if not isinstance(assessments, list):
        return []
    actual = [
        row.get("candidate_ref")
        for row in assessments
        if isinstance(row, dict) and isinstance(row.get("candidate_ref"), str)
    ]
    problems: list[str] = []
    expected = sorted(expected_rows)
    if sorted(actual) != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        problems.append(
            "verifier assessments must cover the exact supplied candidate_ref set; "
            f"missing={missing}, extra={extra}, expected_count={len(expected)}, "
            f"actual_count={len(actual)}"
        )

    available_evidence_ids = _evidence_ids(
        {key: value for key, value in view.items() if key != "candidates"}
    )
    for row in assessments:
        if not isinstance(row, dict):
            continue
        candidate_ref = row.get("candidate_ref")
        neutral = expected_rows.get(candidate_ref)
        if neutral is None:
            continue
        for field in ("claim", "location"):
            if row.get(field) != neutral.get(field):
                problems.append(
                    f"assessment {candidate_ref} changed the supplied {field}"
                )
        if "hypothesis_ids" in row and row.get("hypothesis_ids") != neutral.get(
            "hypothesis_ids", []
        ):
            problems.append(
                f"assessment {candidate_ref} changed the supplied hypothesis_ids"
            )
        cited_evidence = {
            item for item in row.get("evidence_ids", [])
            if isinstance(item, str)
        }
        unknown_evidence = sorted(cited_evidence - available_evidence_ids)
        if unknown_evidence:
            problems.append(
                f"assessment {candidate_ref} cites evidence not present in its "
                f"least-context view: {unknown_evidence}"
            )
    return problems


_ROLE_TASK: dict[NodeRole, str] = {
    NodeRole.MAPPER: "Map entrypoints, trust boundaries and identities.",
    NodeRole.ARCHITECTURE: "Describe the architecture and where trust changes hands.",
    NodeRole.AUTHENTICATION: "Examine authentication, sessions, tokens and recovery.",
    NodeRole.AUTHORIZATION: "Examine object and function authorization, ownership and tenancy.",
    NodeRole.BUSINESS_LOGIC: "Examine workflow, state machines, money and inventory invariants.",
    NodeRole.INJECTION_DATAFLOW: "Trace attacker-controlled sources to dangerous sinks.",
    NodeRole.API_PROTOCOL: "Examine API surface, protocol handling and middleware.",
    NodeRole.BROWSER: "Examine client-side boundaries, DOM sinks and origins.",
    NodeRole.RUNTIME_VERIFICATION: (
        "Reproduce candidate claims against the supplied authorized runtime evidence; "
        "prefer refutation, record blockers, and do not infer exploitability from a "
        "status code alone."
    ),
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

Assess EVERY supplied candidate exactly once. Preserve its candidate_ref exactly.
Reconstruct the claim from the supplied evidence and actively try to refute it.
classification must be one of: VERIFIED, LIKELY_BUT_UNPROVEN, FALSE_POSITIVE,
DUPLICATE_ROOT_CAUSE, BLOCKED_BY_ENVIRONMENT. VERIFIED requires at least one
stable evidence_id already present in the Evidence block; never invent an
evidence reference. VERIFIED means only that this independent verification pass
could not refute the claim and established the stated basis. It does NOT assign
severity, create a canonical finding, or make a release decision.
Refuting a claim is a success, not a failure.

Return ONLY a JSON object of this shape, with no prose around it:
{"assessments": [{"candidate_ref": "sha256:...", "classification": "VERIFIED",
                  "claim": "...", "location": "...", "why": "...",
                  "refutation_attempt": "...", "evidence_ids": ["EV-..."],
                  "hypothesis_ids": []}],
 "examined": ["..."], "notes": "..."}
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
        unique_candidates: list[dict[str, Any]] = []
        seen_refs: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            neutral = verifier_view(candidate)
            candidate_ref = neutral["candidate_ref"]
            if candidate_ref in seen_refs:
                continue
            seen_refs.add(candidate_ref)
            unique_candidates.append(neutral)
        payload["candidates"] = unique_candidates

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

        problems = (
            validate_verifier_output(payload)
            if node.role is NodeRole.INDEPENDENT_VERIFIER
            else validate_node_output(payload)
        )
        if not problems and node.role is NodeRole.INDEPENDENT_VERIFIER:
            problems.extend(_validate_verifier_binding(payload, view))
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
    "VERIFIER_CLASSIFICATIONS",
    "VERIFIER_OUTPUT_SCHEMA",
    "ReasoningExecutor",
    "build_prompt",
    "validate_verifier_output",
    "verifier_view",
]
