"""Attack chain correlation.

Severity is usually assigned per finding, which systematically underrates the
thing that actually gets exploited. Enumeration is Low. A weak reset token is
Medium. Missing MFA on recovery is Medium. Together they are account takeover.

This module composes verified findings into named chains. Three rules keep it
honest:

1. **Only verified findings compose.** A chain built from hypotheses is a
   hypothesis about a hypothesis. Unverified components are reported as a
   *potential* chain with its missing links named, never as a chain.
2. **Severity is not inflated, it is derived.** A chain's severity comes from the
   chain definition — the impact of the composed outcome — not from bumping the
   worst component up a notch.
3. **Every chain cites its components and its prerequisites.** A chain that
   cannot name which findings compose it is not emitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

VERIFIED = "VERIFIED"

CONFIRMED = "CONFIRMED"
POTENTIAL = "POTENTIAL"


@dataclass(frozen=True)
class ChainLink:
    """One capability a chain needs, and how to recognize it in a finding."""

    key: str
    description: str
    #: Catalog family prefixes that can satisfy this link.
    families: tuple[str, ...]
    #: Substrings matched case-insensitively against a finding's title,
    #: affected surface, and catalog hypothesis IDs.
    signals: tuple[str, ...]


@dataclass(frozen=True)
class ChainDefinition:
    chain_id: str
    name: str
    outcome: str
    severity: str
    links: tuple[ChainLink, ...]
    prerequisites: tuple[str, ...]
    rationale: str


def _link(key, description, families, signals) -> ChainLink:
    return ChainLink(key, description, tuple(families), tuple(signals))


CHAINS: tuple[ChainDefinition, ...] = (
    ChainDefinition(
        "CHAIN-ATO-001",
        "Account takeover through recovery",
        "An attacker who knows only an email address can take over an account.",
        "CRITICAL",
        (
            _link("enumeration", "A way to confirm that an account exists",
                  ("AUTH", "API", "PRIV"),
                  ("enumerate", "enumerated", "enumeration", "enumerable", "user exists",
                   "account exists", "timing", "different error", "response differs")),
            _link("weak_recovery", "A guessable, long-lived, or replayable reset artifact",
                  ("AUTH", "CRYPTO", "SESS"),
                  ("reset", "recovery", "forgot password", "otp", "one-time", "token entropy",
                   "predictable", "does not expire")),
            _link("missing_second_factor", "No step-up control on the recovery path",
                  ("AUTH", "SESS"),
                  ("mfa", "2fa", "second factor", "step-up", "step up", "otp bypass")),
        ),
        ("The account exists.", "The recovery channel is reachable by the attacker."),
        "Each component is individually modest. Composed, they are a full authentication bypass "
        "that leaves no credential-stuffing signal.",
    ),
    ChainDefinition(
        "CHAIN-XTENANT-001",
        "Cross-tenant data exfiltration",
        "An authenticated tenant reads another tenant's stored objects at scale.",
        "CRITICAL",
        (
            _link("object_authorization", "An object read that omits the owner predicate",
                  ("AUTHZ", "DB", "API"),
                  ("idor", "bola", "ownership", "tenant", "object authorization",
                   "missing predicate", "cross-tenant")),
            _link("object_reference_exposure", "A way to learn or guess other tenants' object keys",
                  ("PRIV", "API", "CLOUD", "WEB"),
                  ("signed url", "signed urls", "presigned", "sequential", "enumerable id",
                   "leak", "leaks", "object key", "object keys")),
            _link("bulk_reach", "A path that returns many objects per request",
                  ("API", "AUTHZ", "DB"),
                  ("export", "exports", "bulk", "list", "lists", "listing", "search",
                   "report", "download all", "pagination")),
        ),
        ("The caller holds any authenticated tenant session.",
         "Objects of different tenants share one store."),
        "An IDOR that returns one record is a bug. The same IDOR reachable from an export path "
        "with guessable keys is a breach.",
    ),
    ChainDefinition(
        "CHAIN-DOUBLE-EXEC-001",
        "Double execution of a value transfer",
        "A single authorized economic action is executed more than once.",
        "HIGH",
        (
            _link("replayable_trigger", "A callback or request that can be replayed",
                  ("API", "RACE", "CRYPTO"),
                  ("webhook", "callback", "replay", "replays", "replayable", "signature",
                   "nonce", "timestamp")),
            _link("missing_idempotency", "No idempotency key or conditional write",
                  ("RACE", "MONEY", "DB"),
                  ("idempotent", "idempotency", "idempotence", "check-then-act", "race",
                   "races", "concurrent", "concurrency", "duplicate", "duplicates",
                   "not atomic", "toctou")),
            _link("value_transition", "The action moves money or irreversible state",
                  ("MONEY", "BIZ"),
                  ("refund", "refunds", "payout", "payouts", "charge", "charges",
                   "credit", "credits", "ledger", "balance", "state transition", "fulfil")),
        ),
        ("The attacker can cause the trigger to fire more than once.",
         "The action has an external effect that cannot be rolled back."),
        "Replay alone is noise and a missing idempotency key alone is a correctness bug. "
        "Together on a money path they are direct financial loss.",
    ),
    ChainDefinition(
        "CHAIN-AGENT-EXFIL-001",
        "Agent-mediated data exfiltration",
        "Untrusted content steers an agent into sending data to an attacker destination.",
        "HIGH",
        (
            _link("untrusted_ingestion", "The agent ingests content an attacker can write",
                  ("AI",),
                  ("prompt injection", "indirect", "untrusted content", "retrieved",
                   "rag", "ingest", "fetched page")),
            _link("tool_authority", "A reachable tool with meaningful authority",
                  ("AI",),
                  ("tool", "tools", "mcp", "function call", "excessive agency",
                   "confused deputy", "allowlist")),
            _link("egress", "A path that can move data outward",
                  ("SSRF", "AI", "PRIV", "CLOUD"),
                  ("outbound", "egress", "webhook", "send", "sends", "upload", "uploads",
                   "ssrf", "exfil", "external request", "external requests")),
        ),
        ("The agent processes content the attacker can influence.",
         "The tool runs with credentials or data access the attacker does not have."),
        "Prompt injection with no privileged tool is noise. A privileged tool with no untrusted "
        "input is fine. The two together are the confused deputy.",
    ),
    ChainDefinition(
        "CHAIN-SUPPLY-RCE-001",
        "Build-time code execution through the supply chain",
        "Attacker-controlled content executes inside the build or deploy pipeline.",
        "CRITICAL",
        (
            _link("unverified_artifact", "An artifact fetched without integrity enforcement",
                  ("SUPPLY", "CI"),
                  ("integrity", "checksum", "sha256", "unpinned", "unverified", "signature",
                   "dependency confusion")),
            _link("pipeline_execution", "The artifact is executed by the pipeline",
                  ("CI", "SUPPLY"),
                  ("install script", "postinstall", "subprocess", "run", "runs",
                   "build step", "workflow", "action", "actions")),
            _link("privileged_context", "The pipeline holds secrets or write access",
                  ("CI", "CLOUD", "CRYPTO"),
                  ("secret", "token", "contents: write", "id-token", "deploy", "credential",
                   "pull_request_target")),
        ),
        ("The pipeline runs on attacker-influenced input or an attacker-influenced dependency.",),
        "An unpinned dependency is a hygiene issue until the pipeline that installs it holds a "
        "deployment credential.",
    ),
)


@dataclass(frozen=True)
class ChainMatch:
    definition: ChainDefinition
    status: str
    matched: dict[str, str]
    missing: tuple[str, ...]
    unverified: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.definition.chain_id,
            "name": self.definition.name,
            "status": self.status,
            "outcome": self.definition.outcome,
            "severity": self.definition.severity if self.status == CONFIRMED else "UNASSIGNED",
            "component_findings": [
                {"link": key, "finding_id": finding_id}
                for key, finding_id in sorted(self.matched.items())
            ],
            "missing_links": list(self.missing),
            "unverified_components": list(self.unverified),
            "prerequisites": list(self.definition.prerequisites),
            "rationale": self.definition.rationale,
            "claim_status": "VERIFIED_COMPOSITION" if self.status == CONFIRMED else "HYPOTHESIS",
        }


def _haystack(finding: Mapping[str, Any]) -> str:
    parts = [str(finding.get("title", ""))]
    surface = finding.get("affected_surface")
    if isinstance(surface, list):
        parts.extend(str(item) for item in surface)
    elif surface:
        parts.append(str(surface))
    parts.extend(str(item) for item in finding.get("catalog_hypothesis_ids", []) or [])
    parts.extend(str(item) for item in finding.get("mappings", []) or [])
    chain = finding.get("evidence_chain")
    if isinstance(chain, Mapping):
        for entry in chain.values():
            if isinstance(entry, Mapping):
                parts.append(str(entry.get("statement", "")))
    return " ".join(parts).lower()


def _families(finding: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for hypothesis in finding.get("catalog_hypothesis_ids", []) or []:
        parts = str(hypothesis).split("-")
        if len(parts) >= 2:
            result.add(parts[1].upper())
    return result


_SIGNAL_CACHE: dict[str, re.Pattern[str]] = {}


def _signal_pattern(signal: str) -> re.Pattern[str]:
    """Match a signal on whole words, at both ends.

    Naive substring matching is how "stack trace" satisfies a signal for "race".
    A leading boundary alone fixes that and leaves the mirror-image bug intact:
    "event listener" still satisfies "list", and "runtime error" still satisfies
    "run". Both ends are needed.

    Inflections are therefore not matched implicitly. A signal list that needs
    "tools" as well as "tool" says so, because a signal set you can read and
    predict is worth more than one that quietly generalizes.
    """
    if signal not in _SIGNAL_CACHE:
        _SIGNAL_CACHE[signal] = re.compile(
            rf"(?<![a-z0-9]){re.escape(signal)}(?![a-z0-9])", re.I
        )
    return _SIGNAL_CACHE[signal]


def _satisfies(link: ChainLink, finding: Mapping[str, Any]) -> bool:
    text = _haystack(finding)
    return any(_signal_pattern(signal).search(text) for signal in link.signals)


def correlate(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compose findings into attack chains.

    A chain is CONFIRMED only when every link is satisfied by a finding whose
    status is VERIFIED. If links are satisfied only by unverified candidates, the
    chain is POTENTIAL, carries no severity, and names what still needs proof.
    """
    results: list[ChainMatch] = []

    for definition in CHAINS:
        matched: dict[str, str] = {}
        unverified_matched: dict[str, str] = {}

        for link in definition.links:
            for finding in findings:
                if not isinstance(finding, Mapping):
                    continue
                if not _satisfies(link, finding):
                    continue
                finding_id = str(finding.get("finding_id", "")) or "<unnamed>"
                if str(finding.get("status", "")).upper() == VERIFIED:
                    matched.setdefault(link.key, finding_id)
                else:
                    unverified_matched.setdefault(link.key, finding_id)

        # Only links that no verified finding covers count as unverified. Judging
        # the chain on whether *any* unverified finding matched anywhere demotes a
        # fully proven chain because some unrelated candidate happened to share a
        # signal word — and signal words like "listing" and "leak" are common
        # across unrelated titles in a real report.
        unverified_gaps = {
            key: fid for key, fid in unverified_matched.items() if key not in matched
        }
        satisfied = set(matched) | set(unverified_gaps)
        # One satisfied link out of several is a finding, not a chain. Requiring a
        # majority keeps POTENTIAL chains worth reading.
        if len(satisfied) * 2 <= len(definition.links) - 1:
            continue

        missing = tuple(
            link.description for link in definition.links if link.key not in satisfied
        )

        # CONFIRMED means every link is carried by a verified finding — not that
        # nothing unverified appeared anywhere in the report.
        if all(link.key in matched for link in definition.links):
            results.append(ChainMatch(definition, CONFIRMED, matched, ()))
        else:
            combined = {**unverified_gaps, **matched}
            results.append(ChainMatch(
                definition, POTENTIAL, combined, missing,
                tuple(sorted(set(unverified_gaps.values()))),
            ))

    # Confirmed chains first, then by how complete the potential ones are.
    results.sort(key=lambda m: (m.status != CONFIRMED, len(m.missing), m.definition.chain_id))
    return [match.as_dict() for match in results]


def correlate_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Correlate the findings inside a canonical report."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("report findings must be an array")
    chains = correlate(findings)
    confirmed = [c for c in chains if c["status"] == CONFIRMED]
    return {
        "schema_version": "1.0",
        "report_id": report.get("report_id"),
        "chains": chains,
        "confirmed_count": len(confirmed),
        "potential_count": len(chains) - len(confirmed),
        "notes": [
            "A chain is CONFIRMED only when every link is a VERIFIED finding.",
            "Chain severity comes from the composed outcome, not from raising a component.",
            "POTENTIAL chains carry no severity and name what is still missing.",
        ],
    }
