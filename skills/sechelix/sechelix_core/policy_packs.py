"""Release policy as versioned data, carried in the evidence it decided.

A release gate answers "may this ship". That answer is only meaningful if you can
say *which rules produced it*. A report that records `PASS` without recording the
policy that passed it is an unfalsifiable claim: nobody can check it later, and
nobody can tell whether the rules changed between the audit and the release.

So a policy pack is versioned, scoped, and **stamped into the report**. The
resolver records which pack applied, which rules fired, and — the part usually
missing — which rules were evaluated and did not fire. A rule that silently never
applied looks identical to one that passed.

Three rules keep this from becoming a way to configure your way to green.

**`INCOMPLETE` is not a softer `BLOCK`.** `BLOCK` asserts a problem exists.
`INCOMPLETE` asserts the decision cannot be made. Missing evidence produces the
second, and it is never downgraded to a pass because the policy did not mention
it.

**A pack that matches nothing is reported, not assumed.** Scope resolution says
which dimensions it matched on and which were unconstrained, so "the policy did
not apply here" is visible rather than inferred from a clean result.

**Accepted risk needs an owner and an expiry.** An acceptance without a name
attached is not a decision anyone made, and one without an expiry is a permanent
exception acquired by writing a sentence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

BLOCK = "BLOCK"
INCOMPLETE = "INCOMPLETE"
WARN = "WARN"

#: Outcome precedence. A pack producing both a BLOCK and an INCOMPLETE is BLOCKED:
#: a known problem outranks an unknown one.
_PRECEDENCE = {BLOCK: 3, INCOMPLETE: 2, WARN: 1}

ANY = "ANY"


class PolicyError(ValueError):
    """The pack cannot be used to decide anything."""


@dataclass(frozen=True)
class RuleFiring:
    rule_id: str
    statement: str
    outcome: str
    finding_ids: tuple[str, ...]
    rationale: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "statement": self.statement,
            "outcome": self.outcome,
            "finding_ids": list(self.finding_ids),
            "rationale": self.rationale,
        }


@dataclass
class PolicyDecision:
    pack_id: str
    pack_version: str
    outcome: str
    fired: list[RuleFiring] = field(default_factory=list)
    evaluated_not_fired: list[str] = field(default_factory=list)
    scope_match: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def blocks_release(self) -> bool:
        return self.outcome in {BLOCK, INCOMPLETE}

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_pack": {"pack_id": self.pack_id, "version": self.pack_version},
            "outcome": self.outcome,
            "rules_fired": [f.as_dict() for f in self.fired],
            # Recorded so a rule that never applied is visible rather than
            # indistinguishable from one that passed.
            "rules_evaluated_not_fired": list(self.evaluated_not_fired),
            "scope_match": self.scope_match,
            "notes": list(self.notes),
        }


def load_pack(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise PolicyError("a policy pack must be an object")
    for required in ("pack_id", "version", "rules"):
        if required not in data:
            raise PolicyError(f"policy pack is missing {required}")
    if not data["rules"]:
        raise PolicyError("a policy pack with no rules decides nothing and must not be used")
    return dict(data)


def _matches_scope(pack: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve scope, recording what matched and what was unconstrained."""
    scope = pack.get("scope") or {}
    matched: dict[str, Any] = {}
    applies = True

    pairs = (
        ("organization", "organization", False),
        ("repositories", "repository", True),
        ("branches", "branch", True),
        ("environments", "environment", True),
        ("data_sensitivity", "data_sensitivity", True),
    )
    for scope_key, context_key, is_list in pairs:
        declared = scope.get(scope_key)
        if declared in (None, [], ""):
            matched[scope_key] = "UNCONSTRAINED"
            continue
        actual = context.get(context_key)
        if actual is None:
            # The pack constrains a dimension the caller did not supply. That is
            # not a match and not a mismatch — it is unknown, and unknown scope
            # must not silently disable a rule.
            matched[scope_key] = "UNKNOWN"
            applies = False
            continue
        allowed = declared if is_list else [declared]
        hit = str(actual) in {str(a) for a in allowed} or ANY in {str(a) for a in allowed}
        matched[scope_key] = "MATCHED" if hit else "NOT_MATCHED"
        if not hit:
            applies = False

    matched["applies"] = applies
    return matched


def _finding_matches(rule: Mapping[str, Any], finding: Mapping[str, Any]) -> bool:
    condition = rule.get("condition") or {}

    def upper_set(key):
        values = condition.get(key)
        return {str(v).upper() for v in values} if values else None

    severities = upper_set("severities")
    if severities and str(finding.get("severity", "")).upper() not in severities:
        return False

    statuses = upper_set("finding_statuses")
    if statuses and str(finding.get("status", "")).upper() not in statuses:
        return False

    resolutions = upper_set("resolutions")
    if resolutions and str(finding.get("resolution", "OPEN")).upper() not in resolutions:
        return False

    verification_states = upper_set("verification_states")
    if verification_states:
        verification = finding.get("verification") or {}
        if str(verification.get("outcome", "NOT_RUN")).upper() not in verification_states:
            return False

    families = condition.get("catalog_families")
    if families:
        found = set()
        for hypothesis in finding.get("catalog_hypothesis_ids", []) or []:
            parts = str(hypothesis).split("-")
            if len(parts) >= 2:
                found.add(parts[1].upper())
        if not found & {str(f).upper() for f in families}:
            return False

    patterns = condition.get("surface_patterns")
    if patterns:
        surfaces = finding.get("affected_surface") or []
        surfaces = surfaces if isinstance(surfaces, list) else [surfaces]
        blob = " ".join(str(s) for s in surfaces).lower()
        if not any(str(p).lower() in blob for p in patterns):
            return False

    if condition.get("requires_regression") is True:
        regression = finding.get("regression") or {}
        if str(regression.get("status", "NOT_RUN")).upper() == "PASS":
            return False  # the requirement is satisfied, so the rule does not fire

    if condition.get("requires_independent_verification") is True:
        verification = finding.get("verification") or {}
        if verification.get("independent") is True and \
                str(verification.get("outcome", "")).upper() == "VERIFIED":
            return False

    return True


def evaluate(
    pack: Mapping[str, Any],
    report: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> PolicyDecision:
    """Apply one pack to one report. Returns the decision and its full reasoning."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise PolicyError("report findings must be an array")

    # Checked here and not only in load_pack: a pack constructed in memory takes a
    # different path, and a rule-less pack that returns PASS is the exact shape of
    # configuring your way to green.
    if not pack.get("rules"):
        raise PolicyError(
            f"policy pack {pack.get('pack_id', '<unnamed>')} has no rules; a pack that "
            "decides nothing must not be used to decide a release"
        )

    scope_match = _matches_scope(pack, context)
    decision = PolicyDecision(
        pack_id=str(pack["pack_id"]),
        pack_version=str(pack["version"]),
        outcome="PASS",
        scope_match=scope_match,
    )

    if not scope_match["applies"]:
        unknown = [k for k, v in scope_match.items() if v == "UNKNOWN"]
        if unknown:
            # A pack whose applicability cannot be established must not quietly
            # decide nothing. Unknown scope is INCOMPLETE, not PASS.
            decision.outcome = INCOMPLETE
            decision.notes.append(
                "policy scope could not be resolved: "
                f"{', '.join(unknown)} not supplied by the caller"
            )
        else:
            decision.notes.append("this pack does not apply to the supplied context")
        return decision

    worst = 0
    for rule in pack["rules"]:
        matched = [f for f in findings if isinstance(f, Mapping) and _finding_matches(rule, f)]
        if not matched:
            decision.evaluated_not_fired.append(str(rule["rule_id"]))
            continue
        firing = RuleFiring(
            rule_id=str(rule["rule_id"]),
            statement=str(rule["statement"]),
            outcome=str(rule["outcome"]).upper(),
            finding_ids=tuple(str(f.get("finding_id", "")) for f in matched),
            rationale=str(rule.get("rationale", "")),
        )
        decision.fired.append(firing)
        worst = max(worst, _PRECEDENCE.get(firing.outcome, 0))

    accepted = pack.get("accepted_risk") or {}
    problems = _check_accepted_risks(findings, accepted, now or datetime.now(timezone.utc))
    if problems:
        decision.fired.append(RuleFiring(
            "ACCEPTED-RISK-VALIDITY",
            "An accepted risk must name an owner and an expiry that has not passed.",
            BLOCK, tuple(problems),
            "An acceptance with nobody attached is not a decision, and one without "
            "an expiry is a permanent exception acquired by writing a sentence.",
        ))
        worst = max(worst, _PRECEDENCE[BLOCK])

    for level, score in sorted(_PRECEDENCE.items(), key=lambda kv: -kv[1]):
        if worst == score:
            decision.outcome = level
            break
    return decision


def _check_accepted_risks(
    findings: Sequence[Mapping[str, Any]],
    accepted: Mapping[str, Any],
    now: datetime,
) -> list[str]:
    required = list(accepted.get("required_fields")
                    or ["owner", "reason", "approved_at", "expires_at"])
    problems: list[str] = []

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if str(finding.get("resolution", "")).upper() != "ACCEPTED_RISK":
            continue
        finding_id = str(finding.get("finding_id", ""))

        if accepted.get("allowed") is not True:
            problems.append(f"{finding_id}: accepted risk is not permitted by this policy")
            continue

        block = finding.get("accepted_risk") or {}
        missing = [f for f in required if not block.get(f)]
        if missing:
            problems.append(f"{finding_id}: accepted risk is missing {', '.join(missing)}")
            continue

        expires = str(block.get("expires_at", ""))
        try:
            when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            problems.append(f"{finding_id}: accepted risk expiry {expires!r} is not a timestamp")
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when <= now:
            problems.append(f"{finding_id}: accepted risk expired on {expires}")

    return problems


def stamp_report(report: dict[str, Any], decisions: Iterable[PolicyDecision]) -> dict[str, Any]:
    """Record the policy decisions inside the report they decided.

    Without this the report says it passed and cannot say what it passed.
    """
    report["policy_decisions"] = [d.as_dict() for d in decisions]
    return report
