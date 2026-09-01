"""Turn a verified finding into a rule that can go looking for its siblings.

`variant_hunter` classifies a candidate you already found. This module produces
the query that finds candidates in the first place: a verified finding becomes a
Semgrep rule, so the same root cause can be swept across a codebase instead of
being fixed once at the site where it happened to be noticed.

The reason this is worth doing is that a single instance is almost never single.
A missing tenant predicate on one report lookup is a fact about how that codebase
writes queries, and the second instance is usually a search away.

Three constraints keep generated rules from becoming a false-positive machine —
which would undo the thing this project exists for.

**A generated rule is UNVALIDATED until it runs.** Generation proves nothing. The
rule carries that status, and the status only moves when someone runs the rule
and reads the hits.

**A rule hit is a HYPOTHESIS, never a finding.** It is a candidate that enters the
normal evidence and verification workflow at the bottom, exactly like any other
lead. Severity is deliberately not carried over from the seed: the seed's
severity was earned by its own evidence chain, and a syntactic match inherits
none of it.

**Rules are written to under-match.** Where there is a choice between missing a
variant and flagging clean code, these rules miss. A missed variant costs one
more review pass; a noisy rule costs the reader's trust in every rule after it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

VERIFIED = "VERIFIED"

#: Status of a rule that has been generated but never executed.
UNVALIDATED = "UNVALIDATED"

#: Languages we will emit a rule for. Anything else is refused rather than
#: guessed at, because a rule in the wrong dialect silently matches nothing.
SUPPORTED_LANGUAGES = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "tsx": "typescript",
    "go": "go",
    "java": "java",
    "ruby": "ruby",
    "php": "php",
    "csharp": "csharp",
    "cs": "csharp",
}

_EXTENSION_LANGUAGE = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "csharp",
}

_RULE_ID = re.compile(r"[^a-z0-9]+")


class VariantRuleError(ValueError):
    """The finding cannot be turned into a rule."""


@dataclass(frozen=True)
class VariantRule:
    rule_id: str
    seed_finding_id: str
    language: str
    message: str
    patterns: tuple[str, ...]
    status: str = UNVALIDATED

    def as_semgrep(self) -> dict[str, Any]:
        """Render as a Semgrep rule document.

        Severity is fixed at INFO regardless of the seed. A syntactic match has
        not earned the seed's severity, and emitting ERROR here would put
        unverified hits at the top of someone's triage queue.
        """
        return {
            "rules": [{
                "id": self.rule_id,
                "languages": [self.language],
                "severity": "INFO",
                "message": self.message,
                "metadata": {
                    "sechelix_seed_finding": self.seed_finding_id,
                    "sechelix_rule_status": self.status,
                    "claim_status": "HYPOTHESIS",
                    "confidence": "LOW",
                    "note": (
                        "Generated from a verified finding to locate siblings of the same root "
                        "cause. A hit is a candidate for review, not a vulnerability, and carries "
                        "none of the seed's verification."
                    ),
                },
                "patterns": [{"pattern": pattern} for pattern in self.patterns],
            }],
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "seed_finding_id": self.seed_finding_id,
            "language": self.language,
            "status": self.status,
            "pattern_count": len(self.patterns),
            "hit_claim_status": "HYPOTHESIS",
        }


@dataclass(frozen=True)
class RuleRefusal:
    seed_finding_id: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"seed_finding_id": self.seed_finding_id, "refused_because": self.reason}


def _slug(text: str, limit: int = 48) -> str:
    return _RULE_ID.sub("-", text.lower()).strip("-")[:limit].strip("-") or "variant"


def infer_language(finding: Mapping[str, Any]) -> str | None:
    """Take the language from the finding, or from the surface's extension."""
    declared = str(finding.get("language", "")).strip().lower()
    if declared in SUPPORTED_LANGUAGES:
        return SUPPORTED_LANGUAGES[declared]

    surfaces = finding.get("affected_surface")
    surfaces = surfaces if isinstance(surfaces, list) else [surfaces]
    for surface in surfaces:
        if not surface:
            continue
        path = str(surface).split(":")[0].lower()
        for extension, language in _EXTENSION_LANGUAGE.items():
            if path.endswith(extension):
                return language
    return None


def generate_rule(
    finding: Mapping[str, Any],
    patterns: Sequence[str],
    *,
    language: str | None = None,
) -> VariantRule:
    """Build one Semgrep rule from a verified finding and explicit patterns.

    Patterns are supplied by the caller rather than inferred from source text.
    Deriving a pattern automatically from a code excerpt produces rules that
    match the incident instead of the root cause, and they are the rules that
    make people stop reading rule output.
    """
    if str(finding.get("status", "")).upper() != VERIFIED:
        raise VariantRuleError(
            "only a VERIFIED finding may seed a rule; an unverified seed would "
            "propagate a guess across the whole codebase"
        )

    cleaned = tuple(p for p in (str(x).strip() for x in patterns) if p)
    if not cleaned:
        raise VariantRuleError("a rule needs at least one pattern")

    resolved = SUPPORTED_LANGUAGES.get((language or "").lower()) or infer_language(finding)
    if not resolved:
        raise VariantRuleError(
            "could not determine the language; a rule in the wrong dialect matches nothing "
            "and reads as a clean sweep"
        )

    finding_id = str(finding.get("finding_id", "")).strip()
    if not finding_id:
        raise VariantRuleError("the seed finding has no finding_id to attribute the rule to")

    title = str(finding.get("title", "")).strip()
    remediation = finding.get("remediation") or {}
    root_cause = str(remediation.get("root_cause_fix", "")).strip()

    message = (
        f"Possible sibling of {finding_id}: {title or 'a verified finding'}. "
        "This is an unverified candidate — confirm reachability and the missing control before "
        "treating it as a finding."
    )
    if root_cause:
        message += f" The verified instance was fixed by: {root_cause}"

    return VariantRule(
        rule_id=f"sechelix-variant-{_slug(finding_id)}-{_slug(title)}",
        seed_finding_id=finding_id,
        language=resolved,
        message=message,
        patterns=cleaned,
    )


def generate_rules(
    findings: Sequence[Mapping[str, Any]],
    patterns_by_finding: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    """Generate rules for every seed that qualifies, and record why the rest did not."""
    rules: list[VariantRule] = []
    refusals: list[RuleRefusal] = []

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_id = str(finding.get("finding_id", "")).strip()
        if not finding_id:
            continue
        patterns = patterns_by_finding.get(finding_id)
        if not patterns:
            refusals.append(RuleRefusal(
                finding_id,
                "no patterns were supplied; a rule inferred from the excerpt would match this "
                "incident rather than its root cause",
            ))
            continue
        try:
            rules.append(generate_rule(finding, patterns))
        except VariantRuleError as exc:
            refusals.append(RuleRefusal(finding_id, str(exc)))

    return {
        "schema_version": "1.0",
        "rules": [rule.as_dict() for rule in rules],
        "semgrep": {"rules": [r for rule in rules for r in rule.as_semgrep()["rules"]]},
        "refusals": [refusal.as_dict() for refusal in refusals],
        "generated_count": len(rules),
        "refused_count": len(refusals),
        "notes": [
            f"Every rule is {UNVALIDATED}: generation proves nothing until the rule is run.",
            "A rule hit is a HYPOTHESIS and enters the normal verification workflow at the bottom.",
            "Rule severity is INFO regardless of the seed's severity, which was earned by the "
            "seed's own evidence chain and is not inherited by a syntactic match.",
            "These rules are written to under-match. They will miss variants, and that is "
            "preferred over flagging clean code.",
        ],
    }
