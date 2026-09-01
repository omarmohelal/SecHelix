"""PR security bot mode.

A reviewer opening a pull request needs four answers: what did this change do to
the security posture, what did it raise that nobody has checked, what is
actually proven, and may it ship. This module produces those four answers from a
unified diff and whatever reports exist, and renders them as one PR comment.

The hard part is not producing the comment. It is not producing it.

**Silence is the default.** A bot that comments on every pull request is muted
within a week, and a muted bot protects nothing. So a comment is emitted only
when something *material* happened — a term this module defines precisely
(see ``MATERIALITY_REASONS``) rather than leaving to taste. A typo fix, a
refactor that moves no security surface, and a change that only adds a control
all produce an explicit "nothing to say" result with ``comment is None``.

Three things it refuses to do.

**It does not re-implement diff classification.** Deltas come from
``diff_review.review_diff``. One classifier means one place where a rule is
wrong, and one place to fix it.

**Silence is not approval.** Suppressing the comment never raises the release
decision. A pull request with nothing worth saying and no evidence behind it is
``INCOMPLETE`` and silent, not ``PASS``.

**The decision is never better than the evidence.** The outcome is the worst of
three independent ceilings: what the diff raised and nobody examined, whether a
report describes this change at all, and what the release gate actually
returned. ``NEW_RISK`` that nothing verified yields ``INCOMPLETE`` — never
``PASS``, because "we did not look" and "we looked and it is fine" are different
statements. A report's own ``release_recommendation`` is not evidence and is
never read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .diff_review import NEW_RISK, RISK_REDUCED, UNCHANGED, UNKNOWN, review_diff
from .revision import FRESH, assess_freshness

# --------------------------------------------------------------------------- #
# Release vocabulary — the same words scripts/security_gate.py uses.
# --------------------------------------------------------------------------- #

PASS = "PASS"
PASS_WITH_KNOWN_RISK = "PASS_WITH_KNOWN_RISK"
BLOCKED = "BLOCKED"
INCOMPLETE = "INCOMPLETE"

RELEASE_OUTCOMES = (PASS, PASS_WITH_KNOWN_RISK, BLOCKED, INCOMPLETE)

#: How favourable each outcome is. The final decision is the minimum, so no
#: single input can raise the result above what another input supports.
FAVOURABILITY = {PASS: 3, PASS_WITH_KNOWN_RISK: 2, INCOMPLETE: 1, BLOCKED: 0}

VERIFIED = "VERIFIED"
FALSE_POSITIVE = "FALSE_POSITIVE"

#: A delta counts as examined only when a finding in the *head* report cites the
#: same file. Attribution is path-level and is stated as such: it shows that the
#: file was looked at, not that this particular delta was the thing examined.
ADDRESSED_BY_VERIFIED_FINDING = "ADDRESSED_BY_VERIFIED_FINDING"
ADDRESSED_BY_REFUTATION = "ADDRESSED_BY_REFUTATION"
UNADDRESSED = "UNADDRESSED"

#: Directions that raise a question. RISK_REDUCED and UNCHANGED do not.
QUESTIONING_DIRECTIONS = (NEW_RISK, UNKNOWN)

HEAD_REPORT = "HEAD_REPORT"
BASE_REPORT = "BASE_REPORT"
NO_REPORT = "NO_REPORT"

IMPROVED = "IMPROVED"
DEGRADED = "DEGRADED"

COVERAGE_KEYS = ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED", "integrity_critical_unknown")

#: Exactly what makes a pull request worth commenting on. Anything not on this
#: list produces no comment. The list is short on purpose: every reason added
#: here is a reason the bot speaks more often, and every extra comment costs
#: some of the attention the next one needs.
MATERIALITY_REASONS = {
    "NEW_HYPOTHESIS": "the diff raised at least one NEW_RISK or UNKNOWN delta",
    "UNREADABLE_DIFF": "a diff was supplied that the classifier could not parse, so nothing was analyzed",
    "NEW_VERIFIED_FINDING": "a finding is VERIFIED in the head report that was not verified before",
    "CANDIDATE_REFUTED": "a candidate that was open before is refuted in the head report",
    "COVERAGE_DEGRADED": "coverage got worse between the two reports",
    "DECISION_CHANGED": "the release decision differs from the one supplied for the base",
}

NOT_MATERIAL = (
    "no NEW_RISK or UNKNOWN delta, no change in verified or refuted findings, no coverage "
    "regression, and no change of decision"
)


class PullRequestReviewError(ValueError):
    """The inputs cannot be reviewed."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _report(value: Any, label: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise PullRequestReviewError(f"{label} must be a report object or None")
    return value


def _findings(report: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if report is None:
        return []
    findings = report.get("findings")
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        return []
    return [f for f in findings if isinstance(f, Mapping)]


def _normalize_path(path: str) -> str:
    cleaned = str(path).replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def _surface_paths(finding: Mapping[str, Any]) -> set[str]:
    surface = finding.get("affected_surface")
    items: list[str]
    if isinstance(surface, list):
        items = [str(item) for item in surface]
    elif surface:
        items = [str(surface)]
    else:
        items = []
    paths = set()
    for item in items:
        # "app/orders.py:41" and "app/orders.py" both name the same file.
        head = item.split(":", 1)[0]
        normalized = _normalize_path(head)
        if normalized:
            paths.add(normalized)
    return paths


def _paths_match(left: str, right: str) -> bool:
    left, right = _normalize_path(left), _normalize_path(right)
    if not left or not right:
        return False
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def _touches(finding: Mapping[str, Any], path: str) -> bool:
    return any(_paths_match(surface, path) for surface in _surface_paths(finding))


def _status(finding: Mapping[str, Any]) -> str:
    return str(finding.get("status", "")).upper()


def worst(*outcomes: str) -> str:
    """The least favourable of the supplied outcomes.

    This is the whole honesty mechanism of the decision: three ceilings are
    computed independently and combined with ``min``, so a favourable input can
    never lift the result past a less favourable one.
    """
    known = [outcome for outcome in outcomes if outcome in FAVOURABILITY]
    if not known:
        return INCOMPLETE
    return min(known, key=lambda outcome: FAVOURABILITY[outcome])


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Constraint:
    """One ceiling on the decision, and why it sits where it does."""

    source: str
    outcome: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "outcome": self.outcome, "reason": self.reason}


@dataclass(frozen=True)
class ReleaseDecision:
    outcome: str
    constraints: tuple[Constraint, ...]

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(c.reason for c in self.constraints if c.outcome == self.outcome)

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reasons": list(self.reasons),
            "constraints": [c.as_dict() for c in self.constraints],
            "vocabulary": list(RELEASE_OUTCOMES),
            "note": "The outcome is the least favourable of the constraints above.",
        }


@dataclass(frozen=True)
class PullRequestReview:
    material: bool
    materiality_reasons: tuple[str, ...]
    security_delta: dict[str, Any]
    new_hypotheses: tuple[dict[str, Any], ...]
    verified_findings: tuple[dict[str, Any], ...]
    refuted_candidates: tuple[dict[str, Any], ...]
    coverage_change: dict[str, Any]
    decision: ReleaseDecision
    evidence_basis: str
    suppressed_because: str | None = None
    title: str = "SecHelix PR security review"

    @property
    def nothing_to_say(self) -> bool:
        """True when this pull request does not warrant a comment."""
        return not self.material

    @property
    def comment(self) -> str | None:
        """The Markdown comment body, or None when there is nothing to say."""
        return render_comment(self) if self.material else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "material": self.material,
            "materiality_reasons": [
                {"reason": reason, "explanation": MATERIALITY_REASONS[reason]}
                for reason in self.materiality_reasons
            ],
            "comment": self.comment,
            "comment_suppressed_because": self.suppressed_because,
            "security_delta": self.security_delta,
            "new_hypotheses": [dict(h) for h in self.new_hypotheses],
            "verified_findings": [dict(f) for f in self.verified_findings],
            "refuted_candidates": [dict(f) for f in self.refuted_candidates],
            "coverage_change": self.coverage_change,
            "release_decision": self.decision.as_dict(),
            "evidence_basis": self.evidence_basis,
            "notes": [
                "Every entry in new_hypotheses is a HYPOTHESIS raised by the diff. None is a "
                "finding until it is independently verified.",
                "Suppressing the comment never raises the decision: a silent review is not an "
                "approval.",
                "A report's own release_recommendation is not read; only a supplied gate "
                "decision counts.",
            ],
        }


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


def _annotate_hypotheses(delta: Mapping[str, Any],
                         head_findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Turn questioning deltas into hypotheses, saying what has examined each one."""
    hypotheses = []
    for item in delta.get("deltas", []):
        if item.get("direction") not in QUESTIONING_DIRECTIONS:
            continue
        path = str(item.get("path", ""))
        verified = [f for f in head_findings if _status(f) == VERIFIED and _touches(f, path)]
        refuted = [f for f in head_findings if _status(f) == FALSE_POSITIVE and _touches(f, path)]
        if verified:
            state = ADDRESSED_BY_VERIFIED_FINDING
            cited = [str(f.get("finding_id", "")) for f in verified]
        elif refuted:
            state = ADDRESSED_BY_REFUTATION
            cited = [str(f.get("finding_id", "")) for f in refuted]
        else:
            state = UNADDRESSED
            cited = []
        hypothesis = dict(item)
        hypothesis.update({
            "evidence_state": state,
            "cited_findings": cited,
            "attribution": (
                "path-level: a report finding cites this file, which shows the file was "
                "examined, not that this delta was the thing examined"
                if cited else "nothing in the head report cites this file"
            ),
        })
        hypotheses.append(hypothesis)
    return hypotheses


def _finding_row(finding: Mapping[str, Any], basis: str,
                 new_since_base: bool | None = None) -> dict[str, Any]:
    row = {
        "finding_id": str(finding.get("finding_id", "")),
        "title": str(finding.get("title", "")),
        "status": _status(finding),
        "resolution": str(finding.get("resolution", "OPEN")).upper(),
        # Carried from the report, not assigned here.
        "severity_as_reported": str(finding.get("severity", "UNASSIGNED")).upper(),
        "affected_surface": sorted(_surface_paths(finding)),
        "read_from": basis,
    }
    if new_since_base is not None:
        row["new_since_base"] = new_since_base
    return row


def _coverage(report: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if report is None:
        return None
    coverage = report.get("coverage")
    return coverage if isinstance(coverage, Mapping) else None


def _coverage_change(base: Mapping[str, Any] | None, head: Mapping[str, Any] | None,
                     changed_paths: Sequence[str]) -> dict[str, Any]:
    before, after = _coverage(base), _coverage(head)
    payload: dict[str, Any] = {
        "state": UNKNOWN,
        "before": dict(before) if before else None,
        "after": dict(after) if after else None,
        "delta": {},
    }
    if after is None:
        payload["reason"] = (
            "no report describes the changed tree, so nothing measured coverage for this change"
        )
        payload["uninspected_paths"] = list(changed_paths)
        return payload
    if before is None:
        payload["reason"] = "no earlier coverage was supplied to compare against"
        return payload
    if before.get("catalog_version") != after.get("catalog_version"):
        payload["reason"] = (
            f"the two reports were measured against different catalog versions "
            f"({before.get('catalog_version')} then {after.get('catalog_version')}), so their "
            f"counts are not comparable"
        )
        return payload

    delta: dict[str, int] = {}
    for key in COVERAGE_KEYS:
        left, right = before.get(key), after.get(key)
        if isinstance(left, int) and isinstance(right, int):
            delta[key] = right - left
    payload["delta"] = delta
    if not delta:
        payload["reason"] = "neither report records comparable coverage counts"
        return payload

    worse = (delta.get("UNKNOWN", 0) > 0 or delta.get("BLOCKED", 0) > 0
             or delta.get("integrity_critical_unknown", 0) > 0
             or delta.get("APPLICABLE", 0) < 0)
    better = (delta.get("UNKNOWN", 0) < 0 or delta.get("BLOCKED", 0) < 0
              or delta.get("integrity_critical_unknown", 0) < 0
              or delta.get("APPLICABLE", 0) > 0)
    if worse:
        payload["state"] = DEGRADED
        payload["reason"] = "more hypotheses are unresolved than before"
    elif better:
        payload["state"] = IMPROVED
        payload["reason"] = "fewer hypotheses are unresolved than before"
    else:
        payload["state"] = UNCHANGED
        payload["reason"] = "the coverage counts are identical"
    return payload


def _diff_constraint(hypotheses: Sequence[Mapping[str, Any]], parsed_files: int,
                     supplied: bool) -> Constraint:
    if supplied and parsed_files == 0:
        return Constraint(
            "diff", INCOMPLETE,
            "a diff was supplied but could not be parsed, so no part of this change was classified",
        )
    unaddressed = [h for h in hypotheses if h["evidence_state"] == UNADDRESSED]
    if unaddressed:
        return Constraint(
            "diff", INCOMPLETE,
            f"{len(unaddressed)} NEW_RISK or UNKNOWN delta(s) that nothing has verified or "
            f"refuted; not looking is not a pass",
        )
    if hypotheses:
        return Constraint(
            "diff", PASS,
            "every delta this change raised is cited by a finding in the head report",
        )
    return Constraint("diff", PASS, "the diff raised no NEW_RISK or UNKNOWN delta")


def _evidence_constraint(head: Mapping[str, Any] | None, base: Mapping[str, Any] | None,
                         head_commit: str | None) -> Constraint:
    if head is None and base is None:
        return Constraint("evidence", INCOMPLETE,
                          "no security report was supplied, so nothing has inspected this change")
    if head is None:
        return Constraint(
            "evidence", INCOMPLETE,
            "the only report supplied describes the pre-change tree, which is not this change",
        )
    if head_commit:
        verdict = assess_freshness(head, current_commit=head_commit)
        if verdict.state != FRESH:
            return Constraint("evidence", INCOMPLETE,
                              f"the head report is not bound to this change: {verdict.reason}")
        return Constraint("evidence", PASS,
                          f"the head report is bound to this change ({verdict.reason})")
    return Constraint(
        "evidence", PASS,
        "a report was supplied for the changed tree; no head commit was given, so this rests on "
        "the caller's word rather than on a revision binding",
    )


def _gate_constraint(gate_decision: str | None) -> Constraint:
    if gate_decision is None:
        return Constraint(
            "gate", INCOMPLETE,
            "no release gate decision was supplied; a report's own release_recommendation is "
            "not evidence and is not read",
        )
    outcome = str(gate_decision).upper()
    if outcome not in FAVOURABILITY:
        raise PullRequestReviewError(
            f"gate_decision must be one of {list(RELEASE_OUTCOMES)}, got {gate_decision!r}"
        )
    return Constraint("gate", outcome, f"the release gate returned {outcome}")


def review_pull_request(
    diff_text: str,
    *,
    report: Mapping[str, Any] | None = None,
    prior_report: Mapping[str, Any] | None = None,
    gate_decision: str | None = None,
    prior_decision: str | None = None,
    head_commit: str | None = None,
) -> PullRequestReview:
    """Review one pull request.

    ``report`` describes the changed tree (the head of the pull request);
    ``prior_report`` describes the tree before it. Either may be omitted, and
    omitting them is not a pass — it lowers the decision instead.

    Findings are read from the head report when there is one, and otherwise from
    the prior report, clearly labelled: a report about the base tree is still
    worth showing a reviewer, but it cannot have examined code this diff added,
    so it never marks a delta as examined and never raises the decision.
    """
    if not isinstance(diff_text, str):
        raise PullRequestReviewError("diff_text must be a string")
    head = _report(report, "report")
    base = _report(prior_report, "prior_report")

    delta = review_diff(diff_text)
    head_findings = _findings(head)
    base_findings = _findings(base)
    hypotheses = _annotate_hypotheses(delta, head_findings)

    basis = HEAD_REPORT if head is not None else (BASE_REPORT if base is not None else NO_REPORT)
    source_findings = head_findings if head is not None else base_findings

    base_verified = {str(f.get("finding_id")) for f in base_findings if _status(f) == VERIFIED}
    base_present = {str(f.get("finding_id")) for f in base_findings}
    base_refuted = {str(f.get("finding_id")) for f in base_findings
                    if _status(f) == FALSE_POSITIVE}

    verified_findings = tuple(
        _finding_row(f, basis,
                     new_since_base=(str(f.get("finding_id")) not in base_verified)
                     if base is not None else None)
        for f in source_findings if _status(f) == VERIFIED
    )
    refuted_candidates = tuple(
        _finding_row(f, basis,
                     new_since_base=(str(f.get("finding_id")) not in base_refuted)
                     if base is not None else None)
        for f in source_findings if _status(f) == FALSE_POSITIVE
    )

    coverage_change = _coverage_change(base, head, delta.get("files", []))

    constraints = (
        _diff_constraint(hypotheses, int(delta.get("files_changed", 0)), bool(diff_text.strip())),
        _evidence_constraint(head, base, head_commit),
        _gate_constraint(gate_decision),
    )
    outcome = worst(*(c.outcome for c in constraints))
    decision = ReleaseDecision(outcome, constraints)

    # -- materiality ------------------------------------------------------- #
    reasons: list[str] = []
    if hypotheses:
        reasons.append("NEW_HYPOTHESIS")
    if diff_text.strip() and int(delta.get("files_changed", 0)) == 0:
        reasons.append("UNREADABLE_DIFF")
    if head is not None and base is not None:
        newly_verified = [f for f in head_findings
                          if _status(f) == VERIFIED
                          and str(f.get("finding_id")) not in base_verified]
        if newly_verified:
            reasons.append("NEW_VERIFIED_FINDING")
        newly_refuted = [f for f in head_findings
                         if _status(f) == FALSE_POSITIVE
                         and str(f.get("finding_id")) in base_present
                         and str(f.get("finding_id")) not in base_refuted]
        if newly_refuted:
            reasons.append("CANDIDATE_REFUTED")
    if coverage_change["state"] == DEGRADED:
        reasons.append("COVERAGE_DEGRADED")
    if prior_decision is not None and str(prior_decision).upper() != outcome:
        reasons.append("DECISION_CHANGED")

    material = bool(reasons)
    return PullRequestReview(
        material=material,
        materiality_reasons=tuple(reasons),
        security_delta=delta,
        new_hypotheses=tuple(hypotheses),
        verified_findings=verified_findings,
        refuted_candidates=refuted_candidates,
        coverage_change=coverage_change,
        decision=decision,
        evidence_basis=basis,
        suppressed_because=None if material else NOT_MATERIAL,
    )


# --------------------------------------------------------------------------- #
# Comment rendering
# --------------------------------------------------------------------------- #

#: A comment nobody finishes reading is a comment nobody acts on.
MAX_ROWS = 10


def _rows(items: Sequence[Any], limit: int = MAX_ROWS) -> tuple[list[Any], int]:
    return list(items[:limit]), max(0, len(items) - limit)


def render_comment(review: PullRequestReview) -> str:
    """Render the PR comment body.

    Rendering is separate from deciding whether to post: ``review.comment`` is
    ``None`` for an immaterial review, and this function is what produces the
    body when there is something to say.
    """
    delta = review.security_delta
    counts = delta.get("counts", {})
    lines = [
        f"## {review.title}",
        "",
        f"**Release decision: `{review.decision.outcome}`**",
        "",
    ]
    for constraint in review.decision.constraints:
        lines.append(f"- `{constraint.outcome}` from {constraint.source} — {constraint.reason}")
    lines += [
        "",
        "### Security delta",
        "",
        f"`{delta.get('overall', UNKNOWN)}` across {delta.get('files_changed', 0)} changed "
        f"file(s).",
        "",
        "| direction | count |",
        "| --- | --- |",
    ]
    for direction in (NEW_RISK, RISK_REDUCED, UNCHANGED, UNKNOWN):
        lines.append(f"| `{direction}` | {counts.get(direction, 0)} |")

    lines += ["", f"### New hypotheses ({len(review.new_hypotheses)})", ""]
    if review.new_hypotheses:
        shown, extra = _rows(review.new_hypotheses)
        for hypothesis in shown:
            location = f"`{hypothesis.get('path')}:{hypothesis.get('line')}`"
            lines.append(
                f"- {location} — **{hypothesis.get('kind')}** (`{hypothesis.get('direction')}`, "
                f"`{hypothesis.get('evidence_state')}`) — {hypothesis.get('question')}"
            )
        if extra:
            lines.append(f"- …and {extra} more.")
    else:
        lines.append("- None. The diff raised no NEW_RISK or UNKNOWN delta.")

    lines += ["", f"### Verified findings ({len(review.verified_findings)})", ""]
    if review.verified_findings:
        shown, extra = _rows(review.verified_findings)
        for finding in shown:
            suffix = " *(new since the base report)*" if finding.get("new_since_base") else ""
            lines.append(
                f"- **{finding['finding_id']}** — {finding['title']} "
                f"(severity as reported: `{finding['severity_as_reported']}`, "
                f"resolution `{finding['resolution']}`){suffix}"
            )
        if extra:
            lines.append(f"- …and {extra} more.")
        if review.evidence_basis == BASE_REPORT:
            lines.append(
                "- These were read from the report describing the tree **before** this change. "
                "They have not been re-checked against it."
            )
    else:
        lines.append("- None recorded.")

    lines += ["", f"### Refuted candidates ({len(review.refuted_candidates)})", ""]
    if review.refuted_candidates:
        shown, extra = _rows(review.refuted_candidates)
        for finding in shown:
            lines.append(f"- **{finding['finding_id']}** — {finding['title']}")
        if extra:
            lines.append(f"- …and {extra} more.")
    else:
        lines.append("- None recorded.")

    coverage = review.coverage_change
    lines += [
        "",
        "### Coverage",
        "",
        f"`{coverage['state']}` — {coverage.get('reason', '')}",
    ]
    if coverage.get("delta"):
        movement = ", ".join(
            f"{key} {value:+d}" for key, value in sorted(coverage["delta"].items()) if value
        )
        lines.append("")
        lines.append(f"Movement: {movement or 'none'}.")
    uninspected, extra = _rows(coverage.get("uninspected_paths", []))
    if uninspected:
        lines.append("")
        lines.append("Changed files no report describes:")
        lines += [f"- `{path}`" for path in uninspected]
        if extra:
            lines.append(f"- …and {extra} more.")

    lines += [
        "",
        "### What this comment is not",
        "",
        "- Every hypothesis above is **unverified**. It names something worth checking; it is "
        "not a finding and carries no severity.",
        "- `UNKNOWN` is not a pass. It means the change touched a security surface that could "
        "not be read.",
        "- The decision is the least favourable of the constraints listed above, so it is "
        "never better than the evidence behind it.",
        "",
    ]
    return "\n".join(lines)
