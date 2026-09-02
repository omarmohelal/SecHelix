"""A controlled remediation loop: propose, test, review the fix, verify, hand over.

Patch mode produces a proposal. This runs the loop that decides whether the
proposal is any good, and it exists because the dangerous moment in security work
is not finding the bug — it is the fix.

A patch written to close one hole routinely opens another. An authorization check
added to one route and not its sibling. Input validation that rejects the exploit
and also rejects legitimate input, turning a vulnerability into an outage. A
"safe" rewrite that drops the tenant predicate while removing the injection.
Nobody reviews the fix as adversarially as they reviewed the bug, because by then
everyone wants to be finished.

So every candidate patch is put through the same scrutiny the finding was:

    verified finding
      → scratch worktree          (never the working tree, never main)
      → candidate patch
      → existing tests            (did we break something)
      → vulnerability regression  (did we actually close it)
      → differential review       (did we open something new)
      → independent verification  (does a second path agree)
      → PR-ready, or refused with the reason

Three rules.

**The loop never touches main and never touches the caller's working tree.** All
work happens in a scratch location supplied by the caller. This module computes
and reports; applying anything is a separate, human decision.

**A stage that did not run is not a stage that passed.** Every gate defaults to
`NOT_RUN`, and `NOT_RUN` blocks readiness exactly as `FAIL` does. The difference
is recorded, because "we did not check" and "we checked and it was fine" are
different sentences.

**The remediation-risk check can veto its own patch.** A fix that introduces a
new authorization, validation or availability defect is not a fix, and this is
the stage most likely to be skipped under deadline pressure — so it is not
optional here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

VERIFIED = "VERIFIED"

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"

#: Ordered. A later stage is meaningless if an earlier one failed, and the report
#: says which stage stopped the loop rather than only that it stopped.
STAGES = (
    "existing_tests",
    "vulnerability_regression",
    "differential_review",
    "remediation_risk",
    "independent_verification",
)

#: Defect classes a fix commonly introduces. Named so the check has to answer for
#: each one rather than returning a vague "looks fine".
RISK_CLASSES = ("authorization", "validation", "availability")

READY = "READY_FOR_REVIEW"
BLOCKED = "BLOCKED"
INCOMPLETE = "INCOMPLETE"
REFUSED = "REFUSED"


class RemediationError(ValueError):
    """The remediation loop cannot be run for this finding."""


@dataclass
class StageResult:
    name: str
    status: str = NOT_RUN
    detail: str = ""
    evidence_ids: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status == PASS

    def as_dict(self) -> dict[str, Any]:
        return {
            "stage": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class RemediationRisk:
    """Did the patch introduce a new defect while closing the old one?"""

    introduced: dict[str, str] = field(default_factory=dict)
    assessed: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.introduced and set(self.assessed) >= set(RISK_CLASSES)

    def as_dict(self) -> dict[str, Any]:
        unassessed = [c for c in RISK_CLASSES if c not in self.assessed]
        return {
            "introduced": dict(sorted(self.introduced.items())),
            "assessed": sorted(self.assessed),
            # An unassessed class is not a clean one, and the record says which.
            "unassessed": unassessed,
            "clean": self.clean,
        }


@dataclass
class RemediationResult:
    finding_id: str
    outcome: str = INCOMPLETE
    workspace: str = ""
    stages: list[StageResult] = field(default_factory=list)
    risk: RemediationRisk = field(default_factory=RemediationRisk)
    blocked_at: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.outcome == READY

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "workspace": self.workspace,
            "blocked_at": self.blocked_at,
            "stages": [s.as_dict() for s in self.stages],
            "remediation_risk": self.risk.as_dict(),
            # Load-bearing: this module produces a proposal, never a change.
            "applied": False,
            "application_method": "MANUAL_REVIEW_REQUIRED",
            "notes": list(self.notes),
        }


def assess_remediation_risk(
    diff_review_result: Mapping[str, Any],
    *,
    assessed: Sequence[str] = RISK_CLASSES,
) -> RemediationRisk:
    """Read a differential review of the patch itself for newly introduced risk.

    The patch is reviewed the same way any other change is. A fix that adds a
    route, removes a guard, or widens a query is a change like any other, and the
    fact that it was written to close a finding earns it no exemption.
    """
    risk = RemediationRisk(assessed=tuple(assessed))

    deltas = diff_review_result.get("deltas") or []
    for delta in deltas:
        if not isinstance(delta, Mapping):
            continue
        if str(delta.get("direction", "")).upper() != "NEW_RISK":
            continue
        kind = str(delta.get("kind", ""))
        path = str(delta.get("path", ""))
        snippet = str(delta.get("snippet", ""))[:120]

        if kind in {"authorization_guard", "role_definition", "rls_policy", "middleware"}:
            risk.introduced.setdefault(
                "authorization", f"{kind} changed in {path}: {snippet}")
        elif kind in {"db_query", "file_upload", "outbound_fetch", "storage_access"}:
            risk.introduced.setdefault(
                "validation", f"{kind} introduced in {path}: {snippet}")
        elif kind in {"payment_state", "webhook"}:
            risk.introduced.setdefault(
                "availability", f"{kind} changed in {path}: {snippet}")
    return risk


def run_loop(
    finding: Mapping[str, Any],
    *,
    workspace: str,
    existing_tests: StageResult | None = None,
    vulnerability_regression: StageResult | None = None,
    patch_diff_review: Mapping[str, Any] | None = None,
    independent_verification: StageResult | None = None,
) -> RemediationResult:
    """Run the loop over stage results the caller has already executed.

    This module does not execute tests or shell out. The caller runs each stage in
    its own sandbox and reports the outcome; the loop decides what the combination
    means. Keeping execution out of here is what makes "never touches main"
    a property of the design rather than a promise in a docstring.
    """
    finding_id = str(finding.get("finding_id", "")).strip()
    if not finding_id:
        raise RemediationError("finding_id is required")

    status = str(finding.get("status", "")).upper()
    if status != VERIFIED:
        raise RemediationError(
            f"{finding_id} is {status or 'UNKNOWN'}, not VERIFIED; remediating an unconfirmed "
            "candidate changes working code to close something nobody established happens"
        )

    if not workspace or workspace.strip() in {"", ".", "/"}:
        raise RemediationError(
            "a scratch workspace is required; the loop must never run in the caller's "
            "working tree"
        )

    result = RemediationResult(finding_id=finding_id, workspace=workspace)

    supplied = {
        "existing_tests": existing_tests,
        "vulnerability_regression": vulnerability_regression,
        "independent_verification": independent_verification,
    }

    risk = (assess_remediation_risk(patch_diff_review)
            if patch_diff_review is not None else RemediationRisk(assessed=()))
    result.risk = risk

    for name in STAGES:
        if name == "differential_review":
            stage = StageResult(
                name,
                PASS if patch_diff_review is not None else NOT_RUN,
                "patch reviewed as a change in its own right"
                if patch_diff_review is not None else "no review of the patch was supplied",
            )
        elif name == "remediation_risk":
            if patch_diff_review is None:
                stage = StageResult(name, NOT_RUN, "no patch review to assess risk from")
            elif risk.clean:
                stage = StageResult(name, PASS, "no new authorization, validation or "
                                                "availability defect detected")
            else:
                detail = "; ".join(f"{k}: {v}" for k, v in sorted(risk.introduced.items())) \
                    or f"unassessed: {', '.join(risk.as_dict()['unassessed'])}"
                stage = StageResult(name, FAIL, detail)
        else:
            stage = supplied.get(name) or StageResult(name, NOT_RUN, "not supplied by the caller")
        result.stages.append(stage)

    failed = next((s for s in result.stages if s.status == FAIL), None)
    if failed is not None:
        result.outcome = BLOCKED
        result.blocked_at = failed.name
        result.notes.append(f"blocked at {failed.name}: {failed.detail}")
        return result

    not_run = [s.name for s in result.stages if s.status == NOT_RUN]
    if not_run:
        result.outcome = INCOMPLETE
        result.blocked_at = not_run[0]
        result.notes.append(
            f"{len(not_run)} stage(s) never ran: {', '.join(not_run)}. A stage that did not "
            "run is not a stage that passed."
        )
        return result

    result.outcome = READY
    result.notes.append(
        "Every stage passed. This is a patch ready for human review, not an applied fix."
    )
    return result
