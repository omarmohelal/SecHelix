"""Patch mode: turn a verified finding into a reviewable proposal.

A security report that ends at "you should fix this" transfers the whole cost of
remediation to the reader, who then has to re-derive the reasoning the review
already did. Patch mode closes that gap without closing the review loop: it emits
a patch and a rationale as *artifacts*, for a human to read, apply, and test.

Four rules make this safe enough to ship.

**Only verified findings get patches.** A patch for an unverified finding is a
change to working code justified by a guess. Worse, a patch is persuasive — a
reviewer who sees a concrete diff is far more likely to accept the premise than
one who sees a paragraph. That persuasion has to be earned by verification.

**Nothing is applied.** The output is a `.patch` file and a `.md` rationale in an
output directory. Patch mode never writes to the audited tree, never runs `git
apply`, and never commits. The person who owns the code decides.

**A patch is not a fix until a test says so.** Every proposal carries a
regression assertion and a status. `NOT_RUN` is the honest default and is what
gets emitted; nothing here may report `PASS` on a test it did not run.

**The rationale states what the patch does not cover.** A minimal patch usually
addresses one instance of a root cause. Saying so is the difference between a fix
and a false sense of completion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

VERIFIED = "VERIFIED"

#: A finding must reach this bar before a patch is proposed for it.
PATCHABLE_STATUSES = frozenset({VERIFIED})

#: Statuses that are explicitly refused, with the reason surfaced to the caller.
REFUSAL_REASONS = {
    "HYPOTHESIS": "the finding is unverified; a patch would make a guess look like a conclusion",
    "LIKELY_BUT_UNPROVEN": "the finding was not proven; patching it would overstate what is known",
    "FALSE_POSITIVE": "the finding was refuted; there is nothing to fix",
    "DUPLICATE_ROOT_CAUSE": "patch the primary finding for this root cause instead",
    "BLOCKED_BY_ENVIRONMENT": "verification never completed, so the failure mode is unconfirmed",
}


class PatchModeError(ValueError):
    """The finding cannot be turned into a patch proposal."""


@dataclass(frozen=True)
class PatchProposal:
    finding_id: str
    title: str
    severity: str
    patch_path: str
    rationale_path: str
    diff: str
    rationale: str
    regression_status: str
    scope_note: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "patch_path": self.patch_path,
            "rationale_path": self.rationale_path,
            "regression_status": self.regression_status,
            "scope_note": self.scope_note,
            "applied": False,
            "application_method": "MANUAL_REVIEW_REQUIRED",
        }


@dataclass(frozen=True)
class Refusal:
    finding_id: str
    status: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "refused_because": self.reason,
        }


@dataclass
class PatchSet:
    proposals: list[PatchProposal] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "proposals": [p.as_dict() for p in self.proposals],
            "refusals": [r.as_dict() for r in self.refusals],
            "proposed_count": len(self.proposals),
            "refused_count": len(self.refusals),
            "notes": [
                "No patch in this set has been applied to any working tree.",
                "A patch is a proposal for review, not a fix; the regression status says whether "
                "anything has actually been demonstrated.",
                "Patches address the cited instance of a root cause and may not cover every "
                "occurrence; each rationale states its own scope.",
            ],
        }


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")


def _safe_stem(finding_id: str) -> str:
    """Reject anything that could escape the output directory.

    Finding ids reach this from a report, and a report can come from an untrusted
    repository. A finding_id of "../../.ssh/authorized_keys" must never become a
    write path.
    """
    if not _SAFE_ID.match(finding_id):
        raise PatchModeError(f"unsafe finding_id for a filename: {finding_id!r}")
    stem = PurePosixPath(finding_id).name
    if stem in {"", ".", ".."} or stem != finding_id:
        raise PatchModeError(f"unsafe finding_id for a filename: {finding_id!r}")
    return stem


def _surfaces(finding: Mapping[str, Any]) -> list[str]:
    surface = finding.get("affected_surface")
    if isinstance(surface, list):
        return [str(item) for item in surface]
    return [str(surface)] if surface else []


def _chain_statements(finding: Mapping[str, Any]) -> list[tuple[str, str]]:
    chain = finding.get("evidence_chain")
    if not isinstance(chain, Mapping):
        return []
    rows = []
    for link, entry in chain.items():
        if isinstance(entry, Mapping):
            statement = str(entry.get("statement", "")).strip()
            if statement:
                rows.append((str(link), statement))
    return rows


def build_rationale(finding: Mapping[str, Any], *, diff: str) -> tuple[str, str]:
    """Render the human-facing rationale. Returns (markdown, scope_note)."""
    finding_id = str(finding.get("finding_id", ""))
    remediation = finding.get("remediation") or {}
    regression = finding.get("regression") or {}
    root_cause = str(remediation.get("root_cause_fix", "")).strip()
    surfaces = _surfaces(finding)

    scope_note = (
        f"This patch addresses the cited surface only "
        f"({', '.join(surfaces) if surfaces else 'surface not recorded'}). "
        "If the same root cause appears elsewhere, those occurrences are not covered."
    )

    lines = [
        f"# {finding_id} — {finding.get('title', 'untitled finding')}",
        "",
        f"**Severity:** {finding.get('severity', 'UNASSIGNED')} · "
        f"**Status:** {finding.get('status', 'UNKNOWN')} · "
        f"**Confidence:** {finding.get('confidence', 'NOT_ASSESSED')}",
        "",
        "> This is a **proposal**. It has not been applied, and applying it is a decision for",
        "> whoever owns this code.",
        "",
        "## Why this is a real finding",
        "",
    ]

    chain = _chain_statements(finding)
    if chain:
        for link, statement in chain:
            lines.append(f"- **{link}** — {statement}")
    else:
        lines.append("- The report records no evidence chain for this finding.")

    verification = finding.get("verification") or {}
    lines += [
        "",
        "## How it was verified",
        "",
        f"- Outcome: `{verification.get('outcome', 'NOT_RUN')}`",
        f"- Independent verifier: {'yes' if verification.get('independent') else 'no'}",
    ]
    refutation = str(verification.get("refutation_attempt", "")).strip()
    if refutation:
        lines.append(f"- Refutation attempted: {refutation}")

    lines += [
        "",
        "## What the patch changes",
        "",
        root_cause or "_The report records no root-cause fix; the diff below is the whole proposal._",
        "",
        "## What it does not cover",
        "",
        scope_note,
        "",
        "## Before you accept this",
        "",
        f"- Regression status: **{regression.get('status', 'NOT_RUN')}**",
    ]
    command = str(regression.get("command", "")).strip()
    assertion = str(regression.get("assertion", "")).strip()
    if command:
        lines.append(f"- Run: `{command}`")
    if assertion:
        lines.append(f"- It must assert: {assertion}")
    lines += [
        "- A regression status of `NOT_RUN` means nothing has been demonstrated yet. Treat the",
        "  patch as unproven until the assertion above actually fails on the old code and passes",
        "  on the new.",
        "",
        "## Patch",
        "",
        "```diff",
        diff.rstrip("\n") or "# no diff was supplied with this finding",
        "```",
        "",
    ]
    return "\n".join(lines), scope_note


def propose(
    findings: Sequence[Mapping[str, Any]],
    *,
    diffs: Mapping[str, str] | None = None,
    output_dir: str = "work/patches",
) -> PatchSet:
    """Build patch proposals for verified findings and refuse the rest.

    ``diffs`` maps finding_id to a unified diff. Findings without one still get a
    rationale, with the missing diff stated rather than fabricated.
    """
    diffs = diffs or {}
    result = PatchSet()
    base = output_dir.rstrip("/")

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_id = str(finding.get("finding_id", "")).strip()
        if not finding_id:
            continue

        status = str(finding.get("status", "")).upper()
        if status not in PATCHABLE_STATUSES:
            reason = REFUSAL_REASONS.get(
                status, f"status {status or 'UNKNOWN'} is not patchable"
            )
            result.refusals.append(Refusal(finding_id, status or "UNKNOWN", reason))
            continue

        stem = _safe_stem(finding_id)
        diff = diffs.get(finding_id, "")
        rationale, scope_note = build_rationale(finding, diff=diff)
        regression = finding.get("regression") or {}

        result.proposals.append(PatchProposal(
            finding_id=finding_id,
            title=str(finding.get("title", "")),
            severity=str(finding.get("severity", "UNASSIGNED")),
            patch_path=f"{base}/{stem}.patch",
            rationale_path=f"{base}/{stem}.md",
            diff=diff,
            rationale=rationale,
            # Never inherit a PASS the report did not record.
            regression_status=str(regression.get("status", "NOT_RUN")).upper() or "NOT_RUN",
            scope_note=scope_note,
        ))

    return result


def write_patch_set(patch_set: PatchSet, output_dir: str, *, writer=None) -> list[str]:
    """Write the proposals out. ``writer`` is injected so tests never touch disk.

    Only the output directory is written. The audited tree is never modified, and
    nothing here shells out to ``git apply``.
    """
    import pathlib

    written: list[str] = []
    if writer is None:
        root = pathlib.Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)

        def writer(path: str, content: str) -> None:  # noqa: E306
            pathlib.Path(path).write_text(content, encoding="utf-8")

    for proposal in patch_set.proposals:
        if proposal.diff:
            writer(proposal.patch_path, proposal.diff)
            written.append(proposal.patch_path)
        writer(proposal.rationale_path, proposal.rationale)
        written.append(proposal.rationale_path)
    return written
