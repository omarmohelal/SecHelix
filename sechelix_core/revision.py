"""Revision binding for reports.

A security report describes one tree. Reapplying it to a different tree is how a
"clean" result gets attached to code that was never inspected — and it happens
quietly, because a report with a date on it looks current.

This module answers one question: **is this report still about this code?**

Staleness is deliberately conservative. Any doubt resolves to stale, and a report
produced against a dirty working tree is stale immediately, because the commit it
names does not describe what was actually read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

FRESH = "FRESH"
STALE = "STALE"
UNKNOWN_FRESHNESS = "UNKNOWN"

#: Paths whose change invalidates a report even when nothing else moved, because
#: they define the security posture rather than merely using it.
POSTURE_PATHS = (
    "next.config",
    "middleware",
    "security",
    "auth",
    "policy",
    "policies",
    ".github/workflows",
    "requirements",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "go.mod",
    "Cargo.toml",
    "pyproject.toml",
)


class RevisionError(ValueError):
    """The report cannot be bound to a revision."""


@dataclass(frozen=True)
class FreshnessVerdict:
    state: str
    reason: str
    report_commit: str | None = None
    current_commit: str | None = None
    changed_paths: tuple[str, ...] = ()
    posture_changed: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        """Only a FRESH report may be presented as describing the current tree."""
        return self.state == FRESH

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "report_commit": self.report_commit,
            "current_commit": self.current_commit,
            "changed_paths": list(self.changed_paths),
            "posture_changed": list(self.posture_changed),
        }


def _short(commit: str | None) -> str | None:
    return commit[:12] if commit else None


def _is_posture_path(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    return any(marker in lowered for marker in POSTURE_PATHS)


def assess_freshness(
    report: Mapping[str, Any],
    *,
    current_commit: str | None = None,
    changed_paths: Sequence[str] = (),
    current_working_tree: str = "CLEAN",
) -> FreshnessVerdict:
    """Decide whether a report still describes the code in front of you.

    ``changed_paths`` is what moved between the report's commit and the current
    one. Supplying it lets the verdict name *what* invalidated the report instead
    of only saying that something did.
    """
    revision = report.get("target_revision")
    if not isinstance(revision, Mapping):
        return FreshnessVerdict(
            UNKNOWN_FRESHNESS,
            "the report does not record the revision it inspected, so it cannot be "
            "shown to describe any particular tree",
        )

    report_commit = str(revision.get("commit", "")).strip() or None

    # A dirty tree means the named commit is not what was read.
    if str(revision.get("working_tree", "")).upper() == "DIRTY":
        dirty = tuple(str(p) for p in revision.get("dirty_paths", []))
        return FreshnessVerdict(
            STALE,
            "the report was produced against a dirty working tree, so its commit does "
            "not identify the code that was inspected",
            report_commit=_short(report_commit),
            current_commit=_short(current_commit),
            changed_paths=dirty,
        )

    if current_commit is None:
        return FreshnessVerdict(
            UNKNOWN_FRESHNESS,
            "no current revision was supplied, so freshness cannot be established",
            report_commit=_short(report_commit),
        )

    if str(current_working_tree).upper() == "DIRTY":
        return FreshnessVerdict(
            STALE,
            "the current working tree has uncommitted changes that no report has inspected",
            report_commit=_short(report_commit),
            current_commit=_short(current_commit),
        )

    if not report_commit:
        return FreshnessVerdict(
            UNKNOWN_FRESHNESS,
            "the report records no commit",
            current_commit=_short(current_commit),
        )

    # Compare on the shorter of the two, so a short SHA still matches a full one.
    width = min(len(report_commit), len(str(current_commit)))
    if report_commit[:width].lower() != str(current_commit)[:width].lower():
        posture = tuple(p for p in changed_paths if _is_posture_path(p))
        reason = (
            f"the report describes {_short(report_commit)} but the tree is at "
            f"{_short(current_commit)}"
        )
        if posture:
            reason += f"; {len(posture)} security-posture path(s) changed"
        return FreshnessVerdict(
            STALE, reason,
            report_commit=_short(report_commit),
            current_commit=_short(current_commit),
            changed_paths=tuple(str(p) for p in changed_paths),
            posture_changed=posture,
        )

    return FreshnessVerdict(
        FRESH,
        f"the report describes the current revision {_short(report_commit)}",
        report_commit=_short(report_commit),
        current_commit=_short(current_commit),
    )


def bind_report(
    report: dict[str, Any],
    *,
    repository: str,
    commit: str,
    branch: str | None = None,
    working_tree: str = "CLEAN",
    dirty_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Attach a target revision to a report so it can never float free of its tree."""
    if not commit or not all(c in "0123456789abcdef" for c in commit.lower()):
        raise RevisionError(f"commit must be a hex SHA, got {commit!r}")
    if working_tree.upper() not in {"CLEAN", "DIRTY"}:
        raise RevisionError("working_tree must be CLEAN or DIRTY")

    revision: dict[str, Any] = {
        "repository": repository,
        "commit": commit.lower(),
        "working_tree": working_tree.upper(),
    }
    if branch:
        revision["branch"] = branch
    if dirty_paths:
        revision["dirty_paths"] = sorted({str(p) for p in dirty_paths})
    report["target_revision"] = revision
    return report
