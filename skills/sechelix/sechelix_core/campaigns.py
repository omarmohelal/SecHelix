"""Group verified findings by root cause, so remediation is finite.

"43 findings" is a number that makes a team feel behind and tells them nothing
about what to do. It is also usually wrong about the size of the work: forty-three
findings frequently share four root causes, and fixing four things closes all
forty-three.

A campaign is the unit of remediation: one root cause, the findings it explains,
who owns it, and whether the fix has actually been proven. The count that matters
is not how many findings exist but how many distinct mistakes produced them.

Three rules.

**Only verified findings join a campaign.** Grouping hypotheses by a root cause
invents a cause for something nobody has established happens. Unverified
candidates are listed separately as *unattributed*, so they are visible without
inflating the campaign.

**A campaign is not complete until its regression proof passes.** Patch status and
regression status are tracked separately, because "we changed the code" and "we
demonstrated the change works" are different claims and the gap between them is
where remediation theatre lives.

**Remaining risk is stated, not implied by a percentage.** A campaign that closed
nine of ten findings has one open finding, and saying "90% complete" hides which
one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

VERIFIED = "VERIFIED"

#: Campaign lifecycle. NOT_STARTED and BLOCKED are distinct: one is work not begun,
#: the other is work that cannot begin, and collapsing them hides the dependency.
NOT_STARTED = "NOT_STARTED"
IN_PROGRESS = "IN_PROGRESS"
PATCHED_UNPROVEN = "PATCHED_UNPROVEN"
COMPLETE = "COMPLETE"
BLOCKED = "BLOCKED"

PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Severity ordering, used only to pick a campaign's priority from the findings it
#: already contains. Nothing here raises a severity.
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNASSIGNED": 0}


class CampaignError(ValueError):
    """The campaign cannot be formed."""


@dataclass
class Campaign:
    campaign_id: str
    root_cause: str
    finding_ids: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    owner: str | None = None
    priority: str = "MEDIUM"
    deadline: str | None = None
    patch_status: str = NOT_STARTED
    regression_status: str = "NOT_RUN"
    remaining_finding_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.patch_status == BLOCKED:
            return BLOCKED
        if self.remaining_finding_ids:
            return IN_PROGRESS if self.patch_status != NOT_STARTED else NOT_STARTED
        if self.patch_status != COMPLETE:
            return IN_PROGRESS if self.patch_status == IN_PROGRESS else NOT_STARTED
        # Everything is patched. Whether it is *done* depends on proof, not on
        # having written the patch.
        return COMPLETE if self.regression_status == "PASS" else PATCHED_UNPROVEN

    @property
    def complete(self) -> bool:
        return self.status == COMPLETE

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "root_cause": self.root_cause,
            "status": self.status,
            "priority": self.priority,
            "owner": self.owner,
            "deadline": self.deadline,
            "affected_repositories": sorted(self.repositories),
            "affected_findings": sorted(self.finding_ids),
            "finding_count": len(self.finding_ids),
            "patch_status": self.patch_status,
            "regression_status": self.regression_status,
            # Named, never a percentage: "90% complete" hides which one is open.
            "remaining_findings": sorted(self.remaining_finding_ids),
            "remaining_risk": self._remaining_risk(),
            "notes": list(self.notes),
        }

    def _remaining_risk(self) -> str:
        if self.status == COMPLETE:
            return "None recorded: every finding is resolved and regression proof passes."
        if self.status == PATCHED_UNPROVEN:
            return (
                "The patch is applied but no regression proof passes. Until it does, the "
                "claim that this root cause is fixed is unverified."
            )
        if self.status == BLOCKED:
            return "Blocked; the root cause is unaddressed and every listed finding stands."
        open_count = len(self.remaining_finding_ids)
        return (
            f"{open_count} of {len(self.finding_ids)} finding(s) remain unresolved: "
            f"{', '.join(sorted(self.remaining_finding_ids))}"
        )


def _root_cause_of(finding: Mapping[str, Any]) -> str | None:
    remediation = finding.get("remediation") or {}
    stated = str(remediation.get("root_cause_fix", "")).strip()
    return stated or None


def _repository_of(finding: Mapping[str, Any]) -> str | None:
    repo = finding.get("repository")
    return str(repo) if repo else None


def build_campaigns(
    findings: Sequence[Mapping[str, Any]],
    *,
    owners: Mapping[str, str] | None = None,
    deadlines: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Group verified findings by their recorded root cause.

    Findings are grouped on the root-cause text the report already carries. This
    module does not infer a cause: inventing one would be a claim nobody made,
    and a wrong grouping makes remediation look smaller than it is.
    """
    owners = owners or {}
    deadlines = deadlines or {}

    observations = len(findings)
    verified = [f for f in findings if isinstance(f, Mapping)
                and str(f.get("status", "")).upper() == VERIFIED]

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    unattributed: list[str] = []

    for finding in verified:
        cause = _root_cause_of(finding)
        if cause is None:
            # Verified but with no recorded root cause. It is real work that
            # belongs to no campaign yet, and hiding it would understate the job.
            unattributed.append(str(finding.get("finding_id", "")))
            continue
        grouped.setdefault(cause, []).append(finding)

    campaigns: list[Campaign] = []
    for index, (cause, members) in enumerate(sorted(grouped.items()), start=1):
        finding_ids = [str(f.get("finding_id", "")) for f in members]
        repositories = sorted({r for r in (_repository_of(f) for f in members) if r})

        remaining = [
            str(f.get("finding_id", "")) for f in members
            if str(f.get("resolution", "OPEN")).upper() not in {"FIXED", "FALSE_POSITIVE",
                                                                "DUPLICATE_ROOT_CAUSE"}
        ]

        regressions = [str((f.get("regression") or {}).get("status", "NOT_RUN")).upper()
                       for f in members]
        if regressions and all(r == "PASS" for r in regressions):
            regression_status = "PASS"
        elif any(r == "FAIL" for r in regressions):
            regression_status = "FAIL"
        else:
            regression_status = "NOT_RUN"

        if remaining:
            patch_status = IN_PROGRESS if len(remaining) < len(members) else NOT_STARTED
        else:
            patch_status = COMPLETE

        severity = max((_RANK.get(str(f.get("severity", "")).upper(), 0) for f in members),
                       default=0)
        priority = next((p for p in PRIORITIES if _RANK[p] == severity), "LOW")

        campaign_id = f"CAMPAIGN-{index:03d}"
        campaigns.append(Campaign(
            campaign_id=campaign_id,
            root_cause=cause,
            finding_ids=finding_ids,
            repositories=repositories,
            owner=owners.get(campaign_id) or owners.get(cause),
            priority=priority,
            deadline=deadlines.get(campaign_id) or deadlines.get(cause),
            patch_status=patch_status,
            regression_status=regression_status,
            remaining_finding_ids=remaining,
        ))

    for campaign in campaigns:
        if campaign.owner is None:
            campaign.notes.append(
                "No owner. Work nobody owns is work nobody does; assign one before "
                "treating this campaign as planned."
            )

    return {
        "schema_version": "1.0",
        # The headline this module exists to produce.
        "summary": {
            "observations": observations,
            "verified_findings": len(verified),
            "root_causes": len(campaigns),
            "campaigns": len(campaigns),
            "unattributed_verified_findings": len(unattributed),
        },
        "campaigns": [c.as_dict() for c in campaigns],
        "unattributed_findings": sorted(unattributed),
        "notes": [
            "Only VERIFIED findings join a campaign; grouping hypotheses by root cause "
            "invents a cause for something nobody established happens.",
            "A campaign is COMPLETE only when every finding is resolved and regression "
            "proof passes. Patched-but-unproven is reported as PATCHED_UNPROVEN.",
            "Root causes are read from each finding's recorded remediation, never inferred.",
        ],
    }


def render_markdown(result: Mapping[str, Any]) -> str:
    """Render the headline a team can act on."""
    summary = result["summary"]
    lines = [
        "# Remediation campaigns",
        "",
        f"{summary['observations']} observations "
        f"→ {summary['verified_findings']} verified findings "
        f"→ {summary['root_causes']} root causes "
        f"→ {summary['campaigns']} campaigns",
        "",
    ]
    if not result["campaigns"]:
        lines.append("_No verified finding carries a recorded root cause yet._")
        return "\n".join(lines) + "\n"

    lines += ["| Campaign | Priority | Status | Findings | Owner | Root cause |",
              "|---|---|---|---:|---|---|"]
    for campaign in result["campaigns"]:
        lines.append(
            f"| {campaign['campaign_id']} | {campaign['priority']} | {campaign['status']} | "
            f"{campaign['finding_count']} | {campaign['owner'] or '**unassigned**'} | "
            f"{campaign['root_cause'][:70]} |"
        )

    lines += ["", "## Remaining risk", ""]
    for campaign in result["campaigns"]:
        lines.append(f"- **{campaign['campaign_id']}** — {campaign['remaining_risk']}")

    if result["unattributed_findings"]:
        lines += [
            "", "## Verified findings with no recorded root cause", "",
            "These are real work that belongs to no campaign yet.", "",
        ]
        lines += [f"- {fid}" for fid in result["unattributed_findings"]]
    return "\n".join(lines) + "\n"
