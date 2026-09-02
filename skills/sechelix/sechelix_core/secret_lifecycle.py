"""Secret lifecycle: what has to be true before an exposed credential is fixed.

Finding the secret is the cheap part and the least useful part. Every scanner
does it, and the output of every scanner is the same: a list of places a string
that looks like a credential appears. That list is not a remediation state. It is
the first row of one.

The state that matters runs:

``detected -> located -> revoked -> rotated -> artifacts/history/logs cleaned -> retested``

This module models that whole run, because the failures that actually leak
credentials happen after detection, and every one of them is a conflation that a
list of hits cannot express.

Four rules.

**A secret's value never enters this module's memory or its output.** A sighting
is reduced at the door to a truncated SHA-256 fingerprint, so two sightings of the
same credential can be correlated without anything ever holding the credential.
``SecretIdentity`` has no field that could carry the value; the value is a local
in one classmethod and is gone when it returns. Everything else — locators, notes,
methods — is passed through the redaction in ``proof_bundle`` on the way out,
because the operator who pastes a secret into a locator field is a real person who
exists.

**Deleting a secret from the working tree does not remediate git history.** This
is the single most common real-world failure in this whole area, and it is a
conflation, not an oversight: the fix for the source surface gets recorded as the
fix for every surface. So the two are not merely tracked separately — the cleanup
action ``REMOVED_FROM_SOURCE`` is not in the accepted set for the ``GIT_HISTORY``
surface, and attaching it there raises. There is no argument to pass that makes it
work, which is the only way this stops happening.

**Rotation without revocation is not remediation.** Issuing a new credential does
nothing to the old one. The old one is still valid, still in whatever forks and
caches and log indexes hold it, and still accepted by the provider. They are
separate steps with separate evidence, and ``REMEDIATED`` is refused until
revocation is *confirmed* — a claim is not a confirmation.

**``UNKNOWN`` is a state, and it never renders as remediated.** A surface nobody
searched is unknown, not clean. A record where nothing was searched and nothing
was done is ``UNKNOWN``, and the renderer for that state does not contain the word
``REMEDIATED`` in any form, because a reader skimming for it will find it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .proof_bundle import RedactionLog, redact

SCHEMA_VERSION = "1.0"

#: Overall lifecycle states. UNKNOWN is first because it is the default and the
#: honest one: a record says nothing until someone looks.
UNKNOWN = "UNKNOWN"
EXPOSED = "EXPOSED"
PARTIALLY_REMEDIATED = "PARTIALLY_REMEDIATED"
REMEDIATED = "REMEDIATED"

STATES = (UNKNOWN, EXPOSED, PARTIALLY_REMEDIATED, REMEDIATED)

#: Step statuses. CLAIMED exists so "we revoked it" can be recorded as what it is
#: — an assertion with no evidence — instead of being rounded up to CONFIRMED or
#: dropped on the floor.
CONFIRMED = "CONFIRMED"
CLAIMED = "CLAIMED"
NOT_DONE = "NOT_DONE"

STEP_STATUSES = (CONFIRMED, CLAIMED, NOT_DONE, UNKNOWN)

#: Where a leaked credential actually lives. A scanner that reads only the working
#: tree reports one of these seven and implies the other six are clean.
SURFACES = (
    "SOURCE",
    "GIT_HISTORY",
    "BUILD_ARTIFACT",
    "FRONTEND_BUNDLE",
    "LOGS",
    "CI_CONFIG",
    "CONTAINER_IMAGE",
)

#: Per-surface exposure status.
NOT_SEARCHED = "NOT_SEARCHED"
SEARCHED_CLEAN = "SEARCHED_CLEAN"
CLEANED = "CLEANED"
NOT_APPLICABLE = "NOT_APPLICABLE"

SURFACE_STATUSES = (NOT_SEARCHED, EXPOSED, SEARCHED_CLEAN, CLEANED, NOT_APPLICABLE)

#: The cleanup action that clears each surface, and *only* that surface.
#:
#: The sets are disjoint on purpose. ``REMOVED_FROM_SOURCE`` appears once, under
#: ``SOURCE``, so a caller cannot record the working-tree deletion as the fix for
#: git history, a published bundle, a log index, or a container layer. Every one
#: of those is a different physical copy that a text editor never touched.
ACCEPTED_CLEANUP: dict[str, frozenset[str]] = {
    "SOURCE": frozenset({"REMOVED_FROM_SOURCE"}),
    "GIT_HISTORY": frozenset({"HISTORY_REWRITTEN"}),
    "BUILD_ARTIFACT": frozenset({"ARTIFACTS_REBUILT_AND_OLD_WITHDRAWN"}),
    "FRONTEND_BUNDLE": frozenset({"BUNDLE_REBUILT_AND_REDEPLOYED"}),
    "LOGS": frozenset({"LOGS_PURGED"}),
    "CI_CONFIG": frozenset({"CI_CONFIG_UPDATED"}),
    "CONTAINER_IMAGE": frozenset({"IMAGES_REBUILT_AND_OLD_TAGS_WITHDRAWN"}),
}

CLEANUP_ACTIONS = tuple(sorted({action for actions in ACCEPTED_CLEANUP.values() for action in actions}))

#: What each cleanup still does not reach. Recorded on the surface so a reader
#: never mistakes "cleaned" for "recalled". Copies that have already left are the
#: reason revocation is the only step with real reach.
RESIDUAL_NOTES: dict[str, str] = {
    "SOURCE": (
        "Removing the line from the working tree touches no other surface. Git history, "
        "build artifacts, deployed bundles, logs and images each keep their own copy."
    ),
    "GIT_HISTORY": (
        "A rewrite does not reach existing clones, forks, pull-request refs, or the "
        "provider-side copies of commits that a rewrite leaves dangling. Anyone who "
        "fetched before the rewrite still has the credential."
    ),
    "BUILD_ARTIFACT": (
        "Artifacts that were already downloaded cannot be withdrawn. Withdrawal removes "
        "the source of future copies, not the copies."
    ),
    "FRONTEND_BUNDLE": (
        "A shipped bundle is on other people's machines. CDN edges, browser caches, "
        "archived deploys and preview environments each hold their own copy."
    ),
    "LOGS": (
        "Log shippers, backups, SIEM indexes and downstream analytics each hold a copy "
        "that purging the origin does not reach."
    ),
    "CI_CONFIG": (
        "CI configuration is normally tracked in git and echoed into build logs. Editing "
        "the file clears neither; record GIT_HISTORY and LOGS separately."
    ),
    "CONTAINER_IMAGE": (
        "Deleting a tag does not delete the layer while any other tag, cache or pulled "
        "copy still references it."
    ),
}

_FINGERPRINT_DOMAIN = b"sechelix.secret-lifecycle.v1:"
DEFAULT_FINGERPRINT_BITS = 64


class SecretLifecycleError(ValueError):
    """The lifecycle record would assert something that is not true."""


def fingerprint(value: str, *, bits: int = DEFAULT_FINGERPRINT_BITS) -> str:
    """Reduce a secret to a correlatable, non-reversing tag.

    This exists so the same credential seen in source and in a build log can be
    recognised as one credential without either sighting storing it.

    It is not a confidentiality control for a *weak* secret. A truncated hash of
    ``hunter2`` is guessable by anyone who thinks to guess it; the fingerprint
    protects a high-entropy token and correlates a low-entropy one. The domain
    prefix stops a published fingerprint from being looked up in a general-purpose
    SHA-256 table, and that is the whole of its guarantee.
    """
    if bits % 4 or not 32 <= bits <= 256:
        raise SecretLifecycleError("fingerprint bits must be a multiple of 4 between 32 and 256")
    digest = hashlib.sha256(_FINGERPRINT_DOMAIN + value.encode("utf-8")).hexdigest()
    return digest[: bits // 4]


@dataclass(frozen=True)
class SecretIdentity:
    """A secret, named by fingerprint.

    There is deliberately no field here that could hold the value. Construction
    goes through :meth:`from_value`, where the value is a parameter and a local
    and nothing else — so "the record accidentally kept the credential" is not a
    bug that can be introduced later without adding a field on purpose.
    """

    fingerprint: str
    kind: str
    detector: str
    truncated_bits: int = DEFAULT_FINGERPRINT_BITS
    algorithm: str = "sha256"

    @classmethod
    def from_value(
        cls,
        value: str,
        *,
        kind: str,
        detector: str,
        bits: int = DEFAULT_FINGERPRINT_BITS,
    ) -> "SecretIdentity":
        if not value:
            raise SecretLifecycleError("cannot fingerprint an empty value")
        return cls(
            fingerprint=fingerprint(value, bits=bits),
            kind=kind,
            detector=detector,
            truncated_bits=bits,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "fingerprint_algorithm": self.algorithm,
            "fingerprint_truncated_bits": self.truncated_bits,
            "kind": self.kind,
            "detector": self.detector,
        }


@dataclass(frozen=True)
class Step:
    """One lifecycle step and the evidence behind it."""

    status: str
    method: str = ""
    note: str = ""
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in STEP_STATUSES:
            raise SecretLifecycleError(f"unknown step status {self.status!r}")
        if self.status == CONFIRMED and not self.evidence_ids:
            raise SecretLifecycleError(
                "a CONFIRMED step requires evidence; without it the correct status is CLAIMED"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "method": self.method,
            "note": self.note,
            "evidence_ids": list(self.evidence_ids),
        }


UNKNOWN_STEP = Step(status=UNKNOWN)


@dataclass
class SurfaceRecord:
    """What is known about one exposure surface."""

    surface: str
    status: str = NOT_SEARCHED
    locators: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    cleanup: Step | None = None
    not_applicable_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "status": self.status,
            "locators": list(self.locators),
            "evidence_ids": list(self.evidence_ids),
            "cleanup": self.cleanup.as_dict() if self.cleanup else None,
            "accepted_cleanup_actions": sorted(ACCEPTED_CLEANUP[self.surface]),
            "residual_note": RESIDUAL_NOTES[self.surface],
            "not_applicable_reason": self.not_applicable_reason,
        }


class SecretLifecycle:
    """One credential, tracked from detection to retest.

    Every surface starts at ``NOT_SEARCHED``. Nothing here upgrades that on its
    own: a surface becomes clean because somebody searched it and said so, and a
    surface that nobody searched keeps saying it was never searched, all the way
    into the exported record.
    """

    def __init__(self, record_id: str, secret: SecretIdentity) -> None:
        self.record_id = record_id
        self.secret = secret
        self.surfaces: dict[str, SurfaceRecord] = {
            name: SurfaceRecord(surface=name) for name in SURFACES
        }
        self.revocation: Step = UNKNOWN_STEP
        self.rotation: Step = UNKNOWN_STEP
        self.retest: Step = UNKNOWN_STEP
        self.retest_assertion: str = ""
        self.limitations: list[str] = []

    # -- location -------------------------------------------------------------

    def _surface(self, surface: str) -> SurfaceRecord:
        if surface not in self.surfaces:
            raise SecretLifecycleError(
                f"unknown exposure surface {surface!r}; choose from {list(SURFACES)}"
            )
        return self.surfaces[surface]

    def locate(self, surface: str, locator: str, *, evidence_ids: Sequence[str] = ()) -> None:
        """Record that the secret is exposed on this surface, at this place."""
        record = self._surface(surface)
        if record.status == CLEANED:
            raise SecretLifecycleError(
                f"{surface} was recorded as cleaned and is now being located again; "
                "resolve the contradiction rather than recording both"
            )
        record.status = EXPOSED
        if locator not in record.locators:
            record.locators.append(locator)
        for evidence_id in evidence_ids:
            if evidence_id not in record.evidence_ids:
                record.evidence_ids.append(evidence_id)

    def searched_clean(self, surface: str, *, evidence_ids: Sequence[str]) -> None:
        """Record that this surface was searched and the secret was not there."""
        record = self._surface(surface)
        if record.status == EXPOSED:
            raise SecretLifecycleError(
                f"{surface} already holds a located exposure; a later clean search does "
                "not retract it"
            )
        if not evidence_ids:
            raise SecretLifecycleError(
                f"{surface}: a clean search is a claim about what is not there and "
                "requires evidence; without it the surface stays NOT_SEARCHED"
            )
        record.status = SEARCHED_CLEAN
        for evidence_id in evidence_ids:
            if evidence_id not in record.evidence_ids:
                record.evidence_ids.append(evidence_id)

    def not_applicable(self, surface: str, reason: str) -> None:
        """Record that this surface does not exist for this target."""
        record = self._surface(surface)
        if record.status == EXPOSED:
            raise SecretLifecycleError(
                f"{surface} holds a located exposure and cannot be NOT_APPLICABLE"
            )
        if not reason.strip():
            raise SecretLifecycleError(f"{surface}: NOT_APPLICABLE requires a reason")
        record.status = NOT_APPLICABLE
        record.not_applicable_reason = reason

    # -- cleanup --------------------------------------------------------------

    def clean(
        self,
        surface: str,
        action: str,
        *,
        status: str = CONFIRMED,
        evidence_ids: Sequence[str] = (),
        note: str = "",
    ) -> None:
        """Record a cleanup of one surface.

        The action has to be one that clears *this* surface. That is what makes
        the source/history conflation impossible rather than merely discouraged:
        ``clean("GIT_HISTORY", "REMOVED_FROM_SOURCE")`` raises, and no flag turns
        it into a pass.
        """
        record = self._surface(surface)
        accepted = ACCEPTED_CLEANUP[surface]
        if action not in accepted:
            if action == "REMOVED_FROM_SOURCE":
                raise SecretLifecycleError(
                    f"REMOVED_FROM_SOURCE does not clear {surface}. Deleting the secret from "
                    "the working tree changes one file in one revision; "
                    f"{surface} holds its own copy. Accepted here: {sorted(accepted)}"
                )
            raise SecretLifecycleError(
                f"{action!r} does not clear {surface}; accepted here: {sorted(accepted)}"
            )
        if record.status == NOT_SEARCHED:
            raise SecretLifecycleError(
                f"{surface} was never searched; cleaning a surface nobody looked at is an "
                "assumption, not a step"
            )
        if record.status in (SEARCHED_CLEAN, NOT_APPLICABLE):
            raise SecretLifecycleError(
                f"{surface} is recorded as {record.status}; there is nothing there to clean"
            )
        step = Step(status=status, method=action, note=note, evidence_ids=tuple(evidence_ids))
        record.cleanup = step
        if step.status == CONFIRMED:
            record.status = CLEANED

    # -- revocation, rotation, retest -----------------------------------------

    def revoke(
        self,
        *,
        status: str,
        method: str = "",
        evidence_ids: Sequence[str] = (),
        note: str = "",
    ) -> None:
        """Record that the credential was invalidated at the issuer."""
        self.revocation = Step(status=status, method=method, note=note,
                               evidence_ids=tuple(evidence_ids))

    def rotate(
        self,
        *,
        status: str,
        method: str = "",
        evidence_ids: Sequence[str] = (),
        note: str = "",
    ) -> None:
        """Record that a replacement credential was issued.

        Separate from revocation on purpose. Rotation restores the service; it
        does nothing to the leaked credential.
        """
        self.rotation = Step(status=status, method=method, note=note,
                             evidence_ids=tuple(evidence_ids))

    def record_retest(
        self,
        *,
        status: str,
        assertion: str = "",
        evidence_ids: Sequence[str] = (),
        note: str = "",
    ) -> None:
        """Record a retest that the *old* credential is now rejected."""
        self.retest = Step(status=status, method="RETEST", note=note,
                           evidence_ids=tuple(evidence_ids))
        self.retest_assertion = assertion

    # -- state ----------------------------------------------------------------

    def blockers(self) -> list[str]:
        """Every reason this record is not REMEDIATED, in reading order."""
        reasons: list[str] = []

        for name in SURFACES:
            record = self.surfaces[name]
            if record.status == EXPOSED:
                where = ", ".join(record.locators) or "location not recorded"
                reasons.append(f"{name} is still exposed ({where}).")
            elif record.status == NOT_SEARCHED:
                reasons.append(
                    f"{name} was never searched, so its status is unknown, not clean."
                )

        if self.revocation.status != CONFIRMED:
            if self.revocation.status == CLAIMED:
                reasons.append(
                    "Revocation is claimed but carries no evidence. Until the issuer is "
                    "shown to reject the credential, it should be treated as live."
                )
            else:
                reasons.append(
                    f"Revocation is {self.revocation.status}. Until the credential is "
                    "invalidated at the issuer, every other step is cosmetic: the leaked "
                    "value still authenticates."
                )
            if self.rotation.status == CONFIRMED:
                reasons.append(
                    "The credential was rotated but not revoked. Rotation issues a new "
                    "credential; it does not invalidate the old one, which remains valid "
                    "in every copy that has already left."
                )

        if self.retest.status != CONFIRMED:
            reasons.append(
                f"Retest is {self.retest.status}; nothing demonstrates that the old "
                "credential is now rejected."
            )

        return reasons

    def confirmed_steps(self) -> list[str]:
        """Steps that actually completed with evidence."""
        done = [
            f"CLEANED:{name}"
            for name in SURFACES
            if self.surfaces[name].status == CLEANED
        ]
        if self.revocation.status == CONFIRMED:
            done.append("REVOKED")
        if self.rotation.status == CONFIRMED:
            done.append("ROTATED")
        if self.retest.status == CONFIRMED:
            done.append("RETESTED")
        return done

    def state(self) -> str:
        """The overall lifecycle state.

        ``REMEDIATED`` only when nothing is outstanding. Otherwise: something was
        genuinely done (``PARTIALLY_REMEDIATED``), or a live exposure is known and
        nothing was done (``EXPOSED``), or nobody has looked (``UNKNOWN``).
        """
        if not self.blockers():
            return REMEDIATED
        if self.confirmed_steps():
            return PARTIALLY_REMEDIATED
        if any(record.status == EXPOSED for record in self.surfaces.values()):
            return EXPOSED
        return UNKNOWN

    # -- export ---------------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        """Export the record. Redacted, and never claiming more than was recorded."""
        limitations = list(self.limitations)
        limitations.append(
            "A fingerprint correlates sightings. It is not evidence that two sightings "
            "are the same issued credential, and it does not protect a low-entropy value."
        )
        if any(
            self.surfaces[name].status == CLEANED
            for name in SURFACES
        ):
            limitations.append(
                "A cleaned surface means the origin copy is gone. Copies that already "
                "left — clones, caches, downloads, log shippers — are outside the reach "
                "of any cleanup and are the reason revocation is the load-bearing step."
            )

        raw: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_id": self.record_id,
            "secret": self.secret.as_dict(),
            "state": self.state(),
            "surfaces": [self.surfaces[name].as_dict() for name in SURFACES],
            "revocation": self.revocation.as_dict(),
            "rotation": self.rotation.as_dict(),
            "retest": {**self.retest.as_dict(), "assertion": self.retest_assertion},
            "confirmed_steps": self.confirmed_steps(),
            "blockers": self.blockers(),
            "limitations": limitations,
        }

        log = RedactionLog()
        record = redact(raw, log)
        record["redaction"] = log.as_dict()
        return record


def is_remediated(record: Mapping[str, Any]) -> bool:
    """True only for the literal REMEDIATED state.

    Exists so no caller has to write ``state != EXPOSED``, which reads as
    "remediated" and silently promotes UNKNOWN and PARTIALLY_REMEDIATED.
    """
    return record.get("state") == REMEDIATED


def render_markdown(record: Mapping[str, Any]) -> str:
    """Render a record for humans, withholding what the record withholds."""
    state = record.get("state", UNKNOWN)
    secret = record.get("secret", {})
    lines = [
        f"# Secret {secret.get('fingerprint', '(no fingerprint)')} — {secret.get('kind', 'unclassified')}",
        "",
    ]

    if state == REMEDIATED:
        lines += [
            "**State: `REMEDIATED`.** The credential was invalidated at the issuer, every "
            "located surface was cleared by an action that clears that surface, every "
            "surface was searched, and a retest shows the old credential is rejected.",
            "",
        ]
    elif state == PARTIALLY_REMEDIATED:
        lines += [
            "**State: `PARTIALLY_REMEDIATED`.** Some steps completed with evidence and "
            "some did not. The outstanding items are listed below; until they are closed "
            "the credential should be treated as live.",
            "",
        ]
    elif state == EXPOSED:
        lines += [
            "**State: `EXPOSED`.** The credential is located on at least one surface and "
            "no step has completed with evidence.",
            "",
        ]
    else:
        # Deliberately free of the word this state must never be mistaken for. A
        # reader skimming a page for it will find it wherever it appears, caveat
        # or no caveat.
        lines += [
            "**State: `UNKNOWN`.** Nothing here establishes where this credential is or "
            "whether it was invalidated. An unsearched surface is unknown, not clean, "
            "and this record contains no evidence that the issuer rejects the value.",
            "",
        ]

    lines += ["## Surfaces", "", "| Surface | Status | Where | Cleanup |", "|---|---|---|---|"]
    for surface in record.get("surfaces", []):
        cleanup = surface.get("cleanup") or {}
        cleanup_text = (
            f"{cleanup.get('method', '')} ({cleanup.get('status', '')})"
            if cleanup else "—"
        )
        where = ", ".join(surface.get("locators", [])) or "—"
        lines.append(
            f"| {surface.get('surface')} | `{surface.get('status')}` | {where} | {cleanup_text} |"
        )

    revocation = record.get("revocation", {})
    rotation = record.get("rotation", {})
    retest = record.get("retest", {})
    lines += [
        "",
        "## Steps",
        "",
        f"- Revocation: `{revocation.get('status', UNKNOWN)}` — {revocation.get('method') or 'no method recorded'}",
        f"- Rotation: `{rotation.get('status', UNKNOWN)}` — {rotation.get('method') or 'no method recorded'}",
        f"- Retest: `{retest.get('status', UNKNOWN)}` — {retest.get('assertion') or 'no assertion recorded'}",
        "",
    ]

    blockers = record.get("blockers", [])
    if blockers:
        lines += ["## Outstanding", ""]
        lines += [f"- {item}" for item in blockers]
        lines.append("")

    limitations = record.get("limitations", [])
    if limitations:
        lines += ["## Limitations", ""]
        lines += [f"- {item}" for item in limitations]

    return "\n".join(lines).rstrip("\n") + "\n"
