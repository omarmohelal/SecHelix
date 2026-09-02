"""Independent verification by more than one path, without letting them see each other.

A single verifier that shares a model, a prompt lineage and a set of assumptions
with the reviewer is not fully independent. For a material finding you may want
several verification paths — a second reviewer, tool evidence, runtime evidence —
and a way to combine them that does not quietly manufacture agreement.

The whole value is in the *blindness*. If verifier B can see verifier A's
conclusion before voting, B is no longer an independent path; it is a reviewer of
A. This module enforces that structurally: a vote cannot be recorded once the
tally is visible, and sealed votes cannot be read until every expected voter has
submitted.

Four outcomes, and the third is the point:

``CONSENSUS_VERIFIED``   every voter that reached a conclusion agrees it is real
``CONSENSUS_REFUTED``    every voter that reached a conclusion agrees it is not
``DISAGREEMENT``         voters reached opposite conclusions
``INSUFFICIENT_EVIDENCE`` too few voters reached any conclusion

**DISAGREEMENT is not a vulnerability.** It is also not a non-vulnerability. It
means the evidence supports both readings, which is a fact about the evidence and
a request for a human — not something to resolve by counting louder. Nothing here
converts a disagreement into a finding, and nothing lets a majority overwrite a
dissent without recording that it did.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

CONSENSUS_VERIFIED = "CONSENSUS_VERIFIED"
CONSENSUS_REFUTED = "CONSENSUS_REFUTED"
DISAGREEMENT = "DISAGREEMENT"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

#: A voter's conclusion. ABSTAIN is a real answer — it means the path could not
#: reach a conclusion, which is different from concluding "not a problem".
VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
ABSTAIN = "ABSTAIN"

CONCLUSIONS = frozenset({VERIFIED, REFUTED, ABSTAIN})

#: Verification paths. Kept explicit so a tally can say *what kinds* of evidence
#: agreed — three model reviewers agreeing is weaker than a model plus a tool
#: plus a runtime observation, and the record should let a reader see that.
PATH_KINDS = frozenset({"REVIEWER", "TOOL", "RUNTIME", "HUMAN"})

#: Below this many concluding voters there is no quorum to speak of.
DEFAULT_MINIMUM_VOTERS = 2


class QuorumError(ValueError):
    """The quorum cannot be formed or counted."""


@dataclass(frozen=True)
class Vote:
    voter_id: str
    path_kind: str
    conclusion: str
    rationale: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.conclusion not in CONCLUSIONS:
            raise QuorumError(f"conclusion must be one of {sorted(CONCLUSIONS)}")
        if self.path_kind not in PATH_KINDS:
            raise QuorumError(f"path_kind must be one of {sorted(PATH_KINDS)}")
        if not self.rationale.strip():
            raise QuorumError("a vote without a rationale cannot be reviewed and is refused")

    def as_dict(self) -> dict[str, Any]:
        return {
            "voter_id": self.voter_id,
            "path_kind": self.path_kind,
            "conclusion": self.conclusion,
            "rationale": self.rationale,
            "evidence_ids": list(self.evidence_ids),
        }


class SealedQuorum:
    """Collects votes without revealing them until every expected voter has voted.

    The blindness is the mechanism. Reading the tally early, or voting after
    reading it, would make the later votes dependent on the earlier ones — at
    which point they are not independent paths and the consensus is an artifact
    of ordering.
    """

    def __init__(self, finding_id: str, expected_voters: Sequence[str],
                 *, minimum_voters: int = DEFAULT_MINIMUM_VOTERS) -> None:
        if len(set(expected_voters)) != len(expected_voters):
            raise QuorumError("expected_voters contains a duplicate")
        if len(expected_voters) < minimum_voters:
            raise QuorumError(
                f"{len(expected_voters)} expected voter(s) cannot satisfy a minimum of "
                f"{minimum_voters}"
            )
        self.finding_id = str(finding_id)
        self.expected = tuple(expected_voters)
        self.minimum_voters = minimum_voters
        self._votes: dict[str, Vote] = {}
        self._opened = False

    @property
    def sealed(self) -> bool:
        return not self._opened

    @property
    def outstanding(self) -> tuple[str, ...]:
        return tuple(v for v in self.expected if v not in self._votes)

    def submit(self, vote: Vote) -> None:
        if self._opened:
            raise QuorumError(
                "the quorum is already open; a vote cast after the tally is visible is "
                "not an independent one"
            )
        if vote.voter_id not in self.expected:
            raise QuorumError(f"{vote.voter_id} is not an expected voter for {self.finding_id}")
        if vote.voter_id in self._votes:
            raise QuorumError(f"{vote.voter_id} has already voted")
        self._votes[vote.voter_id] = vote

    def open(self) -> "QuorumResult":
        """Reveal and count. Refuses while any expected voter is outstanding."""
        if self.outstanding:
            raise QuorumError(
                f"cannot open: {', '.join(self.outstanding)} has not voted. Opening early "
                "would let a remaining voter see the tally before deciding."
            )
        self._opened = True
        return tally(self.finding_id, self._votes.values(),
                     minimum_voters=self.minimum_voters)

    def peek(self) -> None:
        raise QuorumError(
            "a sealed quorum cannot be inspected before it is opened; that is the whole "
            "point of sealing it"
        )


@dataclass
class QuorumResult:
    finding_id: str
    # Defaults to the most conservative outcome: a result that was never counted
    # must not read as a consensus.
    outcome: str = INSUFFICIENT_EVIDENCE
    votes: list[Vote] = field(default_factory=list)
    concluding: int = 0
    abstained: int = 0
    requires_human_review: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def verifies_the_finding(self) -> bool:
        """Only a clean consensus verifies. Everything else does not."""
        return self.outcome == CONSENSUS_VERIFIED

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "concluding_voters": self.concluding,
            "abstentions": self.abstained,
            "path_kinds": sorted({v.path_kind for v in self.votes if v.conclusion != ABSTAIN}),
            "requires_human_review": self.requires_human_review,
            "votes": [v.as_dict() for v in self.votes],
            "vote_digest": self.digest(),
            "notes": list(self.notes),
        }

    def digest(self) -> str:
        """A stable digest of the votes, so a recorded tally can be checked later."""
        material = "|".join(
            f"{v.voter_id}:{v.path_kind}:{v.conclusion}" for v in sorted(
                self.votes, key=lambda x: x.voter_id)
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def tally(finding_id: str, votes: Iterable[Vote], *,
          minimum_voters: int = DEFAULT_MINIMUM_VOTERS) -> QuorumResult:
    """Count votes into one of the four outcomes."""
    collected = list(votes)
    result = QuorumResult(finding_id=str(finding_id), votes=collected)

    concluding = [v for v in collected if v.conclusion != ABSTAIN]
    result.concluding = len(concluding)
    result.abstained = len(collected) - len(concluding)

    if len(concluding) < minimum_voters:
        result.outcome = INSUFFICIENT_EVIDENCE
        result.requires_human_review = True
        result.notes.append(
            f"{len(concluding)} voter(s) reached a conclusion; {minimum_voters} required. "
            "An abstention is not a vote for safety."
        )
        return result

    verdicts = {v.conclusion for v in concluding}
    if verdicts == {VERIFIED}:
        result.outcome = CONSENSUS_VERIFIED
    elif verdicts == {REFUTED}:
        result.outcome = CONSENSUS_REFUTED
    else:
        result.outcome = DISAGREEMENT
        result.requires_human_review = True
        result.notes.append(
            "Voters reached opposite conclusions. This is a fact about the evidence, not a "
            "finding and not a clearance; it is not resolved by counting."
        )

    kinds = {v.path_kind for v in concluding}
    if result.outcome == CONSENSUS_VERIFIED and kinds == {"REVIEWER"}:
        result.notes.append(
            "All concluding paths were reviewers. Agreement among reviewers of the same kind "
            "is weaker evidence than agreement across reviewer, tool and runtime paths."
        )
    return result


def apply_to_finding(finding: dict[str, Any], result: QuorumResult) -> dict[str, Any]:
    """Record a quorum on a finding without ever raising its status.

    A quorum can confirm what verification already found, and it can withhold. It
    never promotes: a finding the verifier did not verify does not become verified
    because several paths later agreed it looked real.
    """
    finding["quorum"] = result.as_dict()
    if result.outcome == CONSENSUS_REFUTED:
        finding["status"] = "FALSE_POSITIVE"
        finding["resolution"] = "FALSE_POSITIVE"
    elif result.outcome in {DISAGREEMENT, INSUFFICIENT_EVIDENCE}:
        # Not a vulnerability and not a clearance. It stays where it was, flagged.
        finding["requires_human_review"] = True
    return finding
