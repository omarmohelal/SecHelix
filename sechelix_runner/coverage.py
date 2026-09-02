"""The coverage ledger.

The question this answers is the one no audit tool usually can: **what did the
last audit not look at?**

A finding list tells you what was found. It cannot distinguish "we examined the
payment routes and they were fine" from "we never opened the payment routes".
Those are opposite facts and they look identical in a report that only lists
findings. The ledger keeps the second one.

Every tracked item carries the commit at which it was last covered and a hash of
what it contained then. That is what makes the two rules below enforceable.

**Stale coverage never silently becomes current.** If a file was examined at
commit A and its contents changed by commit B, the old coverage does not carry
forward. It becomes ``STALE`` -- which is a prompt to re-examine, not a pass.

**Never-covered is a first-class state.** An item the ledger has seen exist but
that no run has ever examined is ``NEVER_COVERED``. It is the most useful state
in here and the one a findings list structurally cannot express.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from .digests import digest, digest_bytes

LEDGER_FILENAME = "coverage.json"


class CoverageStatus(str, Enum):
    """How an item stands relative to previous runs.

    ``NOT_REVISITED`` and ``NEVER_COVERED`` are deliberately distinct: the first
    was examined once and skipped this time, the second has never been examined
    at all. Collapsing them would hide the only one that is genuinely alarming.
    """

    NEW = "NEW"
    CHANGED = "CHANGED"
    REUSED = "REUSED"
    STALE = "STALE"
    NOT_REVISITED = "NOT_REVISITED"
    NEVER_COVERED = "NEVER_COVERED"
    UNKNOWN = "UNKNOWN"


#: The dimensions the ledger tracks. Anything a run can enumerate and later
#: re-enumerate belongs here; anything it can only guess at does not.
COVERAGE_KINDS = (
    "route",
    "entrypoint",
    "trust_boundary",
    "identity",
    "state_machine",
    "sink",
    "file",
    "symbol",
    "hypothesis",
    "runtime_path",
)


@dataclass
class CoverageItem:
    """One tracked thing and the history of it being looked at."""

    kind: str
    identifier: str
    content_hash: str | None = None
    first_seen_commit: str | None = None
    #: Commit at which this item was last actually examined. ``None`` means no
    #: run has ever covered it, which is what makes NEVER_COVERED detectable.
    last_covered_commit: str | None = None
    last_covered_run: str | None = None
    #: Hash of the contents at the moment coverage was recorded, so drift since
    #: then is detectable rather than assumed away.
    covered_content_hash: str | None = None
    #: Whether the most recent coverage happened *after* the contents had drifted
    #: from the previously covered state. Without this, re-examining a changed
    #: item is indistinguishable from re-examining an unchanged one, because
    #: covering resolves the drift before anything can observe it.
    recovered_after_change: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.identifier}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "content_hash": self.content_hash,
            "first_seen_commit": self.first_seen_commit,
            "last_covered_commit": self.last_covered_commit,
            "last_covered_run": self.last_covered_run,
            "covered_content_hash": self.covered_content_hash,
            "recovered_after_change": self.recovered_after_change,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageItem:
        return cls(**{k: data.get(k) for k in cls.__dataclass_fields__})


@dataclass
class TargetIdentity:
    """What binds a ledger to one audited thing.

    ``origin`` and ``name`` identify the project; ``commit`` and ``branch``
    identify the state. A ledger is refused if the project does not match,
    because carrying coverage across two different repositories would be a
    silent lie about what was examined.
    """

    origin: str
    name: str
    commit: str
    branch: str

    @property
    def target_id(self) -> str:
        return digest({"origin": self.origin, "name": self.name})

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "name": self.name,
            "commit": self.commit,
            "branch": self.branch,
            "target_id": self.target_id,
        }

    @classmethod
    def from_world(cls, world: dict[str, Any]) -> TargetIdentity:
        target = world.get("target", {})
        return cls(
            origin=target.get("origin", "UNKNOWN"),
            name=target.get("name", "UNKNOWN"),
            commit=target.get("commit", "UNKNOWN"),
            branch=target.get("branch", "UNKNOWN"),
        )


class LedgerMismatch(ValueError):
    """The ledger belongs to a different target."""


class CoverageLedger:
    """Coverage for one target, across every run against it."""

    def __init__(self, identity: TargetIdentity) -> None:
        self.identity = identity
        self.items: dict[str, CoverageItem] = {}
        self.run_history: list[dict[str, Any]] = []

    # -- persistence ---------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str, identity: TargetIdentity) -> CoverageLedger:
        """Load a ledger, refusing one that belongs to a different project."""
        path = Path(path)
        ledger = cls(identity)
        if not path.exists():
            return ledger
        data = json.loads(path.read_text(encoding="utf-8"))
        recorded = data.get("identity", {})
        if recorded.get("target_id") not in (None, identity.target_id):
            raise LedgerMismatch(
                f"ledger at {path} belongs to target {recorded.get('name')!r} "
                f"({recorded.get('origin')!r}), not {identity.name!r}"
            )
        ledger.items = {
            key: CoverageItem.from_dict(value)
            for key, value in data.get("items", {}).items()
        }
        ledger.run_history = data.get("run_history", [])
        return ledger

    def save(self, path: Path | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "identity": self.identity.to_dict(),
                    "items": {k: v.to_dict() for k, v in sorted(self.items.items())},
                    "run_history": self.run_history[-50:],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path

    # -- observation ---------------------------------------------------------

    def observe(self, kind: str, identifier: str, content_hash: str | None = None) -> None:
        """Record that an item exists, without claiming it was examined.

        This is the distinction the whole module rests on. Observing a route
        does not cover it; only :meth:`cover` does.
        """
        key = f"{kind}:{identifier}"
        existing = self.items.get(key)
        if existing is None:
            self.items[key] = CoverageItem(
                kind=kind,
                identifier=identifier,
                content_hash=content_hash,
                first_seen_commit=self.identity.commit,
            )
        else:
            existing.content_hash = content_hash

    def cover(self, kind: str, identifier: str, run_id: str) -> None:
        """Record that an item was actually examined in ``run_id``."""
        key = f"{kind}:{identifier}"
        item = self.items.get(key)
        if item is None:
            self.observe(kind, identifier)
            item = self.items[key]
        item.recovered_after_change = (
            item.covered_content_hash is not None
            and item.content_hash is not None
            and item.covered_content_hash != item.content_hash
        )
        item.last_covered_commit = self.identity.commit
        item.last_covered_run = run_id
        item.covered_content_hash = item.content_hash

    # -- classification ------------------------------------------------------

    def classify(self, key: str, *, covered_this_run: bool) -> CoverageStatus:
        """Where one item stands. See :class:`CoverageStatus`."""
        item = self.items.get(key)
        if item is None:
            return CoverageStatus.UNKNOWN

        never_covered = item.last_covered_commit is None
        drifted = (
            item.covered_content_hash is not None
            and item.content_hash is not None
            and item.covered_content_hash != item.content_hash
        )

        if covered_this_run:
            if never_covered:
                return CoverageStatus.NEW
            if item.recovered_after_change or drifted:
                # Re-examined after the contents moved. Distinct from REUSED,
                # which means the covered state still matches what was covered.
                return CoverageStatus.CHANGED
            return CoverageStatus.REUSED

        if never_covered:
            return CoverageStatus.NEVER_COVERED
        if drifted:
            # Previously covered, contents moved, nobody looked again. Old
            # coverage does not carry forward.
            return CoverageStatus.STALE
        return CoverageStatus.NOT_REVISITED

    def report(self, covered_keys: Iterable[str]) -> dict[str, Any]:
        """Full coverage picture for a run."""
        covered = set(covered_keys)
        by_status: dict[str, list[str]] = {s.value: [] for s in CoverageStatus}
        for key in sorted(self.items):
            status = self.classify(key, covered_this_run=key in covered)
            by_status[status.value].append(key)
        return {
            "identity": self.identity.to_dict(),
            "totals": {status: len(keys) for status, keys in by_status.items()},
            "items": by_status,
            "blind_spots": sorted(
                by_status[CoverageStatus.NEVER_COVERED.value]
                + by_status[CoverageStatus.STALE.value]
            ),
        }

    def record_run(self, run_id: str, covered_keys: Iterable[str]) -> None:
        self.run_history.append(
            {
                "run_id": run_id,
                "commit": self.identity.commit,
                "branch": self.identity.branch,
                "covered": sorted(set(covered_keys)),
            }
        )


def observe_world(ledger: CoverageLedger, world: dict[str, Any], root: Path | None = None) -> None:
    """Populate a ledger from an offline world snapshot.

    Files get a real content hash where the tree is readable, so drift is
    detected on contents rather than on mtime. An unreadable file is observed
    without a hash: it exists, and whether it changed is ``UNKNOWN`` rather
    than assumed unchanged.
    """
    for path in world.get("file_index", []):
        content_hash = None
        if root is not None:
            candidate = Path(root) / path
            try:
                content_hash = digest_bytes(candidate.read_bytes())
            except OSError:
                content_hash = None
        ledger.observe("file", path, content_hash)

    for kind, world_key in (
        ("route", "routes"),
        ("entrypoint", "client_entrypoints"),
        ("identity", "identities"),
        ("state_machine", "state_machines"),
        ("sink", "sinks"),
    ):
        for value in world.get(world_key, []) or []:
            ledger.observe(kind, str(value))
