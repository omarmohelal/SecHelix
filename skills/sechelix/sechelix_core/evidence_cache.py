"""Incremental evidence cache: reuse only what can still be shown to hold.

Evidence is the expensive part of an audit. Re-auditing a repository after a
two-line change currently means producing all of it again, so the honest options
are "spend the whole cost again" or "trust yesterday's answer". The second one is
how a stale clean result gets attached to changed code.

This module removes that choice by making reuse *provable*. Each evidence record
is bound to a **dependency fingerprint**: the repository, the commit, and every
file the record actually read, each with the content hash it had when it was
read. On a new revision the fingerprint is replayed against what changed, and the
record lands in exactly one state:

``REUSED``
    Every recorded dependency still hashes to what it hashed before.
``INVALIDATED``
    At least one recorded dependency changed. Named, with which ones.
``RECOMPUTED``
    Was invalid and has since been regenerated against this revision.
``UNKNOWN``
    The fingerprint is incomplete, so validity cannot be established at all.

**``UNKNOWN`` is never ``REUSED``.** That is the rule the whole module exists to
enforce. Silently reusing evidence whose provenance you cannot establish is
exactly how a passing result gets attached to code nobody inspected, and it is
invisible afterwards, because a reused record looks identical to a fresh one.
Anything that cannot be proven still valid is invalid.

The same reasoning makes an *empty* dependency set ``UNKNOWN`` rather than
``REUSED``. Evidence that claims to depend on nothing is not universally valid;
it is unverifiable. A record with no inputs recorded is far more likely to be a
producer that forgot to declare them than a genuine observation about nothing, and
treating the two the same way means the forgetful producer's output survives every
change forever.

Reuse is decided per record, so the cache never speaks for evidence it has not
seen: a hypothesis with no cached record is not "still valid", it is simply
absent, and :func:`hypotheses_to_rerun` says nothing about it.

Nothing here mutates an evidence record. ``schemas/evidence-v1.schema.json`` sets
``additionalProperties: false``, and more to the point a cache is bookkeeping
about evidence, not part of the evidence. Fingerprints live alongside records in
:class:`CachedEvidence`, so a cached record still validates against its contract
unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

REUSED = "REUSED"
INVALIDATED = "INVALIDATED"
RECOMPUTED = "RECOMPUTED"
UNKNOWN = "UNKNOWN"

#: Every record lands in exactly one of these, and the counts sum to the record count.
CACHE_STATES = (REUSED, INVALIDATED, RECOMPUTED, UNKNOWN)

#: States that mean the record must be produced again before anything may rely on it.
#: ``UNKNOWN`` is in here deliberately: unprovable is treated exactly like invalid.
INVALID_STATES = frozenset({INVALIDATED, UNKNOWN})

#: How many dependency paths a reason names before it truncates.
_REASON_PATH_LIMIT = 5

_HEX = frozenset("0123456789abcdef")


class EvidenceCacheError(ValueError):
    """The cache entry or verdict cannot be constructed."""


def content_hash(data: bytes | str) -> str:
    """SHA-256 of a dependency's content, in the form fingerprints record."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _normalize(path: str) -> str:
    """Fold a path to one comparable form. Must be idempotent.

    A dependency recorded as ``src\\auth.py`` and a change set reporting
    ``src/auth.py`` are the same file. Comparing them unequal means the change is
    never seen and the record is reused — the exact failure this module exists to
    prevent — so normalization happens on both sides of every comparison.
    """
    text = str(path).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text.strip("/"):
        return ""
    return PurePosixPath(text).as_posix().lstrip("/")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= _HEX


def _short(commit: str | None) -> str | None:
    return commit[:12] if commit else None


def _listed(paths: Sequence[str]) -> str:
    shown = ", ".join(paths[:_REASON_PATH_LIMIT])
    if len(paths) > _REASON_PATH_LIMIT:
        shown += f", and {len(paths) - _REASON_PATH_LIMIT} more"
    return shown


@dataclass(frozen=True)
class DependencyFingerprint:
    """What a piece of evidence actually depended on when it was produced.

    ``inputs`` is a sorted tuple of ``(path, sha256)`` pairs — not merely the paths
    read, but the content that was read, so a file that changed and changed back is
    correctly seen as unchanged and a file listed in a change set for an unrelated
    reason does not force needless work.

    ``context`` optionally narrows *what* in those files the evidence is about (a
    symbol, a dataflow, a route). It is recorded for the reader; it deliberately
    does not narrow invalidation. See :func:`evaluate_cache`.
    """

    repository: str = ""
    commit: str = ""
    inputs: tuple[tuple[str, str], ...] = ()
    context: str | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for path, _ in self.inputs)

    def incompleteness(self) -> str | None:
        """Why this fingerprint cannot establish validity, or ``None`` if it can.

        Returning a reason rather than a boolean is deliberate: the caller has to
        put something in the report, and "UNKNOWN" with no cause is the kind of
        result a reader rounds down to "probably fine".
        """
        if not self.repository and not self.commit and not self.inputs:
            return (
                "the record carries no dependency fingerprint, so nothing about what it "
                "read can be established"
            )
        if not self.repository:
            return "the fingerprint names no repository, so it cannot be matched to a tree"
        if not self.commit:
            return "the fingerprint names no commit, so it cannot be matched to a revision"
        if not self.inputs:
            return (
                "the fingerprint records no dependencies; evidence that claims to depend on "
                "nothing cannot be shown to still hold"
            )
        for path, digest in self.inputs:
            if not path:
                return "the fingerprint records a dependency with no path"
            if not _is_sha256(digest):
                return (
                    f"the dependency {path!r} carries no usable content hash, so its current "
                    "state cannot be compared to the recorded one"
                )
        return None

    @property
    def complete(self) -> bool:
        """True only when every part needed to prove or disprove reuse is present."""
        return self.incompleteness() is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "commit": self.commit,
            "inputs": [{"path": path, "sha256": digest} for path, digest in self.inputs],
            "context": self.context,
            "complete": self.complete,
        }


#: The fingerprint of a record that never declared one. Always ``UNKNOWN``.
UNRECORDED_FINGERPRINT = DependencyFingerprint()


def fingerprint(
    *,
    repository: str,
    commit: str,
    inputs: Mapping[str, str] | Iterable[tuple[str, str]] | None = None,
    context: str | None = None,
) -> DependencyFingerprint:
    """Build a dependency fingerprint, normalized so comparison is meaningful.

    Paths are folded to one form, hashes are lowercased, and the inputs are sorted,
    so two producers that read the same files in a different order or on a
    different platform produce the same fingerprint.

    A path recorded twice with two different hashes raises: the record cannot say
    what it read, and silently keeping one of the two answers would decide validity
    by dictionary ordering.
    """
    pairs: list[tuple[str, str]] = []
    if isinstance(inputs, Mapping):
        pairs = [(str(path), str(digest)) for path, digest in inputs.items()]
    elif isinstance(inputs, (str, bytes)):
        # A bare string is iterable, so this would otherwise be read character by
        # character and produce a fingerprint of nonsense rather than an error.
        raise EvidenceCacheError(
            f"fingerprint inputs must be a mapping or (path, sha256) pairs, got {inputs!r}"
        )
    elif inputs is not None:
        for item in inputs:
            if isinstance(item, (str, bytes)):
                raise EvidenceCacheError(
                    f"each fingerprint input must be a (path, sha256) pair, got {item!r}"
                )
            try:
                path, digest = item
            except (TypeError, ValueError) as exc:
                raise EvidenceCacheError(
                    f"each fingerprint input must be a (path, sha256) pair, got {item!r}"
                ) from exc
            pairs.append((str(path), str(digest)))

    resolved: dict[str, str] = {}
    for raw_path, raw_digest in pairs:
        path = _normalize(raw_path)
        digest = raw_digest.strip().lower()
        previous = resolved.get(path)
        if previous is not None and previous != digest:
            raise EvidenceCacheError(
                f"dependency {path!r} was recorded with two different hashes "
                f"({previous} and {digest}); the fingerprint cannot say what was read"
            )
        resolved[path] = digest

    return DependencyFingerprint(
        repository=str(repository or "").strip(),
        commit=str(commit or "").strip().lower(),
        inputs=tuple(sorted(resolved.items())),
        context=str(context).strip() if context else None,
    )


@dataclass(frozen=True)
class CachedEvidence:
    """One evidence record plus the fingerprint that says when it may be reused."""

    evidence_id: str
    fingerprint: DependencyFingerprint = UNRECORDED_FINGERPRINT
    hypothesis_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "fingerprint": self.fingerprint.as_dict(),
            "related_hypothesis_ids": list(self.hypothesis_ids),
        }


def cache_entry(
    record: Mapping[str, Any],
    fingerprint: DependencyFingerprint | None = None,
) -> CachedEvidence:
    """Bind an ``evidence-v1`` record to a fingerprint without touching the record.

    The record is read, never modified: the evidence contract forbids extra
    properties, and a cache is bookkeeping about evidence rather than a claim the
    evidence itself makes.

    A record with no fingerprint is accepted and will evaluate to ``UNKNOWN``.
    Refusing it here would push callers to invent a fingerprint to get past the
    error, which is the worse failure.
    """
    if not isinstance(record, Mapping):
        raise EvidenceCacheError(f"an evidence record must be a mapping, got {type(record).__name__}")
    evidence_id = str(record.get("evidence_id", "")).strip()
    if not evidence_id:
        raise EvidenceCacheError("an evidence record must carry an evidence_id to be cached")

    hypothesis_ids: list[str] = []
    related = record.get("related_hypothesis_ids")
    if isinstance(related, (list, tuple)):
        for item in related:
            value = str(item).strip()
            if value and value not in hypothesis_ids:
                hypothesis_ids.append(value)

    return CachedEvidence(
        evidence_id=evidence_id,
        fingerprint=fingerprint if fingerprint is not None else UNRECORDED_FINGERPRINT,
        hypothesis_ids=tuple(hypothesis_ids),
    )


@dataclass(frozen=True)
class RecordVerdict:
    """What happened to one cached record on this revision, and why."""

    evidence_id: str
    state: str
    reason: str
    changed_paths: tuple[str, ...] = ()
    undetermined_paths: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()

    @property
    def reusable(self) -> bool:
        """Only ``REUSED`` evidence may be carried forward without redoing the work."""
        return self.state == REUSED

    @property
    def must_recompute(self) -> bool:
        """``INVALIDATED`` and ``UNKNOWN`` alike: both mean produce it again."""
        return self.state in INVALID_STATES

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "state": self.state,
            "reason": self.reason,
            "changed_paths": list(self.changed_paths),
            "undetermined_paths": list(self.undetermined_paths),
            "related_hypothesis_ids": list(self.hypothesis_ids),
            "reusable": self.reusable,
        }


@dataclass(frozen=True)
class CacheVerdict:
    """The audit telemetry for one replay of the cache against one revision."""

    repository: str
    commit: str
    verdicts: tuple[RecordVerdict, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        """Per-state counts. These always sum to ``len(self.verdicts)``."""
        counts = {state: 0 for state in CACHE_STATES}
        for verdict in self.verdicts:
            counts[verdict.state] += 1
        return counts

    def by_state(self, state: str) -> tuple[RecordVerdict, ...]:
        return tuple(verdict for verdict in self.verdicts if verdict.state == state)

    def get(self, evidence_id: str) -> RecordVerdict | None:
        for verdict in self.verdicts:
            if verdict.evidence_id == evidence_id:
                return verdict
        return None

    @property
    def reusable_evidence_ids(self) -> tuple[str, ...]:
        return tuple(verdict.evidence_id for verdict in self.verdicts if verdict.reusable)

    @property
    def stale_evidence_ids(self) -> tuple[str, ...]:
        return tuple(verdict.evidence_id for verdict in self.verdicts if verdict.must_recompute)

    def as_dict(self) -> dict[str, Any]:
        counts = self.counts
        return {
            "schema_version": "1.0",
            "repository": self.repository,
            "commit": self.commit,
            "record_count": len(self.verdicts),
            "counts": counts,
            "records": [verdict.as_dict() for verdict in self.verdicts],
            "invalidations": [
                {
                    "evidence_id": verdict.evidence_id,
                    "reason": verdict.reason,
                    "changed_paths": list(verdict.changed_paths),
                }
                for verdict in self.by_state(INVALIDATED)
            ],
            "unresolved": [
                {"evidence_id": verdict.evidence_id, "reason": verdict.reason}
                for verdict in self.by_state(UNKNOWN)
            ],
            "hypotheses_to_rerun": hypotheses_to_rerun(self),
            "notes": [
                "UNKNOWN is not a pass. A record whose provenance cannot be established is "
                "treated exactly like one that was invalidated.",
                "Only REUSED evidence describes this revision without being produced again.",
                "The cache says nothing about hypotheses it holds no evidence for; absence "
                "from this verdict is not coverage.",
            ],
        }


def _classify(
    entry: CachedEvidence,
    *,
    repository: str,
    commit: str,
    changed: frozenset[str] | None,
    hashes: Mapping[str, str],
) -> RecordVerdict:
    fp = entry.fingerprint

    # Checked first, and before anything that could conclude REUSED: a record whose
    # fingerprint cannot be read must not benefit from the fact that nothing it
    # failed to declare appears in the change set.
    incomplete = fp.incompleteness()
    if incomplete:
        return RecordVerdict(entry.evidence_id, UNKNOWN, incomplete, hypothesis_ids=entry.hypothesis_ids)

    if fp.repository != repository:
        return RecordVerdict(
            entry.evidence_id,
            INVALIDATED,
            f"the evidence is bound to repository {fp.repository!r}, but the cache is being "
            f"replayed against {repository!r}, so it does not describe this tree",
            hypothesis_ids=entry.hypothesis_ids,
        )

    changed_deps: list[str] = []
    undetermined: list[str] = []
    for path, digest in fp.inputs:
        current = hashes.get(path)
        if current is not None:
            # A hash beats a path list in both directions: it catches a file that
            # changed without appearing in the change set, and it spares a file
            # listed as changed whose content came back to what was read.
            if current != digest:
                changed_deps.append(path)
        elif changed is None:
            undetermined.append(path)
        elif path in changed:
            changed_deps.append(path)

    if changed_deps:
        return RecordVerdict(
            entry.evidence_id,
            INVALIDATED,
            f"{len(changed_deps)} of {len(fp.inputs)} recorded dependencies changed at "
            f"{_short(commit)}: {_listed(changed_deps)}",
            changed_paths=tuple(changed_deps),
            hypothesis_ids=entry.hypothesis_ids,
        )

    if undetermined:
        if fp.commit == commit:
            # The record names this exact revision, so the tree it read is the tree
            # being asked about. Nothing needs to be diffed for that to hold.
            return RecordVerdict(
                entry.evidence_id,
                REUSED,
                f"the evidence was produced against this exact revision ({_short(commit)}), so "
                f"its {len(fp.inputs)} recorded dependencies cannot have moved",
                hypothesis_ids=entry.hypothesis_ids,
            )
        return RecordVerdict(
            entry.evidence_id,
            UNKNOWN,
            f"{len(undetermined)} of {len(fp.inputs)} recorded dependencies could not be checked "
            f"against {_short(commit)} — no change set or content hash covers "
            f"{_listed(undetermined)}",
            undetermined_paths=tuple(undetermined),
            hypothesis_ids=entry.hypothesis_ids,
        )

    return RecordVerdict(
        entry.evidence_id,
        REUSED,
        f"all {len(fp.inputs)} recorded dependencies still hold at {_short(commit)}",
        hypothesis_ids=entry.hypothesis_ids,
    )


def evaluate_cache(
    entries: Sequence[CachedEvidence],
    *,
    repository: str,
    commit: str,
    changed_paths: Sequence[str] | None = None,
    current_hashes: Mapping[str, str] | None = None,
) -> CacheVerdict:
    """Replay a cache against a revision and classify every record.

    ``changed_paths`` is what moved between the cached revision and this one.
    ``None`` and ``()`` mean different things and the difference matters: ``()``
    asserts that nothing changed, while ``None`` says no change set was supplied,
    which leaves dependencies unchecked and therefore ``UNKNOWN``. Defaulting to
    ``None`` means forgetting the argument costs recomputation, never a false
    reuse.

    ``current_hashes`` maps paths in the current revision to their content hashes.
    Where it covers a dependency it is authoritative and overrides the change set.
    A path absent from it is not treated as deleted — a deletion is a change and
    belongs in ``changed_paths`` — because callers legitimately supply a partial
    map.

    Invalidation is per file, never per symbol. A fingerprint's ``context`` records
    which symbol or dataflow the evidence was about, but a change anywhere in a
    dependency invalidates the record, because nothing here can prove the edit
    missed that symbol.
    """
    repository = str(repository or "").strip()
    commit = str(commit or "").strip().lower()
    if not repository or not commit:
        raise EvidenceCacheError(
            "evaluate_cache needs the repository and commit the cache is being replayed "
            "against; without them no record can be shown to still hold"
        )

    changed = None if changed_paths is None else frozenset(_normalize(p) for p in changed_paths)
    hashes = {
        _normalize(path): str(digest).strip().lower()
        for path, digest in (current_hashes or {}).items()
    }

    seen: set[str] = set()
    verdicts: list[RecordVerdict] = []
    for entry in entries:
        if not isinstance(entry, CachedEvidence):
            raise EvidenceCacheError(
                f"every cache entry must be a CachedEvidence, got {type(entry).__name__}"
            )
        if entry.evidence_id in seen:
            raise EvidenceCacheError(
                f"duplicate cache entry for {entry.evidence_id!r}; two fingerprints for one "
                "record make its state depend on iteration order"
            )
        seen.add(entry.evidence_id)
        verdicts.append(
            _classify(entry, repository=repository, commit=commit, changed=changed, hashes=hashes)
        )

    # Sorted so the same cache and the same revision produce the same telemetry
    # regardless of the order the entries arrived in.
    verdicts.sort(key=lambda verdict: verdict.evidence_id)
    return CacheVerdict(repository=repository, commit=commit, verdicts=tuple(verdicts))


def mark_recomputed(verdict: CacheVerdict, evidence_ids: Sequence[str]) -> CacheVerdict:
    """Record that named invalid records have been regenerated for this revision.

    Only ``INVALIDATED`` and ``UNKNOWN`` records may become ``RECOMPUTED``. Marking
    a ``REUSED`` record raises: either the work was done and the telemetry claiming
    it was saved is wrong, or it was not and the state would be a lie. Both are
    caller defects worth surfacing rather than averaging away.
    """
    wanted: list[str] = []
    for evidence_id in evidence_ids:
        value = str(evidence_id).strip()
        if value and value not in wanted:
            wanted.append(value)

    known = {record.evidence_id for record in verdict.verdicts}
    missing = sorted(set(wanted) - known)
    if missing:
        raise EvidenceCacheError(
            f"cannot mark records that were never evaluated as recomputed: {missing}"
        )

    updated: list[RecordVerdict] = []
    for record in verdict.verdicts:
        if record.evidence_id not in wanted or record.state == RECOMPUTED:
            updated.append(record)
            continue
        if record.state == REUSED:
            raise EvidenceCacheError(
                f"{record.evidence_id!r} was REUSED, so it was not recomputed; recording it as "
                "RECOMPUTED would misstate what this revision actually cost"
            )
        updated.append(
            RecordVerdict(
                record.evidence_id,
                RECOMPUTED,
                f"the record was {record.state} because {record.reason}; it has since been "
                f"regenerated against {_short(verdict.commit)}",
                changed_paths=record.changed_paths,
                undetermined_paths=record.undetermined_paths,
                hypothesis_ids=record.hypothesis_ids,
            )
        )
    return CacheVerdict(repository=verdict.repository, commit=verdict.commit, verdicts=tuple(updated))


def hypotheses_to_rerun(verdict: CacheVerdict) -> list[str]:
    """Catalog hypotheses whose evidence did not survive this revision.

    A hypothesis is listed when *any* record supporting it is ``INVALIDATED`` or
    ``UNKNOWN``, even if its other records were reused: a conclusion drawn from
    four observations is not three-quarters valid when one of them stops holding.

    ``RECOMPUTED`` records are not listed — they have already been produced again.
    Neither are hypotheses the cache holds no evidence for; the cache can only
    speak about records it has seen, and an empty list here means nothing needs
    *re-running*, not that anything has been covered.
    """
    pending: set[str] = set()
    for record in verdict.verdicts:
        if record.must_recompute:
            pending.update(record.hypothesis_ids)
    return sorted(pending)
