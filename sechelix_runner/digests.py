"""Canonical digests.

Replay and tamper detection both depend on hashing a structure the same way
twice, on any platform, in any process. ``json.dumps`` does not give that for
free: key order, float formatting and non-ASCII escaping all vary with call
site. This module fixes those choices once so a digest computed while a run
executes still matches the digest computed months later during replay.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Prefix so a digest is self-describing in an artifact and a future algorithm
#: change is visible rather than silent.
_ALGORITHM = "sha256"


def canonical_json(value: Any) -> str:
    """Serialize ``value`` so equal structures always produce equal text.

    ``sort_keys`` removes dict-ordering nondeterminism, ``ensure_ascii`` removes
    the encoding question, and the tight separators remove whitespace drift.
    ``allow_nan=False`` is the important one: ``NaN`` and ``Infinity`` are not
    JSON, they compare unequal to themselves, and letting them into a digest
    means a record that can never be verified.
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_fallback,
    )


def _fallback(value: Any) -> Any:
    """Render values json does not know, without inventing an identity.

    Anything that reaches here is serialized by *type and repr*, so two
    different objects never collide into one digest just because both were
    unserializable.
    """
    return {"__type__": type(value).__name__, "__repr__": repr(value)}


def digest(value: Any) -> str:
    """Return ``sha256:<hex>`` over the canonical form of ``value``."""
    payload = canonical_json(value).encode("utf-8")
    return f"{_ALGORITHM}:{hashlib.sha256(payload).hexdigest()}"


def digest_bytes(payload: bytes) -> str:
    """Return ``sha256:<hex>`` over raw bytes, for files rather than structures."""
    return f"{_ALGORITHM}:{hashlib.sha256(payload).hexdigest()}"


def verify(value: Any, expected: str) -> bool:
    """Whether ``value`` still hashes to ``expected``.

    Comparison is a plain equality on two hex strings that are already public in
    the run artifacts, so there is nothing here to leak through timing.
    """
    return digest(value) == expected
