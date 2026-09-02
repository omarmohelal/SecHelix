"""Runtime trace mode: correlate what a system did with what the code says.

Static review reads intent; runtime observation reads behaviour. Neither is the
whole answer, and the interesting bugs live in the gap between them — a guard that
exists in the source and never runs, a redirect that is documented and not
followed, a cookie whose flags are set in one code path and not the one that
actually serves the request.

This module closes that gap in the only direction that is safe: it takes
observations the caller already recorded and asks whether they agree with a static
claim. Four rules keep it from becoming an exploit tool or a false verifier.

**It records and correlates; it never generates traffic.** There is no request
builder here, no payload, no client. That is a structural property rather than a
promise: :func:`traffic_capabilities` inspects this module's own namespace for
anything that could put bytes on a wire or start a process, and importing the
module fails if it ever finds one. A module that cannot reach the network cannot
be talked into sending something destructive.

**Execution mode is LOCAL or STAGING unless someone chooses otherwise.**
``PRODUCTION_SAFE`` is never a default and cannot be selected without stating the
restrictions it was selected under. "We ran it against production" with no stated
limits is not a safeguard, it is a hope.

**Redaction is on by default and some things are dropped rather than redacted.**
Cookie *values*, credential headers, session identifiers and request bodies have
no metadata reading, so there is no correct way for them to appear in a trace;
they are removed by name before anything is written. What remains goes through
:func:`sechelix_core.proof_bundle.redact`, which is the same redaction a proof
bundle gets — reused rather than reimplemented, so a pattern added there protects
this too. Query-string values are redacted wholesale, because a redactor that has
to decide which query parameter is a token will eventually decide wrong, and a
surface is matched on its path and parameter *names*.

**A runtime observation alone never verifies a finding.** A trace can only ever
carry ``HYPOTHESIS``; the contract has no way to express anything else. Observing
that a request returned 200 shows what happened, not why, and "why" is what a
finding claims. Combined with static evidence a claim becomes *ready for an
independent verifier*, which is a queue, not a promotion.

Underneath all of it sits one distinction the module exists to preserve.
``UNRELATED`` means the observation was compared to the claim and had nothing to
do with it. ``INSUFFICIENT`` means it could not be told. Collapsing the second
into the first turns every gap in instrumentation into a quiet reassurance, so
they are separate strengths, separately counted, and the contract refuses to let
an uncomparable observation be filed as an irrelevant one.
"""

from __future__ import annotations

import re
import types
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .proof_bundle import REDACTED, RedactionLog, redact

LOCAL = "LOCAL"
STAGING = "STAGING"
PRODUCTION_SAFE = "PRODUCTION_SAFE"

#: Modes an observation may be collected in. The vocabulary matches
#: ``schemas/scope-v1.schema.json`` so a trace can be read beside the scope that
#: authorized it. ``STATIC`` is absent on purpose: there is no such thing as a
#: statically collected runtime observation.
EXECUTION_MODES = (LOCAL, STAGING, PRODUCTION_SAFE)

#: The default. Choosing production is a decision someone has to make explicitly.
DEFAULT_EXECUTION_MODE = LOCAL

HTTP_EXCHANGE = "HTTP_EXCHANGE"
API_CALL = "API_CALL"
REDIRECT_CHAIN = "REDIRECT_CHAIN"
COOKIE_METADATA = "COOKIE_METADATA"
WEBSOCKET_HANDSHAKE = "WEBSOCKET_HANDSHAKE"
WEBHOOK_DELIVERY = "WEBHOOK_DELIVERY"
APPLICATION_TRACE = "APPLICATION_TRACE"

#: Every kind is metadata *about* an exchange, never its content.
OBSERVATION_KINDS = (
    HTTP_EXCHANGE,
    API_CALL,
    REDIRECT_CHAIN,
    COOKIE_METADATA,
    WEBSOCKET_HANDSHAKE,
    WEBHOOK_DELIVERY,
    APPLICATION_TRACE,
)

CONFIRMS = "CONFIRMS"
CONTRADICTS = "CONTRADICTS"
UNRELATED = "UNRELATED"
INSUFFICIENT = "INSUFFICIENT"

#: The four answers a correlation can give. ``UNRELATED`` and ``INSUFFICIENT`` are
#: both "no support", and they are not the same result: one is an observation, the
#: other is the absence of one.
CORRELATION_STRENGTHS = (CONFIRMS, CONTRADICTS, UNRELATED, INSUFFICIENT)

EXACT = "EXACT"
TEMPLATE = "TEMPLATE"
FILE = "FILE"
NONE = "NONE"
UNDETERMINED = "UNDETERMINED"

#: How precisely two surfaces lined up. ``FILE`` is a real but coarse match: the
#: two agree on a file and disagree, or say nothing, about a line.
SURFACE_MATCHES = (EXACT, TEMPLATE, FILE, NONE, UNDETERMINED)

#: The only status this module can produce. See the module docstring.
HYPOTHESIS = "HYPOTHESIS"

TRACE_SCHEMA_VERSION = "1.0"


class RuntimeTraceError(ValueError):
    """The observation, claim or trace cannot be constructed."""


# ---------------------------------------------------------------------------
# The no-traffic guarantee, enforced rather than asserted
# ---------------------------------------------------------------------------

#: Import roots that can put bytes on a wire, start a process, or open a browser.
#: The list is deliberately broader than "network": a module that can spawn a
#: subprocess can send whatever it likes, and the guarantee here is about what
#: this code is *able* to do, not what it currently chooses to do.
_TRAFFIC_CAPABLE_ROOTS = frozenset({
    "aiohttp", "asyncio", "ftplib", "http", "httpx", "imaplib", "multiprocessing",
    "nntplib", "os", "paramiko", "poplib", "requests", "selenium", "smtplib",
    "socket", "socketserver", "ssl", "subprocess", "telnetlib", "urllib",
    "urllib3", "webbrowser", "xmlrpc",
})


def traffic_capabilities() -> tuple[str, ...]:
    """Names in this module's namespace that could emit traffic. Always empty.

    Checked at import time. A guarantee that lives only in a docstring survives
    exactly until someone needs "just one request" for a retry helper, and the
    docstring is not what breaks.
    """
    found: set[str] = set()
    for name, value in list(globals().items()):
        if name.startswith("__"):
            continue
        if isinstance(value, types.ModuleType):
            origin = value.__name__
        else:
            origin = getattr(value, "__module__", "") or ""
        if origin.split(".")[0] in _TRAFFIC_CAPABLE_ROOTS:
            found.add(f"{name} ({origin})")
    return tuple(sorted(found))


def _refuse_traffic_capability() -> None:
    leaked = traffic_capabilities()
    if leaked:
        raise RuntimeTraceError(
            "runtime_trace records and correlates observations; it must not be able to "
            f"produce them. These names can emit traffic or start a process: {list(leaked)}"
        )


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

#: Signal names that are *dropped*, not redacted. A cookie value, a credential
#: header, a session identifier and a request body have no metadata reading — the
#: only honest amount of them to keep is none. Redacting them instead would mean
#: betting that a pattern list is complete against arbitrary user content, and
#: that bet is lost quietly.
#: The rule is component-wise and deliberately blunt: any name with one of these
#: words in it goes, so ``session_id`` and ``api_key_id`` are dropped along with
#: ``session`` and ``api_key``. Cookie facts are dropped too, because they belong
#: in a ``COOKIE_METADATA`` observation, which has a field for every flag and none
#: for a value.
_DROPPED_SIGNAL_KEY = re.compile(
    r"(^|_)(value|values|secret|secrets|token|tokens|password|passwd|passphrase|"
    r"authorization|auth|credential|credentials|cookie|cookies|session|sid|jwt|"
    r"bearer|key|keys|body|payload|signature|sig)(_|$)"
)

#: A signal name the contract accepts. Anything that cannot be folded into this
#: shape is refused at construction rather than silently renamed.
_SIGNAL_KEY = re.compile(r"^[a-z][a-z0-9_]*$")

_NON_KEY_CHARS = re.compile(r"[^a-z0-9]+")

_HTTP_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
})


def _normalize_signal_name(name: Any) -> str:
    folded = _NON_KEY_CHARS.sub("_", str(name).strip().lower()).strip("_")
    if not _SIGNAL_KEY.match(folded):
        raise RuntimeTraceError(
            f"signal name {name!r} cannot be recorded: a name must fold to "
            f"{_SIGNAL_KEY.pattern}, and {folded!r} does not"
        )
    return folded


def _redact_query_values(text: str) -> str:
    """Replace every query-parameter value, keeping the parameter names.

    Deciding *which* parameter holds a token is a judgement call made once per
    parameter name in a codebase nobody here has read. Parameter names are what a
    surface is matched on; the values are never needed, so they never survive.
    """
    head, sep, tail = text.partition("?")
    if not sep:
        return text
    query, hash_sep, fragment = tail.partition("#")
    parts = []
    for pair in query.split("&"):
        if not pair:
            continue
        name, eq, _value = pair.partition("=")
        parts.append(f"{name}={REDACTED}" if eq else name)
    return f"{head}?{'&'.join(parts)}{hash_sep}{fragment}"


def _redact_scalar(value: Any, log: RedactionLog) -> Any:
    if isinstance(value, str):
        return redact(_redact_query_values(value), log)
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    raise RuntimeTraceError(
        f"a signal value must be a string, number, boolean, null, or a list of those; "
        f"got {type(value).__name__}"
    )


def _redact_value(value: Any, log: RedactionLog) -> Any:
    if isinstance(value, (list, tuple)):
        return tuple(_redact_scalar(item, log) for item in value)
    return _redact_scalar(value, log)


# ---------------------------------------------------------------------------
# Surfaces
# ---------------------------------------------------------------------------


def _split_surface(surface: str) -> tuple[str | None, str]:
    """Fold a surface to ``(method, locator)``. Query and fragment are discarded.

    A surface reaches this from three different worlds — a route as the server
    templated it, a URL as a client saw it, and a file path as a static reader
    recorded it — and they have to be comparable or nothing correlates.
    """
    text = str(surface).strip().replace("\\", "/")
    method: str | None = None
    head, _, rest = text.partition(" ")
    if rest and head.upper() in _HTTP_METHODS and head.upper() == head:
        method, text = head.upper(), rest.strip()
    if "://" in text:
        _, _, authority = text.partition("://")
        _, slash, path = authority.partition("/")
        text = f"/{path}" if slash else "/"
    text = text.partition("#")[0].partition("?")[0]
    while text.startswith("./"):
        text = text[2:]
    if len(text) > 1:
        text = text.rstrip("/")
    return method, text


def _is_placeholder(segment: str) -> bool:
    return bool(segment) and (
        (segment.startswith("{") and segment.endswith("}"))
        or (segment.startswith("<") and segment.endswith(">"))
        or segment.startswith(":")
        or segment == "*"
    )


def _file_parts(locator: str) -> tuple[str, str] | None:
    """Split ``app/reports.py:41`` into its file and the part after the colon."""
    path, sep, tail = locator.rpartition(":")
    if not sep or not path or "/" not in locator and "." not in locator:
        return None
    return path, tail


def _match_surfaces(observed: str, claimed: str) -> str:
    """How the observed surface lines up with one the claim names."""
    observed_method, observed_locator = _split_surface(observed)
    claimed_method, claimed_locator = _split_surface(claimed)
    if not observed_locator or not claimed_locator:
        return UNDETERMINED
    if observed_method and claimed_method and observed_method != claimed_method:
        return NONE

    if observed_locator == claimed_locator:
        return EXACT

    observed_file = _file_parts(observed_locator)
    claimed_file = _file_parts(claimed_locator)
    if observed_file and claimed_file and observed_file[0] == claimed_file[0]:
        # Same file, different line or symbol. A real match, and a coarse one; the
        # strength is recorded so a reader is not told this was exact.
        return FILE
    if observed_file and observed_file[0] == claimed_locator:
        return FILE
    if claimed_file and claimed_file[0] == observed_locator:
        return FILE

    observed_segments = observed_locator.strip("/").split("/")
    claimed_segments = claimed_locator.strip("/").split("/")
    if len(observed_segments) != len(claimed_segments):
        return NONE
    templated = False
    for left, right in zip(observed_segments, claimed_segments):
        if left == right:
            continue
        if _is_placeholder(right) or _is_placeholder(left):
            templated = True
            continue
        return NONE
    return TEMPLATE if templated else EXACT


_MATCH_RANK = {EXACT: 3, TEMPLATE: 2, FILE: 1, NONE: 0, UNDETERMINED: -1}


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """One recorded thing a system did, reduced to metadata.

    ``signals`` is a sorted tuple of ``(name, value)`` pairs so two traces built
    from the same recording are byte-identical. ``dropped_signals`` names what was
    removed, because a reader has to be able to tell a field that was dropped from
    one that was never observed.
    """

    observation_id: str
    kind: str
    surface: str = ""
    signals: tuple[tuple[str, Any], ...] = ()
    dropped_signals: tuple[str, ...] = ()
    surface_redacted: bool = False
    observed_at: str | None = None
    note: str = ""
    redaction_counts: tuple[tuple[str, int], ...] = ()

    @property
    def signal_map(self) -> dict[str, Any]:
        return {name: value for name, value in self.signals}

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "observation_id": self.observation_id,
            "kind": self.kind,
            "signals": {name: _jsonable(value) for name, value in self.signals},
        }
        if self.surface:
            record["surface"] = self.surface
        if self.surface_redacted:
            record["surface_redacted"] = True
        if self.observed_at:
            record["observed_at"] = self.observed_at
        if self.dropped_signals:
            record["dropped_signals"] = list(self.dropped_signals)
        if self.note:
            record["note"] = self.note
        return record


def _jsonable(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value


def observe(
    observation_id: str,
    kind: str,
    *,
    surface: str = "",
    signals: Mapping[str, Any] | None = None,
    observed_at: str | None = None,
    note: str = "",
) -> Observation:
    """Record one observation, redacted before it exists as an object.

    Redaction happens here rather than at render time on purpose: an unredacted
    ``Observation`` is never constructed, so there is no window in which one could
    be logged, cached, or passed to something that writes.
    """
    observation_id = str(observation_id).strip()
    if not observation_id:
        raise RuntimeTraceError("an observation must carry an observation_id")
    if kind not in OBSERVATION_KINDS:
        raise RuntimeTraceError(
            f"unknown observation kind {kind!r}; choose from {list(OBSERVATION_KINDS)}"
        )

    log = RedactionLog()

    path, sep, query = str(surface or "").partition("?")
    redacted_path = redact(path, log) if path else ""
    surface_redacted = REDACTED in redacted_path
    clean_surface = redacted_path
    if sep:
        clean_surface = _redact_query_values(f"{redacted_path}?{query}")

    kept: dict[str, Any] = {}
    dropped: set[str] = set()
    for raw_name, raw_value in (signals or {}).items():
        name = _normalize_signal_name(raw_name)
        if _DROPPED_SIGNAL_KEY.search(name):
            dropped.add(name)
            continue
        value = _redact_value(raw_value, log)
        if name in kept and kept[name] != value:
            raise RuntimeTraceError(
                f"signal {name!r} was recorded twice with different values; the "
                "observation cannot say what was seen"
            )
        kept[name] = value

    return Observation(
        observation_id=observation_id,
        kind=kind,
        surface=clean_surface,
        signals=tuple(sorted(kept.items())),
        dropped_signals=tuple(sorted(dropped)),
        surface_redacted=surface_redacted,
        observed_at=str(observed_at) if observed_at else None,
        note=redact(_redact_query_values(str(note)), log) if note else "",
        redaction_counts=tuple(sorted(log.counts.items())),
    )


def cookie_metadata(
    observation_id: str,
    cookie_name: str,
    *,
    surface: str = "",
    secure: bool | None = None,
    http_only: bool | None = None,
    same_site: str | None = None,
    domain: str | None = None,
    path: str | None = None,
    observed_at: str | None = None,
) -> Observation:
    """Record a cookie's flags. There is no parameter for its value.

    :func:`observe` would drop a value signal anyway; this signature means a caller
    holding a cookie value has nowhere to put it in the first place, which is the
    difference between a rule and a filter.
    """
    signals: dict[str, Any] = {"name": str(cookie_name)}
    for key, value in (
        ("secure", secure),
        ("http_only", http_only),
        ("same_site", same_site),
        ("domain", domain),
        ("path", path),
    ):
        if value is not None:
            signals[key] = value
    return observe(
        observation_id,
        COOKIE_METADATA,
        surface=surface,
        signals=signals,
        observed_at=observed_at,
    )


# ---------------------------------------------------------------------------
# Static claims
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StaticClaim:
    """What static review believes, and what it predicts should be observable.

    ``surfaces`` usually carries both halves of the same thing — the code location
    a static reader recorded and the route it serves — because a runtime path will
    never equal a file path and something has to bridge them.

    ``expected_signals`` is the falsifiable part. A claim that predicts nothing
    cannot be checked by observation, and this module says so rather than treating
    silence as agreement.
    """

    claim_id: str
    surfaces: tuple[str, ...] = ()
    expected_signals: tuple[tuple[str, Any], ...] = ()
    evidence_ids: tuple[str, ...] = ()
    statement: str = ""

    @property
    def expectation_map(self) -> dict[str, Any]:
        return {name: value for name, value in self.expected_signals}


def claim(
    claim_id: str,
    *,
    surfaces: Sequence[str] = (),
    expected_signals: Mapping[str, Any] | None = None,
    evidence_ids: Sequence[str] = (),
    statement: str = "",
) -> StaticClaim:
    """Build a static claim to correlate observations against."""
    claim_id = str(claim_id).strip()
    if not claim_id:
        raise RuntimeTraceError("a claim must carry a claim_id")

    expectations: dict[str, Any] = {}
    for raw_name, value in (expected_signals or {}).items():
        name = _normalize_signal_name(raw_name)
        if _DROPPED_SIGNAL_KEY.search(name):
            raise RuntimeTraceError(
                f"a claim cannot predict {name!r}: that signal is dropped rather than "
                "recorded, so no observation could ever agree or disagree with it"
            )
        expectations[name] = tuple(value) if isinstance(value, (list, tuple)) else value

    return StaticClaim(
        claim_id=claim_id,
        surfaces=tuple(str(s).strip() for s in surfaces if str(s).strip()),
        expected_signals=tuple(sorted(expectations.items())),
        evidence_ids=tuple(dict.fromkeys(str(e).strip() for e in evidence_ids if str(e).strip())),
        statement=str(statement),
    )


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Correlation:
    """What one observation said about one claim, and why."""

    observation_id: str
    claim_id: str
    strength: str
    surface_match: str
    reason: str
    matched_surface: str | None = None
    compared_signals: tuple[str, ...] = ()
    uncomparable_signals: tuple[str, ...] = ()
    disagreeing_signals: tuple[str, ...] = ()
    static_evidence_ids: tuple[str, ...] = ()

    @property
    def supports(self) -> bool:
        """Only ``CONFIRMS`` supports a claim. The other three do not, differently."""
        return self.strength == CONFIRMS

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "observation_id": self.observation_id,
            "claim_id": self.claim_id,
            "strength": self.strength,
            "surface_match": self.surface_match,
            "reason": self.reason,
        }
        if self.matched_surface is not None:
            record["matched_surface"] = self.matched_surface
        if self.compared_signals:
            record["compared_signals"] = list(self.compared_signals)
        if self.uncomparable_signals:
            record["uncomparable_signals"] = list(self.uncomparable_signals)
        if self.disagreeing_signals:
            record["disagreeing_signals"] = list(self.disagreeing_signals)
        if self.static_evidence_ids:
            record["static_evidence_ids"] = list(self.static_evidence_ids)
        return record


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, str) and isinstance(right, str):
        return left.strip().casefold() == right.strip().casefold()
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def _redaction_touched(value: Any) -> bool:
    if isinstance(value, str):
        return REDACTED in value
    if isinstance(value, (list, tuple)):
        return any(_redaction_touched(item) for item in value)
    return False


def correlate(observation: Observation, static_claim: StaticClaim) -> Correlation:
    """Decide what one observation says about one claim.

    The order of the checks is the contract. Anything that cannot be compared ends
    as ``INSUFFICIENT`` *before* anything is allowed to conclude ``UNRELATED``,
    because "we could not tell" collapsing into "nothing to see" is how a gap in
    instrumentation becomes a reassurance.
    """
    base = {
        "observation_id": observation.observation_id,
        "claim_id": static_claim.claim_id,
        "static_evidence_ids": static_claim.evidence_ids,
    }

    if not observation.surface:
        return Correlation(
            strength=INSUFFICIENT, surface_match=UNDETERMINED,
            reason="the observation records no surface, so it can be neither matched to "
                   "this claim nor excluded from it",
            **base,
        )
    if observation.surface_redacted:
        return Correlation(
            strength=INSUFFICIENT, surface_match=UNDETERMINED,
            reason="redaction altered the observed surface, so comparing it to this "
                   "claim's surfaces would compare a placeholder to a path",
            **base,
        )
    if not static_claim.surfaces:
        return Correlation(
            strength=INSUFFICIENT, surface_match=UNDETERMINED,
            reason="the claim names no surface, so nothing observed can be tied to it",
            **base,
        )

    best_match, best_surface = UNDETERMINED, None
    for candidate in static_claim.surfaces:
        result = _match_surfaces(observation.surface, candidate)
        if _MATCH_RANK[result] > _MATCH_RANK[best_match]:
            best_match, best_surface = result, candidate
        if best_match == EXACT:
            break

    if best_match == UNDETERMINED:
        # Every candidate was uncomparable rather than different. Saying "unrelated"
        # here would report a malformed surface as an answer about relevance.
        return Correlation(
            strength=INSUFFICIENT, surface_match=UNDETERMINED,
            reason=f"none of this claim's surfaces ({', '.join(static_claim.surfaces)}) "
                   f"could be compared to {observation.surface!r}",
            **base,
        )

    if best_match == NONE:
        return Correlation(
            strength=UNRELATED, surface_match=NONE,
            reason=f"{observation.surface!r} does not correspond to any surface this "
                   f"claim names ({', '.join(static_claim.surfaces)})",
            **base,
        )

    expectations = static_claim.expectation_map
    if not expectations:
        return Correlation(
            strength=INSUFFICIENT, surface_match=best_match, matched_surface=best_surface,
            reason="the surfaces match, but the claim predicts no runtime signal, so "
                   "there is nothing an observation could agree or disagree with",
            **base,
        )

    observed = observation.signal_map
    compared: list[str] = []
    uncomparable: list[str] = []
    disagreeing: list[str] = []
    for name, expected in sorted(expectations.items()):
        if name not in observed:
            uncomparable.append(name)
            continue
        if _redaction_touched(observed[name]):
            # Comparing "[REDACTED]" to a real value would manufacture a
            # disagreement out of a safety measure.
            uncomparable.append(name)
            continue
        compared.append(name)
        if not _same(observed[name], expected):
            disagreeing.append(name)

    if not compared:
        return Correlation(
            strength=INSUFFICIENT, surface_match=best_match, matched_surface=best_surface,
            reason=f"the surfaces match, but none of the signal(s) this claim predicts "
                   f"({', '.join(sorted(expectations))}) could be compared: "
                   f"{', '.join(uncomparable)} were not observed or were redacted",
            uncomparable_signals=tuple(uncomparable),
            **base,
        )

    if disagreeing:
        return Correlation(
            strength=CONTRADICTS, surface_match=best_match, matched_surface=best_surface,
            reason=f"at {best_surface}, the observation disagrees with the claim on "
                   f"{', '.join(disagreeing)}",
            compared_signals=tuple(compared),
            uncomparable_signals=tuple(uncomparable),
            disagreeing_signals=tuple(disagreeing),
            **base,
        )

    return Correlation(
        strength=CONFIRMS, surface_match=best_match, matched_surface=best_surface,
        reason=f"at {best_surface}, the observation agrees with the claim on "
               f"{', '.join(compared)}",
        compared_signals=tuple(compared),
        uncomparable_signals=tuple(uncomparable),
        **base,
    )


def correlate_all(
    observations: Sequence[Observation],
    claims: Sequence[StaticClaim],
) -> tuple[Correlation, ...]:
    """Correlate every observation against every claim, in a stable order.

    ``UNRELATED`` results are kept rather than filtered. "We looked and it had
    nothing to do with this" is a result, and dropping it leaves a reader unable to
    tell it apart from an observation that was never considered.
    """
    results = [
        correlate(observation, static_claim)
        for static_claim in claims
        for observation in observations
    ]
    results.sort(key=lambda item: (item.claim_id, item.observation_id))
    return tuple(results)


# ---------------------------------------------------------------------------
# What the correlations add up to
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SupportAssessment:
    """What a claim's runtime evidence amounts to. Never more than a hypothesis."""

    claim_id: str
    reason: str
    static_evidence_ids: tuple[str, ...] = ()
    confirming: tuple[str, ...] = ()
    contradicting: tuple[str, ...] = ()
    insufficient: tuple[str, ...] = ()
    unrelated: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        """Always ``HYPOTHESIS``.

        Not a placeholder for a value this module has not computed yet: a runtime
        observation records behaviour, and a finding claims cause. Only an
        independent verifier moves a status, and this is not one.
        """
        return HYPOTHESIS

    @property
    def verification_ready(self) -> bool:
        """Whether an independent verifier now has something to work with.

        Readiness is a queue, not a promotion. It requires static evidence, because
        runtime agreement alone is consistent with a dozen explanations, and it
        requires no contradiction, because a contradiction is the more interesting
        result and should be resolved before anything is verified.
        """
        return bool(self.confirming) and bool(self.static_evidence_ids) and not self.contradicting

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status,
            "verification_ready": self.verification_ready,
            "static_evidence_ids": list(self.static_evidence_ids),
            "confirming_observation_ids": list(self.confirming),
            "contradicting_observation_ids": list(self.contradicting),
            "insufficient_observation_ids": list(self.insufficient),
            "unrelated_observation_ids": list(self.unrelated),
            "reason": self.reason,
        }


def assess_support(
    static_claim: StaticClaim,
    correlations: Sequence[Correlation],
) -> SupportAssessment:
    """Summarize what runtime observation did and did not establish for one claim."""
    mine = [c for c in correlations if c.claim_id == static_claim.claim_id]
    buckets: dict[str, list[str]] = {strength: [] for strength in CORRELATION_STRENGTHS}
    for correlation in mine:
        buckets[correlation.strength].append(correlation.observation_id)

    confirming = tuple(sorted(buckets[CONFIRMS]))
    contradicting = tuple(sorted(buckets[CONTRADICTS]))
    insufficient = tuple(sorted(buckets[INSUFFICIENT]))
    unrelated = tuple(sorted(buckets[UNRELATED]))
    evidence = static_claim.evidence_ids

    if contradicting:
        reason = (
            f"{len(contradicting)} runtime observation(s) disagree with this claim. A "
            "contradiction is the more interesting result and is resolved before "
            "anything is verified; the claim stays a HYPOTHESIS."
        )
    elif confirming and evidence:
        reason = (
            f"{len(confirming)} runtime observation(s) agree with this claim, and it "
            f"cites {len(evidence)} static evidence record(s). That is enough to hand to "
            "an independent verifier, and not enough to be verified: the status stays "
            "HYPOTHESIS until the verifier says otherwise."
        )
    elif confirming:
        reason = (
            f"{len(confirming)} runtime observation(s) agree with this claim, but it "
            "cites no static evidence. Observation records behaviour, not cause, so on "
            "its own it leaves the claim a HYPOTHESIS."
        )
    elif insufficient and not unrelated:
        reason = (
            f"{len(insufficient)} observation(s) could not be compared to this claim. "
            "Nothing was shown either way — this is not evidence that the claim is wrong."
        )
    elif unrelated and not insufficient:
        reason = (
            f"{len(unrelated)} observation(s) were compared to this claim and had nothing "
            "to do with it. That is an observation about relevance, not about the claim."
        )
    elif mine:
        reason = (
            f"of {len(mine)} correlation(s), {len(unrelated)} were unrelated and "
            f"{len(insufficient)} could not be told apart either way; nothing here "
            "supports or undermines the claim."
        )
    else:
        reason = (
            "no runtime observation was correlated against this claim, which says "
            "nothing about it in either direction"
        )

    return SupportAssessment(
        claim_id=static_claim.claim_id,
        reason=reason,
        static_evidence_ids=evidence,
        confirming=confirming,
        contradicting=contradicting,
        insufficient=insufficient,
        unrelated=unrelated,
    )


# ---------------------------------------------------------------------------
# The artifact
# ---------------------------------------------------------------------------

#: Stated in every trace, because the reader of an artifact is rarely the person
#: who produced it and the caveats do not travel any other way.
TRACE_NOTES = (
    "No traffic was generated to produce this trace. Every observation was supplied "
    "by the caller; this module records and correlates.",
    "A runtime observation records behaviour, not cause. Nothing here verifies "
    "anything: every claim in this trace is a HYPOTHESIS.",
    "INSUFFICIENT and UNRELATED are different answers. UNRELATED means the "
    "observation was compared and had nothing to do with the claim; INSUFFICIENT "
    "means it could not be told.",
    "Cookie values, credential headers, session identifiers and request bodies are "
    "dropped rather than recorded, and query-string values are redacted.",
)


def build_trace(
    trace_id: str,
    *,
    mode: str = DEFAULT_EXECUTION_MODE,
    observations: Sequence[Observation] = (),
    claims: Sequence[StaticClaim] = (),
    production_safeguards: Sequence[str] = (),
    repository: str | None = None,
    commit: str | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Assemble a ``runtime-trace-v1`` artifact from observations and claims.

    ``mode`` defaults to ``LOCAL``. ``PRODUCTION_SAFE`` is refused unless
    ``production_safeguards`` names the restrictions it was chosen under — the
    same rule ``scope-v1`` applies to a production-mode scope, enforced here so a
    trace cannot be more permissive than the scope that authorized it.
    """
    trace_id = str(trace_id).strip()
    if not trace_id:
        raise RuntimeTraceError("a trace must carry a trace_id")

    mode = str(mode).strip().upper()
    if mode not in EXECUTION_MODES:
        raise RuntimeTraceError(
            f"unknown execution mode {mode!r}; choose from {list(EXECUTION_MODES)}"
        )
    safeguards = tuple(dict.fromkeys(str(s).strip() for s in production_safeguards if str(s).strip()))
    if mode == PRODUCTION_SAFE and not safeguards:
        raise RuntimeTraceError(
            "PRODUCTION_SAFE must be chosen explicitly and carry the restrictions it was "
            "chosen under; a production trace with no stated limits is not a safeguard"
        )
    if mode != PRODUCTION_SAFE and safeguards:
        raise RuntimeTraceError(
            f"production safeguards were supplied for a {mode} trace; recording "
            "restrictions that were never in force overstates what was done"
        )

    seen: set[str] = set()
    for observation in observations:
        if observation.observation_id in seen:
            raise RuntimeTraceError(
                f"duplicate observation_id {observation.observation_id!r}; two recordings "
                "under one id make a correlation depend on iteration order"
            )
        seen.add(observation.observation_id)

    claim_ids: set[str] = set()
    for static_claim in claims:
        if static_claim.claim_id in claim_ids:
            raise RuntimeTraceError(f"duplicate claim_id {static_claim.claim_id!r}")
        claim_ids.add(static_claim.claim_id)

    correlations = correlate_all(observations, claims)
    counts = {strength: 0 for strength in CORRELATION_STRENGTHS}
    for correlation in correlations:
        counts[correlation.strength] += 1

    totals: dict[str, int] = {}
    for observation in observations:
        for pattern, hits in observation.redaction_counts:
            totals[pattern] = totals.get(pattern, 0) + hits

    artifact: dict[str, Any] = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "trace_id": trace_id,
        "execution_mode": mode,
        "emits_traffic": False,
        "redaction": {
            "applied": True,
            "replacement": REDACTED,
            "total_values_redacted": sum(totals.values()),
            "by_pattern": dict(sorted(totals.items())),
        },
        "observations": [observation.as_dict() for observation in observations],
        "correlations": [correlation.as_dict() for correlation in correlations],
        "assessments": [
            assess_support(static_claim, correlations).as_dict() for static_claim in claims
        ],
        "counts": counts,
        "notes": list(TRACE_NOTES) + [str(note) for note in notes],
    }
    if safeguards:
        artifact["production_safeguards"] = list(safeguards)
    if repository:
        artifact["repository"] = str(repository)
    if commit:
        artifact["commit"] = str(commit)
    return artifact


_refuse_traffic_capability()
