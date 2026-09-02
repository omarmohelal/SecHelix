"""Dependency exploitability: CVE presence is not exploitability.

A scanner reports that a package with a known advisory is installed. That is a
fact about a lockfile. Whether an attacker can do anything with it is a different
question, and the distance between the two is where security teams lose their
time: a queue of hundreds of "criticals", most of which are unreachable, none of
which anyone can prove unreachable, all of which have to be looked at anyway.

This module makes the question explicit by walking a chain:

``installed → imported → vulnerable symbol used → reachable from an entry point →
attacker-controlled input reaches it → externally exposed``

Each link is ``CONFIRMED``, ``REFUTED`` or ``UNKNOWN``, and the verdict names
*which link decided it*, with the evidence that link cited. A verdict that cannot
say where the chain broke is an opinion.

Four rules keep it honest.

**``UNKNOWN`` never renders as ``NOT_EXPLOITABLE``.** This is the rule the module
exists for. Not being able to prove reachability is not proof of unreachability,
and the difference is the difference between "we checked" and "we did not look".
``NOT_EXPLOITABLE`` is reachable only through a link that was ``REFUTED`` *and*
cited evidence for the refutation; the contract enforces the pairing, so no
renderer downstream can quietly collapse the two.

**A claim without evidence is not a claim.** A link recorded as ``CONFIRMED`` or
``REFUTED`` with no evidence ids is read as ``UNKNOWN`` and listed as downgraded.
This fails closed in both directions: an unevidenced refutation cannot clear a
dependency, and an unevidenced confirmation cannot condemn one.

**Severity is carried, never computed, and never stands in for reachability.**
The advisory's label is relayed as the advisory wrote it; where the advisory
states only a scoring vector, the label stays ``UNASSIGNED`` rather than being
derived, because deriving one would make this the source of a number it is only
supposed to be passing on. Nothing in :func:`assess` reads severity — a
``CRITICAL`` with an unproven chain is ``UNKNOWN``, exactly like a ``LOW`` with
the same chain.

**Nothing is fetched.** Advisories arrive as data from the caller, in OSV or
Trivy shape. :func:`network_capabilities` inspects this module's namespace for
anything that could reach the network and importing fails if it finds one, so the
promise is a property of the module rather than a line in this docstring.
"""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

INSTALLED = "INSTALLED"
IMPORTED = "IMPORTED"
VULNERABLE_SYMBOL_USED = "VULNERABLE_SYMBOL_USED"
REACHABLE_FROM_ENTRY_POINT = "REACHABLE_FROM_ENTRY_POINT"
ATTACKER_CONTROLLED_INPUT = "ATTACKER_CONTROLLED_INPUT"
EXTERNALLY_EXPOSED = "EXTERNALLY_EXPOSED"

#: The chain, in order. Order is load-bearing: a broken chain is reported at its
#: *earliest* break, because that is the cheapest thing for a reader to check and
#: the least likely to be wrong.
CHAIN = (
    INSTALLED,
    IMPORTED,
    VULNERABLE_SYMBOL_USED,
    REACHABLE_FROM_ENTRY_POINT,
    ATTACKER_CONTROLLED_INPUT,
    EXTERNALLY_EXPOSED,
)

#: What each link asks, published so a reader can disagree with the question
#: rather than guess it.
LINK_QUESTIONS = {
    INSTALLED: "is a version of the package in the advisory's affected range actually installed",
    IMPORTED: "does this codebase import the package at all",
    VULNERABLE_SYMBOL_USED: "is the specific vulnerable symbol used, rather than merely the package",
    REACHABLE_FROM_ENTRY_POINT: "does a call path exist from an entry point to that use",
    ATTACKER_CONTROLLED_INPUT: "does attacker-controlled input reach it along that path",
    EXTERNALLY_EXPOSED: "is that entry point exposed outside the trust boundary",
}

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
UNKNOWN = "UNKNOWN"

LINK_STATES = (CONFIRMED, REFUTED, UNKNOWN)

#: States that assert something and therefore have to cite evidence.
CLAIMED_STATES = frozenset({CONFIRMED, REFUTED})

EXPLOITABLE = "EXPLOITABLE"
NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
UNKNOWN_EXPLOITABILITY = UNKNOWN

VERDICTS = (EXPLOITABLE, NOT_EXPLOITABLE, UNKNOWN_EXPLOITABILITY)

#: Severity vocabulary, shared with ``schemas/finding-v1.schema.json`` so a
#: dependency verdict sits beside a finding without a translation table.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED")
UNASSIGNED = "UNASSIGNED"

ADVISORY = "ADVISORY"
NOT_STATED = "NOT_STATED"

GRAPH_SCHEMA_VERSION = "1.0"


class DependencyGraphError(ValueError):
    """The advisory, link or assessment cannot be constructed."""


# ---------------------------------------------------------------------------
# The offline guarantee, enforced rather than asserted
# ---------------------------------------------------------------------------

#: Import roots that could fetch an advisory — or anything else. The check is
#: duplicated from :mod:`sechelix_core.runtime_trace` rather than shared, because
#: a guarantee that lives in another module can be weakened by an edit to that
#: module, and this one has to hold on its own.
_NETWORK_CAPABLE_ROOTS = frozenset({
    "aiohttp", "asyncio", "ftplib", "http", "httpx", "imaplib", "multiprocessing",
    "os", "paramiko", "poplib", "requests", "smtplib", "socket", "socketserver",
    "ssl", "subprocess", "telnetlib", "urllib", "urllib3", "webbrowser", "xmlrpc",
})


def network_capabilities() -> tuple[str, ...]:
    """Names in this module's namespace that could reach the network. Always empty.

    The caller supplies advisory data. A module that could go and get some would
    eventually be asked to, and then the analysis depends on what a remote service
    said on the day it ran.
    """
    found: set[str] = set()
    for name, value in list(globals().items()):
        if name.startswith("__"):
            continue
        if isinstance(value, types.ModuleType):
            origin = value.__name__
        else:
            origin = getattr(value, "__module__", "") or ""
        if origin.split(".")[0] in _NETWORK_CAPABLE_ROOTS:
            found.add(f"{name} ({origin})")
    return tuple(sorted(found))


def _refuse_network_capability() -> None:
    leaked = network_capabilities()
    if leaked:
        raise DependencyGraphError(
            "dependency_graph reasons over advisory data the caller supplies; it must not "
            f"be able to fetch any. These names can reach the network: {list(leaked)}"
        )


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Advisory:
    """A normalized advisory. Every field is relayed, none is derived."""

    advisory_id: str
    package: str = ""
    ecosystem: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    severity: str = UNASSIGNED
    severity_source: str = NOT_STATED
    severity_vector: str = ""
    aliases: tuple[str, ...] = ()
    summary: str = ""
    url: str = ""

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "advisory_id": self.advisory_id,
            "package": self.package,
            "severity": self.severity,
            "severity_source": self.severity_source,
        }
        for key, value in (
            ("ecosystem", self.ecosystem),
            ("installed_version", self.installed_version),
            ("fixed_version", self.fixed_version),
            ("severity_vector", self.severity_vector),
            ("summary", self.summary),
            ("advisory_url", self.url),
        ):
            if value:
                record[key] = value
        if self.aliases:
            record["aliases"] = list(self.aliases)
        return record


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _osv_fixed_version(affected: Mapping[str, Any]) -> str:
    for entry in affected.get("ranges", []) or []:
        if not isinstance(entry, Mapping):
            continue
        for event in entry.get("events", []) or []:
            if isinstance(event, Mapping) and event.get("fixed"):
                return _text(event["fixed"])
    return ""


def normalize_advisory(raw: Mapping[str, Any]) -> Advisory:
    """Normalize an OSV- or Trivy-shaped advisory. Nothing is fetched or scored.

    A severity *label* is taken only where the advisory states one. Where it
    states a scoring vector instead, the vector is carried and the label stays
    ``UNASSIGNED``: turning a vector into a label is a computation, and a computed
    severity that looks like a reported one is exactly the kind of number this
    project refuses to publish.
    """
    if not isinstance(raw, Mapping):
        raise DependencyGraphError(
            f"an advisory must be a mapping in OSV or Trivy shape, got {type(raw).__name__}"
        )

    severity_vector = ""
    if "VulnerabilityID" in raw or "PkgName" in raw:
        advisory_id = _text(raw.get("VulnerabilityID"))
        package = _text(raw.get("PkgName"))
        ecosystem = _text(raw.get("Ecosystem") or raw.get("Type"))
        installed = _text(raw.get("InstalledVersion"))
        fixed = _text(raw.get("FixedVersion"))
        label = _text(raw.get("Severity")).upper()
        aliases = tuple(_text(a) for a in raw.get("Aliases", []) or [] if _text(a))
        summary = _text(raw.get("Title") or raw.get("Description"))
        url = _text(raw.get("PrimaryURL"))
    elif "id" in raw:
        advisory_id = _text(raw.get("id"))
        affected = next(
            (a for a in raw.get("affected", []) or [] if isinstance(a, Mapping)), {}
        )
        package_block = affected.get("package") if isinstance(affected, Mapping) else {}
        package_block = package_block if isinstance(package_block, Mapping) else {}
        package = _text(package_block.get("name"))
        ecosystem = _text(package_block.get("ecosystem"))
        installed = ""
        fixed = _osv_fixed_version(affected) if isinstance(affected, Mapping) else ""
        database_specific = raw.get("database_specific")
        label = ""
        if isinstance(database_specific, Mapping):
            label = _text(database_specific.get("severity")).upper()
        for entry in raw.get("severity", []) or []:
            if isinstance(entry, Mapping) and _text(entry.get("score")):
                severity_vector = _text(entry["score"])
                break
        aliases = tuple(_text(a) for a in raw.get("aliases", []) or [] if _text(a))
        summary = _text(raw.get("summary") or raw.get("details"))
        url = ""
    else:
        raise DependencyGraphError(
            "an advisory must be OSV-shaped (an 'id') or Trivy-shaped (a "
            f"'VulnerabilityID'); got keys {sorted(raw)[:8]}"
        )

    if not advisory_id:
        raise DependencyGraphError("an advisory must carry an identifier")

    if label in SEVERITIES and label != UNASSIGNED:
        severity, source = label, ADVISORY
    else:
        # Includes the case where the advisory states a severity this vocabulary
        # does not have. Inventing a mapping for it would be a computation.
        severity, source = UNASSIGNED, NOT_STATED

    return Advisory(
        advisory_id=advisory_id,
        package=package,
        ecosystem=ecosystem,
        installed_version=installed,
        fixed_version=fixed,
        severity=severity,
        severity_source=source,
        severity_vector=severity_vector,
        aliases=aliases,
        summary=summary,
        url=url,
    )


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Link:
    """One question in the chain, its answer, and what the answer rests on."""

    name: str
    state: str
    statement: str
    evidence_ids: tuple[str, ...] = ()

    @property
    def is_claim(self) -> bool:
        """True when the link asserts something and therefore owes evidence."""
        return self.state in CLAIMED_STATES

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
        }


def link(
    name: str,
    state: str,
    *,
    statement: str = "",
    evidence_ids: Sequence[str] = (),
) -> Link:
    """Record one link. A missing statement is filled with the question it answers."""
    if name not in CHAIN:
        raise DependencyGraphError(f"unknown link {name!r}; choose from {list(CHAIN)}")
    state = str(state).strip().upper()
    if state not in LINK_STATES:
        raise DependencyGraphError(f"unknown link state {state!r}; choose from {list(LINK_STATES)}")
    ids = tuple(dict.fromkeys(str(e).strip() for e in evidence_ids if str(e).strip()))
    text = str(statement).strip() or f"{LINK_QUESTIONS[name]}: recorded as {state}"
    return Link(name=name, state=state, statement=text, evidence_ids=ids)


def _resolve(links: Iterable[Link]) -> tuple[dict[str, Link], list[dict[str, str]]]:
    """Fill in the links nobody assessed and downgrade the ones with no evidence."""
    provided: dict[str, Link] = {}
    for item in links:
        if not isinstance(item, Link):
            raise DependencyGraphError(
                f"every link must be built with link(), got {type(item).__name__}"
            )
        if item.name in provided:
            raise DependencyGraphError(
                f"link {item.name!r} was recorded twice; the verdict would depend on "
                "which one was read last"
            )
        provided[item.name] = item

    resolved: dict[str, Link] = {}
    downgraded: list[dict[str, str]] = []
    for name in CHAIN:
        item = provided.get(name)
        if item is None:
            resolved[name] = Link(
                name=name,
                state=UNKNOWN,
                statement=f"nobody assessed this link ({LINK_QUESTIONS[name]})",
            )
            continue
        if item.is_claim and not item.evidence_ids:
            reason = (
                f"the link was recorded as {item.state} with no evidence; an unevidenced "
                "claim is read as UNKNOWN, in both directions"
            )
            downgraded.append({"name": name, "claimed_state": item.state, "reason": reason})
            resolved[name] = Link(
                name=name,
                state=UNKNOWN,
                statement=f"{item.statement} — {reason}",
            )
            continue
        resolved[name] = item
    return resolved, downgraded


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExploitabilityVerdict:
    """One dependency, one chain, one verdict, and the link that decided it."""

    advisory: Advisory
    verdict: str
    deciding_link: str
    decided_by_state: str
    reason: str
    links: tuple[Link, ...]
    downgraded: tuple[tuple[str, str, str], ...] = ()

    @property
    def deciding_evidence_ids(self) -> tuple[str, ...]:
        for item in self.links:
            if item.name == self.deciding_link:
                return item.evidence_ids
        return ()

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for item in self.links:
            for evidence_id in item.evidence_ids:
                seen.setdefault(evidence_id, None)
        return tuple(seen)

    @property
    def actionable(self) -> bool:
        """Only ``EXPLOITABLE`` is a demonstrated path. ``UNKNOWN`` is not a pass."""
        return self.verdict == EXPLOITABLE

    @property
    def ruled_out(self) -> bool:
        """True only for ``NOT_EXPLOITABLE``. Never true for ``UNKNOWN``."""
        return self.verdict == NOT_EXPLOITABLE

    def as_dict(self) -> dict[str, Any]:
        record = self.advisory.as_dict()
        record.update({
            "verdict": self.verdict,
            "deciding_link": self.deciding_link,
            "decided_by_state": self.decided_by_state,
            "deciding_evidence_ids": list(self.deciding_evidence_ids),
            "reason": self.reason,
            "links": [item.as_dict() for item in self.links],
            "evidence_ids": list(self.evidence_ids),
        })
        if self.downgraded:
            record["downgraded_links"] = [
                {"name": name, "claimed_state": claimed, "reason": reason}
                for name, claimed, reason in self.downgraded
            ]
        return record


def assess(advisory: Advisory | Mapping[str, Any], links: Sequence[Link] = ()) -> ExploitabilityVerdict:
    """Decide whether this advisory is exploitable *here*, and say what decided it.

    Severity is never read. A ``CRITICAL`` advisory whose reachability nobody
    established is ``UNKNOWN``, exactly like a ``LOW`` one; treating severity as
    evidence of reachability is the substitution this module exists to refuse.
    """
    if not isinstance(advisory, Advisory):
        advisory = normalize_advisory(advisory)

    resolved, downgraded = _resolve(links)
    ordered = tuple(resolved[name] for name in CHAIN)

    refuted = [item for item in ordered if item.state == REFUTED]
    if refuted:
        broken = refuted[0]
        reason = (
            f"the chain is broken at {broken.name}: {broken.statement} "
            f"(evidence: {', '.join(broken.evidence_ids)})"
        )
        return ExploitabilityVerdict(
            advisory=advisory, verdict=NOT_EXPLOITABLE, deciding_link=broken.name,
            decided_by_state=REFUTED, reason=reason, links=ordered,
            downgraded=_as_rows(downgraded),
        )

    unknown = [item for item in ordered if item.state == UNKNOWN]
    if unknown:
        first = unknown[0]
        reason = (
            f"{first.name} is UNKNOWN: {first.statement}. Nothing here shows the "
            "dependency is unreachable — not being able to prove reachability is not "
            "proof of unreachability, so this is not a clean result."
        )
        return ExploitabilityVerdict(
            advisory=advisory, verdict=UNKNOWN_EXPLOITABILITY, deciding_link=first.name,
            decided_by_state=UNKNOWN, reason=reason, links=ordered,
            downgraded=_as_rows(downgraded),
        )

    terminal = ordered[-1]
    reason = (
        f"every link in the chain is CONFIRMED with evidence; it completes at "
        f"{terminal.name}: {terminal.statement} "
        f"(evidence: {', '.join(terminal.evidence_ids)})"
    )
    return ExploitabilityVerdict(
        advisory=advisory, verdict=EXPLOITABLE, deciding_link=terminal.name,
        decided_by_state=CONFIRMED, reason=reason, links=ordered,
        downgraded=_as_rows(downgraded),
    )


def _as_rows(downgraded: Sequence[Mapping[str, str]]) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (row["name"], row["claimed_state"], row["reason"]) for row in downgraded
    )


# ---------------------------------------------------------------------------
# The artifact
# ---------------------------------------------------------------------------

#: Stated in every report, because a verdict list gets read by someone who was not
#: there when it was produced.
GRAPH_NOTES = (
    "UNKNOWN is not NOT_EXPLOITABLE. Not being able to prove reachability is not "
    "proof of unreachability, and nothing here should be read as a clean result.",
    "CVE presence is not exploitability. Every verdict names the link that decided "
    "it and the evidence that link cited.",
    "Severity is carried from the advisory, never recomputed, and never used as a "
    "substitute for reachability.",
    "Nothing was fetched to produce this report. Every advisory was supplied by the "
    "caller.",
)


def build_report(
    verdicts: Sequence[ExploitabilityVerdict],
    *,
    repository: str | None = None,
    commit: str | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Assemble a ``dependency-exploitability-v1`` artifact.

    Counts carry all three verdicts. A summary that reports the exploitable and
    the ruled-out while leaving the undetermined uncounted is the same collapse
    this module refuses one verdict at a time.
    """
    counts = {name: 0 for name in VERDICTS}
    seen: set[str] = set()
    for verdict in verdicts:
        if verdict.advisory.advisory_id in seen:
            raise DependencyGraphError(
                f"two assessments for {verdict.advisory.advisory_id!r}; a reader cannot "
                "tell which one the count refers to"
            )
        seen.add(verdict.advisory.advisory_id)
        counts[verdict.verdict] += 1

    artifact: dict[str, Any] = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "assessments": [verdict.as_dict() for verdict in verdicts],
        "counts": counts,
        "notes": list(GRAPH_NOTES) + [str(note) for note in notes],
    }
    if repository:
        artifact["repository"] = str(repository)
    if commit:
        artifact["commit"] = str(commit)
    return artifact


def render_markdown(artifact: Mapping[str, Any]) -> str:
    """Render a report for humans without letting UNKNOWN read as reassurance."""
    counts = artifact["counts"]
    lines = [
        "# Dependency exploitability",
        "",
        f"**{counts[EXPLOITABLE]} exploitable · {counts[NOT_EXPLOITABLE]} ruled out with "
        f"evidence · {counts[UNKNOWN_EXPLOITABILITY]} undetermined.**",
        "",
        "Undetermined is not ruled out. It means the chain could not be established "
        "either way, which is a statement about this analysis rather than about the "
        "dependency.",
        "",
        "| Advisory | Package | Severity | Verdict | Decided by |",
        "|---|---|---|---|---|",
    ]
    for assessment in artifact["assessments"]:
        severity = assessment["severity"]
        if assessment["severity_source"] == NOT_STATED:
            severity = f"{severity} (advisory stated none)"
        lines.append(
            f"| {assessment['advisory_id']} | {assessment['package']} | {severity} | "
            f"{assessment['verdict']} | {assessment['deciding_link']} "
            f"({assessment['decided_by_state']}) |"
        )
    lines += ["", "## Notes", ""]
    lines += [f"- {note}" for note in artifact["notes"]]
    return "\n".join(lines) + "\n"


_refuse_network_capability()
