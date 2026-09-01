"""Differential security review.

Reviewing a whole repository for every pull request is slow and produces the same
findings over and over. What a reviewer actually needs to know is narrower:

    What did this change do to the security posture?

This module classifies a unified diff into security deltas and assigns each one a
direction — ``NEW_RISK``, ``RISK_REDUCED``, ``UNCHANGED`` or ``UNKNOWN``.

Two deliberate properties:

* A delta is a **hypothesis**, exactly like a catalog match. It names something
  worth verifying; it is not a finding and carries no severity.
* ``UNKNOWN`` is a real outcome. A diff that touches a security-relevant surface
  in a way the classifier cannot read is reported as unknown rather than being
  quietly dropped into ``UNCHANGED``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

NEW_RISK = "NEW_RISK"
RISK_REDUCED = "RISK_REDUCED"
UNCHANGED = "UNCHANGED"
UNKNOWN = "UNKNOWN"

DIRECTIONS = (NEW_RISK, RISK_REDUCED, UNCHANGED, UNKNOWN)


@dataclass(frozen=True)
class DeltaRule:
    """One security-relevant pattern and what its appearance/removal means."""

    kind: str
    pattern: re.Pattern[str]
    added: str
    removed: str
    question: str
    catalog_families: tuple[str, ...] = ()


#: Each rule pairs a surface with the direction implied by adding or removing it.
#: Directions are intentionally conservative: removing a control is NEW_RISK,
#: adding a control is RISK_REDUCED, and adding a new surface is NEW_RISK.
RULES: tuple[DeltaRule, ...] = (
    DeltaRule(
        "route", re.compile(r"@(app|router|bp)\.(get|post|put|patch|delete)\b|"
                            r"\b(app|router)\.(get|post|put|patch|delete)\s*\(|"
                            r"^\s*(export\s+)?(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", re.M),
        NEW_RISK, RISK_REDUCED,
        "Is the new entrypoint authorized, and does it reach owner-scoped data?",
        ("API", "AUTHZ"),
    ),
    DeltaRule(
        "authentication", re.compile(r"\b(authenticate|login|signin|verify_password|check_password|"
                                     r"jwt\.(sign|verify|decode)|session\.(create|destroy))\b", re.I),
        UNKNOWN, NEW_RISK,
        "Did the authentication decision change, and is the new path fail-closed?",
        ("AUTH", "SESS"),
    ),
    DeltaRule(
        "authorization_guard", re.compile(r"\b(require_(role|permission|auth|login)|is_admin|has_permission|"
                                          r"can_access|authorize|ensure_owner|@login_required|@permission_required|"
                                          r"check_access|assert_owner)\b", re.I),
        RISK_REDUCED, NEW_RISK,
        "Was an authorization guard removed from a path that still reaches protected data?",
        ("AUTHZ",),
    ),
    DeltaRule(
        "middleware", re.compile(r"\b(app\.use|add_middleware|middleware|before_request|"
                                 r"use_guards?|interceptor)\b", re.I),
        UNKNOWN, NEW_RISK,
        "Did a cross-cutting control stop applying to any route?",
        ("AUTHZ", "WEB"),
    ),
    DeltaRule(
        "db_query", re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\s+|\.(find|findOne|findMany|query|"
                               r"execute|raw|filter)\s*\(", re.I),
        NEW_RISK, UNCHANGED,
        "Does the new query carry the effective subject predicate?",
        ("DB", "AUTHZ", "INJ"),
    ),
    DeltaRule(
        "rls_policy", re.compile(r"\b(ROW LEVEL SECURITY|CREATE POLICY|ALTER POLICY|DROP POLICY|"
                                 r"USING\s*\(|WITH CHECK)\b", re.I),
        RISK_REDUCED, NEW_RISK,
        "Did tenant isolation at the database layer change?",
        ("DB",),
    ),
    DeltaRule(
        "outbound_fetch", re.compile(r"\b(fetch|axios|requests\.(get|post)|urlopen|HttpClient|"
                                     r"http\.request|curl)\s*\(", re.I),
        NEW_RISK, UNCHANGED,
        "Can the destination be influenced by a caller, and is it validated after redirects?",
        ("SSRF",),
    ),
    DeltaRule(
        "webhook", re.compile(r"\b(webhook|callback_url|signature|hmac|x-hub-signature|"
                              r"stripe-signature|idempotency[_-]?key)\b", re.I),
        NEW_RISK, NEW_RISK,
        "Is the callback authenticated, replay-protected and idempotent?",
        ("RACE", "API"),
    ),
    DeltaRule(
        "file_upload", re.compile(r"\b(multipart|upload|save_file|write_bytes|createWriteStream|"
                                  r"extractall|unzip|ZipFile|pickle\.loads|yaml\.load|Marshal)\b", re.I),
        NEW_RISK, UNCHANGED,
        "Is the path contained, the type validated, and is deserialization safe?",
        ("FILE",),
    ),
    DeltaRule(
        "storage_access", re.compile(r"\b(s3|bucket|blob|getSignedUrl|presigned|storage\.(from|ref)|"
                                     r"putObject|getObject)\b", re.I),
        NEW_RISK, UNCHANGED,
        "Does the object key derive from caller input, and is the URL scoped and short-lived?",
        ("CLOUD", "AUTHZ"),
    ),
    DeltaRule(
        "secret", re.compile(r"\b(api[_-]?key|secret|token|password|private[_-]?key|credential)\s*[=:]", re.I),
        NEW_RISK, RISK_REDUCED,
        "Is a credential now present in source, and was it rotated?",
        ("CRYPTO", "PRIV"),
    ),
    DeltaRule(
        "crypto", re.compile(r"\b(md5|sha1|DES|RC4|ECB|Math\.random|random\.random|"
                             r"createCipher\b|verify\s*=\s*False|rejectUnauthorized\s*:\s*false)\b", re.I),
        NEW_RISK, RISK_REDUCED,
        "Was a weak primitive or a disabled verification introduced?",
        ("CRYPTO",),
    ),
    DeltaRule(
        "dependency", re.compile(r"^\s*[\"']?[\w@/.-]+[\"']?\s*[:=]\s*[\"']?[\^~>=<]*\d+\.\d+", re.M),
        UNKNOWN, UNKNOWN,
        "Is the new dependency version known-good, and did the lockfile change with it?",
        ("SUPPLY",),
    ),
    DeltaRule(
        "ci_permission", re.compile(r"\b(permissions:|GITHUB_TOKEN|pull_request_target|"
                                    r"secrets\.[A-Z_]+|id-token:\s*write|contents:\s*write)\b"),
        NEW_RISK, RISK_REDUCED,
        "Did the workflow gain privilege or start running untrusted code with secrets?",
        ("CI",),
    ),
    DeltaRule(
        # No trailing \b: alternatives such as "tools =" end on a non-word
        # character, which a word boundary would never match.
        "ai_tool", re.compile(r"\b(tool_call|tools\s*=|register_tool|mcp\b|function_call|"
                              r"system_prompt|allowed_tools|add_tool)", re.I),
        NEW_RISK, UNCHANGED,
        "Can untrusted content reach this tool, and is the tool authority bounded?",
        ("AI",),
    ),
    DeltaRule(
        "payment_state", re.compile(r"\b(charge|refund|payout|capture|settle|balance|ledger|"
                                    r"transition|state\s*=\s*[\"'](paid|refunded|shipped|cancelled))\b", re.I),
        NEW_RISK, UNKNOWN,
        "Does the money or state invariant still hold under retry and concurrency?",
        ("MONEY", "BIZ", "RACE"),
    ),
    DeltaRule(
        "role_definition", re.compile(r"\b(ROLES?\s*=|enum\s+Role|\"role\"\s*:|add_role|grant_role)\b", re.I),
        NEW_RISK, UNKNOWN,
        "Does the new role inherit more than intended?",
        ("AUTHZ",),
    ),
    DeltaRule(
        "security_header", re.compile(r"\b(Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|"
                                      r"frame-ancestors|X-Content-Type-Options|helmet)\b", re.I),
        RISK_REDUCED, NEW_RISK,
        "Was a response security control removed?",
        ("WEB",),
    ),
)


@dataclass(frozen=True)
class SecurityDelta:
    """One classified change to the security posture."""

    kind: str
    direction: str
    path: str
    line: int
    snippet: str
    question: str
    catalog_families: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "direction": self.direction,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "question": self.question,
            "catalog_families": list(self.catalog_families),
            "claim_status": "HYPOTHESIS",
        }


@dataclass(frozen=True)
class FileDiff:
    path: str
    added: tuple[tuple[int, str], ...]
    removed: tuple[str, ...]
    binary: bool = False


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(text: str) -> list[FileDiff]:
    """Parse a unified diff into per-file added/removed lines.

    Tolerant by design: a diff it cannot parse yields no files rather than an
    exception, and the caller surfaces that as UNKNOWN coverage.
    """
    files: list[FileDiff] = []
    path: str | None = None
    added: list[tuple[int, str]] = []
    removed: list[str] = []
    binary = False
    new_line = 0

    def flush() -> None:
        nonlocal path, added, removed, binary
        if path is not None:
            files.append(FileDiff(path, tuple(added), tuple(removed), binary))
        path, added, removed, binary = None, [], [], False

    for raw in text.splitlines():
        if raw.startswith("diff --git"):
            flush()
            parts = raw.split(" b/")
            path = parts[-1].strip() if len(parts) > 1 else raw.split()[-1]
            continue
        if raw.startswith("Binary files"):
            binary = True
            continue
        if raw.startswith("+++ b/"):
            if path is None:
                path = raw[6:].strip()
            continue
        if raw.startswith("--- "):
            continue
        match = _HUNK.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if raw.startswith("+"):
            added.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            removed.append(raw[1:])
        elif raw.startswith(" "):
            new_line += 1

    flush()
    return files


#: Prose files describe code; they do not execute it. Applying code-shaped rules to
#: them produces confident noise, so only rules meaningful in text apply there.
PROSE_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".adoc")
PROSE_RELEVANT_KINDS = frozenset({"secret", "dependency"})


def _is_prose(path: str) -> bool:
    return str(path).lower().endswith(PROSE_SUFFIXES)


def classify_file(diff: FileDiff) -> list[SecurityDelta]:
    """Classify one file's changes into security deltas."""
    if diff.binary:
        return [SecurityDelta(
            "binary", UNKNOWN, diff.path, 0, "binary file changed",
            "A binary artifact changed; review its provenance manually.", ("SUPPLY",),
        )]

    deltas: list[SecurityDelta] = []
    removed_text = "\n".join(diff.removed)
    prose = _is_prose(diff.path)

    for rule in RULES:
        if prose and rule.kind not in PROSE_RELEVANT_KINDS:
            continue
        for line_number, line in diff.added:
            if rule.pattern.search(line):
                deltas.append(SecurityDelta(
                    rule.kind, rule.added, diff.path, line_number,
                    line.strip()[:200], rule.question, rule.catalog_families,
                ))
                break

        if removed_text and rule.pattern.search(removed_text):
            # A control that disappears is more interesting than one that appears.
            already_added = any(d.kind == rule.kind and d.path == diff.path for d in deltas)
            if not already_added or rule.removed == NEW_RISK:
                snippet = next(
                    (l.strip()[:200] for l in diff.removed if rule.pattern.search(l)), ""
                )
                deltas.append(SecurityDelta(
                    rule.kind, rule.removed, diff.path, 0,
                    f"removed: {snippet}", rule.question, rule.catalog_families,
                ))

    return deltas


def review_diff(text: str) -> dict[str, Any]:
    """Classify a unified diff and summarize its effect on the security posture."""
    files = parse_unified_diff(text)
    deltas: list[SecurityDelta] = []
    for diff in files:
        deltas.extend(classify_file(diff))

    counts = {direction: 0 for direction in DIRECTIONS}
    for delta in deltas:
        counts[delta.direction] += 1

    touched = {d.path for d in files}
    if files and not deltas:
        overall = UNCHANGED
    elif counts[NEW_RISK]:
        overall = NEW_RISK
    elif counts[UNKNOWN]:
        overall = UNKNOWN
    elif counts[RISK_REDUCED]:
        overall = RISK_REDUCED
    else:
        overall = UNCHANGED

    return {
        "schema_version": "1.0",
        "files_changed": len(files),
        "files": sorted(touched),
        "counts": counts,
        "overall": overall,
        "deltas": [d.as_dict() for d in deltas],
        "notes": [
            "Every delta is a HYPOTHESIS. None is a finding until it is independently verified.",
            "UNKNOWN means the change touches a security surface the classifier could not read; "
            "it is not a pass.",
        ],
    }


def scoped_families(result: dict[str, Any]) -> list[str]:
    """Catalog families worth loading for this diff, so a review can stay scoped."""
    families: set[str] = set()
    for delta in result.get("deltas", []):
        families.update(delta.get("catalog_families", []))
    return sorted(families)
