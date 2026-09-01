"""Export one verified finding as a self-contained, checkable bundle.

A security claim you cannot check is a security claim you have to take on trust.
A proof bundle is the opposite: every artifact behind one finding, in files, with
a manifest and a digest over the manifest, so a recipient can verify that what
they received is what was produced.

This is the unit of external proof. A trophy-case entry, a disclosure email, and
a customer-facing report are all the same thing — a claim plus its evidence —
and shipping them as a directory rather than a paragraph is what makes the claim
falsifiable by the person receiving it.

Four rules.

**Only verified findings export.** A bundle is a proof, and there is nothing to
prove about a candidate that was never confirmed. Anything else is refused with
its reason, so a caller sees what was excluded instead of silently getting less.

**Redaction is on by default, not opt-in.** Bundles get emailed to strangers.
Secrets, tokens and absolute paths are stripped before writing, and the manifest
records that redaction occurred and how many values it touched. A bundle that
quietly contained a live credential would be worse than no bundle.

**The digest covers the manifest, and the manifest covers the files.** Tampering
with any artifact changes its recorded hash; tampering with the manifest changes
the digest. Neither is a signature — it detects accident and casual edit, not a
motivated forger with write access, and the bundle says so rather than implying
cryptographic provenance it does not have.

**Nothing is claimed that the report did not record.** If regression status was
`NOT_RUN`, the bundle says `NOT_RUN`. The export step never upgrades a status.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

VERIFIED = "VERIFIED"

BUNDLE_VERSION = "1.0"

#: Files a complete bundle contains. A file is omitted when the report has no
#: material for it; the manifest then records it as absent rather than empty, so a
#: reader can tell "not applicable" from "we forgot".
ARTIFACTS = (
    "finding.json",
    "evidence.json",
    "verification.json",
    "root-cause.json",
    "patch.diff",
    "regression.json",
    "retest.json",
)

#: Patterns redacted before anything is written. Deliberately broad: a false
#: redaction costs a reader one question, a missed one costs a credential.
_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\b(bearer|authorization)\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("password_assignment", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}")),
    ("windows_home", re.compile(r"[A-Za-z]:\\\\?Users\\\\?[^\\\\/\s\"']+")),
    ("posix_home", re.compile(r"/(?:home|Users)/[^/\s\"']+")),
)

REDACTED = "[REDACTED]"


class ProofBundleError(ValueError):
    """The finding cannot be exported as a proof bundle."""


@dataclass
class RedactionLog:
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "applied": self.total > 0,
            "replacement": REDACTED,
            "total_values_redacted": self.total,
            "by_pattern": dict(sorted(self.counts.items())),
        }


def redact(value: Any, log: RedactionLog) -> Any:
    """Recursively redact secrets and home paths. Structure is preserved."""
    if isinstance(value, str):
        text = value
        for name, pattern in _REDACTIONS:
            text, hits = pattern.subn(REDACTED, text)
            if hits:
                log.counts[name] = log.counts.get(name, 0) + hits
        return text
    if isinstance(value, Mapping):
        return {k: redact(v, log) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, log) for item in value]
    return value


def _evidence_for(report: Mapping[str, Any], finding: Mapping[str, Any]) -> list[Any]:
    """Collect the evidence records this finding actually cites."""
    wanted: set[str] = set()
    for key in ("evidence_ids",):
        wanted.update(str(i) for i in finding.get(key, []) or [])
    for block in ("verification", "remediation", "regression"):
        section = finding.get(block)
        if isinstance(section, Mapping):
            wanted.update(str(i) for i in section.get("evidence_ids", []) or [])

    records = report.get("evidence")
    if not isinstance(records, list):
        return []
    return [r for r in records if isinstance(r, Mapping) and str(r.get("evidence_id", "")) in wanted]


def _artifacts(report: Mapping[str, Any], finding: Mapping[str, Any],
               diff: str | None) -> dict[str, Any]:
    verification = finding.get("verification") or {}
    remediation = finding.get("remediation") or {}
    regression = finding.get("regression") or {}

    built: dict[str, Any] = {
        "finding.json": {
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "status": finding.get("status"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "affected_surface": finding.get("affected_surface"),
            "catalog_hypothesis_ids": finding.get("catalog_hypothesis_ids"),
            "evidence_chain": finding.get("evidence_chain"),
            "resolution": finding.get("resolution"),
        },
        "verification.json": {
            "independent": verification.get("independent"),
            "outcome": verification.get("outcome"),
            "verifier": verification.get("verifier"),
            "refutation_attempt": verification.get("refutation_attempt"),
            "evidence_ids": verification.get("evidence_ids"),
        },
        "regression.json": {
            # Never upgraded. NOT_RUN in the report is NOT_RUN in the bundle.
            "status": regression.get("status", "NOT_RUN"),
            "command": regression.get("command"),
            "assertion": regression.get("assertion"),
            "evidence_ids": regression.get("evidence_ids"),
        },
    }

    evidence = _evidence_for(report, finding)
    if evidence:
        built["evidence.json"] = evidence
    if remediation:
        built["root-cause.json"] = {
            "root_cause_fix": remediation.get("root_cause_fix"),
            "evidence_ids": remediation.get("evidence_ids"),
            "residual_risk": finding.get("residual_risk"),
        }
    if diff:
        built["patch.diff"] = diff

    retest = [r for r in evidence if str(r.get("phase", "")).upper() in {"RETEST", "REGRESSION"}]
    if retest:
        built["retest.json"] = retest
    return built


def _serialize(name: str, payload: Any) -> str:
    if name.endswith(".diff"):
        return str(payload)
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def build_bundle(
    report: Mapping[str, Any],
    finding_id: str,
    *,
    diff: str | None = None,
    redacted: bool = True,
) -> dict[str, Any]:
    """Build one bundle. Returns file contents plus a manifest and its digest."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ProofBundleError("report findings must be an array")

    finding = next(
        (f for f in findings if isinstance(f, Mapping)
         and str(f.get("finding_id", "")) == str(finding_id)),
        None,
    )
    if finding is None:
        raise ProofBundleError(f"no finding {finding_id!r} in this report")

    status = str(finding.get("status", "")).upper()
    if status != VERIFIED:
        raise ProofBundleError(
            f"{finding_id} is {status or 'UNKNOWN'}, not VERIFIED; a bundle is a proof, "
            "and there is nothing to prove about an unconfirmed candidate"
        )

    log = RedactionLog()
    built = _artifacts(report, finding, diff)
    if redacted:
        built = {name: redact(payload, log) for name, payload in built.items()}

    files = {name: _serialize(name, payload) for name, payload in built.items()}

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "finding_id": str(finding_id),
        "report_id": report.get("report_id"),
        "target_revision": report.get("target_revision"),
        "generated_by": "sechelix_core.proof_bundle",
        "files": [
            {
                "name": name,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "bytes": len(content.encode("utf-8")),
            }
            for name, content in sorted(files.items())
        ],
        "absent": [name for name in ARTIFACTS if name not in files],
        "redaction": log.as_dict() if redacted else {
            "applied": False,
            "replacement": None,
            "total_values_redacted": 0,
            "by_pattern": {},
        },
        "integrity_note": (
            "manifest.sha256 covers manifest.json, which records a digest for every file. "
            "This detects accidental modification and casual editing. It is not a signature "
            "and proves nothing about origin."
        ),
    }

    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    files["manifest.json"] = manifest_text
    files["manifest.sha256"] = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest() + "\n"

    return {"finding_id": str(finding_id), "files": files, "manifest": manifest}


def verify_bundle(files: Mapping[str, str]) -> list[str]:
    """Check a received bundle. Returns problems; empty means internally consistent."""
    problems: list[str] = []
    if "manifest.json" not in files:
        return ["manifest.json is missing"]
    if "manifest.sha256" not in files:
        problems.append("manifest.sha256 is missing")
    else:
        expected = files["manifest.sha256"].strip()
        actual = hashlib.sha256(files["manifest.json"].encode("utf-8")).hexdigest()
        if expected != actual:
            problems.append("manifest.sha256 does not match manifest.json")

    try:
        manifest = json.loads(files["manifest.json"])
    except json.JSONDecodeError as exc:
        return problems + [f"manifest.json is not valid JSON: {exc}"]

    for entry in manifest.get("files", []):
        name = entry.get("name")
        if name not in files:
            problems.append(f"{name} is listed in the manifest but missing")
            continue
        actual = hashlib.sha256(files[name].encode("utf-8")).hexdigest()
        if actual != entry.get("sha256"):
            problems.append(f"{name} does not match its recorded digest")
    return problems


def export_bundles(
    report: Mapping[str, Any],
    *,
    diffs: Mapping[str, str] | None = None,
    redacted: bool = True,
) -> dict[str, Any]:
    """Export every verified finding, recording why each other one was refused."""
    diffs = diffs or {}
    bundles, refusals = [], []
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, Mapping):
            continue
        fid = str(finding.get("finding_id", ""))
        if not fid:
            continue
        try:
            bundles.append(build_bundle(report, fid, diff=diffs.get(fid), redacted=redacted))
        except ProofBundleError as exc:
            refusals.append({"finding_id": fid, "refused_because": str(exc)})
    return {
        "schema_version": "1.0",
        "bundles": bundles,
        "refusals": refusals,
        "exported_count": len(bundles),
        "refused_count": len(refusals),
        "redacted": redacted,
    }
