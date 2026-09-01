#!/usr/bin/env python3
"""Render one canonical SecHelix report-v1 document as JSON, Markdown, SARIF, or HTML.

The renderer is deliberately dependency-free. It validates the minimum report-v1
envelope, recursively redacts secret-bearing values, and treats all report text
as untrusted when producing Markdown and HTML.
"""

from __future__ import annotations

import argparse
import copy
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REQUIRED_REPORT_KEYS = (
    "schema_version",
    "report_id",
    "scope_id",
    "mode",
    "generated_at",
    "coverage",
    "tools",
    "evidence",
    "findings",
    "rejected_false_positives",
    "blocked_checks",
    "release_recommendation",
    "redaction_summary",
)
COVERAGE_STATE_KEYS = ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED")
COVERAGE_KEYS = COVERAGE_STATE_KEYS + ("TOTAL", "integrity_critical_unknown")
EXECUTION_MODES = {"STATIC", "LOCAL", "STAGING", "PRODUCTION_SAFE"}
RELEASE_OUTCOMES = {"PASS", "PASS_WITH_KNOWN_RISK", "BLOCKED", "INCOMPLETE"}
EVIDENCE_CHAIN_LINKS = (
    ("attacker_control", "Attacker control"),
    ("reachability", "Reachability"),
    ("boundary_failure", "Boundary failure"),
    ("safe_reproduction", "Safe reproduction"),
    ("impact", "Impact"),
    ("preconditions", "Preconditions"),
    ("root_cause", "Root cause"),
)
SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:api_?key|authorization|cookie|credential|mnemonic|password|private_?key|seed_?phrase|secret|token)(?:$|_)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "UNASSIGNED": "none",
}
FINDING_STATUSES = {
    "HYPOTHESIS",
    "VERIFIED",
    "LIKELY_BUT_UNPROVEN",
    "FALSE_POSITIVE",
    "DUPLICATE_ROOT_CAUSE",
    "BLOCKED_BY_ENVIRONMENT",
}


class ReportValidationError(ValueError):
    """The canonical input report is not safe to render."""


def validate_report(report: Mapping[str, Any]) -> None:
    """Validate the minimum canonical report-v1 envelope.

    Full JSON Schema validation can run upstream. This validation is retained
    here so a malformed or empty document can never be rendered as a credible
    security report.
    """

    if not isinstance(report, Mapping):
        raise ReportValidationError("report must be a JSON object")
    missing = [key for key in REQUIRED_REPORT_KEYS if key not in report]
    if missing:
        raise ReportValidationError(f"report missing required key(s): {', '.join(missing)}")
    if not str(report["scope_id"]).strip():
        raise ReportValidationError("scope_id is required")
    if str(report["mode"]).upper() not in EXECUTION_MODES:
        raise ReportValidationError(f"mode must be one of {sorted(EXECUTION_MODES)}")
    if not isinstance(report["coverage"], Mapping):
        raise ReportValidationError("coverage must be an object")
    missing_coverage = [key for key in ("catalog_version",) + COVERAGE_KEYS if key not in report["coverage"]]
    if missing_coverage:
        raise ReportValidationError(f"coverage missing required key(s): {', '.join(missing_coverage)}")
    if not str(report["coverage"]["catalog_version"]).strip():
        raise ReportValidationError("coverage.catalog_version is required")
    coverage_values = [report["coverage"][key] for key in COVERAGE_KEYS]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in coverage_values):
        raise ReportValidationError("coverage counts must be non-negative integers")
    if sum(report["coverage"][key] for key in COVERAGE_STATE_KEYS) == 0:
        raise ReportValidationError("coverage is empty; a release report must record applicability")
    for key in ("tools", "evidence", "findings", "rejected_false_positives", "blocked_checks", "redaction_summary"):
        if not isinstance(report[key], list):
            raise ReportValidationError(f"{key} must be an array")
    finding_ids = []
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, Mapping):
            raise ReportValidationError(f"findings[{index}] must be an object")
        for key in ("finding_id", "title", "severity", "status"):
            if not str(finding.get(key, "")).strip():
                raise ReportValidationError(f"findings[{index}] missing {key}")
        if str(finding["severity"]).upper() not in SEVERITY_TO_SARIF:
            raise ReportValidationError(f"findings[{index}] has unsupported severity {finding['severity']!r}")
        if str(finding["status"]).upper() not in FINDING_STATUSES:
            raise ReportValidationError(f"findings[{index}] has unsupported status {finding['status']!r}")
        finding_ids.append(str(finding["finding_id"]))
    if len(finding_ids) != len(set(finding_ids)):
        raise ReportValidationError("finding IDs must be unique")
    if str(report["release_recommendation"]).upper() not in RELEASE_OUTCOMES:
        raise ReportValidationError(f"release_recommendation must be one of {sorted(RELEASE_OUTCOMES)}")


def _redact_string(value: str) -> str:
    redacted = value
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact(value: Any, *, key: str = "") -> Any:
    """Return a deep copy with secret-bearing keys and common tokens removed."""

    if key and SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): redact(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return copy.deepcopy(value)


def _text(value: Any, default: str = "Not provided") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _md(value: Any, default: str = "Not provided") -> str:
    """Escape untrusted content for GFM, including inline HTML."""

    return html.escape(_text(value, default), quote=False).replace("|", "\\|")


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _join(value: Any, separator: str = ", ") -> str:
    parts = [_text(item, "") for item in _items(value)]
    return separator.join(part for part in parts if part)


def _report_title(report: Mapping[str, Any]) -> str:
    project = _text(report.get("project"), "")
    return project or _text(report.get("scope_id"), "Unnamed scope")


def _evidence_index(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    index: dict[str, Mapping[str, Any]] = {}
    for record in _items(report.get("evidence")):
        if isinstance(record, Mapping) and str(record.get("evidence_id", "")).strip():
            index[str(record["evidence_id"])] = record
    return index


def _chain_text(finding: Mapping[str, Any], name: str) -> str:
    chain = finding.get("evidence_chain")
    link = chain.get(name) if isinstance(chain, Mapping) else None
    if not isinstance(link, Mapping):
        return ""
    marker = "established" if link.get("established") is True else "not established"
    parts = [f"[{marker}]", _text(link.get("statement"), "")]
    evidence = _join(link.get("evidence_ids"))
    if evidence:
        parts.append(f"(evidence: {evidence})")
    return " ".join(part for part in parts if part)


def _verification_text(finding: Mapping[str, Any]) -> str:
    verification = finding.get("verification")
    if not isinstance(verification, Mapping):
        return ""
    independence = "independent" if verification.get("independent") is True else "not independent"
    outcome = _text(verification.get("outcome"), "NOT_RUN")
    verifier = _text(verification.get("verifier"), "unnamed verifier")
    evidence = _join(verification.get("evidence_ids")) or "none recorded"
    refutation = _text(verification.get("refutation_attempt"), "no refutation attempt recorded")
    return f"{outcome} ({independence}) by {verifier}; evidence: {evidence}; refutation attempt: {refutation}"


def _remediation_text(finding: Mapping[str, Any]) -> str:
    remediation = finding.get("remediation")
    if not isinstance(remediation, Mapping):
        return ""
    fix = _text(remediation.get("root_cause_fix"), "")
    evidence = _join(remediation.get("evidence_ids"))
    return f"{fix} (evidence: {evidence})" if fix and evidence else fix


def _regression_text(finding: Mapping[str, Any]) -> str:
    regression = finding.get("regression")
    if not isinstance(regression, Mapping):
        return ""
    status = _text(regression.get("status"), "NOT_RUN")
    command = _text(regression.get("command"), "no command recorded")
    assertion = _text(regression.get("assertion"), "no assertion recorded")
    evidence = _join(regression.get("evidence_ids")) or "none recorded"
    return f"{status} — command: {command}; assertion: {assertion}; evidence: {evidence}"


def _tool_text(tool: Any) -> str:
    if not isinstance(tool, Mapping):
        return _text(tool, "")
    name = _text(tool.get("name"), "unnamed tool")
    version = _text(tool.get("version"), "unversioned")
    purpose = _text(tool.get("purpose"), "")
    return f"{name} {version} — {purpose}" if purpose else f"{name} {version}"


def _evidence_text(record: Any) -> str:
    if not isinstance(record, Mapping):
        return _text(record, "")
    source = record.get("source")
    origin = _text(source.get("name"), "") if isinstance(source, Mapping) else ""
    header = f"{_text(record.get('evidence_id'), 'unidentified evidence')} [{_text(record.get('kind'), 'CONTEXT')}/{_text(record.get('status'), 'RAW')}]"
    if origin:
        header = f"{header} via {origin}"
    return f"{header}: {_text(record.get('summary'), '')}"


def _finding_fields(finding: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Return the ordered label/value pairs shared by Markdown and HTML."""

    fields: list[tuple[str, str]] = [
        ("Severity", _text(finding.get("severity"))),
        ("Confidence", _text(finding.get("confidence"))),
        ("Status", _text(finding.get("status"))),
        ("Resolution", _text(finding.get("resolution"), "OPEN")),
        ("Catalog hypotheses", _text(_join(finding.get("catalog_hypothesis_ids")), "Not provided")),
        ("Affected surface", _text(_join(finding.get("affected_surface"), "; "), "Not provided")),
        ("Mappings", _text(_join(finding.get("mappings")), "Not provided")),
        ("Evidence", _text(_join(finding.get("evidence_ids")), "Not provided")),
    ]
    fields.extend((label, _text(_chain_text(finding, name))) for name, label in EVIDENCE_CHAIN_LINKS)
    fields.extend([
        ("Independent verification", _text(_verification_text(finding))),
        ("Fix", _text(_remediation_text(finding))),
        ("Regression proof", _text(_regression_text(finding))),
        ("Residual risk", _text(finding.get("residual_risk"))),
    ])
    return tuple(fields)


def _section_list(lines: list[str], title: str, values: Iterable[Any]) -> None:
    items = list(values)
    lines.extend([f"## {title}", ""])
    if not items:
        lines.extend(["_None recorded._", ""])
        return
    for item in items:
        lines.append(f"- {_md(item)}")
    lines.append("")


def render_json(report: Mapping[str, Any]) -> str:
    validate_report(report)
    return json.dumps(redact(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_markdown(report: Mapping[str, Any]) -> str:
    validate_report(report)
    safe = redact(report)
    coverage = safe["coverage"]
    lines = [
        f"# SecHelix security report — {_md(_report_title(safe))}",
        "",
        f"- **Schema:** {_md(safe.get('schema_version'))}",
        f"- **Report ID:** {_md(safe.get('report_id'))}",
        f"- **Mode:** {_md(safe.get('mode'))}",
        f"- **Generated at:** {_md(safe.get('generated_at'))}",
        f"- **Release recommendation:** {_md(safe.get('release_recommendation', 'INCOMPLETE'))}",
        "",
        "## Scope",
        "",
        f"- **Scope ID:** {_md(safe.get('scope_id'))}",
        f"- **Project:** {_md(safe.get('project'))}",
        f"- **Execution mode:** {_md(safe.get('mode'))}",
        f"- **Deployment state:** {_md(safe.get('deployment_state'))}",
        "",
        "## Coverage",
        "",
        "| Catalog | Applicable | Not applicable | Unknown | Blocked | Total | Integrity-critical unknown |",
        "|---|---:|---:|---:|---:|---:|---:|",
        "| "
        + " | ".join(
            [
                _md(coverage.get("catalog_version")),
                _md(coverage.get("APPLICABLE", 0)),
                _md(coverage.get("NOT_APPLICABLE", 0)),
                _md(coverage.get("UNKNOWN", 0)),
                _md(coverage.get("BLOCKED", 0)),
                _md(coverage.get("TOTAL", 0)),
                _md(coverage.get("integrity_critical_unknown", 0)),
            ]
        )
        + " |",
        "",
    ]
    _section_list(lines, "Tools and evidence sources", (_tool_text(tool) for tool in _items(safe.get("tools"))))
    _section_list(lines, "Evidence", (_evidence_text(record) for record in _items(safe.get("evidence"))))

    lines.extend(["## Findings", ""])
    findings: Sequence[Mapping[str, Any]] = safe["findings"]
    if not findings:
        lines.extend(["_No findings recorded._", ""])
    for finding in findings:
        lines.extend([
            f"### {_md(finding.get('finding_id'))}: {_md(finding.get('title'))}",
            "",
        ])
        lines.extend(f"- **{label}:** {_md(value)}" for label, value in _finding_fields(finding))
        lines.append("")

    _section_list(lines, "Rejected candidates", _items(safe.get("rejected_false_positives")))
    _section_list(lines, "Blocked checks", _items(safe.get("blocked_checks")))
    _section_list(lines, "Redaction summary", _items(safe.get("redaction_summary")))
    _section_list(lines, "Notes", _items(safe.get("notes")))
    return "\n".join(lines).rstrip() + "\n"


def _sarif_location(finding: Mapping[str, Any], evidence_by_id: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Derive a SARIF physical location from the first located evidence record."""

    for evidence_id in _items(finding.get("evidence_ids")):
        record = evidence_by_id.get(str(evidence_id))
        location = record.get("location") if isinstance(record, Mapping) else None
        if not isinstance(location, Mapping):
            continue
        path = location.get("path") or location.get("uri")
        if not path:
            continue
        region: dict[str, Any] = {}
        start = location.get("start_line")
        if isinstance(start, int) and not isinstance(start, bool) and start > 0:
            region["startLine"] = start
            end = location.get("end_line")
            if isinstance(end, int) and not isinstance(end, bool) and end >= start:
                region["endLine"] = end
        physical: dict[str, Any] = {"artifactLocation": {"uri": str(path).replace("\\", "/")}}
        if region:
            physical["region"] = region
        return [{"physicalLocation": physical}]
    return []


def render_sarif(report: Mapping[str, Any]) -> str:
    validate_report(report)
    safe = redact(report)
    evidence_by_id = _evidence_index(safe)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in safe["findings"]:
        finding_id = str(finding["finding_id"])
        rule_properties: dict[str, Any] = {
            "security-severity": str(finding.get("severity", "INFO")),
            "confidence": str(finding.get("confidence", "UNKNOWN")),
        }
        mappings = [str(item) for item in _items(finding.get("mappings"))]
        if mappings:
            rule_properties["tags"] = mappings
        rules[finding_id] = {
            "id": finding_id,
            "name": re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding.get("title", finding_id))).strip("-")[:128] or finding_id,
            "shortDescription": {"text": str(finding.get("title", finding_id))},
            "properties": rule_properties,
        }
        result: dict[str, Any] = {
            "ruleId": finding_id,
            "level": SEVERITY_TO_SARIF.get(str(finding.get("severity", "INFO")).upper(), "note"),
            "message": {"text": f"{finding.get('title', finding_id)} — status {finding.get('status', 'UNKNOWN')}"},
            "properties": {
                "status": finding.get("status"),
                "resolution": finding.get("resolution", "OPEN"),
                "surface": _join(finding.get("affected_surface"), "; "),
                "catalogHypothesisIds": [str(item) for item in _items(finding.get("catalog_hypothesis_ids"))],
                "evidenceIds": [str(item) for item in _items(finding.get("evidence_ids"))],
                "independentVerification": _verification_text(finding),
            },
        }
        locations = _sarif_location(finding, evidence_by_id)
        if locations:
            result["locations"] = locations
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SecHelix", "informationUri": "https://github.com/omarmohelal/SecHelix", "rules": list(rules.values())}},
            "results": results,
            "properties": {"releaseRecommendation": safe.get("release_recommendation", "INCOMPLETE")},
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _html_list(values: Iterable[Any]) -> str:
    items = list(values)
    if not items:
        return '<p class="empty">None recorded.</p>'
    return "<ul>" + "".join(f"<li>{html.escape(_text(item))}</li>" for item in items) + "</ul>"


def _html_card(label: str, value: Any) -> str:
    return f'<div class="card"><strong>{html.escape(label)}</strong><p>{html.escape(_text(value))}</p></div>'


def _html_count(label: str, value: Any) -> str:
    return f'<div class="card">{html.escape(label)}<br><strong>{html.escape(_text(value))}</strong></div>'


def render_html(report: Mapping[str, Any]) -> str:
    validate_report(report)
    safe = redact(report)
    coverage = safe["coverage"]
    findings_html = []
    for finding in safe["findings"]:
        details = "".join(
            f"<dt>{html.escape(label)}</dt><dd>{html.escape(value)}</dd>"
            for label, value in _finding_fields(finding)
        )
        findings_html.append(
            '<article class="finding">'
            f"<p class=\"meta\">{html.escape(_text(finding.get('severity')))} · {html.escape(_text(finding.get('status')))}</p>"
            f"<h3>{html.escape(_text(finding.get('finding_id')))}: {html.escape(_text(finding.get('title')))}</h3>"
            f"<dl>{details}</dl></article>"
        )
    scope_cards = "".join([
        _html_card("Scope ID", safe.get("scope_id")),
        _html_card("Mode", safe.get("mode")),
        _html_card("Project", safe.get("project")),
        _html_card("Generated at", safe.get("generated_at")),
    ])
    coverage_cards = "".join([
        _html_count("Applicable", coverage.get("APPLICABLE", 0)),
        _html_count("Not applicable", coverage.get("NOT_APPLICABLE", 0)),
        _html_count("Unknown", coverage.get("UNKNOWN", 0)),
        _html_count("Blocked", coverage.get("BLOCKED", 0)),
        _html_count("Total", coverage.get("TOTAL", 0)),
        _html_count("Integrity-critical unknown", coverage.get("integrity_critical_unknown", 0)),
    ])
    title = f"SecHelix report — {_report_title(safe)}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#081018;--panel:#101b27;--line:#26384a;--text:#e5edf4;--muted:#9db0c2;--cyan:#62d9ff;--green:#55e6a5}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}}main{{width:min(1040px,calc(100% - 32px));margin:auto;padding:48px 0}}h1,h2,h3{{line-height:1.15}}h1{{font-size:clamp(2rem,6vw,4rem)}}h2{{margin-top:3rem;border-bottom:1px solid var(--line);padding-bottom:.5rem}}.eyebrow,.meta{{color:var(--cyan);font:700 .78rem ui-monospace,monospace;text-transform:uppercase;letter-spacing:.08em}}.recommendation{{display:inline-block;padding:.45rem .7rem;border:1px solid var(--green);border-radius:.5rem;color:var(--green)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card,.finding{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}}dl{{display:grid;grid-template-columns:minmax(140px,220px) 1fr;gap:8px 16px}}dt{{color:var(--muted);font-weight:700}}dd{{margin:0;overflow-wrap:anywhere}}.empty{{color:var(--muted)}}@media(max-width:640px){{dl{{grid-template-columns:1fr}}}}
</style></head><body><main>
<p class="eyebrow">Evidence-first application security</p><h1>{html.escape(title)}</h1>
<p class="recommendation">{html.escape(_text(safe.get('release_recommendation', 'INCOMPLETE')))}</p>
<h2>Scope</h2><div class="grid">{scope_cards}</div>
<h2>Coverage</h2><p>Catalog {html.escape(_text(coverage.get('catalog_version')))}</p><div class="grid">{coverage_cards}</div>
<h2>Tools and evidence sources</h2>{_html_list(_tool_text(tool) for tool in _items(safe.get('tools')))}
<h2>Evidence</h2>{_html_list(_evidence_text(record) for record in _items(safe.get('evidence')))}
<h2>Findings</h2>{''.join(findings_html) if findings_html else '<p class="empty">No findings recorded.</p>'}
<h2>Rejected candidates</h2>{_html_list(_items(safe.get('rejected_false_positives')))}
<h2>Blocked checks</h2>{_html_list(_items(safe.get('blocked_checks')))}
<h2>Redaction summary</h2>{_html_list(_items(safe.get('redaction_summary')))}
<h2>Notes</h2>{_html_list(_items(safe.get('notes')))}
</main></body></html>\n"""


RENDERERS = {"json": render_json, "markdown": render_markdown, "sarif": render_sarif, "html": render_html}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="canonical SecHelix JSON report")
    parser.add_argument("--format", choices=tuple(RENDERERS), required=True)
    parser.add_argument("--output", type=Path, help="output path; stdout when omitted")
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        rendered = RENDERERS[args.format](report)
    except (OSError, json.JSONDecodeError, ReportValidationError) as exc:
        parser.error(str(exc))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
