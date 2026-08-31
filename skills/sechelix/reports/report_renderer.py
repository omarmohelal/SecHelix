#!/usr/bin/env python3
"""Render one canonical SecHelix report as JSON, Markdown, SARIF, or HTML.

The renderer is deliberately dependency-free. It validates the minimum report
shape, recursively redacts secret-bearing values, and treats all report text as
untrusted when producing Markdown and HTML.
"""

from __future__ import annotations

import argparse
import copy
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REQUIRED_REPORT_KEYS = ("schema_version", "scope", "coverage", "findings", "blocked_checks", "release_recommendation")
COVERAGE_KEYS = ("applicable", "not_applicable", "unknown", "blocked", "integrity_critical_unknown")
EXECUTION_MODES = {"STATIC", "LOCAL", "STAGING", "PRODUCTION_SAFE"}
RELEASE_OUTCOMES = {"PASS", "PASS_WITH_KNOWN_RISK", "BLOCKED", "INCOMPLETE"}
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
}
FINDING_STATUSES = {
    "HYPOTHESIS", "VERIFIED", "LIKELY_BUT_UNPROVEN", "LIKELY_UNPROVEN",
    "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE", "BLOCKED",
    "BLOCKED_BY_ENVIRONMENT", "UNPROVEN",
}


class ReportValidationError(ValueError):
    """The canonical input report is not safe to render."""


def validate_report(report: Mapping[str, Any]) -> None:
    """Validate the minimum canonical report envelope.

    Full JSON Schema validation can run upstream. This validation is retained
    here so a malformed or empty document can never be rendered as a credible
    security report.
    """

    if not isinstance(report, Mapping):
        raise ReportValidationError("report must be a JSON object")
    missing = [key for key in REQUIRED_REPORT_KEYS if key not in report]
    if missing:
        raise ReportValidationError(f"report missing required key(s): {', '.join(missing)}")
    if not isinstance(report["scope"], Mapping):
        raise ReportValidationError("scope must be an object")
    if not str(report["scope"].get("project", "")).strip():
        raise ReportValidationError("scope.project is required")
    if str(report["scope"].get("mode", "")).upper() not in EXECUTION_MODES:
        raise ReportValidationError(f"scope.mode must be one of {sorted(EXECUTION_MODES)}")
    if not isinstance(report["coverage"], Mapping):
        raise ReportValidationError("coverage must be an object")
    missing_coverage = [key for key in COVERAGE_KEYS if key not in report["coverage"]]
    if missing_coverage:
        raise ReportValidationError(f"coverage missing required key(s): {', '.join(missing_coverage)}")
    coverage_values = [report["coverage"][key] for key in COVERAGE_KEYS]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in coverage_values):
        raise ReportValidationError("coverage counts must be non-negative integers")
    if sum(coverage_values[:4]) == 0:
        raise ReportValidationError("coverage is empty; a release report must record applicability")
    if not isinstance(report["findings"], list):
        raise ReportValidationError("findings must be an array")
    if not isinstance(report["blocked_checks"], list):
        raise ReportValidationError("blocked_checks must be an array")
    finding_ids = []
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, Mapping):
            raise ReportValidationError(f"findings[{index}] must be an object")
        for key in ("id", "title", "severity", "status"):
            if not str(finding.get(key, "")).strip():
                raise ReportValidationError(f"findings[{index}] missing {key}")
        if str(finding["severity"]).upper() not in SEVERITY_TO_SARIF:
            raise ReportValidationError(f"findings[{index}] has unsupported severity {finding['severity']!r}")
        if str(finding["status"]).upper() not in FINDING_STATUSES:
            raise ReportValidationError(f"findings[{index}] has unsupported status {finding['status']!r}")
        finding_ids.append(str(finding["id"]))
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
    scope = safe["scope"]
    coverage = safe["coverage"]
    lines = [
        f"# SecHelix security report — {_md(scope.get('project', 'Unnamed project'))}",
        "",
        f"- **Schema:** {_md(safe.get('schema_version'))}",
        f"- **Mode:** {_md(scope.get('mode'))}",
        f"- **Release recommendation:** {_md(safe.get('release_recommendation', 'INCOMPLETE'))}",
        "",
        "## Scope",
        "",
        f"- **In scope:** {_md(scope.get('in_scope'))}",
        f"- **Out of scope:** {_md(scope.get('out_of_scope'))}",
        f"- **Restrictions:** {_md(scope.get('restrictions'))}",
        "",
        "## Architecture and trust boundaries",
        "",
        _md(safe.get("architecture", {}).get("summary") if isinstance(safe.get("architecture"), Mapping) else safe.get("architecture")),
        "",
    ]
    _section_list(lines, "Trust boundaries", _items((safe.get("architecture") or {}).get("trust_boundaries") if isinstance(safe.get("architecture"), Mapping) else []))

    lines.extend(["## Role × object × action matrix", ""])
    matrix = safe.get("role_object_action_matrix", [])
    if matrix:
        lines.extend(["| Role | Object | Actions |", "|---|---|---|"])
        for row in matrix:
            if isinstance(row, Mapping):
                lines.append(f"| {_md(row.get('role'))} | {_md(row.get('object'))} | {_md(row.get('actions'))} |")
        lines.append("")
    else:
        lines.extend(["_Not provided._", ""])

    lines.extend([
        "## Coverage",
        "",
        "| Applicable | Not applicable | Unknown | Blocked |",
        "|---:|---:|---:|---:|",
        f"| {_md(coverage.get('applicable', 0))} | {_md(coverage.get('not_applicable', 0))} | {_md(coverage.get('unknown', 0))} | {_md(coverage.get('blocked', 0))} |",
        "",
    ])
    _section_list(lines, "Tools and evidence sources", safe.get("tools", []))

    lines.extend(["## Findings", ""])
    findings: Sequence[Mapping[str, Any]] = safe["findings"]
    if not findings:
        lines.extend(["_No findings recorded._", ""])
    for finding in findings:
        lines.extend([
            f"### {_md(finding.get('id'))}: {_md(finding.get('title'))}",
            "",
            f"- **Severity:** {_md(finding.get('severity'))}",
            f"- **Confidence:** {_md(finding.get('confidence'))}",
            f"- **Status:** {_md(finding.get('status'))}",
            f"- **Resolution:** {_md(finding.get('resolution', 'OPEN'))}",
            f"- **Surface:** {_md(finding.get('surface'))}",
            f"- **Prerequisites:** {_md(finding.get('prerequisites'))}",
            f"- **Attacker control:** {_md(finding.get('attacker_control'))}",
            f"- **Reachability:** {_md(finding.get('reachability'))}",
            f"- **Boundary failure:** {_md(finding.get('boundary_failure'))}",
            f"- **Safe reproduction:** {_md(finding.get('reproduction'))}",
            f"- **Impact:** {_md(finding.get('impact'))}",
            f"- **Root cause:** {_md(finding.get('root_cause'))}",
            f"- **Independent verification:** {_md(finding.get('independent_verification'))}",
            f"- **Fix:** {_md(finding.get('fix'))}",
            f"- **Regression proof:** {_md(finding.get('regression'))}",
            f"- **Residual risk:** {_md(finding.get('residual_risk'))}",
            f"- **References:** {_md(finding.get('references'))}",
            "",
        ])

    _section_list(lines, "Rejected candidates", safe.get("rejected_findings", []))
    _section_list(lines, "Blocked checks", safe.get("blocked_checks", []))
    return "\n".join(lines).rstrip() + "\n"


def _sarif_location(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations = finding.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return []
    first = locations[0]
    if not isinstance(first, Mapping) or not first.get("path"):
        return []
    region: dict[str, Any] = {}
    if isinstance(first.get("line"), int) and first["line"] > 0:
        region["startLine"] = first["line"]
    physical: dict[str, Any] = {"artifactLocation": {"uri": str(first["path"]).replace("\\", "/")}}
    if region:
        physical["region"] = region
    return [{"physicalLocation": physical}]


def render_sarif(report: Mapping[str, Any]) -> str:
    validate_report(report)
    safe = redact(report)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in safe["findings"]:
        finding_id = str(finding["id"])
        rules[finding_id] = {
            "id": finding_id,
            "name": re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding.get("title", finding_id))).strip("-")[:128] or finding_id,
            "shortDescription": {"text": str(finding.get("title", finding_id))},
            "properties": {
                "security-severity": str(finding.get("severity", "INFO")),
                "confidence": str(finding.get("confidence", "UNKNOWN")),
            },
        }
        result: dict[str, Any] = {
            "ruleId": finding_id,
            "level": SEVERITY_TO_SARIF.get(str(finding.get("severity", "INFO")).upper(), "note"),
            "message": {"text": f"{finding.get('title', finding_id)} — status {finding.get('status', 'UNKNOWN')}"},
            "properties": {
                "status": finding.get("status"),
                "resolution": finding.get("resolution", "OPEN"),
                "surface": finding.get("surface"),
                "independentVerification": finding.get("independent_verification"),
            },
        }
        locations = _sarif_location(finding)
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


def render_html(report: Mapping[str, Any]) -> str:
    validate_report(report)
    safe = redact(report)
    scope = safe["scope"]
    coverage = safe["coverage"]
    findings_html = []
    for finding in safe["findings"]:
        fields = (
            ("Surface", finding.get("surface")),
            ("Attacker control", finding.get("attacker_control")),
            ("Reachability", finding.get("reachability")),
            ("Boundary failure", finding.get("boundary_failure")),
            ("Safe reproduction", finding.get("reproduction")),
            ("Impact", finding.get("impact")),
            ("Root cause", finding.get("root_cause")),
            ("Independent verification", finding.get("independent_verification")),
            ("Fix", finding.get("fix")),
            ("Regression proof", finding.get("regression")),
            ("Residual risk", finding.get("residual_risk")),
        )
        details = "".join(f"<dt>{html.escape(label)}</dt><dd>{html.escape(_text(value))}</dd>" for label, value in fields)
        findings_html.append(
            '<article class="finding">'
            f"<p class=\"meta\">{html.escape(_text(finding.get('severity')))} · {html.escape(_text(finding.get('status')))}</p>"
            f"<h3>{html.escape(_text(finding.get('id')))}: {html.escape(_text(finding.get('title')))}</h3>"
            f"<dl>{details}</dl></article>"
        )
    architecture = safe.get("architecture", {})
    architecture_summary = architecture.get("summary") if isinstance(architecture, Mapping) else architecture
    trust_boundaries = architecture.get("trust_boundaries", []) if isinstance(architecture, Mapping) else []
    title = f"SecHelix report — {_text(scope.get('project', 'Unnamed project'))}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#081018;--panel:#101b27;--line:#26384a;--text:#e5edf4;--muted:#9db0c2;--cyan:#62d9ff;--green:#55e6a5}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}}main{{width:min(1040px,calc(100% - 32px));margin:auto;padding:48px 0}}h1,h2,h3{{line-height:1.15}}h1{{font-size:clamp(2rem,6vw,4rem)}}h2{{margin-top:3rem;border-bottom:1px solid var(--line);padding-bottom:.5rem}}.eyebrow,.meta{{color:var(--cyan);font:700 .78rem ui-monospace,monospace;text-transform:uppercase;letter-spacing:.08em}}.recommendation{{display:inline-block;padding:.45rem .7rem;border:1px solid var(--green);border-radius:.5rem;color:var(--green)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card,.finding{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}}dl{{display:grid;grid-template-columns:minmax(140px,220px) 1fr;gap:8px 16px}}dt{{color:var(--muted);font-weight:700}}dd{{margin:0;overflow-wrap:anywhere}}.empty{{color:var(--muted)}}@media(max-width:640px){{dl{{grid-template-columns:1fr}}}}
</style></head><body><main>
<p class="eyebrow">Evidence-first application security</p><h1>{html.escape(title)}</h1>
<p class="recommendation">{html.escape(_text(safe.get('release_recommendation', 'INCOMPLETE')))}</p>
<h2>Scope</h2><div class="grid"><div class="card"><strong>Mode</strong><p>{html.escape(_text(scope.get('mode')))}</p></div><div class="card"><strong>In scope</strong><p>{html.escape(_text(scope.get('in_scope')))}</p></div><div class="card"><strong>Restrictions</strong><p>{html.escape(_text(scope.get('restrictions')))}</p></div></div>
<h2>Architecture</h2><p>{html.escape(_text(architecture_summary))}</p><h3>Trust boundaries</h3>{_html_list(trust_boundaries)}
<h2>Coverage</h2><div class="grid"><div class="card">Applicable<br><strong>{html.escape(_text(coverage.get('applicable', 0)))}</strong></div><div class="card">Not applicable<br><strong>{html.escape(_text(coverage.get('not_applicable', 0)))}</strong></div><div class="card">Unknown<br><strong>{html.escape(_text(coverage.get('unknown', 0)))}</strong></div><div class="card">Blocked<br><strong>{html.escape(_text(coverage.get('blocked', 0)))}</strong></div></div>
<h2>Findings</h2>{''.join(findings_html) if findings_html else '<p class="empty">No findings recorded.</p>'}
<h2>Rejected candidates</h2>{_html_list(safe.get('rejected_findings', []))}
<h2>Blocked checks</h2>{_html_list(safe.get('blocked_checks', []))}
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
