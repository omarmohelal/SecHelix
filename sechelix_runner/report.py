"""Rendering a recorded run.

Four formats, one source: whatever is in ``run.json``. Nothing here recomputes a
status, and nothing invents a finding a node did not produce.

The recurring problem these renderers are written against is that **an empty
report looks like a clean report**. A run where every lane was blocked produces
no findings, and so does a run of genuinely clean code. Every format below is
required to say which one happened, in the place a reader will actually look:
SARIF gets a real result rather than an empty array, HTML gets a banner, and
Markdown gets a sentence.
"""

from __future__ import annotations

import html
import json
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spectool/main/schemata/sarif-schema-2.1.0.json"


def _incomplete(run: dict[str, Any]) -> list[str]:
    return list(run.get("unsatisfied_mandatory", []))


def _undelivered(run: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Nodes that did not deliver, with the reason. This is the real content of
    a run that found nothing."""
    rows: list[tuple[str, str, str]] = []
    for node_id, record in sorted(run.get("records", {}).items()):
        if record.get("status") in ("SUCCEEDED", "SKIPPED"):
            continue
        rows.append(
            (node_id, record.get("status", "?"),
             record.get("blocker") or record.get("error") or "")
        )
    return rows


def to_sarif(run: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0.

    When a run is incomplete this emits a ``warning`` result saying so rather
    than an empty ``results`` array. An empty array in a code-scanning UI reads
    as "we looked and it was fine", which is exactly the wrong message for a run
    in which nothing was examined.
    """
    results: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    incomplete = _incomplete(run)
    if incomplete:
        rules.append(
            {
                "id": "sechelix/run-incomplete",
                "name": "RunIncomplete",
                "shortDescription": {"text": "SecHelix run did not complete"},
                "fullDescription": {
                    "text": (
                        "Mandatory nodes did not deliver, so this run cannot support a "
                        "security claim in either direction. It is not a statement that "
                        "the code is safe, and not a statement that it is unsafe."
                    )
                },
                "defaultConfiguration": {"level": "warning"},
            }
        )
        detail = "; ".join(f"{n} ({s}): {r}" for n, s, r in _undelivered(run)[:8])
        results.append(
            {
                "ruleId": "sechelix/run-incomplete",
                "level": "warning",
                "message": {
                    "text": (
                        f"SecHelix run {run.get('run_id')} is INCOMPLETE. "
                        f"Unsatisfied mandatory nodes: {', '.join(incomplete)}. "
                        f"No security claim can be made from this run. {detail}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": ".sechelix/"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    for finding in run.get("findings", []) or []:
        rule_id = finding.get("rule_id") or "sechelix/finding"
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding.get("severity")),
                "message": {"text": finding.get("title") or finding.get("claim", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("file", "unknown")},
                            "region": {"startLine": int(finding.get("line", 1) or 1)},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecHelix",
                        "informationUri": "https://sechelix.com",
                        "semanticVersion": run.get("runner_version", "0.0.0"),
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not incomplete,
                        "startTimeUtc": run.get("started_at"),
                        "endTimeUtc": run.get("finished_at"),
                    }
                ],
                "results": results,
            }
        ],
    }


def _sarif_level(severity: str | None) -> str:
    return {
        "CRITICAL": "error", "HIGH": "error",
        "MEDIUM": "warning", "LOW": "note", "INFO": "note",
    }.get(str(severity or "").upper(), "warning")


def to_html(run: dict[str, Any]) -> str:
    """A single self-contained page. No scripts, no external resources.

    A security report that pulls a stylesheet from a CDN is a security report
    that phones home from whatever machine opens it.
    """
    incomplete = _incomplete(run)
    banner = (
        f'<div class="banner bad"><strong>INCOMPLETE.</strong> Mandatory nodes did not '
        f'deliver: {html.escape(", ".join(incomplete))}. No security claim can be made '
        f'from this run &mdash; this is <em>not</em> a statement that the code is safe.</div>'
        if incomplete
        else '<div class="banner ok"><strong>All mandatory nodes delivered.</strong></div>'
    )

    rows = "\n".join(
        "<tr><td><code>{}</code></td><td>{}</td><td class='{}'>{}</td><td>{}</td></tr>".format(
            html.escape(node_id),
            html.escape(record.get("role", "")),
            "s-ok" if record.get("status") in ("SUCCEEDED", "SKIPPED") else "s-bad",
            html.escape(record.get("status", "")),
            html.escape((record.get("blocker") or record.get("error") or "")[:160]),
        )
        for node_id, record in sorted(run.get("records", {}).items())
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SecHelix run {html.escape(str(run.get('run_id', '')))}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.55 system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; }}
 .banner {{ padding: .85rem 1rem; border-radius: .5rem; margin: 1rem 0; }}
 .banner.bad {{ background: #fdecea; color: #611a15; }}
 .banner.ok {{ background: #edf7ed; color: #1e4620; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8883; vertical-align: top; }}
 .s-bad {{ color: #b3261e; font-weight: 600; }} .s-ok {{ color: #1e6b32; }}
 dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }}
 dt {{ color: #6b7280; }} code {{ font-size: .92em; }}
 @media (prefers-color-scheme: dark) {{
   .banner.bad {{ background: #3b1513; color: #f8c8c4; }}
   .banner.ok {{ background: #14301a; color: #b9e7c1; }}
 }}
</style></head><body>
<h1>SecHelix run</h1>
{banner}
<dl>
 <dt>Run</dt><dd><code>{html.escape(str(run.get('run_id','')))}</code></dd>
 <dt>Commit</dt><dd><code>{html.escape(str(run.get('target_commit','')))}</code></dd>
 <dt>Executor</dt><dd><code>{html.escape(str(run.get('executor','')))}</code></dd>
 <dt>Runner</dt><dd><code>{html.escape(str(run.get('runner_version','')))}</code></dd>
</dl>
<h2>Nodes</h2>
<table><thead><tr><th>Node</th><th>Role</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>
{rows}
</tbody></table>
<p><small>Generated by SecHelix. A node that did not deliver leaves its question
open; it is not evidence either way.</small></p>
</body></html>
"""


def to_markdown(run: dict[str, Any]) -> str:
    lines = [
        f"# SecHelix run {run.get('run_id','')}",
        "",
        f"- runner: `{run.get('runner_version','')}`",
        f"- commit: `{run.get('target_commit','')}`",
        f"- executor: `{run.get('executor','')}`",
        "",
        "## Nodes",
        "",
        "| node | role | status | detail |",
        "|---|---|---|---|",
    ]
    for node_id, record in sorted(run.get("records", {}).items()):
        detail = record.get("blocker") or record.get("error") or ""
        lines.append(
            f"| `{node_id}` | {record.get('role','')} | **{record.get('status','')}** | {detail} |"
        )
    lines += ["", "## Result", ""]
    incomplete = _incomplete(run)
    if incomplete:
        lines.append(
            "**INCOMPLETE.** Unsatisfied mandatory nodes: "
            + ", ".join(f"`{n}`" for n in incomplete)
            + ". No security claim can be made from this run."
        )
    else:
        lines.append("All mandatory nodes satisfied.")
    return "\n".join(lines)


RENDERERS = {
    "markdown": to_markdown,
    "json": lambda run: json.dumps(run, indent=2, sort_keys=True),
    "sarif": lambda run: json.dumps(to_sarif(run), indent=2, sort_keys=True),
    "html": to_html,
}
