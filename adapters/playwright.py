"""Playwright JSON reporter failure normalization."""

from __future__ import annotations

from typing import Any, Mapping

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def _walk_suites(suites: list[Any], digest: str, output: list[dict[str, Any]], parents: tuple[str, ...] = ()) -> None:
    for raw_suite in suites:
        suite = require_mapping(raw_suite, "Playwright suite")
        title = text(suite.get("title"))
        trail = parents + ((title,) if title else ())
        for raw_spec in require_list(suite.get("specs"), "Playwright specs"):
            spec = require_mapping(raw_spec, "Playwright spec")
            spec_title = text(spec.get("title"), "Playwright test")
            tests = require_list(spec.get("tests"), "Playwright tests")
            for raw_test in tests:
                test = require_mapping(raw_test, "Playwright test")
                expected = text(test.get("expectedStatus"), "passed")
                for index, raw_result in enumerate(require_list(test.get("results"), "Playwright results")):
                    result = require_mapping(raw_result, "Playwright result")
                    status = text(result.get("status"), "unknown")
                    if status == expected:
                        continue
                    error = result.get("error", {})
                    error_map = error if isinstance(error, Mapping) else {}
                    message = text(error_map.get("message"), f"Test completed with status {status}")
                    full_title = " > ".join((*trail, spec_title))
                    output.append(
                        candidate(
                            source="playwright",
                            source_type="dynamic-test-evidence",
                            rule_id="playwright-test-result",
                            claim=f"{full_title}: {message}",
                            digest=digest,
                            finding_location=location(path=spec.get("file") or suite.get("file"), line=spec.get("line"), column=spec.get("column")),
                            observations=[message],
                            signal=tool_signal(status=status, expected_status=expected, retry=result.get("retry")),
                            properties={
                                "test": full_title,
                                "project": test.get("projectName"),
                                "attempt": index,
                                "duration_ms": result.get("duration"),
                            },
                        )
                    )
        _walk_suites(require_list(suite.get("suites"), "Playwright child suites"), digest, output, trail)


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "Playwright input")
    output: list[dict[str, Any]] = []
    _walk_suites(require_list(root.get("suites"), "Playwright suites"), digest, output)
    return output
