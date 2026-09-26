#!/usr/bin/env python3
"""Optional real-browser integration benchmark for the bounded XSS proof.

Unlike the deterministic primitive benchmark, this harness uses the actual
Playwright-backed SecHelix browser by default. If Playwright/Chromium is not
available, the result is BLOCKED_BY_ENVIRONMENT rather than a failed or fake
measurement.
"""

from __future__ import annotations

import argparse
import html
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    LocalProofExecutor,
    ProofBehavior,
    XssBrowserSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy

MEASURED = "MEASURED"
BLOCKED_BY_ENVIRONMENT = "BLOCKED_BY_ENVIRONMENT"
FAILED = "FAILED"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        payload = urllib.parse.parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        if parsed.path == "/vulnerable":
            sink = payload
        elif parsed.path == "/clean":
            sink = html.escape(payload, quote=True)
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = (
            "<!doctype html><html><body><div id=\"sink\">"
            + sink
            + "</div></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def run_real_browser_xss_benchmark(
    *,
    browser_factory: Callable[..., Any] | None = None,
    sechelix_commit: str = "UNKNOWN",
) -> dict[str, Any]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        policy.grant(
            "127.0.0.1",
            port,
            protocol="http",
            purpose="SecHelix real-browser XSS integration fixture",
            scope_id="REAL-BROWSER-XSS",
        )
        kwargs: dict[str, Any] = {
            "timeout_seconds": 5,
            "max_requests": 4,
        }
        if browser_factory is not None:
            kwargs["browser_factory"] = browser_factory
        executor = LocalProofExecutor(policy, **kwargs)
        base = f"http://127.0.0.1:{port}"

        cases = []
        blocked: list[str] = []
        for case_id, path, expected in (
            ("XSS-REAL-VULNERABLE", "/vulnerable", ProofBehavior.VULNERABLE_BEHAVIOR),
            ("XSS-REAL-CLEAN", "/clean", ProofBehavior.SECURE_BEHAVIOR),
        ):
            plan = build_plan(
                ProofClass.XSS_EXECUTION,
                case_id,
                available_authority={"local_browser_runtime"},
            )
            clock = time.monotonic()
            result = executor.execute(
                plan,
                XssBrowserSpec(
                    url_template=base + path + "?q={payload}",
                    injection_selector="#sink",
                    timeout_ms=10_000,
                ),
            )
            elapsed = time.monotonic() - clock
            cases.append(
                {
                    "case_id": case_id,
                    "expected_behavior": expected.value,
                    "observed_behavior": result.behavior.value,
                    "matched": result.behavior is expected,
                    "elapsed_seconds": round(elapsed, 6),
                    "request_count": result.request_count,
                    "blocker": result.blocker or None,
                }
            )
            if result.behavior is ProofBehavior.BLOCKED:
                blocked.append(result.blocker or "browser backend unavailable")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    elapsed_total = time.monotonic() - started
    if blocked:
        measurement_status = BLOCKED_BY_ENVIRONMENT
    elif all(case["matched"] for case in cases):
        measurement_status = MEASURED
    else:
        measurement_status = FAILED

    return {
        "schema_version": "sechelix-real-browser-integration/v1",
        "result_kind": "REAL_BROWSER_XSS_INTEGRATION_BENCHMARK",
        "measurement_status": measurement_status,
        "sechelix_commit": sechelix_commit,
        "execution_mode": "LOCAL",
        "network_scope": "literal-loopback-only",
        "browser_backend": (
            "injected-test-backend"
            if browser_factory is not None
            else "SecHelix SafeAuthorizedBrowser / Playwright Chromium"
        ),
        "case_count": len(cases),
        "cases": cases,
        "elapsed_seconds": round(elapsed_total, 6),
        "limitations": [
            "This measures the bounded XSS proof plus browser-engine integration only.",
            "It is not a full SecHelix workflow benchmark.",
            "It does not measure candidate generation, verifier accuracy, remediation, or release-gate accuracy.",
            "A missing Playwright/Chromium runtime is BLOCKED_BY_ENVIRONMENT, not a clean or vulnerable result.",
        ],
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run the optional real-browser SecHelix XSS integration benchmark"
    )
    parser.add_argument("--sechelix-commit", default="UNKNOWN")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run_real_browser_xss_benchmark(sechelix_commit=args.sechelix_commit)
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0 if result["measurement_status"] in {MEASURED, BLOCKED_BY_ENVIRONMENT} else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
