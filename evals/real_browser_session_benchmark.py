#!/usr/bin/env python3
"""Optional real-browser integration benchmark for imported session isolation.

The benchmark uses two separate browser contexts against a literal-loopback
fixture: one receives a valid ephemeral session cookie and must reach a protected
selector, while the second receives an invalid session and must not. Missing
Playwright/Chromium is reported as BLOCKED_BY_ENVIRONMENT.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from sechelix_runner.pentest.access import AccessKind, ResolvedAccess
from sechelix_runner.pentest.browser import BrowserUnavailable, SessionProbe
from sechelix_runner.pentest.gateway import PolicyToolGateway
from sechelix_runner.pentest.request_policy import InteractionPolicy
from sechelix_runner.pentest.safe_browser import SafeAuthorizedBrowser
from sechelix_runner.pentest.scope import ScopeEndpoint, TargetScope
from sechelix_runner.sandbox import ExecutionMode

MEASURED = "MEASURED"
BLOCKED_BY_ENVIRONMENT = "BLOCKED_BY_ENVIRONMENT"
FAILED = "FAILED"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/protected":
            self.send_response(404)
            self.end_headers()
            return
        if "session=fixture-session-valid" not in str(self.headers.get("Cookie") or ""):
            body = b"<!doctype html><html><body><div id='login'>login</div></body></html>"
            self.send_response(401)
        else:
            body = b"<!doctype html><html><body><div id='protected'>protected</div></body></html>"
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def _access(*, valid: bool) -> ResolvedAccess:
    return ResolvedAccess(
        profile_name="valid-session" if valid else "invalid-session",
        role="buyer",
        kind=AccessKind.SESSION,
        username=None,
        password=None,
        headers={},
        cookies=(
            {
                "name": "session",
                "value": "fixture-session-valid" if valid else "fixture-session-invalid",
                "domain": "127.0.0.1",
                "path": "/",
                "secure": False,
                "httpOnly": True,
            },
        ),
    )


def run_real_browser_session_benchmark(
    *,
    browser_factory: Callable[..., Any] = SafeAuthorizedBrowser,
    sechelix_commit: str = "UNKNOWN",
) -> dict[str, Any]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    cases: list[dict[str, Any]] = []
    blockers: list[str] = []
    try:
        url = f"http://127.0.0.1:{port}/protected"
        scope = TargetScope(
            primary_url=url,
            mode=ExecutionMode.LOCAL,
            endpoints=(
                ScopeEndpoint(
                    host="127.0.0.1",
                    schemes=("http",),
                    ports=(port,),
                ),
            ),
        )
        scope.validate_for_live_test()
        probe = SessionProbe(url=url, success_selector="#protected", timeout_ms=5_000)

        for case_id, valid, expected_verified in (
            ("SESSION-REAL-VALID", True, True),
            ("SESSION-REAL-INVALID", False, False),
        ):
            clock = time.monotonic()
            try:
                gateway = PolicyToolGateway(scope=scope)
                with browser_factory(
                    scope,
                    access=_access(valid=valid),
                    interaction_policy=InteractionPolicy(),
                    gateway=gateway,
                    authentication_context=(
                        "persona:valid-session" if valid else "persona:invalid-session"
                    ),
                ) as browser:
                    result = browser.verify_session(probe)
                elapsed = time.monotonic() - clock
                cases.append(
                    {
                        "case_id": case_id,
                        "expected_verified": expected_verified,
                        "observed_verified": bool(result.verified),
                        "matched": bool(result.verified) is expected_verified,
                        "challenge": result.challenge.value,
                        "elapsed_seconds": round(elapsed, 6),
                    }
                )
            except BrowserUnavailable as exc:
                elapsed = time.monotonic() - clock
                blockers.append(str(exc))
                cases.append(
                    {
                        "case_id": case_id,
                        "expected_verified": expected_verified,
                        "observed_verified": None,
                        "matched": False,
                        "challenge": None,
                        "elapsed_seconds": round(elapsed, 6),
                        "blocker": str(exc),
                    }
                )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    if blockers:
        measurement_status = BLOCKED_BY_ENVIRONMENT
    elif all(case["matched"] for case in cases):
        measurement_status = MEASURED
    else:
        measurement_status = FAILED

    return {
        "schema_version": "sechelix-real-browser-session-integration/v1",
        "result_kind": "REAL_BROWSER_SESSION_INTEGRATION_BENCHMARK",
        "measurement_status": measurement_status,
        "sechelix_commit": sechelix_commit,
        "execution_mode": "LOCAL",
        "network_scope": "literal-loopback-only",
        "browser_backend": (
            "SecHelix SafeAuthorizedBrowser / Playwright Chromium"
            if browser_factory is SafeAuthorizedBrowser
            else "injected-test-backend"
        ),
        "case_count": len(cases),
        "cases": cases,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "credential_material_persisted": False,
        "is_full_sechelix_workflow": False,
        "limitations": [
            "This measures imported-session browser isolation and verification only.",
            "Session cookie values are ephemeral fixture inputs and are not serialized.",
            "It is not a session-revocation proof and not a full SecHelix workflow benchmark.",
            "Missing Playwright/Chromium is BLOCKED_BY_ENVIRONMENT rather than a clean result.",
        ],
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run the optional real-browser SecHelix session integration benchmark"
    )
    parser.add_argument("--sechelix-commit", default="UNKNOWN")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run_real_browser_session_benchmark(sechelix_commit=args.sechelix_commit)
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0 if result["measurement_status"] in {MEASURED, BLOCKED_BY_ENVIRONMENT} else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
