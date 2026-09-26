#!/usr/bin/env python3
"""Optional real-browser integration benchmark for session revocation propagation.

Each case opens a fresh browser context with one ephemeral valid session,
establishes a protected-surface control, revokes the fixture session through a
local operator hook, and verifies the same browser context again. One fixture
intentionally ignores revocation; the clean sibling enforces it.
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
    clean_active = True
    vulnerable_active = True

    def do_GET(self) -> None:  # noqa: N802
        cookie_ok = "session=fixture-session-valid" in str(self.headers.get("Cookie") or "")
        if self.path == "/clean":
            allowed = cookie_ok and type(self).clean_active
        elif self.path == "/vulnerable":
            # Intentionally stale authority: the endpoint ignores revocation.
            allowed = cookie_ok
        else:
            self.send_response(404)
            self.end_headers()
            return

        if allowed:
            body = b"<!doctype html><html><body><div id='protected'>protected</div></body></html>"
            self.send_response(200)
        else:
            body = b"<!doctype html><html><body><div id='login'>login</div></body></html>"
            self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def _reset() -> None:
    _Handler.clean_active = True
    _Handler.vulnerable_active = True


def _access() -> ResolvedAccess:
    return ResolvedAccess(
        profile_name="revocation-fixture",
        role="buyer",
        kind=AccessKind.SESSION,
        username=None,
        password=None,
        headers={},
        cookies=(
            {
                "name": "session",
                "value": "fixture-session-valid",
                "domain": "127.0.0.1",
                "path": "/",
                "secure": False,
                "httpOnly": True,
            },
        ),
    )


def run_real_browser_session_revocation_benchmark(
    *,
    browser_factory: Callable[..., Any] = SafeAuthorizedBrowser,
    sechelix_commit: str = "UNKNOWN",
) -> dict[str, Any]:
    _reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    cases: list[dict[str, Any]] = []
    blockers: list[str] = []
    try:
        for case_id, path, expected_post_revocation in (
            ("SESSION-REVOCATION-REAL-VULNERABLE", "/vulnerable", True),
            ("SESSION-REVOCATION-REAL-CLEAN", "/clean", False),
        ):
            url = f"http://127.0.0.1:{port}{path}"
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
            probe = SessionProbe(url=url, success_selector="#protected", timeout_ms=5_000)
            clock = time.monotonic()
            try:
                with browser_factory(
                    scope,
                    access=_access(),
                    interaction_policy=InteractionPolicy(),
                    gateway=PolicyToolGateway(scope=scope),
                    authentication_context="persona:revocation-fixture",
                ) as browser:
                    control = browser.verify_session(probe)
                    if path == "/clean":
                        _Handler.clean_active = False
                    else:
                        _Handler.vulnerable_active = False
                    replay = browser.verify_session(probe)

                elapsed = time.monotonic() - clock
                matched = bool(control.verified) and (
                    bool(replay.verified) is expected_post_revocation
                )
                cases.append(
                    {
                        "case_id": case_id,
                        "control_verified": bool(control.verified),
                        "expected_post_revocation_verified": expected_post_revocation,
                        "observed_post_revocation_verified": bool(replay.verified),
                        "matched": matched,
                        "control_challenge": control.challenge.value,
                        "replay_challenge": replay.challenge.value,
                        "elapsed_seconds": round(elapsed, 6),
                    }
                )
            except BrowserUnavailable as exc:
                elapsed = time.monotonic() - clock
                blockers.append(str(exc))
                cases.append(
                    {
                        "case_id": case_id,
                        "control_verified": None,
                        "expected_post_revocation_verified": expected_post_revocation,
                        "observed_post_revocation_verified": None,
                        "matched": False,
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
        "schema_version": "sechelix-real-browser-session-revocation/v1",
        "result_kind": "REAL_BROWSER_SESSION_REVOCATION_INTEGRATION_BENCHMARK",
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
            "This measures real-browser session revocation propagation on a local fixture only.",
            "The revocation mutation is an operator-controlled local fixture hook.",
            "Session cookie values are ephemeral and are not serialized.",
            "Missing Playwright/Chromium is BLOCKED_BY_ENVIRONMENT rather than a security result.",
        ],
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run the optional real-browser session-revocation integration benchmark"
    )
    parser.add_argument("--sechelix-commit", default="UNKNOWN")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run_real_browser_session_revocation_benchmark(
        sechelix_commit=args.sechelix_commit
    )
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0 if result["measurement_status"] in {MEASURED, BLOCKED_BY_ENVIRONMENT} else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
