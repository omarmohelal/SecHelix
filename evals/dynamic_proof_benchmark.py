#!/usr/bin/env python3
"""Deterministic LOCAL benchmark for SecHelix dynamic proof primitives.

This is intentionally narrower than a full SecHelix workflow benchmark. It
measures whether bounded proof executors distinguish paired vulnerable and clean
LOCAL fixtures. It does not measure model reasoning, candidate generation,
independent verification, remediation, or release-gate accuracy.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from pathlib import Path
from typing import Callable, Sequence

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    CsrfHttpSpec,
    IdorHttpSpec,
    RaceHttpSpec,
    LocalProofExecutor,
    MoneyFlowInvariantHttpSpec,
    PaymentInvariantHttpSpec,
    ProofBehavior,
    SessionRevocationHttpSpec,
    SettlementRefundSequenceHttpSpec,
    SsrfHttpSpec,
    StateTransitionHttpSpec,
    TraversalHttpSpec,
    WebhookHttpSpec,
    WorkflowSequenceHttpSpec,
    XssBrowserSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    family: str
    expected: ProofBehavior
    run: Callable[[str, LocalProofExecutor], object]


class _Handler(BaseHTTPRequestHandler):
    state_vulnerable = "cancelled"
    state_clean = "cancelled"
    payment_vulnerable = 10_000
    payment_clean = 10_000
    workflow_vulnerable = "created"
    workflow_clean = "created"
    money_flow_vulnerable = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    money_flow_clean = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    settlement_refund_vulnerable = {"customer": 10_000, "worker": 1_000, "platform": 500}
    settlement_refund_clean = {"customer": 10_000, "worker": 1_000, "platform": 500}
    settlement_refund_vulnerable_settle_count = 0
    settlement_refund_vulnerable_refund_count = 0
    settlement_refund_clean_settle_count = 0
    settlement_refund_clean_refund_count = 0
    session_vulnerable_active = True
    session_clean_active = True
    csrf_vulnerable_count = 0
    csrf_clean_count = 0
    race_vulnerable_count = 0
    race_clean_count = 0
    race_clean_lock = threading.Lock()
    webhook_vulnerable_count = 0
    webhook_clean_count = 0
    traversal_sentinel = b"SECHELIX_DYNAMIC_TRAVERSAL_SENTINEL"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/traversal/vulnerable":
            requested = urllib.parse.parse_qs(parsed.query).get("path", [""])[0]
            if "sentinel" in requested:
                self._send(200, type(self).traversal_sentinel)
            else:
                self._send(200, b"safe")
            return
        if parsed.path == "/traversal/clean":
            requested = urllib.parse.parse_qs(parsed.query).get("path", [""])[0]
            if ".." in requested or "sentinel" in requested:
                self._send(403, b"denied")
            else:
                self._send(200, b"safe")
            return
        if parsed.path == "/ssrf/vulnerable":
            callback = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
            try:
                with urllib.request.urlopen(callback, timeout=1) as response:
                    response.read()
                self._send(200, b"fetched")
            except Exception:
                self._send(502, b"failed")
            return
        if parsed.path == "/ssrf/clean":
            self._send(400, b"url fetch disabled")
            return

        if self.path == "/idor/vulnerable/1":
            if self.headers.get("X-Bench-Identity") not in {"owner", "foreign"}:
                self._send(401)
                return
            self._send(200, b'{"id":1,"owner":"owner"}')
            return
        if self.path == "/idor/clean/1":
            identity = self.headers.get("X-Bench-Identity")
            if identity == "owner":
                self._send(200, b'{"id":1,"owner":"owner"}')
            elif identity == "foreign":
                self._send(403)
            else:
                self._send(401)
            return
        if self.path == "/session/vulnerable":
            if self.headers.get("X-Bench-Session") != "fixture-session":
                self._send(401)
                return
            # Intentionally stale authority: revocation state is ignored.
            self._send(200, b"protected")
            return
        if self.path == "/session/clean":
            if self.headers.get("X-Bench-Session") != "fixture-session":
                self._send(401)
                return
            if not type(self).session_clean_active:
                self._send(401)
                return
            self._send(200, b"protected")
            return
        self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        if self.path == "/race/vulnerable":
            type(self).race_vulnerable_count += 1
            self._send(200)
            return
        if self.path == "/race/clean":
            with type(self).race_clean_lock:
                if type(self).race_clean_count == 0:
                    type(self).race_clean_count = 1
            self._send(200)
            return

        if self.path == "/webhook/vulnerable":
            signature = self.headers.get("X-Bench-Signature")
            if signature != "bench-valid":
                self._send(401)
                return
            type(self).webhook_vulnerable_count += 1
            self._send(200)
            return
        if self.path == "/webhook/clean":
            signature = self.headers.get("X-Bench-Signature")
            if signature != "bench-valid":
                self._send(401)
                return
            if type(self).webhook_clean_count == 0:
                type(self).webhook_clean_count = 1
            self._send(200)
            return

        if self.path == "/csrf/vulnerable":
            if self.headers.get("X-Bench-Session") != "fixture-session":
                self._send(401)
                return
            type(self).csrf_vulnerable_count += 1
            self._send(200)
            return
        if self.path == "/csrf/clean":
            if self.headers.get("X-Bench-Session") != "fixture-session":
                self._send(401)
                return
            expected_origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Origin") != expected_origin:
                self._send(403)
                return
            type(self).csrf_clean_count += 1
            self._send(200)
            return

        if self.path == "/state/vulnerable":
            type(self).state_vulnerable = "completed"
            self._send(200)
            return
        if self.path == "/state/clean":
            self._send(409)
            return

        if self.path == "/payment/vulnerable":
            type(self).payment_vulnerable -= 250
            self._send(200)
            return
        if self.path == "/payment/clean":
            if type(self).payment_clean == 10_000:
                type(self).payment_clean -= 250
            self._send(200)
            return

        if self.path == "/money-flow/vulnerable":
            state = type(self).money_flow_vulnerable
            state["buyer"] -= 1000
            state["seller"] += 900
            state["platform"] += 100
            self._send(200)
            return
        if self.path == "/money-flow/clean":
            state = type(self).money_flow_clean
            if state["buyer"] == 10_000:
                state["buyer"] -= 1000
                state["seller"] += 900
                state["platform"] += 100
            self._send(200)
            return

        if self.path == "/settlement-refund/vulnerable/settle":
            state = type(self).settlement_refund_vulnerable
            if type(self).settlement_refund_vulnerable_settle_count == 0:
                state["customer"] -= 1000
                state["worker"] += 800
                state["platform"] += 200
            type(self).settlement_refund_vulnerable_settle_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/vulnerable/refund":
            state = type(self).settlement_refund_vulnerable
            # Settlement is idempotent enough for the control path, but the
            # partial refund is incorrectly applied on every replay.
            if type(self).settlement_refund_vulnerable_refund_count >= 0:
                state["customer"] += 400
                state["worker"] -= 320
                state["platform"] -= 80
            type(self).settlement_refund_vulnerable_refund_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/clean/settle":
            state = type(self).settlement_refund_clean
            if type(self).settlement_refund_clean_settle_count == 0:
                state["customer"] -= 1000
                state["worker"] += 800
                state["platform"] += 200
            type(self).settlement_refund_clean_settle_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/clean/refund":
            state = type(self).settlement_refund_clean
            if type(self).settlement_refund_clean_refund_count == 0:
                state["customer"] += 400
                state["worker"] -= 320
                state["platform"] -= 80
            type(self).settlement_refund_clean_refund_count += 1
            self._send(200)
            return

        if self.path == "/workflow/vulnerable/step1":
            if type(self).workflow_vulnerable != "created":
                self._send(409)
                return
            type(self).workflow_vulnerable = "approved"
            self._send(200)
            return
        if self.path == "/workflow/vulnerable/step2":
            type(self).workflow_vulnerable = "completed"
            self._send(200)
            return

        if self.path == "/workflow/clean/step1":
            if type(self).workflow_clean != "created":
                self._send(409)
                return
            type(self).workflow_clean = "approved"
            self._send(200)
            return
        if self.path == "/workflow/clean/step2":
            if type(self).workflow_clean != "approved":
                self._send(409)
                return
            type(self).workflow_clean = "completed"
            self._send(200)
            return

        self._send(404)

    def _send(self, status: int, body: bytes = b"ok") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def _reset() -> None:
    _Handler.state_vulnerable = "cancelled"
    _Handler.state_clean = "cancelled"
    _Handler.payment_vulnerable = 10_000
    _Handler.payment_clean = 10_000
    _Handler.workflow_vulnerable = "created"
    _Handler.workflow_clean = "created"
    _Handler.money_flow_vulnerable = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    _Handler.money_flow_clean = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    _Handler.settlement_refund_vulnerable = {"customer": 10_000, "worker": 1_000, "platform": 500}
    _Handler.settlement_refund_clean = {"customer": 10_000, "worker": 1_000, "platform": 500}
    _Handler.settlement_refund_vulnerable_settle_count = 0
    _Handler.settlement_refund_vulnerable_refund_count = 0
    _Handler.settlement_refund_clean_settle_count = 0
    _Handler.settlement_refund_clean_refund_count = 0
    _Handler.session_vulnerable_active = True
    _Handler.session_clean_active = True
    _Handler.csrf_vulnerable_count = 0
    _Handler.csrf_clean_count = 0
    _Handler.race_vulnerable_count = 0
    _Handler.race_clean_count = 0
    _Handler.webhook_vulnerable_count = 0
    _Handler.webhook_clean_count = 0


class _BenchmarkXssBrowser:
    """Deterministic browser-fixture adapter for the proof primitive benchmark."""

    def __init__(
        self,
        scope,
        *,
        interaction_policy,
        gateway,
        execute_marker: bool = False,
        inert_text: bool = False,
    ) -> None:
        self.scope = scope
        self.interaction_policy = interaction_policy
        self.gateway = gateway
        self.execute_marker = execute_marker
        self.inert_text = inert_text

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def navigate(self, url, *, timeout_ms):
        return SimpleNamespace(
            status=200,
            url=url.split("?", 1)[0] + "?q=[REDACTED]",
            challenge=SimpleNamespace(value="NONE"),
            blocked_requests=0,
        )

    def window_marker_matches(self, name, expected):
        return self.execute_marker

    def text(self, selector, *, timeout_ms):
        return "SECHELIX_XSS_MARKER_1" if self.inert_text else "no marker"


def _cases() -> tuple[BenchmarkCase, ...]:
    def race_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.RACE_IDEMPOTENCY,
            "BENCH-RACE-VULN",
            available_authority={"fixture_write_access"},
        )
        return executor.execute(
            plan,
            RaceHttpSpec(
                url=base + "/race/vulnerable",
                concurrency=2,
                read_state=lambda: _Handler.race_vulnerable_count,
                expected_single_state=1,
            ),
        )

    def race_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.RACE_IDEMPOTENCY,
            "BENCH-RACE-CLEAN",
            available_authority={"fixture_write_access"},
        )
        return executor.execute(
            plan,
            RaceHttpSpec(
                url=base + "/race/clean",
                concurrency=2,
                read_state=lambda: _Handler.race_clean_count,
                expected_single_state=1,
            ),
        )

    def webhook_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "BENCH-WEBHOOK-VULN",
            available_authority={"fixture_endpoint_access"},
        )
        return executor.execute(
            plan,
            WebhookHttpSpec(
                url=base + "/webhook/vulnerable",
                body=b'{"event":"benchmark"}',
                signature_header="X-Bench-Signature",
                valid_signature="bench-valid",
                read_state=lambda: _Handler.webhook_vulnerable_count,
                expected_single_state=1,
            ),
        )

    def webhook_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WEBHOOK_SIGNATURE,
            "BENCH-WEBHOOK-CLEAN",
            available_authority={"fixture_endpoint_access"},
        )
        return executor.execute(
            plan,
            WebhookHttpSpec(
                url=base + "/webhook/clean",
                body=b'{"event":"benchmark"}',
                signature_header="X-Bench-Signature",
                valid_signature="bench-valid",
                read_state=lambda: _Handler.webhook_clean_count,
                expected_single_state=1,
            ),
        )

    def traversal_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "BENCH-TRAVERSAL-VULN",
            available_authority={"fixture_filesystem"},
        )
        return executor.execute(
            plan,
            TraversalHttpSpec(
                url_template=base + "/traversal/vulnerable?path={path}",
                safe_path="public/readme.txt",
                traversal_path="../sentinel.txt",
                sentinel_marker=_Handler.traversal_sentinel,
            ),
        )

    def traversal_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "BENCH-TRAVERSAL-CLEAN",
            available_authority={"fixture_filesystem"},
        )
        return executor.execute(
            plan,
            TraversalHttpSpec(
                url_template=base + "/traversal/clean?path={path}",
                safe_path="public/readme.txt",
                traversal_path="../sentinel.txt",
                sentinel_marker=_Handler.traversal_sentinel,
            ),
        )

    def ssrf_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SSRF_CALLBACK,
            "BENCH-SSRF-VULN",
            available_authority={"local_callback_listener"},
        )
        return executor.execute(
            plan,
            SsrfHttpSpec(
                submit_url_template=base + "/ssrf/vulnerable?url={callback}",
                callback_timeout_seconds=1,
            ),
        )

    def ssrf_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SSRF_CALLBACK,
            "BENCH-SSRF-CLEAN",
            available_authority={"local_callback_listener"},
        )
        return executor.execute(
            plan,
            SsrfHttpSpec(
                submit_url_template=base + "/ssrf/clean?url={callback}",
                callback_timeout_seconds=0.2,
            ),
        )

    def state_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "BENCH-STATE-VULN",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        return executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=base + "/state/vulnerable",
                read_state=lambda: _Handler.state_vulnerable,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )

    def state_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "BENCH-STATE-CLEAN",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        return executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=base + "/state/clean",
                read_state=lambda: _Handler.state_clean,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )

    def payment_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "BENCH-PAYMENT-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=base + "/payment/vulnerable",
                read_balance_minor=lambda: _Handler.payment_vulnerable,
                expected_single_delta_minor=-250,
            ),
        )

    def payment_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "BENCH-PAYMENT-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=base + "/payment/clean",
                read_balance_minor=lambda: _Handler.payment_clean,
                expected_single_delta_minor=-250,
            ),
        )

    def money_flow_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "BENCH-MONEY-FLOW-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=base + "/money-flow/vulnerable",
                read_balances_minor=lambda: dict(_Handler.money_flow_vulnerable),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )

    def money_flow_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "BENCH-MONEY-FLOW-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=base + "/money-flow/clean",
                read_balances_minor=lambda: dict(_Handler.money_flow_clean),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )

    def settlement_refund_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SETTLEMENT_REFUND_SEQUENCE,
            "BENCH-SETTLEMENT-REFUND-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            SettlementRefundSequenceHttpSpec(
                settlement_url=base + "/settlement-refund/vulnerable/settle",
                refund_url=base + "/settlement-refund/vulnerable/refund",
                read_balances_minor=lambda: dict(_Handler.settlement_refund_vulnerable),
                expected_settlement_deltas_minor={
                    "customer": -1000,
                    "worker": 800,
                    "platform": 200,
                },
                expected_refund_deltas_minor={
                    "customer": 400,
                    "worker": -320,
                    "platform": -80,
                },
            ),
        )

    def settlement_refund_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SETTLEMENT_REFUND_SEQUENCE,
            "BENCH-SETTLEMENT-REFUND-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            SettlementRefundSequenceHttpSpec(
                settlement_url=base + "/settlement-refund/clean/settle",
                refund_url=base + "/settlement-refund/clean/refund",
                read_balances_minor=lambda: dict(_Handler.settlement_refund_clean),
                expected_settlement_deltas_minor={
                    "customer": -1000,
                    "worker": 800,
                    "platform": 200,
                },
                expected_refund_deltas_minor={
                    "customer": 400,
                    "worker": -320,
                    "platform": -80,
                },
            ),
        )

    def workflow_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "BENCH-WORKFLOW-VULN",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _Handler.workflow_vulnerable = "created"
            return True

        return executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=base + "/workflow/vulnerable/step1",
                step_two_url=base + "/workflow/vulnerable/step2",
                read_state=lambda: _Handler.workflow_vulnerable,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )

    def workflow_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "BENCH-WORKFLOW-CLEAN",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _Handler.workflow_clean = "created"
            return True

        return executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=base + "/workflow/clean/step1",
                step_two_url=base + "/workflow/clean/step2",
                read_state=lambda: _Handler.workflow_clean,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )


    def idor_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.AUTHORIZATION_IDOR,
            "BENCH-IDOR-VULN",
            available_authority={"identity_a_credentials", "identity_b_credentials"},
        )
        return executor.execute(
            plan,
            IdorHttpSpec(
                url_template=base + "/idor/vulnerable/{object_id}",
                object_id="1",
                identity_a_headers={"X-Bench-Identity": "owner"},
                identity_b_headers={"X-Bench-Identity": "foreign"},
            ),
        )

    def idor_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.AUTHORIZATION_IDOR,
            "BENCH-IDOR-CLEAN",
            available_authority={"identity_a_credentials", "identity_b_credentials"},
        )
        return executor.execute(
            plan,
            IdorHttpSpec(
                url_template=base + "/idor/clean/{object_id}",
                object_id="1",
                identity_a_headers={"X-Bench-Identity": "owner"},
                identity_b_headers={"X-Bench-Identity": "foreign"},
            ),
        )

    def csrf_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.CSRF_REQUEST,
            "BENCH-CSRF-VULN",
            available_authority={"fixture_authenticated_session", "fixture_write_access"},
        )
        return executor.execute(
            plan,
            CsrfHttpSpec(
                url=base + "/csrf/vulnerable",
                authenticated_headers={"X-Bench-Session": "fixture-session"},
            ),
        )

    def csrf_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.CSRF_REQUEST,
            "BENCH-CSRF-CLEAN",
            available_authority={"fixture_authenticated_session", "fixture_write_access"},
        )
        return executor.execute(
            plan,
            CsrfHttpSpec(
                url=base + "/csrf/clean",
                authenticated_headers={"X-Bench-Session": "fixture-session"},
            ),
        )

    def session_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SESSION_REVOCATION,
            "BENCH-SESSION-VULN",
            available_authority={"fixture_authenticated_session", "fixture_session_revocation"},
        )

        def revoke() -> None:
            _Handler.session_vulnerable_active = False

        return executor.execute(
            plan,
            SessionRevocationHttpSpec(
                url=base + "/session/vulnerable",
                authenticated_headers={"X-Bench-Session": "fixture-session"},
                revoke_session=revoke,
            ),
        )

    def session_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SESSION_REVOCATION,
            "BENCH-SESSION-CLEAN",
            available_authority={"fixture_authenticated_session", "fixture_session_revocation"},
        )

        def revoke() -> None:
            _Handler.session_clean_active = False

        return executor.execute(
            plan,
            SessionRevocationHttpSpec(
                url=base + "/session/clean",
                authenticated_headers={"X-Bench-Session": "fixture-session"},
                revoke_session=revoke,
            ),
        )

    def xss_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "BENCH-XSS-VULN",
            available_authority={"local_browser_runtime"},
        )

        def factory(scope, **kwargs):
            return _BenchmarkXssBrowser(scope, execute_marker=True, **kwargs)

        browser_executor = LocalProofExecutor(
            executor.policy,
            timeout_seconds=executor.timeout_seconds,
            max_requests=executor.max_requests,
            browser_factory=factory,
        )
        return browser_executor.execute(
            plan,
            XssBrowserSpec(
                url_template=base + "/xss?q={payload}",
                injection_selector="#sink",
            ),
        )

    def xss_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.XSS_EXECUTION,
            "BENCH-XSS-CLEAN",
            available_authority={"local_browser_runtime"},
        )

        def factory(scope, **kwargs):
            return _BenchmarkXssBrowser(scope, inert_text=True, **kwargs)

        browser_executor = LocalProofExecutor(
            executor.policy,
            timeout_seconds=executor.timeout_seconds,
            max_requests=executor.max_requests,
            browser_factory=factory,
        )
        return browser_executor.execute(
            plan,
            XssBrowserSpec(
                url_template=base + "/xss?q={payload}",
                injection_selector="#sink",
            ),
        )

    return (
        BenchmarkCase("RACE-VULNERABLE", "race-idempotency", ProofBehavior.VULNERABLE_BEHAVIOR, race_vulnerable),
        BenchmarkCase("RACE-CLEAN", "race-idempotency", ProofBehavior.SECURE_BEHAVIOR, race_clean),
        BenchmarkCase("WEBHOOK-VULNERABLE", "webhook-signature-replay", ProofBehavior.VULNERABLE_BEHAVIOR, webhook_vulnerable),
        BenchmarkCase("WEBHOOK-CLEAN", "webhook-signature-replay", ProofBehavior.SECURE_BEHAVIOR, webhook_clean),
        BenchmarkCase("TRAVERSAL-VULNERABLE", "path-traversal", ProofBehavior.VULNERABLE_BEHAVIOR, traversal_vulnerable),
        BenchmarkCase("TRAVERSAL-CLEAN", "path-traversal", ProofBehavior.SECURE_BEHAVIOR, traversal_clean),
        BenchmarkCase("SSRF-VULNERABLE", "ssrf-callback", ProofBehavior.VULNERABLE_BEHAVIOR, ssrf_vulnerable),
        BenchmarkCase("SSRF-CLEAN", "ssrf-callback", ProofBehavior.SECURE_BEHAVIOR, ssrf_clean),
        BenchmarkCase("STATE-VULNERABLE", "state-transition", ProofBehavior.VULNERABLE_BEHAVIOR, state_vulnerable),
        BenchmarkCase("STATE-CLEAN", "state-transition", ProofBehavior.SECURE_BEHAVIOR, state_clean),
        BenchmarkCase("PAYMENT-VULNERABLE", "payment-invariant", ProofBehavior.VULNERABLE_BEHAVIOR, payment_vulnerable),
        BenchmarkCase("PAYMENT-CLEAN", "payment-invariant", ProofBehavior.SECURE_BEHAVIOR, payment_clean),
        BenchmarkCase("MONEY-FLOW-VULNERABLE", "money-flow-invariant", ProofBehavior.VULNERABLE_BEHAVIOR, money_flow_vulnerable),
        BenchmarkCase("MONEY-FLOW-CLEAN", "money-flow-invariant", ProofBehavior.SECURE_BEHAVIOR, money_flow_clean),
        BenchmarkCase("SETTLEMENT-REFUND-VULNERABLE", "settlement-refund-sequence", ProofBehavior.VULNERABLE_BEHAVIOR, settlement_refund_vulnerable),
        BenchmarkCase("SETTLEMENT-REFUND-CLEAN", "settlement-refund-sequence", ProofBehavior.SECURE_BEHAVIOR, settlement_refund_clean),
        BenchmarkCase("WORKFLOW-VULNERABLE", "workflow-sequence", ProofBehavior.VULNERABLE_BEHAVIOR, workflow_vulnerable),
        BenchmarkCase("WORKFLOW-CLEAN", "workflow-sequence", ProofBehavior.SECURE_BEHAVIOR, workflow_clean),
        BenchmarkCase("IDOR-VULNERABLE", "authorization-idor", ProofBehavior.VULNERABLE_BEHAVIOR, idor_vulnerable),
        BenchmarkCase("IDOR-CLEAN", "authorization-idor", ProofBehavior.SECURE_BEHAVIOR, idor_clean),
        BenchmarkCase("CSRF-VULNERABLE", "csrf-request", ProofBehavior.VULNERABLE_BEHAVIOR, csrf_vulnerable),
        BenchmarkCase("CSRF-CLEAN", "csrf-request", ProofBehavior.SECURE_BEHAVIOR, csrf_clean),
        BenchmarkCase("SESSION-VULNERABLE", "session-revocation", ProofBehavior.VULNERABLE_BEHAVIOR, session_vulnerable),
        BenchmarkCase("SESSION-CLEAN", "session-revocation", ProofBehavior.SECURE_BEHAVIOR, session_clean),
        BenchmarkCase("XSS-VULNERABLE", "xss-browser-marker", ProofBehavior.VULNERABLE_BEHAVIOR, xss_vulnerable),
        BenchmarkCase("XSS-CLEAN", "xss-browser-marker", ProofBehavior.SECURE_BEHAVIOR, xss_clean),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def run_dynamic_proof_benchmark(*, sechelix_commit: str = "NOT_MEASURED") -> dict[str, object]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    policy = NetworkPolicy(ExecutionMode.LOCAL)
    policy.grant(
        "127.0.0.1",
        port,
        protocol="http",
        purpose="SecHelix deterministic dynamic proof benchmark",
        scope_id="EVAL-DYNAMIC-PROOFS",
    )
    executor = LocalProofExecutor(policy, timeout_seconds=2, max_requests=8)
    base = f"http://127.0.0.1:{port}"

    rows: list[dict[str, object]] = []
    started = time.perf_counter()
    try:
        for case in _cases():
            _reset()
            case_started = time.perf_counter()
            result = case.run(base, executor)
            elapsed_ms = round((time.perf_counter() - case_started) * 1000, 3)
            behavior = result.behavior
            rows.append(
                {
                    "case_id": case.case_id,
                    "family": case.family,
                    "proof_class": result.proof_class.value,
                    "expected_behavior": case.expected.value,
                    "observed_behavior": behavior.value,
                    "correct": behavior is case.expected,
                    "request_count": result.request_count,
                    "elapsed_ms": elapsed_ms,
                    "promotes_finding": result.to_dict()["promotes_finding"],
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    vulnerable_rows = [row for row in rows if row["expected_behavior"] == ProofBehavior.VULNERABLE_BEHAVIOR.value]
    clean_rows = [row for row in rows if row["expected_behavior"] == ProofBehavior.SECURE_BEHAVIOR.value]
    inconclusive = sum(row["observed_behavior"] == ProofBehavior.INCONCLUSIVE.value for row in rows)
    correct = sum(bool(row["correct"]) for row in rows)
    covered_proof_classes = sorted({str(row["proof_class"]) for row in rows})
    all_proof_classes = sorted(item.value for item in ProofClass)
    missing_proof_classes = sorted(set(all_proof_classes) - set(covered_proof_classes))

    return {
        "schema_version": "sechelix-dynamic-proof-benchmark/v1",
        "measurement_status": "MEASURED",
        "result_kind": "DYNAMIC_PROOF_PRIMITIVE_BENCHMARK",
        "is_full_sechelix_workflow": False,
        "run": {
            "sechelix_commit": sechelix_commit,
            "execution_mode": "LOCAL",
            "network_scope": "literal-loopback-only",
            "case_count": len(rows),
            "duration_ms": duration_ms,
            "model": "NONE",
            "provider": "NONE",
            "external_scanners": [],
            "browser_backend": "deterministic-fixture-adapter-for-xss-pair",
        },
        "metrics": {
            "case_accuracy": _ratio(correct, len(rows)),
            "vulnerable_behavior_recall": _ratio(
                sum(bool(row["correct"]) for row in vulnerable_rows),
                len(vulnerable_rows),
            ),
            "clean_behavior_rejection_rate": _ratio(
                sum(bool(row["correct"]) for row in clean_rows),
                len(clean_rows),
            ),
            "inconclusive_rate": _ratio(inconclusive, len(rows)),
            "proof_class_coverage": _ratio(
                len(covered_proof_classes),
                len(all_proof_classes),
            ),
        },
        "coverage": {
            "covered_proof_classes": covered_proof_classes,
            "missing_proof_classes": missing_proof_classes,
        },
        "cases": rows,
        "limitations": [
            "Measures deterministic proof primitives only, not candidate discovery or model reasoning.",
            "Does not measure independent-verifier accuracy, remediation, regression generation, or release-gate accuracy.",
            "Synthetic loopback fixtures do not represent production latency, concurrency, infrastructure, or deployment policy.",
            "The XSS pair measures proof-classification logic through a deterministic browser fixture adapter; it is not a Playwright/browser-engine compatibility benchmark.",
            "A passing clean fixture establishes only the bounded declared invariant for that fixture.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sechelix-commit", default="NOT_MEASURED")
    args = parser.parse_args(argv)

    result = run_dynamic_proof_benchmark(sechelix_commit=args.sechelix_commit)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["metrics"]["case_accuracy"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
