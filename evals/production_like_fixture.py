#!/usr/bin/env python3
"""Deterministic LOCAL stateful application fixture for SecHelix evaluation.

This module provides a small loopback-only HTTP application with durable SQLite
state, three distinct authenticated personas, a multi-step refund workflow, and
an explicit deterministic reset. It exists to exercise a more production-like
fixture shape without pretending that fixture realism is a SecHelix security
score.

The self-test validates only the fixture contract. It does not discover
vulnerabilities, assess SecHelix accuracy, or establish production
effectiveness.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

RESULT_KIND = "STATEFUL_APPLICATION_FIXTURE_SELF_TEST"
SCHEMA_VERSION = "sechelix-stateful-application-fixture/v1"

PERSONA_TOKENS = {
    "customer": "fixture-customer-token",
    "reviewer": "fixture-reviewer-token",
    "finance": "fixture-finance-token",
}
TOKEN_TO_PERSONA = {value: key for key, value in PERSONA_TOKENS.items()}

ORDER_ID = "ORDER-1"
REFUND_ID = "REFUND-1"


class FixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any]


class RefundWorkflowStore:
    """SQLite-backed deterministic workflow state."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def reset(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                DROP TABLE IF EXISTS refunds;
                DROP TABLE IF EXISTS orders;

                CREATE TABLE orders (
                    id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    total_minor INTEGER NOT NULL,
                    currency TEXT NOT NULL
                );

                CREATE TABLE refunds (
                    id TEXT PRIMARY KEY,
                    order_id TEXT NOT NULL,
                    amount_minor INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    approved_by TEXT,
                    settled_by TEXT,
                    FOREIGN KEY(order_id) REFERENCES orders(id)
                );
                """
            )
            conn.execute(
                "INSERT INTO orders(id, customer_id, total_minor, currency) VALUES (?, ?, ?, ?)",
                (ORDER_ID, "customer", 5000, "USD"),
            )

    def order_for_persona(self, order_id: str, persona: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, customer_id, total_minor, currency FROM orders WHERE id = ?",
                (order_id,),
            ).fetchone()
        if row is None or (persona == "customer" and row["customer_id"] != persona):
            return None
        return dict(row)

    def refund(self, refund_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, order_id, amount_minor, status, requested_by,
                       approved_by, settled_by
                FROM refunds
                WHERE id = ?
                """,
                (refund_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def request_refund(self, order_id: str, persona: str) -> Response:
        if persona != "customer":
            return Response(403, {"error": "persona cannot request refund"})
        with self._connect() as conn:
            order = conn.execute(
                "SELECT id, customer_id, total_minor FROM orders WHERE id = ?",
                (order_id,),
            ).fetchone()
            if order is None or order["customer_id"] != persona:
                return Response(404, {"error": "order not found"})
            existing = conn.execute(
                "SELECT id, status FROM refunds WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            if existing is not None:
                return Response(409, {"error": "refund already exists", "status": existing["status"]})
            conn.execute(
                """
                INSERT INTO refunds(
                    id, order_id, amount_minor, status, requested_by
                ) VALUES (?, ?, ?, 'REQUESTED', ?)
                """,
                (REFUND_ID, order_id, order["total_minor"], persona),
            )
        return Response(201, {"refund_id": REFUND_ID, "status": "REQUESTED"})

    def approve_refund(self, refund_id: str, persona: str) -> Response:
        if persona != "reviewer":
            return Response(403, {"error": "persona cannot approve refund"})
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM refunds WHERE id = ?",
                (refund_id,),
            ).fetchone()
            if row is None:
                return Response(404, {"error": "refund not found"})
            if row["status"] != "REQUESTED":
                return Response(409, {"error": "refund is not awaiting approval"})
            conn.execute(
                "UPDATE refunds SET status = 'APPROVED', approved_by = ? WHERE id = ?",
                (persona, refund_id),
            )
        return Response(200, {"refund_id": refund_id, "status": "APPROVED"})

    def settle_refund(self, refund_id: str, persona: str) -> Response:
        if persona != "finance":
            return Response(403, {"error": "persona cannot settle refund"})
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM refunds WHERE id = ?",
                (refund_id,),
            ).fetchone()
            if row is None:
                return Response(404, {"error": "refund not found"})
            if row["status"] != "APPROVED":
                return Response(409, {"error": "refund is not approved"})
            conn.execute(
                "UPDATE refunds SET status = 'SETTLED', settled_by = ? WHERE id = ?",
                (persona, refund_id),
            )
        return Response(200, {"refund_id": refund_id, "status": "SETTLED"})


class FixtureRequestHandler(BaseHTTPRequestHandler):
    server_version = "SecHelixStatefulFixture/1"

    @property
    def store(self) -> RefundWorkflowStore:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _persona(self) -> str | None:
        value = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not value.startswith(prefix):
            return None
        return TOKEN_TO_PERSONA.get(value[len(prefix) :])

    def _write(self, response: Response) -> None:
        payload = json.dumps(response.body, sort_keys=True).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _require_persona(self) -> str | None:
        persona = self._persona()
        if persona is None:
            self._write(Response(401, {"error": "fixture authentication required"}))
        return persona

    def do_GET(self) -> None:
        if self.path == "/health":
            self._write(Response(200, {"status": "ok"}))
            return

        persona = self._require_persona()
        if persona is None:
            return

        if self.path == f"/orders/{ORDER_ID}":
            order = self.store.order_for_persona(ORDER_ID, persona)
            if order is None:
                self._write(Response(404, {"error": "order not found"}))
            elif persona != "customer":
                self._write(Response(403, {"error": "order belongs to another persona"}))
            else:
                self._write(Response(200, order))
            return

        if self.path == f"/refunds/{REFUND_ID}":
            refund = self.store.refund(REFUND_ID)
            if refund is None:
                self._write(Response(404, {"error": "refund not found"}))
            else:
                self._write(Response(200, refund))
            return

        self._write(Response(404, {"error": "route not found"}))

    def do_POST(self) -> None:
        persona = self._require_persona()
        if persona is None:
            return

        if self.path == f"/orders/{ORDER_ID}/refunds":
            self._write(self.store.request_refund(ORDER_ID, persona))
            return
        if self.path == f"/refunds/{REFUND_ID}/approve":
            self._write(self.store.approve_refund(REFUND_ID, persona))
            return
        if self.path == f"/refunds/{REFUND_ID}/settle":
            self._write(self.store.settle_refund(REFUND_ID, persona))
            return

        self._write(Response(404, {"error": "route not found"}))


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], store: RefundWorkflowStore):
        super().__init__(address, FixtureRequestHandler)
        self.store = store


class RunningFixture:
    def __init__(self, database_path: str | Path):
        self.store = RefundWorkflowStore(database_path)
        self.store.reset()
        self.server = FixtureServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "RunningFixture":
        self.thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _request(base_url: str, method: str, path: str, persona: str | None = None) -> Response:
    headers = {}
    if persona is not None:
        headers["Authorization"] = f"Bearer {PERSONA_TOKENS[persona]}"
    request = Request(base_url + path, method=method, headers=headers)
    try:
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return Response(response.status, payload)
    except HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        return Response(exc.code, payload)


def run_fixture_self_test(database_path: str | Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    started = time.monotonic()

    with RunningFixture(database_path) as fixture:
        health = _request(fixture.base_url, "GET", "/health")
        checks.append({"name": "loopback_health", "passed": health.status == 200})

        unauth = _request(fixture.base_url, "GET", f"/orders/{ORDER_ID}")
        checks.append({"name": "authentication_required", "passed": unauth.status == 401})

        customer_order = _request(
            fixture.base_url, "GET", f"/orders/{ORDER_ID}", "customer"
        )
        checks.append({"name": "customer_reads_own_order", "passed": customer_order.status == 200})

        cross_role_order = _request(
            fixture.base_url, "GET", f"/orders/{ORDER_ID}", "reviewer"
        )
        checks.append({"name": "cross_role_order_read_denied", "passed": cross_role_order.status == 403})

        premature_settle = _request(
            fixture.base_url, "POST", f"/refunds/{REFUND_ID}/settle", "finance"
        )
        checks.append({"name": "settlement_requires_existing_approved_refund", "passed": premature_settle.status == 404})

        requested = _request(
            fixture.base_url, "POST", f"/orders/{ORDER_ID}/refunds", "customer"
        )
        checks.append({"name": "customer_requests_refund", "passed": requested.status == 201 and requested.body.get("status") == "REQUESTED"})

        wrong_approver = _request(
            fixture.base_url, "POST", f"/refunds/{REFUND_ID}/approve", "finance"
        )
        checks.append({"name": "approval_role_enforced", "passed": wrong_approver.status == 403})

        shortcut = _request(
            fixture.base_url, "POST", f"/refunds/{REFUND_ID}/settle", "finance"
        )
        checks.append({"name": "workflow_prerequisite_enforced", "passed": shortcut.status == 409})

        approved = _request(
            fixture.base_url, "POST", f"/refunds/{REFUND_ID}/approve", "reviewer"
        )
        checks.append({"name": "reviewer_approves_refund", "passed": approved.status == 200 and approved.body.get("status") == "APPROVED"})

        settled = _request(
            fixture.base_url, "POST", f"/refunds/{REFUND_ID}/settle", "finance"
        )
        checks.append({"name": "finance_settles_approved_refund", "passed": settled.status == 200 and settled.body.get("status") == "SETTLED"})

        durable = RefundWorkflowStore(database_path).refund(REFUND_ID)
        checks.append({"name": "state_is_durable_across_connections", "passed": durable is not None and durable.get("status") == "SETTLED"})

        fixture.store.reset()
        reset_refund = fixture.store.refund(REFUND_ID)
        reset_order = fixture.store.order_for_persona(ORDER_ID, "customer")
        checks.append({"name": "deterministic_reset_restores_seed", "passed": reset_refund is None and reset_order is not None and reset_order.get("total_minor") == 5000})

    elapsed = round(time.monotonic() - started, 6)
    passed = all(check["passed"] for check in checks)

    return {
        "schema_version": SCHEMA_VERSION,
        "result_kind": RESULT_KIND,
        "status": "MEASURED" if passed else "FAILED",
        "fixture_tier": "STATEFUL_APPLICATION",
        "network_scope": "LOOPBACK_ONLY",
        "properties": {
            "runtime_execution": True,
            "real_browser": False,
            "durable_state": True,
            "multi_step_workflow": True,
            "deterministic_reset": True,
            "auth_personas": 3,
            "service_count": 1,
            "async_boundary": False,
        },
        "checks": checks,
        "elapsed_seconds": elapsed,
        "production_effectiveness_established": False,
        "arena_full_workflow_measured": False,
        "note": (
            "Fixture self-test only. This proves the LOCAL stateful fixture contract, "
            "not SecHelix security effectiveness or a full-workflow Arena result."
        ),
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic SecHelix stateful LOCAL fixture self-test"
    )
    parser.add_argument("--database", help="optional SQLite path")
    parser.add_argument("--output", help="optional result JSON")
    args = parser.parse_args()

    if args.database:
        result = run_fixture_self_test(args.database)
    else:
        with TemporaryDirectory() as tmp:
            result = run_fixture_self_test(Path(tmp) / "fixture.sqlite3")

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    return 0 if result["status"] == "MEASURED" else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
