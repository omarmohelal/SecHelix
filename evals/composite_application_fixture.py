#!/usr/bin/env python3
"""Deterministic two-service LOCAL composite application fixture.

This fixture raises integration realism one step above the single-service
STATEFUL_APPLICATION fixture while preserving SecHelix's safety boundary:
everything binds to literal loopback, uses synthetic identities/state, and has a
deterministic reset.

Service A owns a refund workflow and writes an outbox event after finance
settlement approval. Service B is a separate loopback ledger worker that consumes
that event and applies the refund credit exactly once. The durable SQLite outbox
is the explicit asynchronous boundary.

The self-test validates only fixture behavior. It does not score SecHelix,
establish Arena correctness, or measure production effectiveness.
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

SCHEMA_VERSION = "sechelix-composite-application-fixture/v1"
RESULT_KIND = "COMPOSITE_APPLICATION_FIXTURE_SELF_TEST"

ORDER_ID = "ORDER-1"
REFUND_ID = "REFUND-1"
EVENT_ID = "EVENT-REFUND-1"

PERSONA_TOKENS = {
    "customer": "fixture-customer-token",
    "reviewer": "fixture-reviewer-token",
    "finance": "fixture-finance-token",
}
TOKEN_TO_PERSONA = {value: key for key, value in PERSONA_TOKENS.items()}


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any]


class CompositeStore:
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
                DROP TABLE IF EXISTS ledger_entries;
                DROP TABLE IF EXISTS outbox;
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
                    queued_by TEXT
                );

                CREATE TABLE outbox (
                    id TEXT PRIMARY KEY,
                    topic TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    amount_minor INTEGER NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE ledger_entries (
                    event_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    amount_minor INTEGER NOT NULL,
                    entry_type TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO orders(id, customer_id, total_minor, currency) VALUES (?, ?, ?, ?)",
                (ORDER_ID, "customer", 5000, "USD"),
            )

    def request_refund(self, persona: str) -> Response:
        if persona != "customer":
            return Response(403, {"error": "persona cannot request refund"})
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM refunds WHERE id = ?", (REFUND_ID,)
            ).fetchone()
            if existing is not None:
                return Response(409, {"error": "refund already exists"})
            order = conn.execute(
                "SELECT total_minor FROM orders WHERE id = ? AND customer_id = ?",
                (ORDER_ID, persona),
            ).fetchone()
            if order is None:
                return Response(404, {"error": "order not found"})
            conn.execute(
                """
                INSERT INTO refunds(id, order_id, amount_minor, status, requested_by)
                VALUES (?, ?, ?, 'REQUESTED', ?)
                """,
                (REFUND_ID, ORDER_ID, order["total_minor"], persona),
            )
        return Response(201, {"refund_id": REFUND_ID, "status": "REQUESTED"})

    def approve_refund(self, persona: str) -> Response:
        if persona != "reviewer":
            return Response(403, {"error": "persona cannot approve refund"})
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM refunds WHERE id = ?", (REFUND_ID,)
            ).fetchone()
            if row is None:
                return Response(404, {"error": "refund not found"})
            if row["status"] != "REQUESTED":
                return Response(409, {"error": "refund is not awaiting approval"})
            conn.execute(
                "UPDATE refunds SET status='APPROVED', approved_by=? WHERE id=?",
                (persona, REFUND_ID),
            )
        return Response(200, {"refund_id": REFUND_ID, "status": "APPROVED"})

    def queue_settlement(self, persona: str) -> Response:
        if persona != "finance":
            return Response(403, {"error": "persona cannot queue settlement"})
        with self._connect() as conn:
            refund = conn.execute(
                "SELECT amount_minor, status FROM refunds WHERE id = ?", (REFUND_ID,)
            ).fetchone()
            if refund is None:
                return Response(404, {"error": "refund not found"})
            if refund["status"] != "APPROVED":
                return Response(409, {"error": "refund is not approved"})
            existing = conn.execute(
                "SELECT status FROM outbox WHERE id = ?", (EVENT_ID,)
            ).fetchone()
            if existing is not None:
                return Response(409, {"error": "settlement already queued"})
            conn.execute(
                """
                INSERT INTO outbox(id, topic, aggregate_id, amount_minor, status)
                VALUES (?, 'refund.settle', ?, ?, 'PENDING')
                """,
                (EVENT_ID, REFUND_ID, refund["amount_minor"]),
            )
            conn.execute(
                "UPDATE refunds SET status='QUEUED', queued_by=? WHERE id=?",
                (persona, REFUND_ID),
            )
        return Response(
            202,
            {"refund_id": REFUND_ID, "event_id": EVENT_ID, "status": "QUEUED"},
        )

    def consume_one(self) -> Response:
        with self._connect() as conn:
            event = conn.execute(
                """
                SELECT id, aggregate_id, amount_minor, status
                FROM outbox
                WHERE status='PENDING'
                ORDER BY id
                LIMIT 1
                """
            ).fetchone()
            if event is None:
                return Response(204, {"status": "EMPTY"})

            refund = conn.execute(
                """
                SELECT r.id, r.status, o.customer_id
                FROM refunds r
                JOIN orders o ON o.id = r.order_id
                WHERE r.id = ?
                """,
                (event["aggregate_id"],),
            ).fetchone()
            if refund is None or refund["status"] != "QUEUED":
                return Response(409, {"error": "event aggregate is not queue-ready"})

            duplicate = conn.execute(
                "SELECT event_id FROM ledger_entries WHERE event_id = ?",
                (event["id"],),
            ).fetchone()
            if duplicate is None:
                conn.execute(
                    """
                    INSERT INTO ledger_entries(event_id, customer_id, amount_minor, entry_type)
                    VALUES (?, ?, ?, 'REFUND')
                    """,
                    (event["id"], refund["customer_id"], event["amount_minor"]),
                )

            conn.execute(
                "UPDATE outbox SET status='CONSUMED' WHERE id=?",
                (event["id"],),
            )
            conn.execute(
                "UPDATE refunds SET status='SETTLED' WHERE id=?",
                (refund["id"],),
            )

        return Response(
            200,
            {"event_id": EVENT_ID, "refund_id": REFUND_ID, "status": "SETTLED"},
        )

    def snapshot(self) -> dict[str, Any]:
        with self._connect() as conn:
            refund = conn.execute(
                "SELECT status FROM refunds WHERE id=?", (REFUND_ID,)
            ).fetchone()
            event = conn.execute(
                "SELECT status FROM outbox WHERE id=?", (EVENT_ID,)
            ).fetchone()
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM ledger_entries WHERE event_id=?",
                (EVENT_ID,),
            ).fetchone()["n"]
            amount = conn.execute(
                "SELECT COALESCE(SUM(amount_minor), 0) AS amount FROM ledger_entries"
            ).fetchone()["amount"]
        return {
            "refund_status": refund["status"] if refund else None,
            "event_status": event["status"] if event else None,
            "ledger_entry_count": int(count),
            "ledger_total_minor": int(amount),
        }


class _BaseHandler(BaseHTTPRequestHandler):
    server_version = "SecHelixCompositeFixture/1"

    @property
    def store(self) -> CompositeStore:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _write(self, response: Response) -> None:
        payload = b"" if response.status == 204 else json.dumps(
            response.body, sort_keys=True
        ).encode("utf-8")
        self.send_response(response.status)
        if payload:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)


class WorkflowHandler(_BaseHandler):
    def _persona(self) -> str | None:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return None
        return TOKEN_TO_PERSONA.get(value.removeprefix("Bearer "))

    def do_GET(self) -> None:
        if self.path == "/health":
            self._write(Response(200, {"service": "workflow", "status": "ok"}))
            return
        self._write(Response(404, {"error": "route not found"}))

    def do_POST(self) -> None:
        persona = self._persona()
        if persona is None:
            self._write(Response(401, {"error": "fixture authentication required"}))
            return
        if self.path == "/refunds/request":
            self._write(self.store.request_refund(persona))
            return
        if self.path == f"/refunds/{REFUND_ID}/approve":
            self._write(self.store.approve_refund(persona))
            return
        if self.path == f"/refunds/{REFUND_ID}/queue-settlement":
            self._write(self.store.queue_settlement(persona))
            return
        self._write(Response(404, {"error": "route not found"}))


class LedgerWorkerHandler(_BaseHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._write(Response(200, {"service": "ledger-worker", "status": "ok"}))
            return
        self._write(Response(404, {"error": "route not found"}))

    def do_POST(self) -> None:
        if self.path == "/internal/consume-one":
            self._write(self.store.consume_one())
            return
        self._write(Response(404, {"error": "route not found"}))


class FixtureServer(ThreadingHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        store: CompositeStore,
    ):
        super().__init__(address, handler)
        self.store = store


class RunningCompositeFixture:
    def __init__(self, database_path: str | Path):
        self.store = CompositeStore(database_path)
        self.store.reset()
        self.workflow = FixtureServer(("127.0.0.1", 0), WorkflowHandler, self.store)
        self.worker = FixtureServer(("127.0.0.1", 0), LedgerWorkerHandler, self.store)
        self.threads = [
            threading.Thread(target=self.workflow.serve_forever, daemon=True),
            threading.Thread(target=self.worker.serve_forever, daemon=True),
        ]

    @staticmethod
    def _base_url(server: ThreadingHTTPServer) -> str:
        host, port = server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def workflow_url(self) -> str:
        return self._base_url(self.workflow)

    @property
    def worker_url(self) -> str:
        return self._base_url(self.worker)

    def __enter__(self) -> "RunningCompositeFixture":
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        for server in (self.workflow, self.worker):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)


def _request(
    base_url: str,
    method: str,
    path: str,
    persona: str | None = None,
) -> Response:
    headers: dict[str, str] = {}
    if persona is not None:
        headers["Authorization"] = f"Bearer {PERSONA_TOKENS[persona]}"
    request = Request(base_url + path, method=method, headers=headers)
    try:
        with urlopen(request, timeout=3) as response:
            raw = response.read()
            body = json.loads(raw.decode("utf-8")) if raw else {}
            return Response(response.status, body)
    except HTTPError as exc:
        raw = exc.read()
        body = json.loads(raw.decode("utf-8")) if raw else {}
        return Response(exc.code, body)


def run_composite_self_test(database_path: str | Path) -> dict[str, Any]:
    started = time.monotonic()
    checks: list[dict[str, Any]] = []

    with RunningCompositeFixture(database_path) as fixture:
        workflow_health = _request(fixture.workflow_url, "GET", "/health")
        worker_health = _request(fixture.worker_url, "GET", "/health")
        checks.append({
            "name": "two_independent_loopback_services",
            "passed": (
                workflow_health.status == 200
                and worker_health.status == 200
                and fixture.workflow_url != fixture.worker_url
            ),
        })

        empty = _request(fixture.worker_url, "POST", "/internal/consume-one")
        checks.append({
            "name": "worker_has_no_effect_without_event",
            "passed": empty.status == 204,
        })

        requested = _request(
            fixture.workflow_url, "POST", "/refunds/request", "customer"
        )
        approved = _request(
            fixture.workflow_url,
            "POST",
            f"/refunds/{REFUND_ID}/approve",
            "reviewer",
        )
        queued = _request(
            fixture.workflow_url,
            "POST",
            f"/refunds/{REFUND_ID}/queue-settlement",
            "finance",
        )
        checks.append({
            "name": "workflow_queues_async_settlement",
            "passed": (
                requested.status == 201
                and approved.status == 200
                and queued.status == 202
                and fixture.store.snapshot()["event_status"] == "PENDING"
                and fixture.store.snapshot()["ledger_entry_count"] == 0
            ),
        })

        consumed = _request(
            fixture.worker_url, "POST", "/internal/consume-one"
        )
        settled = fixture.store.snapshot()
        checks.append({
            "name": "second_service_consumes_async_boundary",
            "passed": (
                consumed.status == 200
                and settled["refund_status"] == "SETTLED"
                and settled["event_status"] == "CONSUMED"
                and settled["ledger_entry_count"] == 1
                and settled["ledger_total_minor"] == 5000
            ),
        })

        replay = _request(
            fixture.worker_url, "POST", "/internal/consume-one"
        )
        after_replay = fixture.store.snapshot()
        checks.append({
            "name": "consumed_event_is_idempotent",
            "passed": (
                replay.status == 204
                and after_replay["ledger_entry_count"] == 1
                and after_replay["ledger_total_minor"] == 5000
            ),
        })

        fixture.store.reset()
        reset = fixture.store.snapshot()
        checks.append({
            "name": "deterministic_reset_clears_both_service_states",
            "passed": (
                reset["refund_status"] is None
                and reset["event_status"] is None
                and reset["ledger_entry_count"] == 0
                and reset["ledger_total_minor"] == 0
            ),
        })

    passed = all(check["passed"] for check in checks)
    return {
        "schema_version": SCHEMA_VERSION,
        "result_kind": RESULT_KIND,
        "status": "MEASURED" if passed else "FAILED",
        "fixture_tier": "COMPOSITE_APPLICATION",
        "network_scope": "LOOPBACK_ONLY",
        "properties": {
            "runtime_execution": True,
            "real_browser": False,
            "durable_state": True,
            "multi_step_workflow": True,
            "deterministic_reset": True,
            "auth_personas": 3,
            "service_count": 2,
            "async_boundary": True,
        },
        "checks": checks,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "production_effectiveness_established": False,
        "arena_full_workflow_measured": False,
        "note": (
            "Fixture self-test only. The two-service LOCAL topology and durable "
            "outbox boundary do not establish SecHelix or production effectiveness."
        ),
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic SecHelix composite LOCAL fixture self-test"
    )
    parser.add_argument("--database", help="optional SQLite path")
    parser.add_argument("--output", help="optional result JSON")
    args = parser.parse_args()

    if args.database:
        result = run_composite_self_test(args.database)
    else:
        with TemporaryDirectory() as tmp:
            result = run_composite_self_test(Path(tmp) / "fixture.sqlite3")

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["status"] == "MEASURED" else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
