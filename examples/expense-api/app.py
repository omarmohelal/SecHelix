"""A small multi-tenant expense API. Standard library only.

Run it:

    python examples/expense-api/app.py --port 8077

Two organizations, four people, three receipts. Tokens are printed at startup
so the demo needs no signup flow.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import auth
import db
import reports


def receipt_json(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "merchant": row["merchant"],
        "amount_cents": row["amount_cents"],
        "memo": row["memo"],
        "status": row["status"],
        "org_id": row["org_id"],
    }


class Handler(BaseHTTPRequestHandler):
    # NOT `connection`: BaseHTTPRequestHandler already uses that name for the
    # client socket, and shadowing it breaks every request.
    store: sqlite3.Connection

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # quieter demo output
        pass

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        query = parse_qs(url.query)
        try:
            person = auth.identify(self.store, self.headers.get("Authorization"))
        except auth.Unauthenticated as exc:
            return self._send(401, {"error": str(exc)})

        parts = [p for p in url.path.split("/") if p]

        # GET /api/receipts
        if parts == ["api", "receipts"]:
            try:
                rows = reports.list_receipts(
                    self.store,
                    person["org_id"],
                    (query.get("sort") or [None])[0],
                    (query.get("dir") or [None])[0],
                )
            except reports.InvalidSort as exc:
                return self._send(400, {"error": str(exc)})
            return self._send(200, {"receipts": [receipt_json(r) for r in rows]})

        # GET /api/receipts/<id>
        if len(parts) == 3 and parts[:2] == ["api", "receipts"]:
            try:
                receipt_id = int(parts[2])
            except ValueError:
                return self._send(400, {"error": "receipt id must be an integer"})

            # Approvers are the only people allowed to open an individual
            # receipt; employees use the list endpoint.
            try:
                auth.require_role("approver")(person)
            except auth.Forbidden as exc:
                return self._send(403, {"error": str(exc)})

            row = self.store.execute(
                "SELECT * FROM receipt WHERE id = ?", (receipt_id,)
            ).fetchone()
            if row is None:
                return self._send(404, {"error": "no such receipt"})
            return self._send(200, receipt_json(row))

        return self._send(404, {"error": "no such route"})


def build(database: Path) -> type[Handler]:
    connection = db.create(database, threadsafe=True)
    return type("BoundHandler", (Handler,), {"store": connection})


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo expense API")
    parser.add_argument("--port", type=int, default=8077)
    parser.add_argument("--db", type=Path, default=Path(tempfile.gettempdir()) / "expense-demo.sqlite")
    args = parser.parse_args()

    handler = build(args.db)
    print(f"expense-api on http://127.0.0.1:{args.port}")
    print("  Northwind approver  Bearer tok-ada")
    print("  Northwind employee  Bearer tok-bo")
    print("  Contoso   approver  Bearer tok-cy")
    print("  Contoso   employee  Bearer tok-dee")
    ThreadingHTTPServer(("127.0.0.1", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
