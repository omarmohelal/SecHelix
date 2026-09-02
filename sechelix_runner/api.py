"""A local HTTP wrapper around the runner.

**The API is not a source of truth.** Every endpoint reads the same run
workspace the CLI reads, and nothing here computes a status, a coverage state or
a release decision of its own. If the API and the CLI ever disagreed about a
run, the API would be wrong by construction -- so it is written to have no
opinions to disagree with.

Three deliberate limits:

**It binds loopback and nothing else.** :func:`serve` refuses a non-loopback
host rather than accepting one and warning about it, because a security tool
that can be casually exposed to a network is a liability regardless of what its
documentation says.

**It is read-mostly.** Runs can be created and cancelled; nothing else mutates.
There is no endpoint that edits a finding, a status or a coverage record,
because a run record that can be edited after the fact is not evidence.

**Run ids are validated by the same code the CLI uses.** The path traversal the
self-audit found was reachable through any wrapper that accepts an id, so this
one goes through :class:`~sechelix_runner.storage.RunWorkspace` and inherits its
refusal rather than re-implementing the check.

Standard library only: ``http.server`` is enough for a local, single-user,
read-mostly surface, and adding a framework would put a dependency into a
package whose whole point is not having any.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .sandbox import is_loopback
from .storage import InvalidRunId, RunWorkspace, list_runs

#: Endpoints, in the order the router tries them.
ROUTES = (
    ("GET", "/runs"),
    ("POST", "/runs"),
    ("GET", "/runs/{id}"),
    ("GET", "/runs/{id}/graph"),
    ("GET", "/runs/{id}/events"),
    ("GET", "/runs/{id}/findings"),
    ("GET", "/runs/{id}/evidence"),
    ("GET", "/runs/{id}/report"),
    ("GET", "/runs/{id}/coverage"),
    ("POST", "/runs/{id}/cancel"),
)


class RunStore:
    """Reads run workspaces. The only data access the API has."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        #: Run ids cancelled in this process. Cancellation is advisory and
        #: in-memory on purpose: persisting it would let the API mutate a run
        #: record, which is exactly what it must not do.
        self.cancelled: set[str] = set()

    def list(self) -> list[str]:
        return list_runs(self.root)

    def workspace(self, run_id: str) -> RunWorkspace:
        workspace = RunWorkspace(self.root, run_id)
        if not workspace.exists:
            raise KeyError(run_id)
        return workspace

    def document(self, run_id: str, name: str) -> Any:
        workspace = self.workspace(run_id)
        try:
            return workspace.read_json(name)
        except FileNotFoundError:
            raise KeyError(f"{run_id}/{name}") from None

    def integrity(self, run_id: str) -> list[str]:
        return self.workspace(run_id).verify()


def handle(store: RunStore, method: str, path: str) -> tuple[int, dict[str, Any]]:
    """Route one request. Pure: takes strings, returns a status and a body.

    Kept free of ``http.server`` so the whole surface is testable without
    binding a socket.
    """
    parts = [p for p in urlparse(path).path.strip("/").split("/") if p]

    if not parts or parts[0] != "runs":
        return 404, {"error": "not found", "routes": [f"{m} {p}" for m, p in ROUTES]}

    if len(parts) == 1:
        if method == "GET":
            return 200, {"runs": store.list()}
        if method == "POST":
            # Creating a run is deliberately not implemented here: starting an
            # audit is a long, budgeted, filesystem-touching operation and the
            # CLI is the honest place for it. Saying so beats a stub that
            # returns a fake run id.
            return 501, {
                "error": "run creation is performed by the CLI",
                "hint": "sechelix audit <path>",
            }
        return 405, {"error": f"{method} not allowed on /runs"}

    run_id = parts[1]
    try:
        if len(parts) == 2 and method == "GET":
            body = store.document(run_id, "run.json")
            body["integrity"] = store.integrity(run_id) or "ok"
            return 200, body
        if len(parts) == 3:
            section = parts[2]
            if method == "POST" and section == "cancel":
                store.cancelled.add(run_id)
                store.workspace(run_id)
                return 200, {"run_id": run_id, "cancelled": True}
            if method != "GET":
                return 405, {"error": f"{method} not allowed on /runs/{{id}}/{section}"}
            if section == "graph":
                return 200, store.document(run_id, "graph.json")
            if section == "events":
                return 200, {"events": store.workspace(run_id).events()}
            if section == "coverage":
                return 200, store.document(run_id, "coverage.json")
            if section == "report":
                return 200, store.document(run_id, "run.json")
            if section in ("findings", "evidence"):
                run = store.document(run_id, "run.json")
                # Findings and evidence are produced by reasoning nodes. When
                # none ran, the honest answer is an empty list plus the reason,
                # never an empty list that reads as "nothing was wrong".
                return 200, {
                    section: [],
                    "unsatisfied_mandatory": run.get("unsatisfied_mandatory", []),
                    "note": (
                        "empty because no reasoning node delivered; this is not a "
                        "statement that none exist"
                    ),
                }
        return 404, {"error": "not found"}
    except InvalidRunId as exc:
        return 400, {"error": str(exc)}
    except KeyError as exc:
        return 404, {"error": f"no such run or document: {exc.args[0]}"}


class _Handler(BaseHTTPRequestHandler):
    store: RunStore

    def _respond(self, method: str) -> None:
        status, body = handle(self.store, method, self.path)
        payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        # This surface is local and read-mostly; nothing here should ever be
        # embedded, sniffed into another type, or reached from a page.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._respond("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._respond("POST")

    def log_message(self, *args: Any) -> None:
        """Silence per-request logging; request paths can carry run ids."""


def make_server(
    root: Path | str, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Build a local server. Refuses any non-loopback bind address."""
    if not is_loopback(host):
        raise PermissionError(
            f"refusing to bind {host}: the SecHelix API is local-only. "
            "Forward a port deliberately if you need remote access."
        )
    handler = type("BoundHandler", (_Handler,), {"store": RunStore(root)})
    return ThreadingHTTPServer((host, port), handler)


def serve(root: Path | str, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the server until interrupted."""
    server = make_server(root, host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"SecHelix API on http://{bound_host}:{bound_port} (local only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
