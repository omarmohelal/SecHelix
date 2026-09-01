#!/usr/bin/env python3
"""Generate the SecHelix V1 evaluation fixture suite.

Fixtures are paired vulnerable/clean modules that require dataflow, state, or
authorization reasoning rather than keyword matching. Sources are deliberately
realistic: routes, repositories, and state machines rather than three-line
snippets. Regenerate with `python scripts/build_eval_fixtures.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "evals" / "fixtures"

PROVENANCE = (
    "Synthetic SecHelix fixture authored for this repository. No third-party code, "
    "no customer data, and no request is executed by the eval runner."
)


def fixture(
    fixture_id: str,
    family: str,
    task: str,
    *,
    language: str,
    filename: str,
    vulnerable: str,
    vulnerable_rationale: str,
    clean: str,
    clean_rationale: str,
    cwe: list[str],
    difficulty: str,
) -> dict:
    return {
        "id": fixture_id,
        "schema_version": "1.1",
        "family": family,
        "task": task,
        "provenance": PROVENANCE,
        "difficulty": difficulty,
        "mappings": {"cwe": cwe},
        "variants": {
            "vulnerable": {
                "expected": "VULNERABLE",
                "language": language,
                "filename": filename,
                "source": vulnerable,
                "rationale": vulnerable_rationale,
            },
            "clean": {
                "expected": "CLEAN",
                "language": language,
                "filename": filename,
                "source": clean,
                "rationale": clean_rationale,
            },
        },
    }


FIXTURES: list[dict] = []

# ---------------------------------------------------------------- authorization
FIXTURES.append(fixture(
    "EVAL-AUTHZ-002",
    "Authorization / BOLA / BFLA",
    "Decide whether a caller can read or export objects owned by another tenant.",
    language="python",
    filename="reports_service.py",
    cwe=["CWE-639", "CWE-862"],
    difficulty="medium",
    vulnerable_rationale=(
        "list_reports scopes by tenant, but export_report re-fetches by primary key "
        "through a second repository call that carries no tenant predicate. The "
        "ownership check on the list path creates a false impression of safety."
    ),
    vulnerable='''\
"""Tenant reporting service."""


class ReportRepository:
    def __init__(self, rows):
        self._rows = rows

    def list_for_tenant(self, tenant_id):
        return [r for r in self._rows if r["tenant_id"] == tenant_id]

    def get(self, report_id):
        for row in self._rows:
            if row["id"] == report_id:
                return row
        return None


class ReportService:
    def __init__(self, repo, audit):
        self._repo = repo
        self._audit = audit

    def list_reports(self, caller):
        # Correctly scoped: the tenant predicate is applied in the query.
        return self._repo.list_for_tenant(caller["tenant_id"])

    def export_report(self, caller, report_id):
        # The caller is authenticated, and the list view already filtered by
        # tenant, so the export path fetches straight by identifier.
        report = self._repo.get(report_id)
        if report is None:
            raise LookupError("report not found")
        self._audit.record(caller["id"], "export", report_id)
        return {"id": report["id"], "rows": report["rows"]}
''',
    clean_rationale=(
        "Both the list and export paths resolve objects through a repository call "
        "that requires the effective tenant, so the ownership invariant holds on "
        "every path instead of only the listing path."
    ),
    clean='''\
"""Tenant reporting service."""


class ReportRepository:
    def __init__(self, rows):
        self._rows = rows

    def list_for_tenant(self, tenant_id):
        return [r for r in self._rows if r["tenant_id"] == tenant_id]

    def get_for_tenant(self, report_id, tenant_id):
        for row in self._rows:
            if row["id"] == report_id and row["tenant_id"] == tenant_id:
                return row
        return None


class ReportService:
    def __init__(self, repo, audit):
        self._repo = repo
        self._audit = audit

    def list_reports(self, caller):
        return self._repo.list_for_tenant(caller["tenant_id"])

    def export_report(self, caller, report_id):
        # Every protected read carries the effective tenant into the query.
        report = self._repo.get_for_tenant(report_id, caller["tenant_id"])
        if report is None:
            raise LookupError("report not found")
        self._audit.record(caller["id"], "export", report_id)
        return {"id": report["id"], "rows": report["rows"]}
''',
))

FIXTURES.append(fixture(
    "EVAL-AUTHZ-003",
    "Authorization / BOLA / BFLA",
    "Decide whether a non-administrative role can reach an administrative action.",
    language="python",
    filename="admin_routes.py",
    cwe=["CWE-285", "CWE-863"],
    difficulty="hard",
    vulnerable_rationale=(
        "require_role checks membership against the roles the CLIENT supplied in the "
        "request payload rather than the roles resolved from the session, so any "
        "caller can assert the admin role. The decorator looks like enforcement."
    ),
    vulnerable='''\
"""Administrative routes."""

from functools import wraps


def require_role(role):
    def decorator(handler):
        @wraps(handler)
        def wrapper(request, *args, **kwargs):
            # Roles arrive with the request so the UI can pre-render menus.
            claimed = request.get("body", {}).get("roles", [])
            if role not in claimed:
                raise PermissionError("forbidden")
            return handler(request, *args, **kwargs)
        return wrapper
    return decorator


class Billing:
    def __init__(self, ledger):
        self._ledger = ledger

    @require_role("admin")
    def issue_refund(self, request, order_id, amount):
        session = request["session"]
        return self._ledger.refund(order_id, amount, actor=session["user_id"])
''',
    clean_rationale=(
        "The role is resolved server-side from the authenticated session and the "
        "client-supplied roles are ignored, so the privileged function is gated by "
        "trusted state."
    ),
    clean='''\
"""Administrative routes."""

from functools import wraps


def require_role(role, directory):
    def decorator(handler):
        @wraps(handler)
        def wrapper(request, *args, **kwargs):
            session = request.get("session") or {}
            user_id = session.get("user_id")
            if not user_id:
                raise PermissionError("unauthenticated")
            # Authoritative roles come from server-side state, never the payload.
            if role not in directory.roles_for(user_id):
                raise PermissionError("forbidden")
            return handler(request, *args, **kwargs)
        return wrapper
    return decorator


class Billing:
    def __init__(self, ledger, directory):
        self._ledger = ledger
        self.issue_refund = require_role("admin", directory)(self._issue_refund)

    def _issue_refund(self, request, order_id, amount):
        session = request["session"]
        return self._ledger.refund(order_id, amount, actor=session["user_id"])
''',
))

# ------------------------------------------------------- authentication/session
FIXTURES.append(fixture(
    "EVAL-AUTH-002",
    "Authentication / Sessions",
    "Decide whether the session lifecycle allows a pre-authentication identifier to survive privilege change.",
    language="python",
    filename="sessions.py",
    cwe=["CWE-384"],
    difficulty="medium",
    vulnerable_rationale=(
        "login mutates the existing session in place and keeps the identifier that "
        "was issued before authentication, so an attacker who plants a known "
        "session id can ride it into the authenticated session (session fixation)."
    ),
    vulnerable='''\
"""Session handling."""

import secrets


class SessionStore:
    def __init__(self):
        self._sessions = {}

    def create_anonymous(self):
        sid = secrets.token_urlsafe(32)
        self._sessions[sid] = {"user_id": None, "roles": []}
        return sid

    def get(self, sid):
        return self._sessions.get(sid)

    def login(self, sid, user):
        session = self._sessions.get(sid)
        if session is None:
            raise LookupError("no session")
        # Promote the visitor's existing session to an authenticated one.
        session["user_id"] = user["id"]
        session["roles"] = user["roles"]
        return sid

    def logout(self, sid):
        self._sessions.pop(sid, None)
''',
    clean_rationale=(
        "login issues a brand-new identifier and destroys the pre-authentication "
        "session, so a fixed identifier cannot survive the privilege transition."
    ),
    clean='''\
"""Session handling."""

import secrets


class SessionStore:
    def __init__(self):
        self._sessions = {}

    def create_anonymous(self):
        sid = secrets.token_urlsafe(32)
        self._sessions[sid] = {"user_id": None, "roles": []}
        return sid

    def get(self, sid):
        return self._sessions.get(sid)

    def login(self, sid, user):
        if sid not in self._sessions:
            raise LookupError("no session")
        # Rotate on privilege change: the old identifier never becomes authenticated.
        self._sessions.pop(sid, None)
        new_sid = secrets.token_urlsafe(32)
        self._sessions[new_sid] = {"user_id": user["id"], "roles": user["roles"]}
        return new_sid

    def logout(self, sid):
        self._sessions.pop(sid, None)
''',
))

# ------------------------------------------------------------------- injection
FIXTURES.append(fixture(
    "EVAL-INJ-002",
    "Injection / Dataflow",
    "Decide whether caller-controlled input reaches a query without parameterization.",
    language="python",
    filename="search_repository.py",
    cwe=["CWE-89"],
    difficulty="hard",
    vulnerable_rationale=(
        "Values are parameterized, but the sort column and direction are "
        "concatenated into the ORDER BY clause after passing through a helper that "
        "only strips whitespace, so caller input still reaches SQL text."
    ),
    vulnerable='''\
"""Product search repository."""

ALLOWED_FILTERS = {"category", "vendor"}


def _clean(value):
    return str(value).strip()


class SearchRepository:
    def __init__(self, connection):
        self._conn = connection

    def search(self, filters, sort_by, direction, limit=50):
        where = []
        params = []
        for key, value in filters.items():
            if key not in ALLOWED_FILTERS:
                continue
            where.append(f"{key} = ?")
            params.append(value)

        clause = " AND ".join(where) or "1=1"
        # Column identifiers cannot be bound, so they are interpolated.
        order = f"{_clean(sort_by)} {_clean(direction)}"
        sql = f"SELECT id, name, price FROM products WHERE {clause} ORDER BY {order} LIMIT ?"
        params.append(int(limit))
        return self._conn.execute(sql, params).fetchall()
''',
    clean_rationale=(
        "The sort column and direction are mapped through explicit allowlists to "
        "fixed literals, so no caller-controlled text reaches the SQL string."
    ),
    clean='''\
"""Product search repository."""

ALLOWED_FILTERS = {"category", "vendor"}
SORT_COLUMNS = {"name": "name", "price": "price", "created": "created_at"}
SORT_DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


class SearchRepository:
    def __init__(self, connection):
        self._conn = connection

    def search(self, filters, sort_by, direction, limit=50):
        where = []
        params = []
        for key, value in filters.items():
            if key not in ALLOWED_FILTERS:
                continue
            where.append(f"{key} = ?")
            params.append(value)

        clause = " AND ".join(where) or "1=1"
        # Identifiers resolve to fixed literals; unknown input is rejected.
        column = SORT_COLUMNS.get(str(sort_by).lower())
        order_dir = SORT_DIRECTIONS.get(str(direction).lower())
        if column is None or order_dir is None:
            raise ValueError("unsupported sort")
        sql = f"SELECT id, name, price FROM products WHERE {clause} ORDER BY {column} {order_dir} LIMIT ?"
        params.append(int(limit))
        return self._conn.execute(sql, params).fetchall()
''',
))

# ------------------------------------------------------------------------- xss
FIXTURES.append(fixture(
    "EVAL-WEB-002",
    "Browser / XSS",
    "Decide whether stored user content reaches the DOM without contextual escaping.",
    language="javascript",
    filename="comment-view.js",
    cwe=["CWE-79"],
    difficulty="medium",
    vulnerable_rationale=(
        "escapeHtml neutralizes angle brackets and quotes for element content, but "
        "the author display name is interpolated into an attribute inside a "
        "template that is assigned with innerHTML, and the URL is written to href "
        "with no scheme check, so a javascript: author link executes."
    ),
    vulnerable='''\
// Renders a stored comment thread.
export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function renderComment(node, comment) {
  const body = escapeHtml(comment.body);
  const name = escapeHtml(comment.author.name);
  // The author's homepage is optional and supplied at signup.
  const link = comment.author.homepage || "#";
  node.innerHTML = `
    <article class="comment">
      <a class="author" href="${link}">${name}</a>
      <p>${body}</p>
    </article>`;
  return node;
}
''',
    clean_rationale=(
        "Content is inserted as text nodes rather than markup, and the homepage URL "
        "is validated against a scheme allowlist before it is assigned to href."
    ),
    clean='''\
// Renders a stored comment thread.
const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

export function safeHref(value) {
  if (!value) return null;
  try {
    return SAFE_SCHEMES.has(new URL(value).protocol) ? value : null;
  } catch {
    return null;
  }
}

export function renderComment(node, comment) {
  const article = document.createElement("article");
  article.className = "comment";

  const href = safeHref(comment.author.homepage);
  const author = document.createElement(href ? "a" : "span");
  author.className = "author";
  if (href) author.setAttribute("href", href);
  author.textContent = comment.author.name;

  const body = document.createElement("p");
  body.textContent = comment.body;

  article.append(author, body);
  node.replaceChildren(article);
  return node;
}
''',
))

# ------------------------------------------------------------------------ ssrf
FIXTURES.append(fixture(
    "EVAL-SSRF-002",
    "SSRF / URL Fetching",
    "Decide whether a validated URL can still reach an internal destination.",
    language="python",
    filename="link_preview.py",
    cwe=["CWE-918"],
    difficulty="hard",
    vulnerable_rationale=(
        "The destination is validated once before the request, but redirects are "
        "followed automatically and the redirect target is never re-validated, so a "
        "permitted host can redirect the fetch to a private address (TOCTOU)."
    ),
    vulnerable='''\
"""Link preview fetcher."""

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_public(host):
    addr = ipaddress.ip_address(socket.gethostbyname(host))
    return not any(addr in net for net in BLOCKED_NETS)


def fetch_preview(url, http_client):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("https required")
    if not _is_public(parsed.hostname):
        raise ValueError("private destination")
    # Validated, so let the client resolve redirects for us.
    response = http_client.get(url, allow_redirects=True, timeout=3)
    return {"status": response.status_code, "body": response.text[:4096]}
''',
    clean_rationale=(
        "Redirects are disabled and each hop is revalidated in a bounded loop, so "
        "the destination is checked immediately before every request."
    ),
    clean='''\
"""Link preview fetcher."""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]
MAX_HOPS = 3


def _assert_allowed(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("https required")
    addr = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if any(addr in net for net in BLOCKED_NETS):
        raise ValueError("private destination")
    return parsed


def fetch_preview(url, http_client):
    current = url
    for _ in range(MAX_HOPS):
        _assert_allowed(current)
        # Never delegate redirect handling; each hop is revalidated above.
        response = http_client.get(current, allow_redirects=False, timeout=3)
        if response.status_code in (301, 302, 303, 307, 308):
            current = urljoin(current, response.headers["location"])
            continue
        return {"status": response.status_code, "body": response.text[:4096]}
    raise ValueError("too many redirects")
''',
))


# ------------------------------------------------------------ files / traversal
FIXTURES.append(fixture(
    "EVAL-FILE-002",
    "Files / Uploads / Parsers",
    "Decide whether a caller-supplied name can escape the storage directory.",
    language="python",
    filename="attachment_store.py",
    cwe=["CWE-22"],
    difficulty="hard",
    vulnerable_rationale=(
        "The traversal filter rejects '..' before decoding, but the name is then "
        "URL-decoded and joined, so an encoded '%2e%2e%2f' survives the check and "
        "escapes the base directory."
    ),
    vulnerable='''\
"""Attachment storage."""

import os
from urllib.parse import unquote

BASE = "/srv/attachments"


def save(name, data):
    if ".." in name or name.startswith("/"):
        raise ValueError("invalid name")
    # Names arrive percent-encoded from the upload form.
    decoded = unquote(name)
    path = os.path.join(BASE, decoded)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return path
''',
    clean_rationale=(
        "The name is decoded first, reduced to its basename, and the resolved path "
        "is asserted to stay inside the base directory before any write."
    ),
    clean='''\
"""Attachment storage."""

import os
from urllib.parse import unquote

BASE = os.path.realpath("/srv/attachments")


def save(name, data):
    # Decode first, then reduce to a single path component.
    decoded = unquote(name)
    leaf = os.path.basename(decoded)
    if not leaf or leaf in {".", ".."}:
        raise ValueError("invalid name")
    path = os.path.realpath(os.path.join(BASE, leaf))
    # Containment is asserted on the resolved path, not the input string.
    if os.path.commonpath([BASE, path]) != BASE:
        raise ValueError("path escapes storage root")
    with open(path, "wb") as handle:
        handle.write(data)
    return path
''',
))

# --------------------------------------------------------- business / payments
FIXTURES.append(fixture(
    "EVAL-MONEY-002",
    "Business Logic / Payments",
    "Decide whether a refund flow can return more value than was captured.",
    language="python",
    filename="refunds.py",
    cwe=["CWE-840"],
    difficulty="hard",
    vulnerable_rationale=(
        "Each refund is checked against the order total instead of the remaining "
        "refundable balance, so repeated partial refunds can cumulatively exceed "
        "the captured amount."
    ),
    vulnerable='''\
"""Refund processing."""


class RefundService:
    def __init__(self, orders, ledger):
        self._orders = orders
        self._ledger = ledger

    def refund(self, order_id, amount, actor):
        order = self._orders.get(order_id)
        if order is None:
            raise LookupError("unknown order")
        if amount <= 0:
            raise ValueError("amount must be positive")
        # A refund may never exceed what the customer paid.
        if amount > order["total"]:
            raise ValueError("refund exceeds order total")
        self._ledger.credit(order["customer_id"], amount)
        self._orders.append_refund(order_id, amount, actor)
        return {"order_id": order_id, "refunded": amount}
''',
    clean_rationale=(
        "The refundable balance is recomputed from prior refunds inside the same "
        "transaction, so the cumulative invariant holds across repeated calls."
    ),
    clean='''\
"""Refund processing."""


class RefundService:
    def __init__(self, orders, ledger):
        self._orders = orders
        self._ledger = ledger

    def refund(self, order_id, amount, actor):
        if amount <= 0:
            raise ValueError("amount must be positive")
        with self._orders.transaction() as tx:
            order = tx.lock_order(order_id)
            if order is None:
                raise LookupError("unknown order")
            already = sum(r["amount"] for r in tx.refunds_for(order_id))
            remaining = order["total"] - already
            # The invariant is cumulative, not per-request.
            if amount > remaining:
                raise ValueError("refund exceeds remaining refundable balance")
            self._ledger.credit(order["customer_id"], amount)
            tx.append_refund(order_id, amount, actor)
        return {"order_id": order_id, "refunded": amount}
''',
))

# ------------------------------------------------------- race / idempotency
FIXTURES.append(fixture(
    "EVAL-RACE-002",
    "Race / Idempotency / Replay",
    "Decide whether concurrent redemptions of a single-use code can both succeed.",
    language="python",
    filename="voucher.py",
    cwe=["CWE-367"],
    difficulty="hard",
    vulnerable_rationale=(
        "The redeemed check and the write are separate statements with no lock or "
        "conditional update, so two concurrent callers can both observe an unused "
        "voucher and both redeem it (check-then-act)."
    ),
    vulnerable='''\
"""Voucher redemption."""


class VoucherService:
    def __init__(self, db, wallet):
        self._db = db
        self._wallet = wallet

    def redeem(self, code, user_id):
        voucher = self._db.query_one(
            "SELECT code, value, redeemed_by FROM vouchers WHERE code = ?", [code]
        )
        if voucher is None:
            raise LookupError("unknown voucher")
        if voucher["redeemed_by"] is not None:
            raise ValueError("already redeemed")

        self._wallet.credit(user_id, voucher["value"])
        self._db.execute(
            "UPDATE vouchers SET redeemed_by = ? WHERE code = ?", [user_id, code]
        )
        return {"code": code, "value": voucher["value"]}
''',
    clean_rationale=(
        "Redemption is a single conditional update whose affected-row count decides "
        "the outcome, so only one concurrent caller can claim the voucher."
    ),
    clean='''\
"""Voucher redemption."""


class VoucherService:
    def __init__(self, db, wallet):
        self._db = db
        self._wallet = wallet

    def redeem(self, code, user_id):
        # Claim atomically: the WHERE clause carries the unused precondition.
        claimed = self._db.execute(
            "UPDATE vouchers SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL",
            [user_id, code],
        )
        if claimed.rowcount != 1:
            raise ValueError("already redeemed or unknown voucher")
        voucher = self._db.query_one("SELECT code, value FROM vouchers WHERE code = ?", [code])
        self._wallet.credit(user_id, voucher["value"])
        return {"code": code, "value": voucher["value"]}
''',
))

# ------------------------------------------------------ secrets / supply chain
FIXTURES.append(fixture(
    "EVAL-SUPPLY-002",
    "Secrets / Supply Chain",
    "Decide whether a build step can execute unverified remote content.",
    language="python",
    filename="plugin_installer.py",
    cwe=["CWE-494"],
    difficulty="medium",
    vulnerable_rationale=(
        "A digest is computed and logged but never compared against the expected "
        "value before the payload is written and executed, so integrity is observed "
        "rather than enforced."
    ),
    vulnerable='''\
"""Plugin installer."""

import hashlib
import subprocess


def install(plugin, http_client, log):
    response = http_client.get(plugin["url"], timeout=10)
    payload = response.content
    digest = hashlib.sha256(payload).hexdigest()
    log.info("downloaded %s sha256=%s expected=%s", plugin["name"], digest, plugin["sha256"])

    target = f"/opt/plugins/{plugin['name']}.py"
    with open(target, "wb") as handle:
        handle.write(payload)
    subprocess.run(["python", target, "--install"], check=True)
    return target
''',
    clean_rationale=(
        "The computed digest is compared against the pinned expected value with a "
        "constant-time check and the install aborts on mismatch before any write."
    ),
    clean='''\
"""Plugin installer."""

import hashlib
import hmac
import subprocess


def install(plugin, http_client, log):
    response = http_client.get(plugin["url"], timeout=10)
    payload = response.content
    digest = hashlib.sha256(payload).hexdigest()
    # Enforce the pin before the payload can touch disk.
    if not hmac.compare_digest(digest, plugin["sha256"]):
        raise ValueError(f"integrity mismatch for {plugin['name']}")
    log.info("verified %s sha256=%s", plugin["name"], digest)

    target = f"/opt/plugins/{plugin['name']}.py"
    with open(target, "wb") as handle:
        handle.write(payload)
    subprocess.run(["python", target, "--install"], check=True)
    return target
''',
))

# ------------------------------------------------------------------ AI / MCP
FIXTURES.append(fixture(
    "EVAL-AI-002",
    "AI / Agent / MCP",
    "Decide whether untrusted retrieved content can drive a privileged tool call.",
    language="python",
    filename="agent_loop.py",
    cwe=["CWE-77"],
    difficulty="hard",
    vulnerable_rationale=(
        "Retrieved document text is concatenated into the same instruction context "
        "as the operator prompt and the tool dispatcher honours any tool the model "
        "names, so injected text in a fetched page can invoke the privileged "
        "delete_records tool."
    ),
    vulnerable='''\
"""Support agent loop."""

TOOLS = {
    "search_docs": lambda args, ctx: ctx["index"].search(args["q"]),
    "send_email": lambda args, ctx: ctx["mailer"].send(args["to"], args["body"]),
    "delete_records": lambda args, ctx: ctx["db"].delete(args["table"], args["where"]),
}


def run(operator_prompt, ticket, model, ctx):
    fetched = ctx["index"].fetch(ticket["url"])
    # Give the model everything it needs in one context.
    prompt = f"{operator_prompt}\\n\\nTicket: {ticket['body']}\\n\\nReference:\\n{fetched}"

    for _ in range(5):
        step = model.next_step(prompt)
        if step["type"] == "final":
            return step["text"]
        tool = TOOLS[step["tool"]]
        result = tool(step["args"], ctx)
        prompt += f"\\n\\nTool {step['tool']} returned: {result}"
    return "step limit reached"
''',
    clean_rationale=(
        "Untrusted content is passed as clearly delimited data rather than "
        "instructions, and the dispatcher enforces a per-run allowlist so retrieved "
        "text cannot reach a privileged tool."
    ),
    clean='''\
"""Support agent loop."""

READ_ONLY_TOOLS = {
    "search_docs": lambda args, ctx: ctx["index"].search(args["q"]),
}
PRIVILEGED_TOOLS = {
    "send_email": lambda args, ctx: ctx["mailer"].send(args["to"], args["body"]),
    "delete_records": lambda args, ctx: ctx["db"].delete(args["table"], args["where"]),
}


def run(operator_prompt, ticket, model, ctx, allowed_tools=frozenset({"search_docs"})):
    fetched = ctx["index"].fetch(ticket["url"])
    # Untrusted content is data, never instructions, and is fenced as such.
    prompt = model.build_prompt(
        system=operator_prompt,
        untrusted={"ticket_body": ticket["body"], "reference_document": fetched},
    )

    for _ in range(5):
        step = model.next_step(prompt)
        if step["type"] == "final":
            return step["text"]
        name = step["tool"]
        if name not in allowed_tools:
            prompt = model.append_tool_error(prompt, name, "tool not permitted in this run")
            continue
        tool = READ_ONLY_TOOLS.get(name) or PRIVILEGED_TOOLS[name]
        result = tool(step["args"], ctx)
        prompt = model.append_tool_result(prompt, name, result)
    return "step limit reached"
''',
))


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    written = []
    for item in FIXTURES:
        path = DEST / f"{item['id'].lower().replace('eval-', '')}.json"
        path.write_text(json.dumps(item, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path.name)
    print(f"wrote {len(written)} fixture(s): {', '.join(sorted(written))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
