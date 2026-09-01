#!/usr/bin/env python3
"""Generate the SecHelix V1 evaluation fixture suite.

Fixtures are paired vulnerable/clean modules that require dataflow, state, or
authorization reasoning rather than keyword matching. Sources are deliberately
realistic: routes, repositories, and state machines rather than three-line
snippets. Regenerate with `python scripts/build_eval_fixtures.py`.

Compensating-control cases
--------------------------
The most valuable negative is code that *looks* vulnerable and is not, because a
real control elsewhere in the module holds the invariant. `evals/run_evals.py`
requires each fixture to carry exactly the `vulnerable` and `clean` variants, so
a third `compensated` variant would break the runner and its tests. These cases
are therefore expressed as a **second fixture whose `clean` variant is the
compensated code**: both variants share the alarming surface (a `pickle.loads`,
an `innerHTML`-class sink, a predicate-free tenant query, a whole request body
copied onto an object), and they differ only in whether the compensating control
actually binds. The paired `vulnerable` variant is the same code with the
control drifted, scoped away, or bypassable, which is what makes the negative a
refutation exercise rather than a cosmetic contrast.
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

FIXTURES.append(fixture(
    "EVAL-AI-003",
    "AI / Agent / MCP",
    "Decide whether a per-run tool allowlist binds the tool that actually executes.",
    language="python",
    filename="tool_router.py",
    cwe=["CWE-863", "CWE-829"],
    difficulty="hard",
    vulnerable_rationale=(
        "A per-run allowlist exists and is enforced before dispatch, which is what "
        "makes the module read as hardened. The allowlist holds bare tool names "
        "while the index is one flat namespace keyed by bare name and re-registered "
        "on every connect, so a second or reconnecting server that advertises an "
        "already approved name takes over the slot. The check binds the string the "
        "model emitted; execution binds whichever server currently owns that string."
    ),
    vulnerable='''\
"""MCP host tool router."""


class ToolRouter:
    """Presents the tools of every connected server as one namespace."""

    def __init__(self, servers):
        self._index = {}
        for server in servers:
            self.register(server)

    def register(self, server):
        for tool in server.list_tools():
            # A server that reconnects re-registers its tools, so the index
            # always reflects what each server currently offers.
            self._index[tool["name"]] = (server, tool)

    def dispatch(self, step, allowed_tools):
        name = step["tool"]
        if name not in allowed_tools:
            raise PermissionError(f"{name} is not permitted in this run")
        server, tool = self._index[name]
        return server.call_tool(tool["name"], step["args"])


def run_step(step, router, run_config):
    # The run's authority is fixed before the loop starts.
    return router.dispatch(step, run_config["allowed_tools"])
''',
    clean_rationale=(
        "Tool identity is the server plus the name, so two servers offering one name "
        "cannot collide, and the allowlist stores the digest of the definition pinned "
        "when the run bound its authority. A tool that is unlisted, that belongs to a "
        "different server, or whose description or schema changed after approval "
        "fails the same comparison, so neither shadowing nor a post-approval "
        "redefinition can inherit an approval."
    ),
    clean='''\
"""MCP host tool router."""

import hashlib
import json


def definition_digest(tool):
    canonical = json.dumps(
        {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "input_schema": tool.get("input_schema", {}),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ToolRouter:
    """Presents the tools of every connected server as one namespace."""

    def __init__(self, servers):
        self._index = {}
        for server in servers:
            self.register(server)

    def register(self, server):
        for tool in server.list_tools():
            # Slots are keyed by server identity, so two servers offering the
            # same bare name occupy two slots and neither can take the other's.
            self._index[(server.server_id, tool["name"])] = {
                "server": server,
                "tool": tool,
                "digest": definition_digest(tool),
            }

    def dispatch(self, step, allowed_tools):
        # allowed_tools maps (server_id, name) to the digest pinned when the run
        # bound its authority, so the check names the definition that executes.
        key = (step.get("server_id"), step.get("tool"))
        entry = self._index.get(key)
        if entry is None:
            raise PermissionError("no such tool on that server")
        if allowed_tools.get(key) != entry["digest"]:
            # Covers an unlisted tool and a definition that changed after it was
            # approved: a redefined tool is a new tool, not an approved one.
            raise PermissionError(f"{key} is not permitted in this run")
        return entry["server"].call_tool(entry["tool"]["name"], step["args"])


def run_step(step, router, run_config):
    # The run's authority is fixed before the loop starts.
    return router.dispatch(step, run_config["allowed_tools"])
''',
))

FIXTURES.append(fixture(
    "EVAL-AI-004",
    "AI / Agent / MCP",
    "Decide whether an agent-selected command can reach execution as something other than data.",
    language="python",
    filename="command_tool.py",
    cwe=["CWE-88", "CWE-77"],
    difficulty="hard",
    vulnerable_rationale=(
        "shell=False, an argv list, and a binary allowlist are all present, which is "
        "the shape reviewers accept as the hardened form of command execution. "
        "Everything after argv[0] still comes from the model, and each allowed "
        "binary interprets some of its own arguments as a program or a configuration "
        "override, so the model can name a subprocess without any shell being "
        "involved. The allowlist constrains which interpreter runs, not what it is "
        "told to do."
    ),
    vulnerable='''\
"""Repository inspection tool exposed to the agent."""

import subprocess

ALLOWED_BINARIES = {"git", "rg", "sed"}
TIMEOUT_SECONDS = 30
MAX_OUTPUT = 4000


def run_command(step, workdir):
    """Run a command the model composed.

    The argument vector goes straight to exec with no shell, so quoting, pipes,
    and semicolons inside the arguments are inert.
    """
    argv = [str(part) for part in step["argv"]]
    if not argv:
        raise ValueError("empty command")
    if argv[0] not in ALLOWED_BINARIES:
        raise PermissionError(f"{argv[0]} is not an allowed binary")
    completed = subprocess.run(
        argv,
        cwd=workdir,
        shell=False,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
        text=True,
    )
    return {"returncode": completed.returncode, "stdout": completed.stdout[:MAX_OUTPUT]}
''',
    clean_rationale=(
        "The model selects an operation rather than composing a command line. Every "
        "flag is a literal of this module, the one model-supplied value must match a "
        "plain-identifier pattern and is placed after a double dash so it cannot be "
        "parsed as an option, and the child runs with a minimal environment so no "
        "inherited variable can reintroduce a hook, pager, or config command. The "
        "legitimate read-only inspection still works."
    ),
    clean='''\
"""Repository inspection tool exposed to the agent."""

import re
import subprocess

TIMEOUT_SECONDS = 30
MAX_OUTPUT = 4000

# The model picks an operation, never a command line. Every flag below is a
# literal of this module, so no option can originate in model output.
OPERATIONS = {
    "log": ["git", "--no-pager", "log", "--max-count=50", "--format=%H %s"],
    "show": ["git", "--no-pager", "show", "--stat"],
    "grep": ["rg", "--no-config", "--fixed-strings", "--max-count=200"],
}
OPERAND = re.compile("[A-Za-z0-9._/-]{1,120}")
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def run_command(step, workdir):
    base = OPERATIONS.get(step.get("operation"))
    if base is None:
        raise PermissionError("operation is not available")
    operand = str(step.get("operand", ""))
    if not OPERAND.fullmatch(operand):
        raise ValueError("operand is not a plain identifier")
    # The single model-supplied value goes after "--", so a leading dash cannot
    # be read as an option by a binary that treats some options as programs.
    argv = [*base, "--", operand]
    completed = subprocess.run(
        argv,
        cwd=workdir,
        shell=False,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
        text=True,
        # A minimal environment: no inherited config, hook, or pager variable.
        env=CHILD_ENV,
    )
    return {"returncode": completed.returncode, "stdout": completed.stdout[:MAX_OUTPUT]}
''',
))

FIXTURES.append(fixture(
    "EVAL-AI-005",
    "AI / Agent / MCP",
    "Decide whether content from an untrusted source can become a durable trusted instruction.",
    language="python",
    filename="agent_memory.py",
    cwe=["CWE-807", "CWE-349"],
    difficulty="hard",
    vulnerable_rationale=(
        "The store has a trust model and the instruction channel is filtered by it, "
        "so the module reads as provenance-aware. The label is computed from who "
        "wrote the string rather than from where the content came from, and the "
        "session summary is attributed to the assistant. A summary of a retrieved "
        "document is therefore stored first-party and replayed into the system "
        "prompt of every later session for that user, so one injection during one "
        "run becomes a standing instruction."
    ),
    vulnerable='''\
"""Durable per-user agent memory."""

FIRST_PARTY = "FIRST_PARTY"
THIRD_PARTY = "THIRD_PARTY"


class MemoryStore:
    def __init__(self, rows, clock):
        self._rows = rows
        self._clock = clock

    def remember(self, user_id, text, author):
        self._rows.insert({
            "user_id": user_id,
            "text": text,
            "author": author,
            # Text the assistant wrote is a conclusion this system reached
            # rather than raw third-party content, so it is stored trusted.
            "trust": FIRST_PARTY if author == "assistant" else THIRD_PARTY,
            "created_at": self._clock.now(),
        })

    def standing_preferences(self, user_id):
        return [
            row["text"]
            for row in self._rows.for_user(user_id)
            if row["trust"] == FIRST_PARTY
        ]


def close_session(session, memory, model):
    summary = model.summarize(session.transcript)
    for fact in summary["durable_facts"]:
        memory.remember(session.user_id, fact["text"], author="assistant")


def build_context(user_id, memory, operator_prompt, model):
    preferences = "\\n".join(memory.standing_preferences(user_id))
    return model.build_prompt(
        system=operator_prompt + "\\n\\nStanding preferences:\\n" + preferences,
    )
''',
    clean_rationale=(
        "Provenance is the union of the origins the content derives from, carried "
        "from the transcript segment through the summary onto the record, so a fact "
        "that touched retrieved content is stored third-party no matter who wrote it "
        "down. Only records whose origins are entirely operator-supplied reach the "
        "system prompt; everything else is recalled into a labelled data field, where "
        "it can inform the run without instructing it."
    ),
    clean='''\
"""Durable per-user agent memory."""

OPERATOR = "OPERATOR"
THIRD_PARTY = "THIRD_PARTY"


class MemoryStore:
    def __init__(self, rows, clock):
        self._rows = rows
        self._clock = clock

    def remember(self, user_id, text, origins):
        # Provenance is where the content came from, not who last wrote it
        # down: a summary of third-party text is still third-party text.
        origins = sorted(set(origins))
        self._rows.insert({
            "user_id": user_id,
            "text": text,
            "origin": OPERATOR if origins == [OPERATOR] else THIRD_PARTY,
            "derived_from": origins,
            "created_at": self._clock.now(),
        })

    def operator_preferences(self, user_id):
        return [
            row["text"]
            for row in self._rows.for_user(user_id)
            if row["origin"] == OPERATOR
        ]

    def recalled_notes(self, user_id):
        return [
            {
                "text": row["text"],
                "origin": row["origin"],
                "derived_from": row["derived_from"],
            }
            for row in self._rows.for_user(user_id)
        ]


def close_session(session, memory, model):
    summary = model.summarize(session.transcript)
    for fact in summary["durable_facts"]:
        # origins_for maps a fact back to the transcript segments it was drawn
        # from, so a fact touching a retrieved chunk stays labelled as such.
        memory.remember(session.user_id, fact["text"], session.origins_for(fact))


def build_context(user_id, memory, operator_prompt, model):
    preferences = "\\n".join(memory.operator_preferences(user_id))
    return model.build_prompt(
        system=operator_prompt + "\\n\\nStanding preferences:\\n" + preferences,
        untrusted={"recalled_notes": memory.recalled_notes(user_id)},
    )
''',
))

FIXTURES.append(fixture(
    "EVAL-AI-006",
    "AI / Agent / MCP",
    "Decide whether a human confirmation binds the action that finally executes.",
    language="python",
    filename="confirmation_gate.py",
    cwe=["CWE-367", "CWE-863"],
    difficulty="hard",
    vulnerable_rationale=(
        "The gate has an out-of-band notifier, an unguessable token, a run binding, "
        "an operator binding, an expiry, and a tool-name check, and the operator "
        "really does see the arguments before answering. Execution then uses the "
        "arguments on the step passed in at call time rather than the ones that were "
        "approved, and the record is never consumed, so within the window the loop "
        "can re-enter execute with the same token and different arguments. The "
        "approval binds the tool name; the effect is set by arguments nobody approved."
    ),
    vulnerable='''\
"""Out-of-band confirmation for privileged agent actions."""

import secrets

APPROVAL_TTL_SECONDS = 300
PRIVILEGED_TOOLS = {"send_email", "delete_records", "issue_refund"}


class ConfirmationGate:
    """The operator answers in a channel the agent run cannot write to."""

    def __init__(self, approvals, notifier, clock):
        self._approvals = approvals
        self._notifier = notifier
        self._clock = clock

    def request(self, run_id, step, operator_id):
        token = secrets.token_urlsafe(32)
        self._approvals.put(token, {
            "run_id": run_id,
            "tool": step["tool"],
            "operator_id": operator_id,
            "issued_at": self._clock.now(),
        })
        # The operator sees the tool and the arguments before answering.
        self._notifier.ask(operator_id, step["tool"], step["args"], token)
        return token

    def execute(self, run_id, step, token, tools):
        record = self._approvals.get(token)
        if record is None or not record.get("approved"):
            raise PermissionError("action was not approved")
        if record["run_id"] != run_id:
            raise PermissionError("approval belongs to another run")
        if record["tool"] != step["tool"]:
            raise PermissionError("approval was for a different tool")
        if self._clock.now() - record["issued_at"] > APPROVAL_TTL_SECONDS:
            raise PermissionError("approval expired")
        return tools[step["tool"]](step["args"])


def run_privileged_step(gate, run_id, step, token, tools):
    if step["tool"] not in PRIVILEGED_TOOLS:
        return tools[step["tool"]](step["args"])
    return gate.execute(run_id, step, token, tools)
''',
    clean_rationale=(
        "The proposal is stored in full and the executor takes no step at all: it "
        "consumes the record and calls the stored tool with the stored arguments, so "
        "the approved action is the executed action and one answer authorizes exactly "
        "one call. The digest is re-derived before use so a record altered in storage "
        "fails the same check, and the run, operator, and expiry bindings still hold."
    ),
    clean='''\
"""Out-of-band confirmation for privileged agent actions."""

import hashlib
import json
import secrets

APPROVAL_TTL_SECONDS = 300
PRIVILEGED_TOOLS = {"send_email", "delete_records", "issue_refund"}


def action_digest(run_id, tool, args):
    canonical = json.dumps(
        {"run_id": run_id, "tool": tool, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ConfirmationGate:
    """The operator answers in a channel the agent run cannot write to."""

    def __init__(self, approvals, notifier, clock):
        self._approvals = approvals
        self._notifier = notifier
        self._clock = clock

    def propose(self, run_id, step, operator_id):
        token = secrets.token_urlsafe(32)
        # The proposal itself is stored, not a reference to a live step.
        self._approvals.put(token, {
            "run_id": run_id,
            "tool": step["tool"],
            "args": step["args"],
            "digest": action_digest(run_id, step["tool"], step["args"]),
            "operator_id": operator_id,
            "issued_at": self._clock.now(),
        })
        self._notifier.ask(operator_id, step["tool"], step["args"], token)
        return token

    def execute(self, run_id, token, tools):
        # Consumed on read, so one answer authorizes exactly one call.
        record = self._approvals.consume(token)
        if record is None or not record.get("approved"):
            raise PermissionError("action was not approved")
        if record["run_id"] != run_id:
            raise PermissionError("approval belongs to another run")
        if self._clock.now() - record["issued_at"] > APPROVAL_TTL_SECONDS:
            raise PermissionError("approval expired")
        if record["digest"] != action_digest(run_id, record["tool"], record["args"]):
            raise PermissionError("approved action was altered in storage")
        # What executes is the stored proposal the operator saw. Nothing the run
        # emits after the answer can change the tool or the arguments.
        return tools[record["tool"]](record["args"])


def run_privileged_step(gate, run_id, step, token, tools):
    if step["tool"] not in PRIVILEGED_TOOLS:
        return tools[step["tool"]](step["args"])
    return gate.execute(run_id, token, tools)
''',
))

FIXTURES.append(fixture(
    "EVAL-AI-007",
    "AI / Agent / MCP",
    "Decide whether a tool result can reach the model inside the operator's channel.",
    language="python",
    filename="context_builder.py",
    cwe=["CWE-140", "CWE-77"],
    difficulty="hard",
    vulnerable_rationale=(
        "Every untrusted segment is labelled and fenced, which is the shape a "
        "reviewer expects of a context builder that takes provenance seriously. The "
        "fence is a fixed literal inside one concatenated string, so a tool result "
        "containing the end marker closes its own block and the text after it lands "
        "in the operator's position. Every segment is in the system role to begin "
        "with, so there is nothing below the operator's channel for it to land in."
    ),
    vulnerable='''\
"""Assemble the model context for one agent step."""

FENCE = "<<<UNTRUSTED>>>"


def _block(label, text):
    # Untrusted material is labelled and delimited so the model can tell it
    # apart from the operator's instructions.
    return f"{FENCE} BEGIN {label}\\n{text}\\n{FENCE} END {label}"


def build_context(operator_prompt, user_message, tool_results):
    sections = [operator_prompt, _block("user_message", user_message)]
    for result in tool_results:
        sections.append(_block(f"tool_result:{result['tool']}", str(result["content"])))
    return [{"role": "system", "content": "\\n\\n".join(sections)}]
''',
    clean_rationale=(
        "Separation is structural rather than lexical: the system role holds only "
        "deployment-owned text, and each tool result is a typed block in its own "
        "message carrying the call id and the origin. Because the boundary is a field "
        "of the serialized request rather than a marker inside a string, no byte "
        "sequence in a result can forge it, and the origin label survives to the "
        "dispatcher."
    ),
    clean='''\
"""Assemble the model context for one agent step."""


def build_context(operator_prompt, user_message, tool_results):
    # The system role carries only text this deployment owns. Nothing produced
    # or fetched during the run is appended to it.
    messages = [{"role": "system", "content": operator_prompt}]
    messages.append({
        "role": "user",
        "content": [{"type": "text", "text": user_message}],
    })
    for result in tool_results:
        # A result is a typed block in its own message, bound to the call it
        # answers and carrying its origin. It is transported as a field of the
        # request, so no byte sequence inside it can move it to another role.
        messages.append({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": result["tool_use_id"],
                "origin": result["origin"],
                "content": result["content"],
            }],
        })
    return messages
''',
))


# ============================================================================
# SEC-IDENTITY-ATO-001 — identity and account takeover
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-AUTH-003",
    "Authentication / Sessions",
    "Decide whether a password reset flow lets a caller take over another account.",
    language="python",
    filename="password_reset.py",
    cwe=["CWE-640", "CWE-287"],
    difficulty="hard",
    vulnerable_rationale=(
        "The reset token is fingerprinted, checked for reuse, and checked for "
        "expiry, so the proof-of-possession side is sound. The account is then "
        "resolved from the email in the request body rather than from the user_id "
        "stored on the token record, so a valid token issued for the attacker's "
        "own address resets the credential of any account they name."
    ),
    vulnerable='''\
"""Password reset completion."""

import hashlib
import secrets
import time

TOKEN_TTL_SECONDS = 900


def _fingerprint(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class PasswordResetService:
    def __init__(self, accounts, tokens, sessions, mailer):
        self._accounts = accounts
        self._tokens = tokens
        self._sessions = sessions
        self._mailer = mailer

    def request_reset(self, email):
        account = self._accounts.find_by_email(email)
        # Respond identically whether or not the address is registered.
        if account is not None:
            raw = secrets.token_urlsafe(32)
            self._tokens.put({
                "fingerprint": _fingerprint(raw),
                "user_id": account["id"],
                "created_at": time.time(),
                "used": False,
            })
            self._mailer.send_reset(account["email"], raw)
        return {"status": "sent"}

    def complete_reset(self, email, raw_token, new_password):
        record = self._tokens.get(_fingerprint(raw_token))
        if record is None or record["used"]:
            raise PermissionError("invalid reset token")
        if time.time() - record["created_at"] > TOKEN_TTL_SECONDS:
            raise PermissionError("expired reset token")

        # The form posts back the address the user typed, so load the account
        # from it and apply the new credential.
        account = self._accounts.find_by_email(email)
        if account is None:
            raise LookupError("unknown account")
        self._accounts.set_password(account["id"], new_password)
        self._tokens.mark_used(record["fingerprint"])
        return {"status": "reset", "user_id": account["id"]}
''',
    clean_rationale=(
        "The token record is the only binding between the proof and the subject: "
        "the account is loaded by record['user_id'], the posted address must match "
        "that account, the token is consumed before the write, and every session "
        "issued before the credential change is revoked."
    ),
    clean='''\
"""Password reset completion."""

import hashlib
import hmac
import secrets
import time

TOKEN_TTL_SECONDS = 900


def _fingerprint(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class PasswordResetService:
    def __init__(self, accounts, tokens, sessions, mailer):
        self._accounts = accounts
        self._tokens = tokens
        self._sessions = sessions
        self._mailer = mailer

    def request_reset(self, email):
        account = self._accounts.find_by_email(email)
        # Respond identically whether or not the address is registered.
        if account is not None:
            raw = secrets.token_urlsafe(32)
            self._tokens.put({
                "fingerprint": _fingerprint(raw),
                "user_id": account["id"],
                "created_at": time.time(),
                "used": False,
            })
            self._mailer.send_reset(account["email"], raw)
        return {"status": "sent"}

    def complete_reset(self, email, raw_token, new_password):
        record = self._tokens.get(_fingerprint(raw_token))
        if record is None or record["used"]:
            raise PermissionError("invalid reset token")
        if time.time() - record["created_at"] > TOKEN_TTL_SECONDS:
            raise PermissionError("expired reset token")

        # The subject comes from the token, never from the request body.
        account = self._accounts.get(record["user_id"])
        if account is None:
            raise LookupError("unknown account")
        if not hmac.compare_digest(account["email"].lower(), str(email).lower()):
            raise PermissionError("token does not belong to this account")

        self._tokens.mark_used(record["fingerprint"])
        self._accounts.set_password(account["id"], new_password)
        # A credential change invalidates everything issued before it.
        self._sessions.revoke_all_for_user(account["id"])
        return {"status": "reset", "user_id": account["id"]}
''',
))

FIXTURES.append(fixture(
    "EVAL-AUTH-004",
    "Authentication / Sessions",
    "Decide whether an account recovery endpoint can be completed without a recent second factor.",
    language="python",
    filename="recovery_routes.py",
    cwe=["CWE-306", "CWE-287"],
    difficulty="hard",
    vulnerable_rationale=(
        "The handler is identical to the protected version, so the enforcement "
        "question is entirely in the router. Step-up is applied only to paths "
        "listed in STEP_UP_ROUTES, that list still names the retired "
        "'/account/recovery/complete' path, and unlisted paths fall through to the "
        "handler, so the recovery completion route is reachable with no second "
        "factor at all."
    ),
    vulnerable='''\
"""Account recovery HTTP surface."""

STEP_UP_MAX_AGE_SECONDS = 300


def complete_recovery(request, services):
    challenge = services["recovery"].load(request["body"]["challenge_id"])
    if challenge is None or challenge["state"] != "VERIFIED":
        raise LookupError("no verified recovery challenge")
    services["accounts"].replace_credential(
        challenge["user_id"], request["body"]["new_password"]
    )
    services["sessions"].revoke_all_for_user(challenge["user_id"])
    return {"status": "recovered", "user_id": challenge["user_id"]}


def read_recovery_status(request, services):
    return services["recovery"].status(request["body"]["challenge_id"])


ROUTES = {
    "/account/recovery/status": read_recovery_status,
    "/account/recovery/finish": complete_recovery,
}

# Paths that require a recent second factor, kept beside the router so the
# privileged surface is easy to audit in one place.
STEP_UP_ROUTES = {"/account/recovery/complete"}


def dispatch(request, services, clock):
    path = request["path"]
    if path in STEP_UP_ROUTES:
        session = services["sessions"].load(request["session_id"])
        verified_at = (session or {}).get("step_up_verified_at")
        if verified_at is None or clock() - verified_at > STEP_UP_MAX_AGE_SECONDS:
            raise PermissionError("recent second-factor verification required")
    handler = ROUTES.get(path)
    if handler is None:
        return {"status": 404}
    return handler(request, services)
''',
    clean_rationale=(
        "The handler still carries no second-factor logic, which is why the module "
        "looks unprotected, but every route declares step_up as part of its "
        "registration, the dispatcher rejects unknown paths instead of falling "
        "through, and the step-up assertion is read from server-side session state "
        "rather than the request. The compensating control is the router contract, "
        "not the handler."
    ),
    clean='''\
"""Account recovery HTTP surface."""

STEP_UP_MAX_AGE_SECONDS = 300


def complete_recovery(request, services):
    # No second-factor logic here on purpose: dispatch() below is the single
    # enforcement boundary for every route in this module.
    challenge = services["recovery"].load(request["body"]["challenge_id"])
    if challenge is None or challenge["state"] != "VERIFIED":
        raise LookupError("no verified recovery challenge")
    services["accounts"].replace_credential(
        challenge["user_id"], request["body"]["new_password"]
    )
    services["sessions"].revoke_all_for_user(challenge["user_id"])
    return {"status": "recovered", "user_id": challenge["user_id"]}


def read_recovery_status(request, services):
    return services["recovery"].status(request["body"]["challenge_id"])


# Registration carries the requirement, so a renamed path cannot silently drop
# its step-up obligation the way a separate path list can.
ROUTES = {
    "/account/recovery/status": {"handler": read_recovery_status, "step_up": False},
    "/account/recovery/finish": {"handler": complete_recovery, "step_up": True},
}


def dispatch(request, services, clock):
    route = ROUTES.get(request["path"])
    # Unknown paths fail closed rather than reaching a handler.
    if route is None:
        raise PermissionError("unknown route")
    if route["step_up"]:
        session = services["sessions"].load(request["session_id"])
        verified_at = (session or {}).get("step_up_verified_at")
        if verified_at is None or clock() - verified_at > STEP_UP_MAX_AGE_SECONDS:
            raise PermissionError("recent second-factor verification required")
    return route["handler"](request, services)
''',
))

# ============================================================================
# SEC-SESSION-TOKEN-001 — sessions, JWT, and token scope
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-SESS-001",
    "Authentication / Sessions",
    "Decide whether a bearer token verifier can be made to accept a token the issuer never signed.",
    language="python",
    filename="token_verifier.py",
    cwe=["CWE-347", "CWE-345"],
    difficulty="hard",
    vulnerable_rationale=(
        "The algorithm is read from the token header and the key is selected by "
        "kid from a map that holds both HMAC secrets and published RSA public "
        "keys, so a caller can re-sign a token as HS256 using the public key "
        "material as the MAC secret. Expiry is also optional: a token with no exp "
        "claim skips the freshness check entirely."
    ),
    vulnerable='''\
"""Bearer token verification."""

import base64
import hashlib
import hmac
import json
import time


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class TokenVerifier:
    def __init__(self, keys, rsa_verify):
        # kid -> key material. HMAC secrets and PEM public keys share this map
        # so that rotation between the two schemes is a configuration change.
        self._keys = keys
        self._rsa_verify = rsa_verify

    def _check_signature(self, algorithm, key, signing_input, signature):
        if algorithm == "HS256":
            expected = hmac.new(key, signing_input, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)
        if algorithm == "RS256":
            return self._rsa_verify(key, signing_input, signature)
        raise ValueError("unsupported algorithm")

    def verify(self, token):
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        key = self._keys[header["kid"]]
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        # Honour the algorithm the issuer selected for this token.
        if not self._check_signature(
            header["alg"], key, signing_input, _b64url_decode(signature_b64)
        ):
            raise PermissionError("bad signature")

        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("exp") and claims["exp"] < time.time():
            raise PermissionError("expired")
        return claims
''',
    clean_rationale=(
        "The algorithm is pinned by the verifier and a token header that names "
        "anything else is rejected, the keyring holds only asymmetric public keys "
        "so no MAC secret exists to confuse it with, and exp, iat, iss, aud, and "
        "sub are required rather than optional."
    ),
    clean='''\
"""Bearer token verification."""

import base64
import json
import time

ALGORITHM = "RS256"
LEEWAY_SECONDS = 30
REQUIRED_CLAIMS = ("sub", "iss", "aud", "iat", "exp")


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class TokenVerifier:
    def __init__(self, public_keys, issuer, audience, rsa_verify):
        # Only asymmetric verification keys live here, so there is no symmetric
        # secret an attacker could reach by naming a different algorithm.
        self._public_keys = public_keys
        self._issuer = issuer
        self._audience = audience
        self._rsa_verify = rsa_verify

    def verify(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            raise PermissionError("malformed token")
        header_b64, payload_b64, signature_b64 = parts
        header = json.loads(_b64url_decode(header_b64))
        # The verifier chooses the algorithm; the token cannot.
        if header.get("alg") != ALGORITHM:
            raise PermissionError("unexpected algorithm")
        key = self._public_keys.get(header.get("kid"))
        if key is None:
            raise PermissionError("unknown key id")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        if not self._rsa_verify(key, signing_input, _b64url_decode(signature_b64)):
            raise PermissionError("bad signature")

        claims = json.loads(_b64url_decode(payload_b64))
        for name in REQUIRED_CLAIMS:
            if name not in claims:
                raise PermissionError(f"missing claim {name}")
        now = time.time()
        if claims["exp"] < now - LEEWAY_SECONDS:
            raise PermissionError("expired")
        if claims["iss"] != self._issuer or claims["aud"] != self._audience:
            raise PermissionError("wrong issuer or audience")
        return claims
''',
))

FIXTURES.append(fixture(
    "EVAL-SESS-002",
    "Authentication / Sessions",
    "Decide whether a revoked session can still authenticate a request.",
    language="python",
    filename="session_gateway.py",
    cwe=["CWE-613", "CWE-672"],
    difficulty="hard",
    vulnerable_rationale=(
        "The in-process cache is populated on first use and is only invalidated "
        "by the single-token revoke path. revoke_all_for_user — the path used by "
        "password changes and administrative lockouts — deletes the rows but "
        "leaves every worker's cached principal in place, and the idle-timeout "
        "check runs only on a cache miss, so a revoked session keeps resolving, "
        "with the roles it held when it was cached."
    ),
    vulnerable='''\
"""Request gateway that resolves the caller from an opaque session token."""

import hashlib
import time

IDLE_TIMEOUT_SECONDS = 1800


def _fingerprint(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class SessionGateway:
    def __init__(self, store, clock=time.time):
        self._store = store
        self._clock = clock
        # Session reads dominate the request path, so resolved principals are
        # kept in process to avoid a round trip on every call.
        self._cache = {}

    def resolve_principal(self, raw_token):
        if not raw_token:
            return None
        fingerprint = _fingerprint(raw_token)
        principal = self._cache.get(fingerprint)
        if principal is not None:
            return principal

        row = self._store.get_session(fingerprint)
        if row is None:
            return None
        now = self._clock()
        if now - row["last_seen_at"] > IDLE_TIMEOUT_SECONDS:
            self._store.delete_session(fingerprint)
            return None
        self._store.touch_session(fingerprint, now)
        principal = {
            "user_id": row["user_id"],
            "roles": row["roles"],
            "tenant_id": row["tenant_id"],
        }
        self._cache[fingerprint] = principal
        return principal

    def revoke(self, raw_token):
        fingerprint = _fingerprint(raw_token)
        self._store.delete_session(fingerprint)
        self._cache.pop(fingerprint, None)

    def revoke_all_for_user(self, user_id):
        # Password changes and administrative lockouts land here.
        self._store.delete_sessions_for_user(user_id)
''',
    clean_rationale=(
        "There is deliberately no explicit revocation branch, which is what makes "
        "the module look unprotected: the session row is the authority, every "
        "request re-reads it, and revocation is implemented as deletion, so the "
        "absence of the row is the denial. Nothing caches the decision, so a "
        "revocation from any process takes effect on the next request."
    ),
    clean='''\
"""Request gateway that resolves the caller from an opaque session token."""

import hashlib
import time

IDLE_TIMEOUT_SECONDS = 1800


def _fingerprint(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class SessionGateway:
    """Resolves a principal for every request.

    There is no "is this session revoked?" branch on purpose. The stored row is
    the authority, revocation deletes it, and every request re-reads it, so the
    missing row is the denial. Nothing here caches the decision, which is what
    keeps a revocation from another process effective immediately.
    """

    def __init__(self, store, clock=time.time):
        self._store = store
        self._clock = clock

    def resolve_principal(self, raw_token):
        if not raw_token:
            return None
        fingerprint = _fingerprint(raw_token)
        row = self._store.get_session(fingerprint)
        if row is None:
            return None
        now = self._clock()
        if now - row["last_seen_at"] > IDLE_TIMEOUT_SECONDS:
            self._store.delete_session(fingerprint)
            return None
        self._store.touch_session(fingerprint, now)
        return {
            "user_id": row["user_id"],
            "roles": row["roles"],
            "tenant_id": row["tenant_id"],
        }

    def revoke(self, raw_token):
        self._store.delete_session(_fingerprint(raw_token))

    def revoke_all_for_user(self, user_id):
        # Password changes and administrative lockouts land here. Because the
        # gateway holds no derived state, deleting the rows is sufficient.
        self._store.delete_sessions_for_user(user_id)
''',
))

# ============================================================================
# SEC-INJECTION-DATAFLOW-001 — injection and dataflow
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-INJ-003",
    "Injection / Dataflow",
    "Decide whether stored user input can reach a query as syntax on a later read.",
    language="python",
    filename="saved_view_repository.py",
    cwe=["CWE-89"],
    difficulty="hard",
    vulnerable_rationale=(
        "The write path is parameterised, which is what makes the module look "
        "safe. The stored expression is later concatenated into the WHERE clause "
        "because it came from the application's own database, so an expression "
        "saved earlier by any tenant user closes the tenant predicate and reopens "
        "it — second-order injection across the isolation boundary."
    ),
    vulnerable='''\
"""Saved report views."""

ALLOWED_TABLES = {"orders", "invoices"}


class SavedViewRepository:
    def __init__(self, connection):
        self._conn = connection

    def save_view(self, tenant_id, name, table_name, expression):
        if table_name not in ALLOWED_TABLES:
            raise ValueError("unsupported table")
        # The write is fully parameterised, so storing the view is safe.
        self._conn.execute(
            "INSERT INTO saved_views (tenant_id, name, table_name, expression) "
            "VALUES (?, ?, ?, ?)",
            [tenant_id, name, table_name, expression],
        )

    def _load(self, tenant_id, view_id):
        return self._conn.execute(
            "SELECT id, table_name, expression FROM saved_views "
            "WHERE id = ? AND tenant_id = ?",
            [view_id, tenant_id],
        ).fetchone()

    def run_view(self, tenant_id, view_id, limit=100):
        view = self._load(tenant_id, view_id)
        if view is None:
            raise LookupError("unknown view")
        if view["table_name"] not in ALLOWED_TABLES:
            raise ValueError("unsupported table")
        # The expression was written by an authenticated user of this tenant and
        # has been round-tripped through our own database, so it is trusted here.
        sql = (
            f"SELECT * FROM {view['table_name']} "
            f"WHERE tenant_id = ? AND ({view['expression']}) "
            "LIMIT ?"
        )
        return self._conn.execute(sql, [tenant_id, int(limit)]).fetchall()
''',
    clean_rationale=(
        "Views are stored as structured predicates rather than SQL text, the same "
        "compiler runs on write and on read so nothing is trusted merely because "
        "it was stored, fields and operators map to fixed literals, and values are "
        "bound as parameters."
    ),
    clean='''\
"""Saved report views."""

import json

ALLOWED_TABLES = {"orders", "invoices"}
COLUMNS = {
    "orders": {"status": "status", "total": "total", "created": "created_at"},
    "invoices": {"status": "status", "amount": "amount", "issued": "issued_at"},
}
OPERATORS = {"eq": "=", "gt": ">", "lt": "<"}


def _compile(table_name, predicates):
    clauses = []
    params = []
    for item in predicates:
        column = COLUMNS[table_name].get(item.get("field"))
        operator = OPERATORS.get(item.get("op"))
        if column is None or operator is None:
            raise ValueError("unsupported predicate")
        clauses.append(f"{column} {operator} ?")
        params.append(item.get("value"))
    return (" AND ".join(clauses) or "1=1"), params


class SavedViewRepository:
    def __init__(self, connection):
        self._conn = connection

    def save_view(self, tenant_id, name, table_name, predicates):
        if table_name not in ALLOWED_TABLES:
            raise ValueError("unsupported table")
        # Compile on write so an unsupported predicate is rejected at the source.
        _compile(table_name, predicates)
        self._conn.execute(
            "INSERT INTO saved_views (tenant_id, name, table_name, predicates) "
            "VALUES (?, ?, ?, ?)",
            [tenant_id, name, table_name, json.dumps(predicates)],
        )

    def run_view(self, tenant_id, view_id, limit=100):
        view = self._conn.execute(
            "SELECT id, table_name, predicates FROM saved_views "
            "WHERE id = ? AND tenant_id = ?",
            [view_id, tenant_id],
        ).fetchone()
        if view is None:
            raise LookupError("unknown view")
        if view["table_name"] not in ALLOWED_TABLES:
            raise ValueError("unsupported table")
        # Stored structure is re-validated on read; identifiers resolve to fixed
        # literals and every value stays a bound parameter.
        clause, params = _compile(view["table_name"], json.loads(view["predicates"]))
        sql = (
            f"SELECT * FROM {view['table_name']} "
            f"WHERE tenant_id = ? AND ({clause}) LIMIT ?"
        )
        return self._conn.execute(sql, [tenant_id, *params, int(limit)]).fetchall()
''',
))

FIXTURES.append(fixture(
    "EVAL-INJ-004",
    "Injection / Dataflow",
    "Decide whether a transcode worker can execute caller-influenced shell syntax.",
    language="python",
    filename="transcode_worker.py",
    cwe=["CWE-78"],
    difficulty="hard",
    vulnerable_rationale=(
        "The main preset path is the safe argv form, which dominates the module "
        "and makes it read as hardened. The legacy watermark branch is still "
        "reachable from the job payload, builds a command string with the "
        "caller's watermark_text inside single quotes, and runs it with "
        "shell=True, so a quote in that text becomes shell syntax."
    ),
    vulnerable='''\
"""Media transcode worker."""

import subprocess

PRESETS = {
    "web-720": ["-vf", "scale=-2:720", "-c:v", "libx264", "-crf", "23"],
    "audio-only": ["-vn", "-c:a", "aac", "-b:a", "128k"],
}
LEGACY_PRESETS = {"watermark"}
TIMEOUT_SECONDS = 600


class TranscodeWorker:
    def __init__(self, assets, output_root):
        self._assets = assets
        self._output_root = output_root

    def _resolve_input(self, tenant_id, asset_id):
        row = self._assets.get_for_tenant(asset_id, tenant_id)
        if row is None:
            raise LookupError("unknown asset")
        return row["storage_path"]

    def run(self, job):
        source = self._resolve_input(job["tenant_id"], job["asset_id"])
        target = f"{self._output_root}/{job['tenant_id']}/{job['asset_id']}.mp4"

        if job["preset"] in LEGACY_PRESETS:
            # drawtext needs quoting that the argv form does not express, so the
            # legacy path is still built as a command line.
            text = job.get("watermark_text", "")
            command = (
                f"ffmpeg -nostdin -i {source} "
                f"-vf drawtext=text='{text}' {target}"
            )
            completed = subprocess.run(
                command, shell=True, capture_output=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
            return {"asset_id": job["asset_id"], "returncode": completed.returncode}

        preset = PRESETS.get(job["preset"])
        if preset is None:
            raise ValueError("unknown preset")
        argv = ["ffmpeg", "-nostdin", "-i", source, *preset, target]
        completed = subprocess.run(
            argv, shell=False, capture_output=True,
            timeout=TIMEOUT_SECONDS, check=False,
        )
        return {"asset_id": job["asset_id"], "returncode": completed.returncode}
''',
    clean_rationale=(
        "Every path builds argv as a list with shell=False, so no caller value "
        "can become syntax, the source path is server-derived from a tenant-scoped "
        "asset lookup rather than supplied by the caller, and the watermark text "
        "is passed as its own argument. shlex.join appears only to render the "
        "command for the job log and is never executed."
    ),
    clean='''\
"""Media transcode worker."""

import shlex
import subprocess

PRESETS = {
    "web-720": ["-vf", "scale=-2:720", "-c:v", "libx264", "-crf", "23"],
    "audio-only": ["-vn", "-c:a", "aac", "-b:a", "128k"],
    "watermark": ["-c:v", "libx264", "-crf", "23"],
}
TIMEOUT_SECONDS = 600


def _watermark_args(text):
    # The filter value is one argv element; ffmpeg parses it, no shell does.
    escaped = str(text).replace(":", "").replace("'", "")
    return ["-vf", f"drawtext=text={escaped}"] if escaped else []


class TranscodeWorker:
    def __init__(self, assets, output_root):
        self._assets = assets
        self._output_root = output_root

    def _resolve_input(self, tenant_id, asset_id):
        # Server-derived: the caller supplies an opaque id, never a path.
        row = self._assets.get_for_tenant(asset_id, tenant_id)
        if row is None:
            raise LookupError("unknown asset")
        return row["storage_path"]

    def run(self, job):
        preset = PRESETS.get(job["preset"])
        if preset is None:
            raise ValueError("unknown preset")
        source = self._resolve_input(job["tenant_id"], job["asset_id"])
        target = f"{self._output_root}/{job['tenant_id']}/{job['asset_id']}.mp4"
        argv = ["ffmpeg", "-nostdin", "-i", source, *preset]
        if job["preset"] == "watermark":
            argv.extend(_watermark_args(job.get("watermark_text", "")))
        argv.append(target)

        # No shell on any path: argv is a list, so caller data stays data.
        completed = subprocess.run(
            argv, shell=False, capture_output=True,
            timeout=TIMEOUT_SECONDS, check=False,
        )
        return {
            "asset_id": job["asset_id"],
            "returncode": completed.returncode,
            # Rendered for the job log only; this string is never executed.
            "command": shlex.join(argv),
        }
''',
))

# ============================================================================
# SEC-BROWSER-DOM-001 — browser and DOM security
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-WEB-003",
    "Browser / XSS",
    "Decide whether a cross-document message handler trusts an origin it should not.",
    language="javascript",
    filename="embed-bridge.js",
    cwe=["CWE-346", "CWE-345"],
    difficulty="hard",
    vulnerable_rationale=(
        "The origin test is a prefix comparison, so https://app.example.com.attacker.test "
        "satisfies it and reaches a command table that includes setAuthToken and "
        "navigate. The acknowledgement is then posted back with a '*' target "
        "origin carrying a session snapshot, so the same handler leaks state to "
        "whichever document sent the message."
    ),
    vulnerable='''\
// Bridge between the host page and the embedded checkout frame.
const TRUSTED_ORIGIN = "https://app.example.com";

const COMMANDS = {
  resize: (payload, ctx) =>
    ctx.frame.style.setProperty("height", `${Number(payload.height)}px`),
  setAuthToken: (payload, ctx) => ctx.session.adopt(payload.token),
  navigate: (payload, ctx) => ctx.router.push(payload.path),
};

export function installBridge(ctx) {
  const handler = (event) => {
    // Only messages coming from our own application are accepted.
    if (event.origin.indexOf(TRUSTED_ORIGIN) !== 0) return;

    const message =
      typeof event.data === "string" ? JSON.parse(event.data) : event.data;
    const command = message && COMMANDS[message.type];
    if (!command) return;
    command(message.payload || {}, ctx);

    // Acknowledge so the frame can continue its handshake.
    if (event.source) {
      event.source.postMessage(
        { type: "ack", id: message.id, session: ctx.session.snapshot() },
        "*"
      );
    }
  };

  window.addEventListener("message", handler);
  return () => window.removeEventListener("message", handler);
}
''',
    clean_rationale=(
        "The origin must match exactly and the sender must be the frame this "
        "module created, the command table is limited to presentation commands "
        "and is looked up with hasOwnProperty so prototype keys cannot resolve, "
        "and the reply is addressed to the exact origin and carries no session "
        "state."
    ),
    clean='''\
// Bridge between the host page and the embedded checkout frame.
const TRUSTED_ORIGIN = "https://app.example.com";

// Presentation only: privileged operations are performed over the authenticated
// API, not over a channel whose peer is a document.
const COMMANDS = {
  resize: (payload, ctx) =>
    ctx.frame.style.setProperty("height", `${Number(payload.height)}px`),
  requestClose: (_payload, ctx) => ctx.onClose(),
};

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function installBridge(ctx) {
  const handler = (event) => {
    // Exact origin, and the sender must be the frame we created ourselves.
    if (event.origin !== TRUSTED_ORIGIN) return;
    if (event.source !== ctx.frame.contentWindow) return;

    const message =
      typeof event.data === "string" ? safeParse(event.data) : event.data;
    if (!message || typeof message.type !== "string") return;
    if (!Object.prototype.hasOwnProperty.call(COMMANDS, message.type)) return;

    COMMANDS[message.type](message.payload || {}, ctx);

    // Addressed to one origin, and it carries no session material.
    event.source.postMessage({ type: "ack", id: message.id }, TRUSTED_ORIGIN);
  };

  window.addEventListener("message", handler);
  return () => window.removeEventListener("message", handler);
}
''',
))

FIXTURES.append(fixture(
    "EVAL-WEB-004",
    "Browser / XSS",
    "Decide whether rendering unsanitised markup in a frame is contained.",
    language="javascript",
    filename="untrusted-preview.js",
    cwe=["CWE-79", "CWE-1021"],
    difficulty="hard",
    vulnerable_rationale=(
        "The sandbox attribute grants allow-scripts together with allow-same-origin, "
        "which lets the framed document run script in the embedder's origin and "
        "remove its own sandbox attribute, so the isolation is nominal. The "
        "attribute is also applied after srcdoc is assigned and after the frame is "
        "in the document, so the load can begin before the restriction exists."
    ),
    vulnerable='''\
// Renders author-submitted rich text that the pipeline cannot fully sanitise.
const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

function safeHref(value) {
  try {
    return SAFE_SCHEMES.has(new URL(value).protocol) ? value : null;
  } catch {
    return null;
  }
}

export function renderPreview(container, document_) {
  const wrapper = document.createElement("section");
  wrapper.className = "preview";

  const caption = document.createElement("p");
  caption.className = "preview-caption";
  caption.textContent = document_.caption;
  wrapper.append(caption);

  const source = safeHref(document_.sourceUrl);
  if (source) {
    const link = document.createElement("a");
    link.setAttribute("href", source);
    link.setAttribute("rel", "noopener noreferrer");
    link.textContent = "original document";
    wrapper.append(link);
  }

  const frame = document.createElement("iframe");
  frame.className = "preview-frame";
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.srcdoc = document_.html;
  wrapper.append(frame);
  container.replaceChildren(wrapper);

  // The preview needs its own scripts for the lightbox and table sorting, and
  // same-origin so those scripts can read the parent stylesheet.
  frame.setAttribute("sandbox", "allow-scripts allow-same-origin");
  return frame;
}
''',
    clean_rationale=(
        "Assigning unsanitised markup to srcdoc is the alarming surface, and the "
        "sandbox is the control that makes it defensible: the frame is created "
        "with an empty sandbox attribute before srcdoc is assigned and before it "
        "is inserted, so the document loads with scripts disabled in a unique "
        "opaque origin with no form submission and no top-level navigation."
    ),
    clean='''\
// Renders author-submitted rich text that the pipeline cannot fully sanitise.
const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

function safeHref(value) {
  try {
    return SAFE_SCHEMES.has(new URL(value).protocol) ? value : null;
  } catch {
    return null;
  }
}

export function renderPreview(container, document_) {
  const wrapper = document.createElement("section");
  wrapper.className = "preview";

  const caption = document.createElement("p");
  caption.className = "preview-caption";
  caption.textContent = document_.caption;
  wrapper.append(caption);

  const source = safeHref(document_.sourceUrl);
  if (source) {
    const link = document.createElement("a");
    link.setAttribute("href", source);
    link.setAttribute("rel", "noopener noreferrer");
    link.textContent = "original document";
    wrapper.append(link);
  }

  const frame = document.createElement("iframe");
  frame.className = "preview-frame";
  // The sandbox is the control, and it is set before any content exists and
  // before the element joins the document: an empty value means no scripts, no
  // forms, no top-level navigation, and a unique opaque origin, so the markup
  // below cannot reach this document, its cookies, or its storage.
  frame.setAttribute("sandbox", "");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.setAttribute("loading", "lazy");
  frame.srcdoc = document_.html;

  wrapper.append(frame);
  container.replaceChildren(wrapper);
  return frame;
}
''',
))

# ============================================================================
# SEC-FILE-PARSER-001 — files, uploads, parsers, deserialization
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-FILE-003",
    "Files / Uploads / Parsers",
    "Decide whether an archive entry can be written outside the destination directory.",
    language="python",
    filename="archive_import.py",
    cwe=["CWE-22"],
    difficulty="hard",
    vulnerable_rationale=(
        "Containment is asserted with a string prefix comparison against a "
        "destination that has no trailing separator, so an entry resolving to a "
        "sibling such as /srv/imports/tenant-42-shared passes the check, and "
        "makedirs creates that sibling on the way. The size budget also trusts the "
        "declared file_size in the archive header rather than the bytes written."
    ),
    vulnerable='''\
"""Archive import."""

import os
import zipfile

MAX_ENTRIES = 2000
MAX_TOTAL_BYTES = 200 * 1024 * 1024


class ArchiveImporter:
    def __init__(self, destination):
        # For example /srv/imports/tenant-42
        self._destination = os.path.abspath(destination)

    def extract(self, archive_path):
        written = []
        total = 0
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ENTRIES:
                raise ValueError("too many entries")

            for member in members:
                if member.is_dir():
                    continue
                total += member.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("archive too large")

                target = os.path.abspath(
                    os.path.join(self._destination, member.filename)
                )
                # Keep every entry underneath the destination directory.
                if not target.startswith(self._destination):
                    raise ValueError(f"entry escapes destination: {member.filename}")

                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(member) as source, open(target, "wb") as handle:
                    handle.write(source.read())
                written.append(target)
        return written
''',
    clean_rationale=(
        "Containment is asserted on whole path components with commonpath after "
        "realpath, so a sibling directory whose name merely starts with the "
        "destination cannot pass, symlink members are rejected instead of being "
        "written, and the size budget counts bytes actually read rather than the "
        "attacker-declared header value."
    ),
    clean='''\
"""Archive import."""

import os
import stat
import zipfile

MAX_ENTRIES = 2000
MAX_TOTAL_BYTES = 200 * 1024 * 1024
CHUNK_BYTES = 64 * 1024


class ArchiveImporter:
    def __init__(self, destination):
        # For example /srv/imports/tenant-42
        self._destination = os.path.realpath(destination)

    def _resolve(self, name):
        target = os.path.realpath(os.path.join(self._destination, name))
        # Compare whole path components, never string prefixes.
        if os.path.commonpath([self._destination, target]) != self._destination:
            raise ValueError(f"entry escapes destination: {name}")
        return target

    def extract(self, archive_path):
        written = []
        total = 0
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ENTRIES:
                raise ValueError("too many entries")

            for member in members:
                if member.is_dir():
                    continue
                mode = member.external_attr >> 16
                if mode and not stat.S_ISREG(mode):
                    raise ValueError(f"unsupported member type: {member.filename}")

                target = self._resolve(member.filename)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(member) as source, open(target, "wb") as handle:
                    while True:
                        chunk = source.read(CHUNK_BYTES)
                        if not chunk:
                            break
                        # Budget the bytes produced, not the declared size.
                        total += len(chunk)
                        if total > MAX_TOTAL_BYTES:
                            raise ValueError("archive expands beyond the budget")
                        handle.write(chunk)
                written.append(target)
        return written
''',
))

FIXTURES.append(fixture(
    "EVAL-FILE-004",
    "Files / Uploads / Parsers",
    "Decide whether a cache entry can reach an unsafe decoder without authentication.",
    language="python",
    filename="job_payload_cache.py",
    cwe=["CWE-502"],
    difficulty="hard",
    vulnerable_rationale=(
        "The signed path is correct, but an entry that simply omits the sig field "
        "takes the legacy branch and is decoded unauthenticated. Anyone able to "
        "write into the shared queue — another tenant's worker, a misconfigured "
        "cache, or a request-forgery reaching the broker — writes an unsigned "
        "entry and reaches the decoder with attacker-chosen bytes."
    ),
    vulnerable='''\
"""Background job payload cache."""

import hashlib
import hmac
import pickle

SIGNATURE_VERSION = "v2"


class PayloadCodec:
    """Serialises job payloads that carry worker-owned objects."""

    def __init__(self, signing_key):
        self._key = signing_key

    def _tag(self, blob):
        return hmac.new(
            self._key, SIGNATURE_VERSION.encode("ascii") + blob, hashlib.sha256
        ).hexdigest()

    def encode(self, payload):
        blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        return {"version": SIGNATURE_VERSION, "blob": blob, "sig": self._tag(blob)}

    def decode(self, entry):
        signature = entry.get("sig")
        if signature is None:
            # Entries queued before the signing rollout have no tag. The broker
            # is internal, so accept them until the backlog drains.
            return pickle.loads(entry["blob"])
        if not hmac.compare_digest(signature, self._tag(entry["blob"])):
            raise ValueError("cache entry failed integrity check")
        return pickle.loads(entry["blob"])


class JobQueue:
    def __init__(self, store, codec):
        self._store = store
        self._codec = codec

    def enqueue(self, name, payload):
        self._store.put(name, self._codec.encode(payload))

    def next_job(self, name):
        entry = self._store.take(name)
        return None if entry is None else self._codec.decode(entry)
''',
    clean_rationale=(
        "pickle.loads is the alarming surface and it is reached only for bytes "
        "this process authenticated: the version is pinned, a missing or "
        "non-string tag is rejected rather than treated as legacy, and the "
        "constant-time comparison runs before the decoder. The compensating "
        "control is that the decoder has no unauthenticated path into it."
    ),
    clean='''\
"""Background job payload cache."""

import hashlib
import hmac
import pickle

SIGNATURE_VERSION = "v2"


class PayloadCodec:
    """Serialises job payloads that carry worker-owned objects.

    pickle is deliberate: these payloads contain worker types that JSON cannot
    express. It is only ever applied to bytes this process produced and tagged,
    the tag is verified in constant time first, and there is no branch that
    reaches the decoder without that verification.
    """

    def __init__(self, signing_key):
        self._key = signing_key

    def _tag(self, blob):
        return hmac.new(
            self._key, SIGNATURE_VERSION.encode("ascii") + blob, hashlib.sha256
        ).hexdigest()

    def encode(self, payload):
        blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        return {"version": SIGNATURE_VERSION, "blob": blob, "sig": self._tag(blob)}

    def decode(self, entry):
        if entry.get("version") != SIGNATURE_VERSION:
            raise ValueError("unsupported cache entry version")
        signature = entry.get("sig")
        if not isinstance(signature, str):
            # A missing tag is a rejected entry, never a legacy exemption.
            raise ValueError("unsigned cache entry")
        if not hmac.compare_digest(signature, self._tag(entry["blob"])):
            raise ValueError("cache entry failed integrity check")
        return pickle.loads(entry["blob"])


class JobQueue:
    def __init__(self, store, codec):
        self._store = store
        self._codec = codec

    def enqueue(self, name, payload):
        self._store.put(name, self._codec.encode(payload))

    def next_job(self, name):
        entry = self._store.take(name)
        return None if entry is None else self._codec.decode(entry)
''',
))

# ============================================================================
# SEC-API-SURFACE-001 — API, GraphQL, WebSocket, gRPC surface
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-AUTHZ-004",
    "Authorization / BOLA / BFLA",
    "Decide whether a generic graph entry point reaches objects the typed query would refuse.",
    language="python",
    filename="graphql_resolvers.py",
    cwe=["CWE-639", "CWE-863"],
    difficulty="hard",
    vulnerable_rationale=(
        "query_order enforces ownership, and the field resolvers inherit that "
        "assumption. query_node decodes a global id and loads the same objects "
        "with no viewer predicate, so selecting node(id) { ... on Customer { "
        "paymentMethods } } reaches another customer's records through resolvers "
        "that were only ever authorised by their expected parent."
    ),
    vulnerable='''\
"""GraphQL resolvers for the orders schema."""

import base64


def decode_global_id(global_id):
    decoded = base64.urlsafe_b64decode(global_id.encode("ascii")).decode("utf-8")
    kind, _, raw = decoded.partition(":")
    return kind, raw


class Resolvers:
    def __init__(self, orders, customers, payments):
        self._orders = orders
        self._customers = customers
        self._payments = payments

    def query_order(self, info, order_id):
        viewer = info.context["viewer"]
        order = self._orders.get(order_id)
        if order is None or order["customer_id"] != viewer["customer_id"]:
            raise PermissionError("forbidden")
        return order

    def query_node(self, info, global_id):
        # Relay-style generic lookup used by the client cache to refetch objects
        # it has already seen.
        kind, raw = decode_global_id(global_id)
        if kind == "Order":
            return self._orders.get(raw)
        if kind == "Customer":
            return self._customers.get(raw)
        raise ValueError("unknown node type")

    def order_customer(self, info, order):
        # Reached from query_order, which has already authorised the order.
        return self._customers.get(order["customer_id"])

    def customer_payment_methods(self, info, customer):
        return self._payments.list_for_customer(customer["id"])
''',
    clean_rationale=(
        "Every resolver, typed or generic, reaches data through the same "
        "viewer-scoped loaders, so the generic node entry point cannot be a "
        "weaker path than the typed query, and each field resolver re-establishes "
        "the boundary rather than inheriting it from whichever parent happened to "
        "call it."
    ),
    clean='''\
"""GraphQL resolvers for the orders schema."""

import base64


def decode_global_id(global_id):
    decoded = base64.urlsafe_b64decode(global_id.encode("ascii")).decode("utf-8")
    kind, _, raw = decoded.partition(":")
    return kind, raw


class ViewerLoaders:
    """The single authorisation boundary for this schema."""

    def __init__(self, orders, customers, payments):
        self._orders = orders
        self._customers = customers
        self._payments = payments

    def order(self, viewer, order_id):
        row = self._orders.get_for_customer(order_id, viewer["customer_id"])
        if row is None:
            raise PermissionError("forbidden")
        return row

    def customer(self, viewer, customer_id):
        if customer_id != viewer["customer_id"]:
            raise PermissionError("forbidden")
        return self._customers.get(customer_id)

    def payment_methods(self, viewer, customer_id):
        self.customer(viewer, customer_id)
        return self._payments.list_for_customer(customer_id)


class Resolvers:
    def __init__(self, loaders):
        self._loaders = loaders

    def query_order(self, info, order_id):
        return self._loaders.order(info.context["viewer"], order_id)

    def query_node(self, info, global_id):
        kind, raw = decode_global_id(global_id)
        loader = {
            "Order": self._loaders.order,
            "Customer": self._loaders.customer,
        }.get(kind)
        if loader is None:
            raise ValueError("unknown node type")
        # The generic entry point uses exactly the loaders the typed query uses.
        return loader(info.context["viewer"], raw)

    def order_customer(self, info, order):
        return self._loaders.customer(info.context["viewer"], order["customer_id"])

    def customer_payment_methods(self, info, customer):
        # Field resolvers re-establish the boundary instead of inheriting it.
        return self._loaders.payment_methods(info.context["viewer"], customer["id"])
''',
))

FIXTURES.append(fixture(
    "EVAL-AUTHZ-005",
    "Authorization / BOLA / BFLA",
    "Decide whether copying a request body onto an update object can set a privileged field.",
    language="python",
    filename="profile_update.py",
    cwe=["CWE-915", "CWE-269"],
    difficulty="hard",
    vulnerable_rationale=(
        "FIELDS reads as an allowlist but is only used to initialise the "
        "attributes; the loop assigns every key in the body onto the instance and "
        "assigned() reports vars(self), so any extra key — role, tenant_id, "
        "email_verified — is carried into accounts.apply and written. The object "
        "model never constrained anything."
    ),
    vulnerable='''\
"""Profile update endpoint."""


class ProfileUpdate:
    """Writable projection of an account."""

    FIELDS = ("display_name", "bio", "timezone")

    def __init__(self):
        for field in self.FIELDS:
            setattr(self, field, None)

    def assigned(self):
        return {name: value for name, value in vars(self).items() if value is not None}


class ProfileService:
    def __init__(self, accounts, audit):
        self._accounts = accounts
        self._audit = audit

    def update(self, caller, payload):
        update = ProfileUpdate()
        for key, value in payload.items():
            setattr(update, key, value)

        changes = update.assigned()
        if not changes:
            raise ValueError("no writable fields supplied")
        self._accounts.apply(caller["id"], changes)
        self._audit.record(caller["id"], "profile.update", sorted(changes))
        return {"user_id": caller["id"], "updated": sorted(changes)}
''',
    clean_rationale=(
        "Copying the whole request body onto an object is the alarming surface, "
        "and __slots__ is the compensating control: the class defines no __dict__, "
        "so assigning any undeclared attribute raises AttributeError and the "
        "caller's extra keys are dropped. assigned() enumerates the declared slots "
        "rather than whatever happens to have been set."
    ),
    clean='''\
"""Profile update endpoint."""


class ProfileUpdate:
    """Writable projection of an account.

    __slots__ is the control. The class has no __dict__, so assigning any field
    that is not declared here raises AttributeError, and copying an entire
    request body onto an instance cannot introduce a privileged attribute.
    """

    __slots__ = ("display_name", "bio", "timezone")

    def __init__(self):
        for field in self.__slots__:
            setattr(self, field, None)

    def assigned(self):
        # Enumerates the declared slots, not whatever was assigned.
        return {
            name: getattr(self, name)
            for name in self.__slots__
            if getattr(self, name) is not None
        }


class ProfileService:
    def __init__(self, accounts, audit):
        self._accounts = accounts
        self._audit = audit

    def update(self, caller, payload):
        update = ProfileUpdate()
        rejected = []
        for key, value in payload.items():
            try:
                setattr(update, key, value)
            except AttributeError:
                # The object model refused the field; record it and move on.
                rejected.append(key)

        changes = update.assigned()
        if not changes:
            raise ValueError("no writable fields supplied")
        self._accounts.apply(caller["id"], changes)
        self._audit.record(caller["id"], "profile.update", sorted(changes), rejected)
        return {"user_id": caller["id"], "updated": sorted(changes)}
''',
))

# ============================================================================
# SEC-TENANT-RLS-001 — database, tenant, and RLS isolation
# ============================================================================
FIXTURES.append(fixture(
    "EVAL-AUTHZ-006",
    "Authorization / BOLA / BFLA",
    "Decide whether a reporting query escapes the tenant isolation the primary path relies on.",
    language="python",
    filename="tenant_reporting_db.py",
    cwe=["CWE-863", "CWE-89"],
    difficulty="hard",
    vulnerable_rationale=(
        "monthly_summary borrows from the analytics pool, which connects with the "
        "reporting role that bypasses row level security, never sets the tenant "
        "setting, and carries no tenant predicate, so it aggregates every tenant's "
        "rows. The primary path is also fragile: the setting is interpolated into "
        "the statement and is session-scoped, so it survives on the pooled "
        "connection after the request that set it."
    ),
    vulnerable='''\
"""Tenant-scoped database access."""

from contextlib import contextmanager


class TenantDatabase:
    """Row level security policies compare app.tenant_id against each row."""

    def __init__(self, app_pool, analytics_pool):
        self._app_pool = app_pool
        # Reporting queries are slow, so they run on a separate pool that
        # connects with the reporting role.
        self._analytics_pool = analytics_pool

    @contextmanager
    def tenant_connection(self, tenant_id):
        conn = self._app_pool.acquire()
        try:
            conn.execute(f"SET app.tenant_id = '{tenant_id}'")
            yield conn
        finally:
            self._app_pool.release(conn)

    def list_documents(self, tenant_id):
        with self.tenant_connection(tenant_id) as conn:
            return conn.execute(
                "SELECT id, title, owner_id FROM documents ORDER BY created_at DESC"
            ).fetchall()

    def monthly_summary(self, tenant_id, month):
        # Row level security keeps document reads scoped, so the summary does
        # not need to repeat the predicate.
        conn = self._analytics_pool.acquire()
        try:
            return conn.execute(
                "SELECT status, count(*) AS total FROM documents "
                "WHERE date_trunc('month', created_at) = %s GROUP BY status",
                [month],
            ).fetchall()
        finally:
            self._analytics_pool.release(conn)
''',
    clean_rationale=(
        "Both paths use the same RLS-enforcing role, the tenant is bound as a "
        "parameter with set_config scoped to the transaction so nothing leaks to "
        "the next borrower of a pooled connection, and every statement repeats the "
        "tenant predicate as defence in depth rather than delegating isolation "
        "entirely to the policy."
    ),
    clean='''\
"""Tenant-scoped database access."""

from contextlib import contextmanager


class TenantDatabase:
    """Row level security policies compare app.tenant_id against each row."""

    def __init__(self, app_pool):
        # One pool, one role, one enforcement story. Reporting does not get a
        # privileged side door.
        self._app_pool = app_pool

    @contextmanager
    def tenant_transaction(self, tenant_id):
        conn = self._app_pool.acquire()
        try:
            conn.execute("BEGIN")
            # Bound as a parameter, and local to this transaction so it cannot
            # survive on the pooled connection.
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_id)])
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            self._app_pool.release(conn)

    def list_documents(self, tenant_id):
        with self.tenant_transaction(tenant_id) as conn:
            return conn.execute(
                "SELECT id, title, owner_id FROM documents "
                "WHERE tenant_id = %s ORDER BY created_at DESC",
                [tenant_id],
            ).fetchall()

    def monthly_summary(self, tenant_id, month):
        # Same role, same binding, and the predicate is repeated explicitly.
        with self.tenant_transaction(tenant_id) as conn:
            return conn.execute(
                "SELECT status, count(*) AS total FROM documents "
                "WHERE tenant_id = %s AND date_trunc('month', created_at) = %s "
                "GROUP BY status",
                [tenant_id, month],
            ).fetchall()
''',
))

FIXTURES.append(fixture(
    "EVAL-AUTHZ-007",
    "Authorization / BOLA / BFLA",
    "Decide whether queries without a tenant predicate are isolated by the declared row policy.",
    language="python",
    filename="document_repository.py",
    cwe=["CWE-863", "CWE-269"],
    difficulty="hard",
    vulnerable_rationale=(
        "The policy exists, but the migration only enables row level security "
        "without forcing it and the runtime role is the schema owner, which is "
        "exempt from policies on its own tables. Every predicate-free statement in "
        "the repository therefore runs unrestricted, and the setting the policy "
        "reads is never consulted."
    ),
    vulnerable='''\
"""Document repository backed by row level security."""

# Applied by migration 0042.
MIGRATION = """
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY documents_tenant_isolation ON documents
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON documents TO app_owner;
"""

# The role the API connects with; it also owns the schema, which keeps the
# migration and the runtime credentials down to one secret.
RUNTIME_ROLE = "app_owner"


class DocumentRepository:
    """Statements here carry no tenant predicate: the policy above is the
    isolation boundary, and the tenant is bound per transaction."""

    def __init__(self, pool):
        self._pool = pool

    def _session(self, tenant_id):
        conn = self._pool.acquire(role=RUNTIME_ROLE)
        conn.execute("BEGIN")
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_id)])
        return conn

    def get(self, tenant_id, document_id):
        conn = self._session(tenant_id)
        try:
            return conn.execute(
                "SELECT id, title, body FROM documents WHERE id = %s", [document_id]
            ).fetchone()
        finally:
            conn.execute("COMMIT")
            self._pool.release(conn)

    def update_title(self, tenant_id, document_id, title):
        conn = self._session(tenant_id)
        try:
            return conn.execute(
                "UPDATE documents SET title = %s WHERE id = %s", [title, document_id]
            ).rowcount
        finally:
            conn.execute("COMMIT")
            self._pool.release(conn)
''',
    clean_rationale=(
        "Predicate-free statements are the alarming surface and the row policy is "
        "the compensating control that actually binds here: the table forces row "
        "level security so even the owner is subject to it, the runtime connects "
        "as a separate non-owning role, and the setting the policy reads is bound "
        "as a parameter local to each transaction."
    ),
    clean='''\
"""Document repository backed by row level security."""

# Applied by migration 0042. FORCE is required as well as ENABLE: without it the
# table owner -- which every migration runs as -- is exempt from its own policy,
# and the runtime role below is deliberately not the owner.
MIGRATION = """
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
CREATE POLICY documents_tenant_isolation ON documents
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON documents TO app_user;
"""

RUNTIME_ROLE = "app_user"


class DocumentRepository:
    """Statements here carry no tenant predicate: the policy above is the
    isolation boundary, and the tenant is bound per transaction."""

    def __init__(self, pool):
        self._pool = pool

    def _session(self, tenant_id):
        conn = self._pool.acquire(role=RUNTIME_ROLE)
        conn.execute("BEGIN")
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_id)])
        return conn

    def get(self, tenant_id, document_id):
        conn = self._session(tenant_id)
        try:
            return conn.execute(
                "SELECT id, title, body FROM documents WHERE id = %s", [document_id]
            ).fetchone()
        finally:
            conn.execute("COMMIT")
            self._pool.release(conn)

    def update_title(self, tenant_id, document_id, title):
        conn = self._session(tenant_id)
        try:
            return conn.execute(
                "UPDATE documents SET title = %s WHERE id = %s", [title, document_id]
            ).rowcount
        finally:
            conn.execute("COMMIT")
            self._pool.release(conn)
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
