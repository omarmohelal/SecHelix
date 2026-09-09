"""Bearer-token identity and role checks."""

from __future__ import annotations

import sqlite3
from typing import Callable


class Unauthenticated(Exception):
    """No usable credential was presented."""


class Forbidden(Exception):
    """The caller is authenticated but not permitted."""


def identify(connection: sqlite3.Connection, authorization: str | None) -> sqlite3.Row:
    """Resolve the caller from an Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise Unauthenticated("missing bearer token")
    token = authorization[len("Bearer ") :].strip()
    row = connection.execute(
        "SELECT * FROM person WHERE token = ?", (token,)
    ).fetchone()
    if row is None:
        raise Unauthenticated("unknown token")
    return row


def require_role(*allowed: str) -> Callable[[sqlite3.Row], None]:
    """Assert the caller holds one of these roles.

    This answers "may someone like you perform this kind of operation?" — it
    says nothing about *which* records the caller may reach.
    """

    def check(person: sqlite3.Row) -> None:
        if person["role"] not in allowed:
            raise Forbidden(f"role {person['role']!r} may not perform this operation")

    return check
