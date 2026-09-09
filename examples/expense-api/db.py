"""Storage for the demo expense API. SQLite, in a temporary file, stdlib only."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE org (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL
);
CREATE TABLE person (
    id      INTEGER PRIMARY KEY,
    org_id  INTEGER NOT NULL REFERENCES org(id),
    email   TEXT NOT NULL,
    role    TEXT NOT NULL,
    token   TEXT NOT NULL UNIQUE
);
CREATE TABLE receipt (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES org(id),
    person_id   INTEGER NOT NULL REFERENCES person(id),
    merchant    TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    memo        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'submitted'
);
"""

SEED = [
    ("INSERT INTO org VALUES (1, 'Northwind')", ()),
    ("INSERT INTO org VALUES (2, 'Contoso')", ()),
    # Northwind
    ("INSERT INTO person VALUES (1, 1, 'ada@northwind.test',  'approver', 'tok-ada')", ()),
    ("INSERT INTO person VALUES (2, 1, 'bo@northwind.test',   'employee', 'tok-bo')", ()),
    # Contoso — a different tenant entirely
    ("INSERT INTO person VALUES (3, 2, 'cy@contoso.test',     'approver', 'tok-cy')", ()),
    ("INSERT INTO person VALUES (4, 2, 'dee@contoso.test',    'employee', 'tok-dee')", ()),
    ("INSERT INTO receipt VALUES (101, 1, 2, 'Rail travel', 4200, 'Client visit', 'submitted')", ()),
    ("INSERT INTO receipt VALUES (102, 1, 2, 'Hotel', 18900, 'Client visit', 'approved')", ()),
    # The one that must never leave Contoso.
    ("INSERT INTO receipt VALUES (201, 2, 4, 'Legal counsel', 750000, "
     "'Retainer re: Project Halcyon acquisition', 'submitted')", ()),
]


def connect(path: Path | str, threadsafe: bool = False) -> sqlite3.Connection:
    # ThreadingHTTPServer serves each request on its own thread, so the demo
    # server shares one read-mostly connection across them.
    connection = sqlite3.connect(str(path), check_same_thread=not threadsafe)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create(path: Path | str, threadsafe: bool = False) -> sqlite3.Connection:
    """Build a fresh database and seed two organizations."""
    target = Path(path)
    if target.exists():
        target.unlink()
    connection = connect(target, threadsafe=threadsafe)
    connection.executescript(SCHEMA)
    for statement, params in SEED:
        connection.execute(statement, params)
    connection.commit()
    return connection
