"""Receipt listing with a caller-chosen sort order.

The sort column is interpolated into the SQL string, which is the shape every
pattern matcher is trained to flag. Read the two lines above it before deciding.
"""

from __future__ import annotations

import sqlite3

#: The only column names that may ever appear in the ORDER BY clause. This is an
#: allowlist of literals, not a validation of caller input: whatever arrives is
#: either one of these exact strings or the request is rejected, so the value
#: that reaches the query text is always one of five constants defined here.
SORTABLE_COLUMNS = ("id", "merchant", "amount_cents", "status", "person_id")

SORT_DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


class InvalidSort(ValueError):
    """The requested sort is not one this endpoint offers."""


def resolve_sort(column: str | None, direction: str | None) -> tuple[str, str]:
    """Map caller input onto a constant, or refuse."""
    column = column or "id"
    if column not in SORTABLE_COLUMNS:
        raise InvalidSort(f"cannot sort by {column!r}")
    # Return the tuple's own string object rather than the caller's, so nothing
    # derived from the request survives into the query even by identity.
    resolved_column = SORTABLE_COLUMNS[SORTABLE_COLUMNS.index(column)]

    direction = (direction or "asc").lower()
    if direction not in SORT_DIRECTIONS:
        raise InvalidSort(f"cannot sort {direction!r}")
    return resolved_column, SORT_DIRECTIONS[direction]


def list_receipts(
    connection: sqlite3.Connection,
    org_id: int,
    sort: str | None = None,
    direction: str | None = None,
) -> list[sqlite3.Row]:
    column, order = resolve_sort(sort, direction)
    query = f"SELECT * FROM receipt WHERE org_id = ? ORDER BY {column} {order}"
    return connection.execute(query, (org_id,)).fetchall()
