"""Whether the database behind a session has a table.

The application's own database has every table ``create_all`` makes at boot, so in the running vault this always
answers yes. A database built only with the tables a test needs may not have one, and a stand-in for a session
(no ``get_bind``) has no database at all and answers queries itself. Remembered per engine once found, so the
check costs one catalog read per table per process.
"""
from __future__ import annotations

import weakref
from typing import Dict

_FOUND: Dict[str, "weakref.WeakSet"] = {}


def has_table(db, table: str) -> bool:
    get_bind = getattr(db, "get_bind", None)
    if get_bind is None:
        return True
    bind = get_bind()
    engine = getattr(bind, "engine", bind)
    found = _FOUND.setdefault(table, weakref.WeakSet())
    if engine in found:
        return True
    from sqlalchemy import inspect
    if inspect(bind).has_table(table):
        found.add(engine)
        return True
    return False
