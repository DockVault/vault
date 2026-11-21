"""Records the order in which each database transaction takes the locks of signing in and of a change to how an
account signs in, and names every transaction that takes them out of order. For test stacks only: nothing in the
application loads it.

The order (app/services/sign_in.py, "The order of the locks"):

1. the account's turn at signing in (a transaction-scoped advisory lock);
2. a provider's row (``sso_providers``, read under a lock or written);
3. the account's turn at its sessions (a transaction-scoped advisory lock);
4. the account's row (``users``, read under a lock or written);
5. a row of ``credential_changes`` (read under a lock or written).

A transaction may skip any of them and may take one it already holds again. It is out of order when it takes

- the turn at signing in of an account whose turn at its sessions or whose row it holds, or after a provider's row;
- a provider's row after any turn at sessions, any account's row or any row of ``credential_changes``;
- the turn at its sessions of an account whose row it holds, or after a row of ``credential_changes``;
- an account's row it does not hold yet after a row of ``credential_changes``.

Two transactions that each keep to this cannot wait for each other in a ring over these locks. The rows a foreign
key reads when a row that names an account is inserted are not counted: they wait for nothing here, because every
lock the application takes on an account's row under a turn leaves the key free (FOR NO KEY UPDATE).

How it is turned on. The file is put where the stack's web and SFTP containers find it as ``sitecustomize`` (a
directory on PYTHONPATH, mounted by a compose override made for the test run), and ``LOCK_ORDER_OUT`` names a
directory it may write to. Each process writes ``<pid>.jsonl`` there: one line for each transaction that took one
of the locks (the kinds, in order) and one for each acquisition out of order (what was taken, what was held, the
statement and the application's frames that led to it). ``python _lock_order_recorder.py report <directory>`` adds
them up and exits 1 when anything was out of order.

The rule itself (:class:`Held`) is plain Python and is tested offline (test_lock_order_recorder.py).
"""
import json
import os
import re
import sys
import threading
import traceback

SIGN_IN_TURN, PROVIDER_ROW, SESSIONS_TURN, ACCOUNT_ROW, CHANGE_ROW = (
    "sign-in turn", "provider row", "sessions turn", "account row", "change row")
ORDER = (SIGN_IN_TURN, PROVIDER_ROW, SESSIONS_TURN, ACCOUNT_ROW, CHANGE_ROW)
# The advisory lock classes of the two turns (app/core/sign_in_lockout.py, app/api/api_server.py).
ADVISORY = {0x5349: SIGN_IN_TURN, 0x5354: SESSIONS_TURN}
ANY = "*"                        # a lock whose row the statement does not name: it stands for every row

_LOCKING_READ = re.compile(r"\bFOR\s+(NO\s+KEY\s+UPDATE|UPDATE|SHARE)\b", re.I)
_TABLES = (("users", ACCOUNT_ROW), ("sso_providers", PROVIDER_ROW), ("credential_changes", CHANGE_ROW))


def _key(value) -> str:
    return str(value).replace("-", "").lower()


def _row_keys(table, statement, parameters) -> list:
    """The rows of ``table`` the statement names by id, or [ANY] when it names none the recorder can read."""
    found = []
    if isinstance(parameters, dict):
        for name in re.findall(r"\b%s\.id\s*=\s*%%\((\w+)\)s" % table, statement):
            if parameters.get(name) is not None:
                found.append(_key(parameters[name]))
        for names in re.findall(r"\b%s\.id\s+IN\s*\(((?:%%\(\w+\)s[,\s]*)+)\)" % table, statement):
            for name in re.findall(r"%\((\w+)\)s", names):
                if parameters.get(name) is not None:
                    found.append(_key(parameters[name]))
    return found or [ANY]


def locks_of(statement, parameters) -> list:
    """The (kind, key) pairs a statement takes, in the order it takes them."""
    text = statement if isinstance(statement, str) else str(statement)
    if "pg_advisory_xact_lock" in text:
        if isinstance(parameters, dict):
            kind = ADVISORY.get(parameters.get("cls"))
            key = parameters.get("account", parameters.get("key"))
            if kind is not None and key is not None:
                return [(kind, _key(key))]
        return []
    taken = []
    head = text.lstrip()[:7].upper()
    for table, kind in _TABLES:
        if table not in text:
            continue
        written = re.match(r"\s*(UPDATE|DELETE\s+FROM)\s+%s\b" % table, text, re.I) is not None
        locked = (head.startswith("SELECT") and re.search(r"\bFROM\s+%s\b" % table, text, re.I) is not None
                  and _LOCKING_READ.search(text) is not None)
        if written or locked:
            taken.extend((kind, key) for key in _row_keys(table, text, parameters))
    return taken


class Held:
    """The locks one transaction holds, and what is out of order when it takes another."""

    def __init__(self):
        self.locks = []

    def holds(self, kind, key) -> bool:
        return any(k == kind and (j == key or j == ANY) for k, j in self.locks)

    def out_of_order(self, kind, key) -> list:
        """The held locks that should have come after (kind, key); empty when the acquisition is in order."""
        if self.holds(kind, key):
            return []
        later = [(k, j) for k, j in self.locks if ORDER.index(k) > ORDER.index(kind)]
        if kind in (SIGN_IN_TURN, SESSIONS_TURN):
            # A turn is one account's: another account's row or turn held before it starts no ring with it. A
            # provider's row and a row of credential_changes belong to no account and always count.
            later = [(k, j) for k, j in later
                     if k in (PROVIDER_ROW, CHANGE_ROW) or j in (key, ANY) or key == ANY]
        return later

    def take(self, kind, key) -> list:
        wrong = self.out_of_order(kind, key)
        if not self.holds(kind, key):
            self.locks.append((kind, key))
        return wrong


# ------------------------------------------------------------------------------------------------- the recorder

_write_lock = threading.Lock()


def _out_file():
    directory = os.environ.get("LOCK_ORDER_OUT")
    if not directory:
        return None
    return os.path.join(directory, "%d.jsonl" % os.getpid())


def _write(record) -> None:
    path = _out_file()
    if path is None:
        return
    with _write_lock:
        with open(path, "a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")


def _frames() -> list:
    return ["%s:%d %s" % (f.filename.split("/app/", 1)[-1], f.lineno, f.name)
            for f in traceback.extract_stack(limit=60) if "/app/app/" in f.filename][-8:]


def _on_statement(conn, cursor, statement, parameters, context, executemany):
    try:
        taken = locks_of(statement, parameters)
        if not taken:
            return
        held = conn.info.get("lock_order")
        if held is None:
            held = conn.info["lock_order"] = Held()
        for kind, key in taken:
            wrong = held.take(kind, key)
            if wrong:
                _write({"t": "out of order", "took": [kind, key], "held": wrong,
                        "sql": " ".join(str(statement).split())[:200], "where": _frames()})
    except Exception:      # noqa: BLE001 -- the recorder never fails the statement it watches
        pass


def _on_end(conn):
    try:
        held = conn.info.pop("lock_order", None)
        if held is not None and held.locks:
            kinds = []
            for kind, _key_ in held.locks:
                if not kinds or kinds[-1] != kind:
                    kinds.append(kind)
            _write({"t": "transaction", "kinds": kinds})
    except Exception:      # noqa: BLE001
        pass


def install() -> bool:
    """Listen to every engine of this process. False when SQLAlchemy is not there or no directory is named."""
    if not os.environ.get("LOCK_ORDER_OUT"):
        return False
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
    except Exception:      # noqa: BLE001
        return False
    event.listen(Engine, "before_cursor_execute", _on_statement)
    event.listen(Engine, "commit", _on_end)
    event.listen(Engine, "rollback", _on_end)
    return True


# ------------------------------------------------------------------------------------------------- the report

def report(directory) -> int:
    """Add up what the processes wrote under ``directory``; print it; 1 when anything was out of order."""
    transactions, shapes, wrong = 0, {}, []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".jsonl"):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as lines:
            for line in lines:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("t") == "transaction":
                    transactions += 1
                    shape = " > ".join(record["kinds"])
                    shapes[shape] = shapes.get(shape, 0) + 1
                elif record.get("t") == "out of order":
                    wrong.append(record)
    print("transactions that took one of the locks: %d" % transactions)
    for shape, count in sorted(shapes.items(), key=lambda item: -item[1]):
        print("  %7d  %s" % (count, shape))
    print("out of order: %d" % len(wrong))
    seen = {}
    for record in wrong:
        place = (tuple(record["took"][:1]), tuple(h[0] for h in record["held"]), tuple(record["where"][-3:]))
        seen.setdefault(place, []).append(record)
    for (took, held, where), records in sorted(seen.items(), key=lambda item: -len(item[1])):
        print("  %d x  took %s while holding %s" % (len(records), took[0], ", ".join(sorted(set(held)))))
        print("        %s" % records[0]["sql"])
        for frame in records[0]["where"]:
            print("        at %s" % frame)
    return 1 if wrong else 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "report":
        sys.exit(report(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
else:
    install()
